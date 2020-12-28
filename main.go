package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/confluentinc/bincover"
	"github.com/coreos/go-systemd/daemon"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/config"
	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/firewall"
	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/models"
	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/providers"
	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/providers/aws"
	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/providers/cloudarmor"
	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/providers/gcp"
	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/version"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

const (
	name = "cs-cloud-firewall-bouncer"
)

var (
	// Injected from linker flags like `go build -ldflags "-X github.com/fallard84/cs-cloud-firewall-bouncer.isTest=true"`
	isTest = "false"
)

var t tomb.Tomb

func termHandler(sig os.Signal, fb *firewall.Bouncer) error {
	if err := fb.ShutDown(); err != nil {
		return err
	}
	return nil
}

func handleSignals(firewallBouncers []*firewall.Bouncer, done chan struct{}) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan)

	exitChan := make(chan int)
	go func() {
		for {
			s := <-signalChan
			switch s {
			// kill -SIGTERM XXXX
			case syscall.SIGABRT:
				fallthrough
			case syscall.SIGINT:
				fallthrough
			case syscall.SIGTERM:
				for _, fb := range firewallBouncers {
					if err := termHandler(s, fb); err != nil {
						log.Errorf("shutdown fail: %s", err)
						exitChan <- 1
					} else {
						exitChan <- 0
					}
				}
			}
		}
	}()
	go func() {
		code := 0
		for range firewallBouncers {
			if <-exitChan == 1 {
				code = 1
			}
		}
		log.Infof("shutting down bouncer service")
		done <- struct{}{}
		if isTest == "true" {
			bincover.ExitCode = code
		} else {
			os.Exit(code)
		}
	}()
}

func getProviderClients(config config.BouncerConfig) ([]providers.CloudClient, error) {
	cloudClients := []providers.CloudClient{}
	if (models.GCPConfig{}) != config.CloudProviders.GCP && !config.CloudProviders.GCP.Disabled {
		gcpClient, err := gcp.NewClient(&config.CloudProviders.GCP)
		if err != nil {
			return nil, err
		}
		cloudClients = append(cloudClients, gcpClient)
	}
	if (models.AWSConfig{}) != config.CloudProviders.AWS && !config.CloudProviders.AWS.Disabled {
		awsClient, err := aws.NewClient(&config.CloudProviders.AWS)
		if err != nil {
			return nil, err
		}
		cloudClients = append(cloudClients, awsClient)
	}
	if (models.CloudArmorConfig{}) != config.CloudProviders.CloudArmor && !config.CloudProviders.CloudArmor.Disabled {
		cloudArmorClient, err := cloudarmor.NewClient(&config.CloudProviders.CloudArmor)
		if err != nil {
			return nil, err
		}
		cloudClients = append(cloudClients, cloudArmorClient)
	}
	if len(cloudClients) == 0 {
		return nil, fmt.Errorf("at least one cloud provider must be configured")
	}
	return cloudClients, nil
}

func getFirewallBouncers(config config.BouncerConfig) ([]*firewall.Bouncer, error) {
	clients, err := getProviderClients(config)
	if err != nil {
		log.Fatalf("unable to get provider client: %s", err.Error())
		return nil, err
	}
	firewallBouncers := []*firewall.Bouncer{}
	for _, client := range clients {
		firewallBouncers = append(firewallBouncers, &firewall.Bouncer{Client: client, RuleNamePrefix: config.RuleNamePrefix})
	}
	return firewallBouncers, nil
}

func main() {
	var err error
	done := make(chan struct{})

	log.Infof("%s %s", name, version.Version)
	configPath := flag.String("c", "", "path to config file")
	verbose := flag.Bool("v", false, "set verbose mode")

	flag.Parse()

	if configPath == nil || *configPath == "" {
		log.Fatalf("configuration file is required")
	}

	config, err := config.NewConfig(*configPath)
	if err != nil {
		log.Fatalf("unable to load configuration: %s", err)
	}

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	firewallBouncers, err := getFirewallBouncers(*config)
	if err != nil {
		log.Fatalf("unable to get provider firewall bouncers: %s", err.Error())
	}

	bouncer := &csbouncer.StreamBouncer{
		APIKey:         config.APIKey,
		APIUrl:         config.APIUrl,
		TickerInterval: config.UpdateFrequency,
		UserAgent:      fmt.Sprintf("%s/%s", name, version.VersionStr()),
	}
	if err := bouncer.Init(); err != nil {
		log.Fatalf(err.Error())
	}

	go bouncer.Run()

	t.Go(func() error {
		for {
			select {
			case <-t.Dying():
				log.Infoln("terminating bouncer process")
				return nil
			case decisions := <-bouncer.Stream:
				log.Debugf("processing '%d' delete and '%d' new decisions", len(decisions.Deleted), len(decisions.New))
				if len(decisions.Deleted) > 0 || len(decisions.New) > 0 {
					log.Infof("processing '%d' delete and '%d' new decisions", len(decisions.Deleted), len(decisions.New))
					for _, fb := range firewallBouncers {
						if err := fb.Update(decisions); err != nil {
							log.Errorf("unable to process decisions : %s", err)
						} else {
							log.Debugf("process completed")
						}
					}
				}
			}
		}
	})

	if config.Daemon == true {
		sent, err := daemon.SdNotify(false, "READY=1")
		if !sent && err != nil {
			log.Errorf("failed to notify: %s", err)
		}
	}
	handleSignals(firewallBouncers, done)

	go func() {
		err = t.Wait()
		if err != nil {
			log.Fatalf("process return with error: %s", err)
		}
	}()

	<-done
	log.Info("process finished cleanly")
	return
}
