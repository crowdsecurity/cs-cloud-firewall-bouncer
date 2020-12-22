package main

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"

	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/models"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v2"
)

type bouncerConfig struct {
	CloudProviders  models.CloudProviders `yaml:"cloud_providers"`
	RuleNamePrefix  string                `yaml:"rule_name_prefix"`
	UpdateFrequency string                `yaml:"update_frequency"`
	Daemon          bool                  `yaml:"daemonize"`
	LogMode         string                `yaml:"log_mode"`
	LogDir          string                `yaml:"log_dir"`
	LogLevel        log.Level             `yaml:"log_level"`
	APIUrl          string                `yaml:"api_url"`
	APIKey          string                `yaml:"api_key"`
}

/* checkRuleNamePrefixValid validates that the rule name prefix meets the following requirements:

- All lower case characters

- First character is a letter

- Total of 42 alphanumeric characters, including the character "-"
*/
func checkRuleNamePrefixValid(ruleNamePrefix string) error {
	re := regexp.MustCompile(`^(?:[a-z](?:[-a-z0-9]{0,41})?)$`)
	match := re.MatchString(ruleNamePrefix)
	if !match {
		return fmt.Errorf("rule_name_prefix %s does not match the following regex: %s", ruleNamePrefix, re.String())
	}
	return nil
}

func newConfig(configPath string) (*bouncerConfig, error) {
	var LogOutput *lumberjack.Logger //io.Writer

	config := &bouncerConfig{}

	configBuff, err := ioutil.ReadFile(configPath)
	if err != nil {
		return &bouncerConfig{}, fmt.Errorf("failed to read %s : %v", configPath, err)
	}

	if err := yaml.UnmarshalStrict(configBuff, &config); err != nil {
		return &bouncerConfig{}, fmt.Errorf("failed to unmarshal %s : %v", configPath, err)
	}

	config.RuleNamePrefix = strings.ToLower(config.RuleNamePrefix)

	if config.RuleNamePrefix == "" {
		return &bouncerConfig{}, fmt.Errorf("rule_name_prefix must be specified")
	}

	if err := checkRuleNamePrefixValid(config.RuleNamePrefix); err != nil {
		return &bouncerConfig{}, err
	}

	/*Configure logging*/
	if err = types.SetDefaultLoggerConfig(config.LogMode, config.LogDir, config.LogLevel); err != nil {
		log.Fatal(err.Error())
	}
	if config.LogMode == "file" {
		if config.LogDir == "" {
			config.LogDir = "/var/log/"
		}
		LogOutput = &lumberjack.Logger{
			Filename:   config.LogDir + "/cs-cloud-firewall-bouncer.log",
			MaxSize:    500, //megabytes
			MaxBackups: 3,
			MaxAge:     28,   //days
			Compress:   true, //disabled by default
		}
		log.SetOutput(LogOutput)
		log.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})
	} else if config.LogMode != "stdout" {
		return &bouncerConfig{}, fmt.Errorf("log mode '%s' unknown, expecting 'file' or 'stdout'", config.LogMode)
	}
	return config, nil
}
