package gcp

import (
	"context"
	"fmt"
	"net/http"

	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/models"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
)

type Client struct {
	HTTPClient *http.Client
	Project    string
	Network    string
}

func (c *Client) MaxIpsPerRule() int {
	return 256
}

func getProjectIDFromCredentials() (string, error) {
	ctx := context.Background()
	credentials, error := google.FindDefaultCredentials(ctx, compute.ComputeScope)
	if error != nil {
		return "", error
	}
	if credentials.ProjectID == "" {
		return "", fmt.Errorf("Default credentials does not have a project ID associated")
	}
	return credentials.ProjectID, nil
}

func checkGCPConfig(config *models.GCPConfig) error {
	if config == nil {
		return fmt.Errorf("gcp cloud provider must be specified")
	}
	if config.ProjectID == "" {
		var err error
		config.ProjectID, err = getProjectIDFromCredentials()
		if err != nil || config.ProjectID == "" {
			return fmt.Errorf("can't get project id from credentials: %v", err)
		}
	}
	if config.Network == "" {
		return fmt.Errorf("network must be specified in gcp config")
	}
	return nil
}

// NewClient creates a new GCP client
func NewClient(config *models.GCPConfig) (*Client, error) {
	log.Infof("Creating client for GCP")
	err := checkGCPConfig(config)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	client, err := google.DefaultClient(ctx, compute.ComputeScope)
	if err != nil {
		log.Fatalf("Unable to get client: %v", err)
	}

	return &Client{
		HTTPClient: client,
		Project:    config.ProjectID,
		Network:    config.Network,
	}, nil
}

func (c *Client) GetProviderName() string {
	return "gcp"
}

func (c *Client) GetRules(ruleNamePrefix string) ([]*models.FirewallRule, error) {
	svc, err := compute.New(c.HTTPClient)
	if err != nil {
		log.Fatalf("Unable to create Compute service: %v", err.Error())
		return nil, err
	}

	res, err := svc.Firewalls.List(c.Project).Filter(fmt.Sprintf("name=%s*", ruleNamePrefix)).Do()
	if err != nil {
		log.Fatalf("Unable to list firewall rules: %v", err.Error())
		return nil, err
	}
	var rules []*models.FirewallRule
	log.Infof("Found %v rule(s) in GCP", len(res.Items))
	for _, gcpRule := range res.Items {
		log.Infof("%s: %#v", gcpRule.Name, gcpRule.SourceRanges)
		rule := models.FirewallRule{
			Name:         gcpRule.Name,
			SourceRanges: models.ConvertSourceRangesSliceToMap(gcpRule.SourceRanges),
		}
		rules = append(rules, &rule)
	}
	return rules, nil
}

func (c *Client) CreateRule(rule *models.FirewallRule) error {
	log.Infof("Creating GCP firewall rule %v with %#v", rule.Name, rule.SourceRanges)
	svc, err := compute.New(c.HTTPClient)
	if err != nil {
		log.Fatalf("Unable to create Compute service: %v", err.Error())
		return err
	}

	denied := compute.FirewallDenied{
		IPProtocol: "all",
	}

	firewall := compute.Firewall{
		Direction:    "INGRESS",
		Denied:       []*compute.FirewallDenied{&denied},
		Network:      fmt.Sprintf("global/networks/%s", c.Network),
		SourceRanges: models.ConvertSourceRangesMapToSlice(rule.SourceRanges),
		Name:         rule.Name,
	}
	_, err = svc.Firewalls.Insert(c.Project, &firewall).Do()
	if err != nil {
		log.Fatalf("Unable to create firewall rules %v: %v", rule.Name, err.Error())
		return err
	}
	log.Infof("Create successful")
	return nil
}

func (c *Client) DeleteRule(rule *models.FirewallRule) error {
	log.Infof("Deleting GCP firewall rule %v", rule.Name)
	svc, err := compute.New(c.HTTPClient)
	if err != nil {
		log.Fatalf("Unable to create Compute service: %v", err.Error())
		return err
	}
	_, err = svc.Firewalls.Delete(c.Project, rule.Name).Do()
	if err != nil {
		log.Fatalf("Unable to delete firewall rule %v: %v", rule.Name, err.Error())
		return err
	}
	log.Infof("Delete successful")
	return nil
}

func (c *Client) PatchRule(rule *models.FirewallRule) error {
	log.Infof("Patching GCP firewall rule %v with %#v", rule.Name, rule.SourceRanges)
	svc, err := compute.New(c.HTTPClient)
	if err != nil {
		log.Fatalf("Unable to create Compute service: %v", err.Error())
		return err
	}
	firewallPatchRequest := compute.Firewall{
		SourceRanges: models.ConvertSourceRangesMapToSlice(rule.SourceRanges),
	}
	_, err = svc.Firewalls.Patch(c.Project, rule.Name, &firewallPatchRequest).Do()
	if err != nil {
		log.Fatalf("Unable to patch firewall rule %v: %v", rule.Name, err.Error())
		return err
	}
	log.Infof("Patch successful")
	return nil
}
