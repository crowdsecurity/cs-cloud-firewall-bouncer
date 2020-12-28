package cloudarmor

import (
	"context"
	"fmt"
	"strings"

	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/models"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
)

type Client struct {
	svc      GoogleComputeServiceIface
	project  string
	policy   string
	priority int64
	maxRules int
}

const (
	providerName    = "cloudarmor"
	defaultMaxRules = 100
)

var log *logrus.Entry

func init() {
	log = logrus.WithField("provider", providerName)
}

func (c *Client) MaxSourcesPerRule() int {
	return 10
}
func (c *Client) MaxRules() int {
	return c.maxRules
}
func (c *Client) Priority() int64 {
	return c.priority
}

func getProjectIDFromCredentials(config *models.CloudArmorConfig) (string, error) {
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

func checkCloudArmorConfig(config *models.CloudArmorConfig) error {
	if config == nil {
		return fmt.Errorf("gcp cloud provider must be specified")
	}
	if config.ProjectID == "" {
		var err error
		config.ProjectID, err = getProjectIDFromCredentials(config)
		if err != nil || config.ProjectID == "" {
			return fmt.Errorf("can't get project id from credentials: %s", err)
		}
	}
	if config.Policy == "" {
		return fmt.Errorf("policy must be specified in cloudarmor config")
	}
	if config.MaxRules == 0 {
		config.MaxRules = defaultMaxRules
	}
	return nil
}

// NewClient creates a new GCP client
func NewClient(config *models.CloudArmorConfig) (*Client, error) {
	log.Infof("creating client for %s", providerName)
	err := checkCloudArmorConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error while checking GCP config: %s", err)
	}

	return &Client{
		svc:      NewGoogleComputeService(config.Endpoint),
		project:  config.ProjectID,
		policy:   config.Policy,
		priority: config.Priority,
		maxRules: config.MaxRules,
	}, nil
}

func (c *Client) GetProviderName() string {
	return providerName
}

func (c *Client) GetRules(ruleNamePrefix string) ([]*models.FirewallRule, error) {
	res, err := c.svc.GetFirewallPolicy(c.project, c.policy)
	if err != nil {
		return nil, fmt.Errorf("unable to get firewall policy %s: %s", c.policy, err)
	}

	var rules []*models.FirewallRule
	for _, r := range res.Rules {
		if !strings.HasPrefix(r.Description, ruleNamePrefix) {
			continue
		}
		log.Infof("%s  (%d sources): %#v", r.Description, len(r.Match.Config.SrcIpRanges), r.Match.Config.SrcIpRanges)
		rule := models.FirewallRule{
			Name:         r.Description,
			SourceRanges: models.ConvertSourceRangesSliceToMap(r.Match.Config.SrcIpRanges),
			Priority:     r.Priority,
		}
		rules = append(rules, &rule)
	}
	return rules, nil
}

func (c *Client) CreateRule(rule *models.FirewallRule) error {
	log.Infof("creating cloud armor policy rule %s with %#v", rule.Name, rule.SourceRanges)

	policyRule := compute.SecurityPolicyRule{
		Action: "deny(403)",
		Match: &compute.SecurityPolicyRuleMatcher{
			Config: &compute.SecurityPolicyRuleMatcherConfig{
				SrcIpRanges: models.ConvertSourceRangesMapToSlice(rule.SourceRanges),
			},
			VersionedExpr: "SRC_IPS_V1",
		},
		Description: rule.Name,
		Priority:    rule.Priority,
	}
	op, err := c.svc.AddRule(c.project, c.policy, &policyRule)
	if err != nil {
		return fmt.Errorf("unable to create policy rule %s: %s", rule.Name, err)
	}
	if err = c.svc.WaitOperation(c.project, op.Name); err != nil {
		return fmt.Errorf("problem waiting on operation %s: %s", op.Name, err)
	}
	log.Infof("creation of policy rule %s successful", rule.Name)
	return nil
}

func (c *Client) DeleteRule(rule *models.FirewallRule) error {
	log.Infof("deleting policy rule %s", rule.Name)
	op, err := c.svc.RemoveRule(c.project, c.policy, rule.Priority)
	if err != nil {
		return fmt.Errorf("unable to delete policy rule %s: %s", rule.Name, err)
	}
	if err = c.svc.WaitOperation(c.project, op.Name); err != nil {
		return fmt.Errorf("problem waiting on operation %s: %s", op.Name, err)
	}
	log.Infof("deletion of policy rule %s successful", rule.Name)
	return nil
}

func (c *Client) PatchRule(rule *models.FirewallRule) error {
	log.Infof("patching policy rule %s with %#v", rule.Name, rule.SourceRanges)
	rulePatchRequest := compute.SecurityPolicyRule{
		Match: &compute.SecurityPolicyRuleMatcher{
			Config: &compute.SecurityPolicyRuleMatcherConfig{
				SrcIpRanges: models.ConvertSourceRangesMapToSlice(rule.SourceRanges),
			},
			VersionedExpr: "SRC_IPS_V1",
		},
	}
	op, err := c.svc.PatchRule(c.project, c.policy, &rulePatchRequest, rule.Priority)
	if err != nil {
		return fmt.Errorf("unable to patch policy rule %s: %s", rule.Name, err)
	}
	if err = c.svc.WaitOperation(c.project, op.Name); err != nil {
		return fmt.Errorf("problem waiting on operation %s: %s", op.Name, err)
	}
	log.Infof("patching of policy rule %s successful", rule.Name)
	return nil
}
