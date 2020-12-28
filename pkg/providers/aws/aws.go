package aws

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/networkfirewall"
	"github.com/aws/aws-sdk-go/service/networkfirewall/networkfirewalliface"
	backoff "github.com/cenkalti/backoff/v4"
	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/models"
	"github.com/sirupsen/logrus"
)

type Client struct {
	svc               networkfirewalliface.NetworkFirewallAPI
	capacity          int
	firewallPolicy    string
	ruleGroupPriority int64
}

const (
	providerName          = "aws"
	defaultCapacity       = 1000
	defaultPriority int64 = 1
)

func (c *Client) MaxSourcesPerRule() int {
	return c.capacity
}
func (c *Client) MaxRules() int {
	return 1
}

func (c *Client) Priority() int64 {
	return c.ruleGroupPriority
}

func (c *Client) GetProviderName() string {
	return providerName
}

var log *logrus.Entry

func init() {
	log = logrus.WithField("provider", providerName)
}

func assignDefault(config *models.AWSConfig) {
	if config.Capacity == 0 {
		log.Debugf("Setting default rule group capacity (%d)", defaultCapacity)
		config.Capacity = defaultCapacity
	}
	if config.RuleGroupPriority == 0 {
		log.Debugf("Setting default lowest rule group priority (%d)", defaultPriority)
		config.RuleGroupPriority = defaultPriority
	}
}

// NewClient creates a new AWS client
func NewClient(config *models.AWSConfig) (*Client, error) {
	log.Infof("creating client for %s", providerName)
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config: aws.Config{
			Region:   aws.String(config.Region),
			Endpoint: aws.String(config.Endpoint),
		},
	}))
	_, err := sess.Config.Credentials.Get()
	if err != nil {
		return nil, fmt.Errorf("error while loading credentials: %s", err)
	}
	svc := networkfirewall.New(sess)
	assignDefault(config)

	return &Client{
		svc:               svc,
		capacity:          config.Capacity,
		firewallPolicy:    config.FirewallPolicy,
		ruleGroupPriority: config.RuleGroupPriority,
	}, nil
}

func (c *Client) getFirewallPolicy() (*networkfirewall.DescribeFirewallPolicyOutput, error) {
	res, err := c.svc.DescribeFirewallPolicy(&networkfirewall.DescribeFirewallPolicyInput{
		FirewallPolicyName: &c.firewallPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("can't get firewall policy %s: %s", c.firewallPolicy, err)
	}
	return res, nil
}

func (c *Client) addRuleToFirewallPolicy(ruleARN string, fp *networkfirewall.DescribeFirewallPolicyOutput) {
	newRuleRef := networkfirewall.StatelessRuleGroupReference{
		Priority:    aws.Int64(int64(c.ruleGroupPriority)),
		ResourceArn: &ruleARN,
	}
	rules := append(fp.FirewallPolicy.StatelessRuleGroupReferences, &newRuleRef)
	fp.FirewallPolicy.SetStatelessRuleGroupReferences(rules)

	input := networkfirewall.UpdateFirewallPolicyInput{
		FirewallPolicyArn: fp.FirewallPolicyResponse.FirewallPolicyArn,
		FirewallPolicy:    fp.FirewallPolicy,
		UpdateToken:       fp.UpdateToken,
	}
	_, err := c.svc.UpdateFirewallPolicy(&input)
	if err != nil {
		log.Fatalf("unable to update firewall policy %s: %s", *fp.FirewallPolicyResponse.FirewallPolicyName, err)
	}
	log.Infof("update of firewall policy %s successful", *fp.FirewallPolicyResponse.FirewallPolicyName)
}

func (c *Client) removeRuleFromFirewallPolicy(ruleARN string, fp *networkfirewall.DescribeFirewallPolicyOutput) {
	fpRulesRef := fp.FirewallPolicy.StatelessRuleGroupReferences
	fpRulesRefLen := len(fpRulesRef)
	for i, rule := range fpRulesRef {
		if *rule.ResourceArn == ruleARN {
			fpRulesRef[i] = fpRulesRef[fpRulesRefLen-1]
		}
	}
	fpRulesRef = fpRulesRef[:fpRulesRefLen-1]
	fp.FirewallPolicy.SetStatelessRuleGroupReferences(fpRulesRef)

	input := networkfirewall.UpdateFirewallPolicyInput{
		FirewallPolicyArn: fp.FirewallPolicyResponse.FirewallPolicyArn,
		FirewallPolicy:    fp.FirewallPolicy,
		UpdateToken:       fp.UpdateToken,
	}
	_, err := c.svc.UpdateFirewallPolicy(&input)
	if err != nil {
		log.Fatalf("unable to update firewall policy %s: %s", *fp.FirewallPolicyResponse.FirewallPolicyName, err)
	}
	log.Infof("successfully removed rule %s from firewall policy %s", ruleARN, *fp.FirewallPolicyResponse.FirewallPolicyName)
}

func convertSourceMapToAWSSlice(sources map[string]bool) []*networkfirewall.Address {
	slice := []*networkfirewall.Address{}
	for source := range sources {
		log.Debugf("key: %s", source)
		sourceToAppend := source
		slice = append(slice, &networkfirewall.Address{AddressDefinition: &sourceToAppend})
	}
	return slice
}

func (c *Client) GetRules(ruleNamePrefix string) ([]*models.FirewallRule, error) {

	fp, err := c.getFirewallPolicy()
	if err != nil {
		return nil, err
	}

	var rules []*models.FirewallRule
	for _, ruleGroup := range fp.FirewallPolicy.StatelessRuleGroupReferences {
		if strings.Contains(*ruleGroup.ResourceArn, ruleNamePrefix) {
			res, err := c.svc.DescribeRuleGroup(&networkfirewall.DescribeRuleGroupInput{
				RuleGroupArn: ruleGroup.ResourceArn,
			})
			if err != nil {
				return nil, fmt.Errorf("unable to get rule group %s: %s", *ruleGroup.ResourceArn, err)
			}
			if *res.RuleGroupResponse.RuleGroupStatus == networkfirewall.ResourceStatusDeleting {
				log.Debugf("skipping rule %s because it is being deleted", *res.RuleGroupResponse.RuleGroupName)
				break
			}
			var sources []string
			log.Debugf("found rule %s", *res.RuleGroupResponse.RuleGroupName)
			if len(res.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules) > 0 {
				for _, source := range res.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules[0].RuleDefinition.MatchAttributes.Sources {
					sources = append(sources, *source.AddressDefinition)
				}
			}
			log.Infof("%s  (%d sources): %#v", *res.RuleGroupResponse.RuleGroupName, len(sources), sources)
			rule := models.FirewallRule{
				Name:         *res.RuleGroupResponse.RuleGroupName,
				SourceRanges: models.ConvertSourceRangesSliceToMap(sources),
				Priority:     *res.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules[0].Priority,
			}
			rules = append(rules, &rule)
		}
	}
	log.Infof("found %d rule(s)", len(rules))

	return rules, nil
}

func (c *Client) CreateRule(rule *models.FirewallRule) error {
	log.Infof("creating rule group %s with %#v", rule.Name, rule.SourceRanges)
	ruleType := networkfirewall.RuleGroupTypeStateless

	awsRule := networkfirewall.StatelessRule{
		Priority: aws.Int64(rule.Priority),
		RuleDefinition: &networkfirewall.RuleDefinition{
			MatchAttributes: &networkfirewall.MatchAttributes{
				Sources: convertSourceMapToAWSSlice(rule.SourceRanges),
			},
			Actions: []*string{aws.String("aws:drop")},
		},
	}

	rg, err := c.svc.CreateRuleGroup(&networkfirewall.CreateRuleGroupInput{
		Capacity:      aws.Int64(int64(c.capacity)),
		Description:   aws.String("Blocklist generated by CrowdSec Cloud Firewall Bouncer"),
		RuleGroupName: &rule.Name,
		RuleGroup: &networkfirewall.RuleGroup{
			RulesSource: &networkfirewall.RulesSource{
				StatelessRulesAndCustomActions: &networkfirewall.StatelessRulesAndCustomActions{
					StatelessRules: []*networkfirewall.StatelessRule{&awsRule},
				},
			},
		},
		Type: &ruleType,
	})
	if err != nil {
		return fmt.Errorf("unable to create rule group %s: %s", rule.Name, err)
	}
	fp, err := c.getFirewallPolicy()
	if err != nil {
		return err
	}
	c.addRuleToFirewallPolicy(*rg.RuleGroupResponse.RuleGroupArn, fp)

	log.Infof("creation of rule group %s successful", rule.Name)
	return nil
}

func (c *Client) DeleteRule(rule *models.FirewallRule) error {
	log.Infof("deleting firewall rule %s", rule.Name)
	res, err := c.svc.DescribeRuleGroup(&networkfirewall.DescribeRuleGroupInput{
		RuleGroupName: &rule.Name,
		Type:          aws.String(networkfirewall.RuleGroupTypeStateless),
	})
	if err != nil {
		return fmt.Errorf("unable to get rule group %s: %s", rule.Name, err)
	}
	fp, err := c.getFirewallPolicy()
	if err != nil {
		return err
	}
	c.removeRuleFromFirewallPolicy(*res.RuleGroupResponse.RuleGroupArn, fp)

	input := networkfirewall.DeleteRuleGroupInput{
		RuleGroupArn: res.RuleGroupResponse.RuleGroupArn,
	}

	// Deleting rule group too fast might fail because it it still being removed from the firewall policy.
	// Since there does not seem to be any status state in the policy that indicates the completion, we
	// simply retry using exponential backoff, up to 1 min.
	tryToDeleteRuleGroup := func() error {
		_, err := c.svc.DeleteRuleGroup(&input)
		return err
	}
	exponentialBackoff := backoff.NewExponentialBackOff()
	exponentialBackoff.MaxElapsedTime = 1 * time.Minute
	err = backoff.Retry(tryToDeleteRuleGroup, exponentialBackoff)
	if err != nil {
		return fmt.Errorf("unable to delete firewall rule %s: %s", rule.Name, err)
	}
	log.Infof("delete successful")
	return nil
}

func (c *Client) PatchRule(rule *models.FirewallRule) error {
	log.Infof("patching firewall rule %s with %#v", rule.Name, rule.SourceRanges)
	ruleType := networkfirewall.RuleGroupTypeStateless
	res, err := c.svc.DescribeRuleGroup(&networkfirewall.DescribeRuleGroupInput{
		RuleGroupName: &rule.Name,
		Type:          aws.String(networkfirewall.RuleGroupTypeStateless),
	})
	if err != nil {
		return fmt.Errorf("unable to get rule group %s: %s", rule.Name, err)
	}
	res.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules[0].RuleDefinition.MatchAttributes.Sources = convertSourceMapToAWSSlice(rule.SourceRanges)

	input := networkfirewall.UpdateRuleGroupInput{
		RuleGroupName: &rule.Name,
		Type:          &ruleType,
		RuleGroup:     res.RuleGroup,
		UpdateToken:   res.UpdateToken,
	}
	_, err = c.svc.UpdateRuleGroup(&input)
	if err != nil {
		return fmt.Errorf("unable to patch firewall rule %s: %s", rule.Name, err)
	}
	log.Infof("patch of rule %s successful", rule.Name)
	return nil
}
