package aws

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/networkfirewall"
	"github.com/aws/aws-sdk-go/service/networkfirewall/networkfirewalliface"
	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/models"
	"gotest.tools/assert"
)

type mockedAWSSvc struct {
	networkfirewalliface.NetworkFirewallAPI
}

func (s *mockedAWSSvc) DescribeFirewallPolicy(*networkfirewall.DescribeFirewallPolicyInput) (*networkfirewall.DescribeFirewallPolicyOutput, error) {
	return &networkfirewall.DescribeFirewallPolicyOutput{
		FirewallPolicyResponse: &networkfirewall.FirewallPolicyResponse{
			FirewallPolicyName: aws.String("firewall-policy"),
			FirewallPolicyArn:  aws.String("arn:aws:firewall-policy"),
		},
		FirewallPolicy: &networkfirewall.FirewallPolicy{
			StatelessRuleGroupReferences: []*networkfirewall.StatelessRuleGroupReference{
				{
					ResourceArn: aws.String("arn:aws:crowdsec-bingo-jumbo"),
				},
				{
					ResourceArn: aws.String("arn:aws:crowdsec-deleting"),
				},
			},
		},
		UpdateToken: aws.String("token"),
	}, nil
}
func (s *mockedAWSSvc) UpdateFirewallPolicy(*networkfirewall.UpdateFirewallPolicyInput) (*networkfirewall.UpdateFirewallPolicyOutput, error) {
	return &networkfirewall.UpdateFirewallPolicyOutput{}, nil
}
func (s *mockedAWSSvc) DescribeRuleGroup(input *networkfirewall.DescribeRuleGroupInput) (*networkfirewall.DescribeRuleGroupOutput, error) {
	if input.RuleGroupArn != nil && *input.RuleGroupArn == "arn:aws:crowdsec-bingo-jumbo" || input.RuleGroupName != nil && *input.RuleGroupName == "crowdsec-bingo-jumbo" {
		return &networkfirewall.DescribeRuleGroupOutput{
			RuleGroupResponse: &networkfirewall.RuleGroupResponse{
				RuleGroupArn:    aws.String("arn:aws:crowdsec-bingo-jumbo"),
				RuleGroupName:   aws.String("crowdsec-bingo-jumbo"),
				RuleGroupStatus: aws.String(networkfirewall.ResourceStatusActive),
			},
			RuleGroup: &networkfirewall.RuleGroup{
				RulesSource: &networkfirewall.RulesSource{
					StatelessRulesAndCustomActions: &networkfirewall.StatelessRulesAndCustomActions{
						StatelessRules: []*networkfirewall.StatelessRule{
							{
								RuleDefinition: &networkfirewall.RuleDefinition{
									MatchAttributes: &networkfirewall.MatchAttributes{
										Sources: []*networkfirewall.Address{
											{
												AddressDefinition: aws.String("1.2.3.4/32")},
										},
									},
								},
								Priority: aws.Int64(1),
							},
						},
					},
				},
			},
		}, nil
	} else if *input.RuleGroupArn == "arn:aws:crowdsec-deleting" {
		return &networkfirewall.DescribeRuleGroupOutput{
			RuleGroupResponse: &networkfirewall.RuleGroupResponse{
				RuleGroupName:   aws.String("crowdsec-deleting"),
				RuleGroupStatus: aws.String(networkfirewall.ResourceStatusDeleting),
			},
		}, nil
	}
	return nil, fmt.Errorf("Invalid arn")
}
func (s *mockedAWSSvc) UpdateRuleGroup(*networkfirewall.UpdateRuleGroupInput) (*networkfirewall.UpdateRuleGroupOutput, error) {
	return &networkfirewall.UpdateRuleGroupOutput{}, nil
}
func (s *mockedAWSSvc) DeleteRuleGroup(*networkfirewall.DeleteRuleGroupInput) (*networkfirewall.DeleteRuleGroupOutput, error) {
	return &networkfirewall.DeleteRuleGroupOutput{}, nil
}

func (s *mockedAWSSvc) CreateRuleGroup(*networkfirewall.CreateRuleGroupInput) (*networkfirewall.CreateRuleGroupOutput, error) {
	return &networkfirewall.CreateRuleGroupOutput{
		RuleGroupResponse: &networkfirewall.RuleGroupResponse{
			RuleGroupArn: aws.String("arn:aws:crowdsec-bingo-jumbo"),
		},
	}, nil
}
func TestGetRules(t *testing.T) {

	mockSvc := &mockedAWSSvc{}
	c := Client{
		svc: mockSvc,
	}
	rules, err := c.GetRules("crowdsec")
	if err != nil {
		log.Fatal(err)
	}
	assert.Equal(t, 1, len(rules))
	assert.Equal(t, "crowdsec-bingo-jumbo", rules[0].Name)
}
func TestCreateRule(t *testing.T) {

	mockSvc := &mockedAWSSvc{}
	c := Client{
		svc: mockSvc,
	}
	rule := models.FirewallRule{
		Name: "crowdsec-bingo-jumbo",
		SourceRanges: map[string]bool{
			"1.0.0.0/32": true,
			"1.1.0.0/32": true,
			"1.1.1.0/32": true,
		},
	}
	_ = c.CreateRule(&rule)
}

func TestDeleteRule(t *testing.T) {

	mockSvc := &mockedAWSSvc{}
	c := Client{
		svc: mockSvc,
	}
	rule := models.FirewallRule{
		Name:         "crowdsec-bingo-jumbo",
		SourceRanges: map[string]bool{},
	}
	_ = c.DeleteRule(&rule)
}

func TestPatchRule(t *testing.T) {

	mockSvc := &mockedAWSSvc{}
	c := Client{
		svc: mockSvc,
	}
	rule := models.FirewallRule{
		Name:         "crowdsec-bingo-jumbo",
		SourceRanges: map[string]bool{},
	}
	_ = c.PatchRule(&rule)
}

func TestAssignDefaultConfig(t *testing.T) {
	config := models.AWSConfig{
		Capacity:          0,
		RuleGroupPriority: 0,
	}
	assignDefault(&config)
	assert.Equal(t, defaultCapacity, config.Capacity)
	assert.Equal(t, defaultPriority, config.RuleGroupPriority)
}
