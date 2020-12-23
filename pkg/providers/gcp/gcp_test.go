package gcp

import (
	"testing"

	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/models"
	"google.golang.org/api/compute/v1"
	"gotest.tools/assert"
)

type mockGoogleSvc struct {
	GoogleComputeServiceIface
}

func (s *mockGoogleSvc) ListFirewallRules(project string, ruleNamePrefix string) (*compute.FirewallList, error) {
	return &compute.FirewallList{
		Items: []*compute.Firewall{
			{
				Name:         "crowdsec-bingo-jumbo",
				SourceRanges: []string{"1.2.3.4/32"},
			},
		},
	}, nil
}

func (s *mockGoogleSvc) InsertFirewallRule(project string, firewall *compute.Firewall) error {
	return nil
}
func (s *mockGoogleSvc) DeleteFirewallRule(project string, ruleName string) error {
	return nil
}
func (s *mockGoogleSvc) PatchFirewallRule(project string, ruleName string, firewallPatchRequest *compute.Firewall) error {
	return nil
}

func TestGetRules(t *testing.T) {

	mockSvc := &mockGoogleSvc{}
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

	mockSvc := &mockGoogleSvc{}
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

	mockSvc := &mockGoogleSvc{}
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

	mockSvc := &mockGoogleSvc{}
	c := Client{
		svc: mockSvc,
	}
	rule := models.FirewallRule{
		Name: "crowdsec-bingo-jumbo",
		SourceRanges: map[string]bool{
			"1.0.0.0/32": true,
			"1.1.0.0/32": true,
		},
	}
	_ = c.PatchRule(&rule)
}
