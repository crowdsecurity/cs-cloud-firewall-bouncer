package testing

import (
	"net/http"

	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/models"
)

type FakeClientEmpty struct {
	Client  *http.Client
	Project string
	Network string
}

func (c *FakeClientEmpty) GetProviderName() string {
	return "fake-client-empty"
}

func NewEmptyClient(project string, network string) (*FakeClientEmpty, error) {

	return &FakeClientEmpty{
		Client:  nil,
		Project: project,
		Network: network,
	}, nil
}

func (c *FakeClientEmpty) MaxIpsPerRule() int {
	return 3
}

func (c *FakeClientEmpty) GetRules(ruleNamePrefix string) ([]*models.FirewallRule, error) {
	return nil, nil
}

func (c *FakeClientEmpty) CreateRule(rule *models.FirewallRule) error {
	return nil
}

func (c *FakeClientEmpty) DeleteRule(rule *models.FirewallRule) error {
	return nil
}

func (c *FakeClientEmpty) PatchRule(rule *models.FirewallRule) error {
	return nil
}

type FakeClientExistingRules struct {
	Client  *http.Client
	Project string
	Network string
}

func (c *FakeClientExistingRules) GetProviderName() string {
	return "fake-client-existing-rules"
}

func NewClientExistingRules(project string, network string) (*FakeClientExistingRules, error) {

	return &FakeClientExistingRules{
		Client:  nil,
		Project: project,
		Network: network,
	}, nil
}

func (c *FakeClientExistingRules) MaxIpsPerRule() int {
	return 6
}

func (c *FakeClientExistingRules) GetRules(ruleNamePrefix string) ([]*models.FirewallRule, error) {

	return []*models.FirewallRule{{
		Name: "rule1",
		SourceRanges: map[string]bool{
			"1.0.0.0": true,
			"1.1.0.0": true,
			"1.1.1.0": true,
		},
	}, {
		Name: "rule2",
		SourceRanges: map[string]bool{
			"1.1.1.0": true,
		},
	}}, nil
}

func (c *FakeClientExistingRules) CreateRule(rule *models.FirewallRule) error {
	return nil
}

func (c *FakeClientExistingRules) DeleteRule(rule *models.FirewallRule) error {
	return nil
}

func (c *FakeClientExistingRules) PatchRule(rule *models.FirewallRule) error {
	return nil
}
