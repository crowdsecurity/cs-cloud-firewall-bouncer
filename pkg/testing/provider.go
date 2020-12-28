package testing

import (
	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/models"
)

type FakeClientEmpty struct{}

func (c *FakeClientEmpty) GetProviderName() string {
	return "fake-client-empty"
}

func NewEmptyClient() (*FakeClientEmpty, error) {

	return &FakeClientEmpty{}, nil
}

func (c *FakeClientEmpty) MaxSourcesPerRule() int {
	return 3
}

func (c *FakeClientEmpty) MaxRules() int {
	return 2
}

func (c *FakeClientEmpty) Priority() int64 {
	return 0
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
}

func (c *FakeClientExistingRules) GetProviderName() string {
	return "fake-client-existing-rules"
}

func NewClientExistingRules() (*FakeClientExistingRules, error) {

	return &FakeClientExistingRules{}, nil
}

func (c *FakeClientExistingRules) MaxSourcesPerRule() int {
	return 6
}
func (c *FakeClientExistingRules) MaxRules() int {
	return 2
}

func (c *FakeClientExistingRules) Priority() int64 {
	return 0
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
