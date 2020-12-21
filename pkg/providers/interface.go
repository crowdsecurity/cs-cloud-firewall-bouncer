package providers

import (
	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/models"
)

// CloudClient is an interface representing cloud providers client
type CloudClient interface {
	// GetProviderName returns the name of the cloud provider.
	GetProviderName() string
	// MaxIpsPerRule returns the maximum number of source range or IP that a firewall rule can contain.
	MaxIpsPerRule() int
	// GetRules returns the firewall rules that matches the ruleNamePrefix.
	GetRules(ruleNamePrefix string) ([]*models.FirewallRule, error)
	// CreateRule creates the firewall rule at the cloud provider.
	CreateRule(rule *models.FirewallRule) error
	// DeleteRule deletes the firewall rule at the cloud provider that matches the rule name.
	DeleteRule(rule *models.FirewallRule) error
	// PatchRule updates the source ranges of the firewall rule at the cloud provider that matches the rule name.
	PatchRule(rule *models.FirewallRule) error
}
