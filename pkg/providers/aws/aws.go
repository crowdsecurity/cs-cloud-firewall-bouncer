package aws

import (
	"fmt"
	"net/http"

	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/models"
)

type Client struct {
	HTTPClient *http.Client
}

func (c *Client) MaxIpsPerRule() int {
	return 256
}

func (c *Client) GetProviderName() string {
	return "aws"
}

// NewClient creates a new AWS client
func NewClient(config *models.AWSConfig) (*Client, error) {
	return nil, fmt.Errorf("AWS Client not implemented yet.")
}

func (c *Client) GetRules(ruleNamePrefix string) ([]*models.FirewallRule, error) {
	return nil, fmt.Errorf("AWS Client not implemented yet.")
}

func (c *Client) CreateRule(rule *models.FirewallRule) error {
	return fmt.Errorf("AWS Client not implemented yet.")
}

func (c *Client) DeleteRule(rule *models.FirewallRule) error {
	return fmt.Errorf("AWS Client not implemented yet.")
}

func (c *Client) PatchRule(rule *models.FirewallRule) error {
	return fmt.Errorf("AWS Client not implemented yet.")
}
