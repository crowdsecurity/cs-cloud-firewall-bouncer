package models

type CloudProviders struct {
	GCP GCPConfig `yaml:"gcp"`
	AWS AWSConfig `yaml:"aws"`
}

type GCPConfig struct {
	Disabled  bool   `yaml:"disabled"`
	ProjectID string `yaml:"project_id"`
	Network   string `yaml:"network"`
}

type AWSConfig struct {
	Disabled          bool   `yaml:"disabled"`
	Region            string `yaml:"region"`
	FirewallPolicy    string `yaml:"firewall_policy"`
	Capacity          int    `yaml:"capacity"`
	RuleGroupPriority int    `yaml:"rule_group_priority"`
}
