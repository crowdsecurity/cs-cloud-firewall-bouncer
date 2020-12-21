package models

type CloudProviders struct {
	GCP GCPConfig `yaml:"gcp"`
	AWS AWSConfig `yaml:"aws"`
}

type GCPConfig struct {
	ProjectID string `yaml:"project_id"`
	Network   string `yaml:"network"`
}

type AWSConfig struct {
}
