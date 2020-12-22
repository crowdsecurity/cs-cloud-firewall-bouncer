package config

import (
	"reflect"
	"testing"

	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/models"
	log "github.com/sirupsen/logrus"
)

func Test_checkRuleNamePrefixValid(t *testing.T) {
	type args struct {
		ruleNamePrefix string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid",
			args: args{
				"test-rule-1234",
			},
			wantErr: false,
		},
		{
			name: "valid",
			args: args{
				"TEST-rule-1234",
			},
			wantErr: true,
		},
		{
			name: "invalid_first_char",
			args: args{
				"1test-rule",
			},
			wantErr: true,
		},
		{
			name: "invalid_chars",
			args: args{
				"test-rule_`",
			},
			wantErr: true,
		},
		{
			name: "invalid_twodash",
			args: args{
				"test--rule",
			},
			wantErr: true,
		},
		{
			name: "too_many_chars",
			args: args{
				"abcdefghijklmnnopqrstuvwxyz-0123456789abcdefg",
			},
			wantErr: true,
		},
		{
			name: "limit_chars",
			args: args{
				"abcdefghijklmnnopqrstuvwxyz-0123456789abcdef",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkRuleNamePrefixValid(tt.args.ruleNamePrefix); (err != nil) != tt.wantErr {
				t.Errorf("checkRuleNamePrefixValid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateConfig(t *testing.T) {
	type args struct {
		configBuff []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *BouncerConfig
		wantErr bool
	}{
		{
			name: "valid config",
			args: args{
				configBuff: []byte("cloud_providers:\n" +
					"  gcp:\n" +
					"    network: default\n" +
					"rule_name_prefix: crowdsec\n" +
					"update_frequency: 10s\n" +
					"daemonize: false\n" +
					"log_mode: stdout\n" +
					"log_dir: log/\n" +
					"log_level: info\n" +
					"api_url: http://crowdsec:8080/\n" +
					"api_key: 42c09b2ea8b2905b9333db61c6f4f94c"),
			},
			want: &BouncerConfig{
				CloudProviders: models.CloudProviders{
					GCP: models.GCPConfig{
						ProjectID: "",
						Network:   "default",
					},
				},
				RuleNamePrefix:  "crowdsec",
				UpdateFrequency: "10s",
				Daemon:          false,
				LogMode:         "stdout",
				LogDir:          "log/",
				LogLevel:        log.InfoLevel,
				APIUrl:          "http://crowdsec:8080/",
				APIKey:          "42c09b2ea8b2905b9333db61c6f4f94c",
			},
			wantErr: false,
		},
		{
			name: "valid config with logs",
			args: args{
				configBuff: []byte("cloud_providers:\n" +
					"  gcp:\n" +
					"    network: default\n" +
					"rule_name_prefix: crowdsec\n" +
					"update_frequency: 10s\n" +
					"daemonize: false\n" +
					"log_mode: file\n" +
					"log_level: info\n" +
					"api_url: http://crowdsec:8080/\n" +
					"api_key: 42c09b2ea8b2905b9333db61c6f4f94c"),
			},
			want: &BouncerConfig{
				CloudProviders: models.CloudProviders{
					GCP: models.GCPConfig{
						ProjectID: "",
						Network:   "default",
					},
				},
				RuleNamePrefix:  "crowdsec",
				UpdateFrequency: "10s",
				Daemon:          false,
				LogMode:         "file",
				LogDir:          "/var/log/",
				LogLevel:        log.InfoLevel,
				APIUrl:          "http://crowdsec:8080/",
				APIKey:          "42c09b2ea8b2905b9333db61c6f4f94c",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateConfig(tt.args.configBuff)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}
