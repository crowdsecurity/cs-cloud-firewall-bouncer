package config

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"

	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/models"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v2"
)

type BouncerConfig struct {
	CloudProviders  models.CloudProviders `yaml:"cloud_providers"`
	RuleNamePrefix  string                `yaml:"rule_name_prefix"`
	UpdateFrequency string                `yaml:"update_frequency"`
	Daemon          bool                  `yaml:"daemonize"`
	LogMode         string                `yaml:"log_mode"`
	LogDir          string                `yaml:"log_dir"`
	LogLevel        log.Level             `yaml:"log_level"`
	APIUrl          string                `yaml:"api_url"`
	APIKey          string                `yaml:"api_key"`
}

// checkRuleNamePrefixValid validates that the rule name prefix complies specific requirements.
// The rule name generated must comply with RFC1035. Since two random words (maximum 19 characters)
// are appended to the rule name prefix to create unique rule names, this checks that
// the rule name prefix be 1-44 characters long and match the regular expression `^(?:[a-z](?:[-a-z0-9]{0,43})?)$. The first
// character must be a lowercase letter, and all following characters must be a dash, lowercase letter, or
// digit. The name cannot contain two consecutive dash ('-') characters.
func checkRuleNamePrefixValid(ruleNamePrefix string) error {
	if strings.Contains(ruleNamePrefix, "--") {
		return fmt.Errorf("rule_name_prefix %s must not have two consecutive dash ('-') characters", ruleNamePrefix)
	}
	re := regexp.MustCompile(`^(?:[a-z](?:[-a-z0-9]{0,43})?)$`)
	match := re.MatchString(ruleNamePrefix)
	if !match {
		return fmt.Errorf("rule_name_prefix %s does not match the following regex: %s", ruleNamePrefix, re.String())
	}
	return nil
}

func GenerateConfig(configBuff []byte) (*BouncerConfig, error) {

	config := &BouncerConfig{}
	if err := yaml.UnmarshalStrict(configBuff, &config); err != nil {
		return &BouncerConfig{}, fmt.Errorf("failed to unmarshal yaml config file: %s", err)
	}

	config.RuleNamePrefix = strings.ToLower(config.RuleNamePrefix)

	if config.RuleNamePrefix == "" {
		return &BouncerConfig{}, fmt.Errorf("rule_name_prefix must be specified")
	}

	if err := checkRuleNamePrefixValid(config.RuleNamePrefix); err != nil {
		return &BouncerConfig{}, err
	}

	/*Configure logging*/
	if err := types.SetDefaultLoggerConfig(config.LogMode, config.LogDir, config.LogLevel); err != nil {
		log.Fatal(err.Error())
	}
	if config.LogMode == "file" {
		if config.LogDir == "" {
			config.LogDir = "/var/log/"
		}
		var LogOutput *lumberjack.Logger //io.Writer
		LogOutput = &lumberjack.Logger{
			Filename:   config.LogDir + "/cs-cloud-firewall-bouncer.log",
			MaxSize:    500, //megabytes
			MaxBackups: 3,
			MaxAge:     28,   //days
			Compress:   true, //disabled by default
		}
		log.SetOutput(LogOutput)
		log.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})
	} else if config.LogMode != "stdout" {
		return &BouncerConfig{}, fmt.Errorf("log mode '%s' unknown, expecting 'file' or 'stdout'", config.LogMode)
	}
	return config, nil
}

func NewConfig(configPath string) (*BouncerConfig, error) {
	configBuff, err := ioutil.ReadFile(configPath)

	if err != nil {
		return &BouncerConfig{}, fmt.Errorf("failed to read %s : %s", configPath, err)
	}
	return GenerateConfig(configBuff)
}
