package firewall

import (
	"fmt"
	"strings"

	csmodels "github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/models"
	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/providers"
	"github.com/sethvargo/go-diceware/diceware"
	log "github.com/sirupsen/logrus"
)

type Bouncer struct {
	Client         providers.CloudClient
	RuleNamePrefix string
}

// Update updates the cloud firewall with the decisions specified
func (f *Bouncer) Update(decisionStream *csmodels.DecisionsStreamResponse) error {
	rules, err := f.Client.GetRules(f.RuleNamePrefix)
	if err != nil {
		return err
	}
	deleteSourceRanges(rules, decisionStream.Deleted)
	rules = f.addSourceRanges(rules, decisionStream.New)
	err = f.updateProviderFirewallRules(rules)
	if err != nil {
		return err
	}
	return nil
}

func deleteSourceRanges(rules []*models.FirewallRule, decisions []*csmodels.Decision) {
	log.Debugf("deleting source ranges")
	if len(rules) == 0 {
		return
	}
	for _, decision := range decisions {
		deleteSourceRange(rules, *decision.Value)
	}
}

func (f *Bouncer) addSourceRanges(rules []*models.FirewallRule, decisions []*csmodels.Decision) []*models.FirewallRule {
	log.Debugf("adding source ranges")
	for _, decision := range decisions {
		log.Debugf("processiong decision %s", *decision.Value)
		rules = f.addSourceRangeToRules(rules, decision)
	}
	return rules
}

func deleteSourceRange(rules []*models.FirewallRule, source string) {
	cidr := models.GetCIDR(source)
	for _, rule := range rules {
		if rule.SourceRanges[cidr] {
			log.Debugf("deleting %s from %s", cidr, rule.Name)
			delete(rule.SourceRanges, cidr)
			rule.State = models.Modified
		}
	}
}

func sourceExists(rules []*models.FirewallRule, source string) bool {
	for _, rule := range rules {
		if rule.SourceRanges[source] {
			return true
		}
	}
	return false
}

func (f *Bouncer) addSourceRangeToRules(rules []*models.FirewallRule, decision *csmodels.Decision) []*models.FirewallRule {

	source := decision.Value
	cidr := models.GetCIDR(*source)
	if sourceExists(rules, cidr) {
		log.Debugf("%s already exist", cidr)
		return rules
	}
	log.Debugf("Adding %s to rules", cidr)
	rule, rules, err := f.getRuleToUpdate(rules)
	if err != nil {
		log.Warning(err)
		return rules
	}
	rule.SourceRanges[cidr] = true
	log.Debugf("added %s to %s", cidr, rule.Name)
	return rules
}

func (f *Bouncer) getRuleToUpdate(rules []*models.FirewallRule) (*models.FirewallRule, []*models.FirewallRule, error) {
	max := f.Client.MaxSourcesPerRule()
	currentRuleMax := 0
	ruleToUpdate := &models.FirewallRule{
		Name: "blank",
	}
	if len(rules) == 0 {
		log.Debugf("no existing rule, we need to create a new one")
		ruleToUpdate = f.genNewRule()
		rules = append(rules, ruleToUpdate)
		return ruleToUpdate, rules, nil
	}
	// Find the rule that has the most source to fill up
	for _, rule := range rules {
		count := len(rule.SourceRanges)
		if count >= currentRuleMax && count < max {
			currentRuleMax = count
			ruleToUpdate = rule
			if ruleToUpdate.State == "" {
				ruleToUpdate.State = models.Modified
			}
		}
	}
	if ruleToUpdate.Name == "blank" {
		log.Infof("rules are full, we need to create a new one")
		if len(rules) >= f.Client.MaxRules() {
			return nil, rules, fmt.Errorf("can't create a new rule, at maximum capacity")
		}
		ruleToUpdate = f.genNewRule()
		rules = append(rules, ruleToUpdate)
	}
	return ruleToUpdate, rules, nil
}

// genNewRuleName generates a new rule name by appending 2 random words to the rule name prefix.
func (f *Bouncer) genNewRuleName() string {
	randomWords := diceware.MustGenerate(2)
	r := fmt.Sprintf("%s-%s", f.RuleNamePrefix, strings.ToLower(strings.Join(randomWords, "-")))
	return r
}

func (f *Bouncer) genNewRule() *models.FirewallRule {
	return &models.FirewallRule{
		Name:         f.genNewRuleName(),
		SourceRanges: make(map[string]bool),
		State:        models.New,
	}
}

func (f *Bouncer) updateProviderFirewallRules(rules []*models.FirewallRule) error {
	if len(rules) == 0 {
		return nil
	}
	log.Debugf("updating firewall rules")
	for _, rule := range rules {
		log.Debugf("processing rule %#v", *rule)
		switch rule.State {
		case models.New:
			err := f.Client.CreateRule(rule)
			if err != nil {
				return err
			}
		case models.Modified:
			err := f.updateRule(rule)
			if err != nil {
				return err
			}
		default:
			log.Debugf("state did not change, results in noop")
		}
	}
	return nil
}

func (f *Bouncer) updateRule(rule *models.FirewallRule) error {
	log.Debugf("updating firewall rule %s", rule.Name)
	if len(rule.SourceRanges) == 0 {
		err := f.Client.DeleteRule(rule)
		return err
	}
	err := f.Client.PatchRule(rule)
	return err
}

func (f *Bouncer) ShutDown() error {
	log.Infof("shutting down %s firewall bouncer", f.Client.GetProviderName())
	return nil
}
