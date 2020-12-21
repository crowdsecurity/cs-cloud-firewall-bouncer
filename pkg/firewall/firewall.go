package firewall

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/tjarratt/babble"

	csmodels "github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/models"
	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/providers"
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
	err = f.updateGCPFirewallRules(rules)
	if err != nil {
		return err
	}
	return nil
}

func deleteSourceRanges(rules []*models.FirewallRule, decisions []*csmodels.Decision) {
	log.Debugf("Deleting source ranges")
	if len(rules) == 0 {
		return
	}
	for _, decision := range decisions {
		deleteSourceRange(rules, *decision.Value)
	}
}

func (f *Bouncer) addSourceRanges(rules []*models.FirewallRule, decisions []*csmodels.Decision) []*models.FirewallRule {
	log.Debugf("Adding source ranges")
	for _, decision := range decisions {
		log.Debugf("Processiong decision %#v", decision)
		rules = f.addSourceRangeToRules(rules, decision)
	}
	return rules
}

func deleteSourceRange(rules []*models.FirewallRule, source string) {
	for _, rule := range rules {
		if rule.SourceRanges[source] {
			log.Debugf("Deleting %v from %v", source, rule.Name)
			delete(rule.SourceRanges, source)
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
	if sourceExists(rules, *source) {
		log.Debugf("%v already exist", *source)
		return rules
	}
	log.Debugf("Adding %v to rules", *source)
	rule, rules := f.getRuleToUpdate(rules)
	rule.SourceRanges[*(decision.Value)] = true
	log.Debugf("Added %v to %v", *source, rule.Name)
	return rules
}

func (f *Bouncer) getRuleToUpdate(rules []*models.FirewallRule) (*models.FirewallRule, []*models.FirewallRule) {
	max := f.Client.MaxIpsPerRule()
	currentRuleMax := 0
	ruleToUpdate := &models.FirewallRule{
		Name: "blank",
	}
	if len(rules) == 0 {
		ruleToUpdate = f.genNewRule()
		rules = append(rules, ruleToUpdate)
		return ruleToUpdate, rules
	}
	// Find the rule that has the most source to fill up
	for _, rule := range rules {
		count := len(rule.SourceRanges)
		if count > currentRuleMax && count < max {
			currentRuleMax = count
			ruleToUpdate = rule
			if ruleToUpdate.State == "" {
				ruleToUpdate.State = models.Modified
			}
		}
	}
	// Rules are full, we need to create a new one
	if ruleToUpdate.Name == "blank" {
		ruleToUpdate = f.genNewRule()
		rules = append(rules, ruleToUpdate)
	}
	return ruleToUpdate, rules
}

func (f *Bouncer) genNewRuleName() string {
	babbler := babble.NewBabbler()
	babbler.Count = 2
	r := fmt.Sprintf("%s-%s", f.RuleNamePrefix, strings.ToLower(babbler.Babble()))
	return r
}

func (f *Bouncer) genNewRule() *models.FirewallRule {
	return &models.FirewallRule{
		Name:         f.genNewRuleName(),
		SourceRanges: make(map[string]bool),
		State:        models.New,
	}
}

func (f *Bouncer) updateGCPFirewallRules(rules []*models.FirewallRule) error {
	if len(rules) == 0 {
		return nil
	}
	log.Debugf("Updating GCP firewall rules")
	for _, rule := range rules {
		log.Debugf("Processing rule %#v", *rule)
		switch rule.State {
		case models.New:
			err := f.Client.CreateRule(rule)
			if err != nil {
				return err
			}
			break
		case models.Modified:
			err := f.updateGCPRule(rule)
			if err != nil {
				return err
			}
			break
		}
	}
	return nil
}

func (f *Bouncer) updateGCPRule(rule *models.FirewallRule) error {
	log.Debugf("Updating GCP firewall rule %v", rule.Name)
	if len(rule.SourceRanges) == 0 {
		err := f.Client.DeleteRule(rule)
		return err
	}
	err := f.Client.PatchRule(rule)
	return err
}

func (f *Bouncer) ShutDown() error {
	log.Infof("Shutting down %s firewall bouncer", f.Client.GetProviderName())
	return nil
}
