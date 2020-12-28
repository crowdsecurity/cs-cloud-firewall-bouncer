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

func convertDecisionsToMap(decisions []*csmodels.Decision) map[string]bool {

	m := make(map[string]bool)
	for _, decision := range decisions {
		cidr := models.GetCIDR(*decision.Value)
		m[cidr] = true
	}
	return m
}
func removeDuplicatesDecisions(deleted map[string]bool, new map[string]bool) {

	for d := range deleted {
		for n := range new {
			if d == n {
				delete(deleted, d)
			}
		}
	}
}

// Update updates the cloud firewall with the decisions specified
func (f *Bouncer) Update(decisionStream *csmodels.DecisionsStreamResponse) error {
	rules, err := f.Client.GetRules(f.RuleNamePrefix)
	if err != nil {
		return err
	}

	deleted := convertDecisionsToMap(decisionStream.Deleted)
	new := convertDecisionsToMap(decisionStream.New)
	removeDuplicatesDecisions(deleted, new)
	deleteSourceRanges(rules, deleted)

	rules = f.addSourceRanges(rules, new)
	err = f.updateProviderFirewallRules(rules)
	if err != nil {
		return err
	}
	return nil
}

func deleteSourceRanges(rules []*models.FirewallRule, sources map[string]bool) {
	log.Debugf("deleting source ranges")
	if len(rules) == 0 {
		return
	}
	for source := range sources {
		deleteSourceRange(rules, source)
	}
}

func (f *Bouncer) addSourceRanges(rules []*models.FirewallRule, sources map[string]bool) []*models.FirewallRule {
	log.Debugf("adding source ranges")
	for source := range sources {
		log.Debugf("processiong decision %s", source)
		rules = f.addSourceRangeToRules(rules, source)
	}
	return rules
}

func deleteSourceRange(rules []*models.FirewallRule, source string) {
	for _, rule := range rules {
		if rule.SourceRanges[source] {
			log.Debugf("deleting %s from %s", source, rule.Name)
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

func (f *Bouncer) addSourceRangeToRules(rules []*models.FirewallRule, source string) []*models.FirewallRule {
	if sourceExists(rules, source) {
		log.Debugf("%s already exist", source)
		return rules
	}
	log.Debugf("adding %s to rules", source)
	rule, rules, err := f.getRuleToUpdate(rules)
	if err != nil {
		log.Warning(err)
		return rules
	}
	rule.SourceRanges[source] = true
	log.Debugf("added %s to %s", source, rule.Name)
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
		ruleToUpdate = f.genNewRule(rules)
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
		ruleToUpdate = f.genNewRule(rules)
		rules = append(rules, ruleToUpdate)
	}
	return ruleToUpdate, rules, nil
}

func (f *Bouncer) getNextPriority(rules []*models.FirewallRule) int64 {
	if len(rules) == 0 {
		return f.Client.Priority()
	}
	highestPriority := f.Client.Priority()
	for _, rule := range rules {
		if rule.Priority > highestPriority {
			highestPriority = rule.Priority
		}
	}
	return highestPriority + 1
}

// genNewRuleName generates a new rule name by appending 2 random words to the rule name prefix.
func (f *Bouncer) genNewRuleName() string {
	randomWords := diceware.MustGenerate(2)
	r := fmt.Sprintf("%s-%s", f.RuleNamePrefix, strings.ToLower(strings.Join(randomWords, "-")))
	return r
}

func (f *Bouncer) genNewRule(rules []*models.FirewallRule) *models.FirewallRule {

	return &models.FirewallRule{
		Name:         f.genNewRuleName(),
		SourceRanges: make(map[string]bool),
		State:        models.New,
		Priority:     f.getNextPriority(rules),
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
