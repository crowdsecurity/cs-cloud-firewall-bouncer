package firewall

import (
	"fmt"
	"testing"

	csmodels "github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/models"
	"github.com/fallard84/cs-cloud-firewall-bouncer/pkg/providers"
	testingUtils "github.com/fallard84/cs-cloud-firewall-bouncer/pkg/testing"
	"github.com/stretchr/testify/assert"
)

func TestBouncer_getRuleToUpdate(t *testing.T) {
	type args struct {
		rules []*models.FirewallRule
	}
	tests := map[string]args{
		"empty": {
			rules: nil,
		},
		"existing": {
			rules: []*models.FirewallRule{{
				Name: "test-rule-dummy",
				SourceRanges: map[string]bool{
					"1.0.0.0/32": true,
					"1.1.0.0/32": true,
				},
			}},
		},
		"full_create_new": {
			rules: []*models.FirewallRule{{
				Name: "test-rule-dummy",
				SourceRanges: map[string]bool{
					"1.0.0.0/32": true,
					"1.1.0.0/32": true,
					"1.1.1.0/32": true,
				},
			}},
		},
		"full_fail": {
			rules: []*models.FirewallRule{{
				Name: "test-rule-dummy",
				SourceRanges: map[string]bool{
					"1.0.0.0/32": true,
					"1.1.0.0/32": true,
					"1.1.1.0/32": true,
				},
			},
				{
					Name: "test-rule-dummy2",
					SourceRanges: map[string]bool{
						"1.0.0.0/32": true,
						"1.1.0.0/32": true,
						"1.1.1.0/32": true,
					},
				},
			},
		},
	}
	var fakeClient, _ = testingUtils.NewEmptyClient()
	var f = &Bouncer{fakeClient, "test-rule"}
	t.Run("empty", func(t *testing.T) {
		rule, rules, _ := f.getRuleToUpdate(tests["empty"].rules)
		assert.Contains(t, rule.Name, f.RuleNamePrefix)
		assert.Regexp(t, "^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", rule.Name)
		fmt.Printf("rule name: %s", rule.Name)
		assert.Equal(t, 1, len(rules))
		assert.Equal(t, rules[0].Name, rule.Name)
		assert.Equal(t, models.New, rule.State)
	})
	t.Run("existing", func(t *testing.T) {
		rule, rules, _ := f.getRuleToUpdate(tests["existing"].rules)
		assert.Equal(t, "test-rule-dummy", rule.Name)
		assert.Equal(t, 1, len(rules))
		assert.Equal(t, models.Modified, rule.State)
	})
	t.Run("full_create_new", func(t *testing.T) {
		rule, rules, _ := f.getRuleToUpdate(tests["full_create_new"].rules)
		assert.NotEqual(t, "test-rule-dummy", rule.Name)
		assert.Equal(t, 2, len(rules))
		assert.Contains(t, rule.Name, f.RuleNamePrefix)
		assert.Equal(t, models.New, rule.State)
	})
	t.Run("full_fail", func(t *testing.T) {
		rule, rules, err := f.getRuleToUpdate(tests["full_fail"].rules)
		if (err != nil) != true {
			t.Errorf("getRuleToUpdate should throw error when rules at max capacity")
		}
		assert.Nil(t, rule)
		assert.Equal(t, 2, len(rules))
		assert.Equal(t, tests["full_fail"].rules, rules)
	})
}

func TestAddSourceRangeToEmptyRules(t *testing.T) {
	var fakeClient, _ = testingUtils.NewEmptyClient()
	var f = &Bouncer{fakeClient, "test-rule"}
	var rules []*models.FirewallRule
	source1 := "0.0.0.1"
	decision1 := csmodels.Decision{Value: &source1}
	rules = f.addSourceRangeToRules(rules, &decision1)
	assert.Equal(t, len(rules[0].SourceRanges), 1)
}

// TestBouncer_Update Tests the whole update flow
func TestBouncer_Update(t *testing.T) {
	type fields struct {
		Client         providers.CloudClient
		RuleNamePrefix string
	}
	type args struct {
		decisionStream *csmodels.DecisionsStreamResponse
	}
	clientEmpty, _ := testingUtils.NewEmptyClient()
	clientOneRule, _ := testingUtils.NewClientExistingRules()

	source1 := "0.0.0.1"
	source2 := "0.0.0.2"
	source3 := "1.0.0.0"
	source4 := "1.1.1.0"
	decisionsStream := &csmodels.DecisionsStreamResponse{
		Deleted: csmodels.GetDecisionsResponse{&csmodels.Decision{Value: &source1}, &csmodels.Decision{Value: &source4}},
		New:     csmodels.GetDecisionsResponse{&csmodels.Decision{Value: &source2}, &csmodels.Decision{Value: &source3}},
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "empty_project",
			fields: fields{
				Client:         clientEmpty,
				RuleNamePrefix: "test-rule",
			},
			args: args{
				decisionStream: decisionsStream,
			},
			wantErr: false,
		},
		{
			name: "existing_rule",
			fields: fields{
				Client:         clientOneRule,
				RuleNamePrefix: "test-rule",
			},
			args: args{
				decisionStream: decisionsStream,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f = &Bouncer{tt.fields.Client, tt.fields.RuleNamePrefix}
			if err := f.Update(tt.args.decisionStream); (err != nil) != tt.wantErr {
				t.Errorf("Bouncer.Update() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_deleteSourceRanges(t *testing.T) {
	type args struct {
		rules     []*models.FirewallRule
		decisions []*csmodels.Decision
	}
	source1 := "0.0.0.1"
	source2 := "1.0.0.0"
	tests := map[string]args{
		"no_op": {
			rules: []*models.FirewallRule{{
				Name: "test-rule-1",
				SourceRanges: map[string]bool{
					"1.0.0.0/32": true,
				},
			}},
			decisions: []*csmodels.Decision{{Value: &source1}},
		},
		"op": {
			rules: []*models.FirewallRule{{
				Name: "test-rule-1",
				SourceRanges: map[string]bool{
					"1.0.0.0/32": true,
					"1.1.1.0/32": true,
				},
			}},
			decisions: []*csmodels.Decision{{Value: &source2}},
		},
	}
	t.Run("no_op", func(t *testing.T) {
		deleteSourceRanges(tests["no_op"].rules, tests["no_op"].decisions)
		assert.Equal(t, 1, len(tests["no_op"].rules[0].SourceRanges))
	})
	t.Run("op", func(t *testing.T) {
		deleteSourceRanges(tests["op"].rules, tests["op"].decisions)
		assert.Equal(t, 1, len(tests["op"].rules[0].SourceRanges))
	})
}
