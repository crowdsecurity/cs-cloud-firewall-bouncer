package main

import "testing"

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
			name: "too_many_chars",
			args: args{
				"abcdefghijklmnnopqrstuvwxyz-0123456789abcde",
			},
			wantErr: true,
		},
		{
			name: "limit_chars",
			args: args{
				"abcdefghijklmnnopqrstuvwxyz-0123456789abcd",
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
