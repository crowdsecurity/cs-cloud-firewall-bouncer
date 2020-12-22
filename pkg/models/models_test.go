package models

import (
	"reflect"
	"sort"
	"testing"
)

func TestConvertSourceRangesMapToSlice(t *testing.T) {
	type args struct {
		sourceRanges map[string]bool
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{"single list", args{map[string]bool{"1.0.0.0": true}}, []string{"1.0.0.0"}},
		{"multi list", args{map[string]bool{"1.0.0.0": true, "1.1.0.0": true, "1.1.1.0": true}}, []string{"1.0.0.0", "1.1.0.0", "1.1.1.0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertSourceRangesMapToSlice(tt.args.sourceRanges)
			sort.Strings(got)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ConvertSourceRangesMapToSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConvertSourceRangesSliceToMap(t *testing.T) {
	type args struct {
		sourceRanges []string
	}
	tests := []struct {
		name string
		args args
		want map[string]bool
	}{
		{"single list", args{[]string{"1.0.0.0"}}, map[string]bool{"1.0.0.0": true}},
		{"multi list", args{[]string{"1.0.0.0", "1.1.0.0", "1.1.1.0"}}, map[string]bool{"1.0.0.0": true, "1.1.0.0": true, "1.1.1.0": true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ConvertSourceRangesSliceToMap(tt.args.sourceRanges); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ConvertSourceRangesSliceToMap() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetCIDR(t *testing.T) {
	type args struct {
		source string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "ipv4_to_cidr",
			args: args{
				"1.2.3.4",
			},
			want: "1.2.3.4/32",
		},
		{
			name: "cidr_to_cidr",
			args: args{
				"1.2.3.4/32",
			},
			want: "1.2.3.4/32",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetCIDR(tt.args.source); got != tt.want {
				t.Errorf("GetCIDR() = %v, want %v", got, tt.want)
			}
		})
	}
}
