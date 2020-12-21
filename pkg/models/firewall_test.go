package models

import (
	"reflect"
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
			if got := ConvertSourceRangesMapToSlice(tt.args.sourceRanges); !reflect.DeepEqual(got, tt.want) {
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
