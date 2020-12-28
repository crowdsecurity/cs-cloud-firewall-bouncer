package models

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
)

type ruleState string

const (
	// New  indicates the rule needs to be created
	New ruleState = "new"
	// Modified indicates the rule needs to be modified
	Modified ruleState = "modified"
)

// FirewallRule represents a cloud agnostic firewall rule
type FirewallRule struct {
	// Name identifies the firewall rule name
	Name string
	// SourceRanges contains the source ranges defined in the firewall rule
	SourceRanges map[string]bool
	// State determines the operation when updating the firewall rule.
	// An empty State will result in noop when updating the rule at the cloud provider.
	State    ruleState
	Priority int64
}

// ConvertSourceRangesMapToSlice Convert SourceRanges map to slice
func ConvertSourceRangesMapToSlice(sourceRanges map[string]bool) []string {
	slice := []string{}
	for source := range sourceRanges {
		slice = append(slice, source)
	}
	return slice
}

// ConvertSourceRangesSliceToMap Convert SourceRanges slice to map
func ConvertSourceRangesSliceToMap(sourceRanges []string) map[string]bool {
	m := make(map[string]bool)
	for _, source := range sourceRanges {
		m[source] = true
	}
	return m
}

func GetCIDR(source string) string {
	_, cidr, err := net.ParseCIDR(source)
	if err != nil {
		log.Debugf("cannot parse %s to CIDR: %s. Will assume this is IPv4 and append mask /32", source, err.Error())
		return fmt.Sprintf("%s/32", source)
	}
	return cidr.String()
}
