package gcp

import (
	"context"
	"fmt"

	"google.golang.org/api/compute/v1"
)

type GoogleComputeServiceIface interface {
	ListFirewallRules(project string, ruleNamePrefix string) (*compute.FirewallList, error)
	InsertFirewallRule(project string, firewall *compute.Firewall) error
	DeleteFirewallRule(project string, ruleName string) error
	PatchFirewallRule(project string, ruleName string, firewallPatchRequest *compute.Firewall) error
}

type GoogleComputeService struct {
	svc *compute.Service
}

func NewGoogleComputeService() *GoogleComputeService {
	svc, err := compute.NewService(context.Background())
	if err != nil {
		log.Fatalf("Unable to create new compute service: %v", err)
	}
	return &GoogleComputeService{svc}
}

func (s *GoogleComputeService) ListFirewallRules(project string, ruleNamePrefix string) (*compute.FirewallList, error) {
	return s.svc.Firewalls.List(project).Filter(fmt.Sprintf("name=%s*", ruleNamePrefix)).Do()
}

func (s *GoogleComputeService) InsertFirewallRule(project string, firewall *compute.Firewall) error {
	_, err := s.svc.Firewalls.Insert(project, firewall).Do()
	return err
}
func (s *GoogleComputeService) DeleteFirewallRule(project string, ruleName string) error {
	_, err := s.svc.Firewalls.Delete(project, ruleName).Do()
	return err
}
func (s *GoogleComputeService) PatchFirewallRule(project string, ruleName string, firewallPatchRequest *compute.Firewall) error {
	_, err := s.svc.Firewalls.Patch(project, ruleName, firewallPatchRequest).Do()
	return err
}
