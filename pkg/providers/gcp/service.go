package gcp

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
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

// To use an OAuth token (e.g., a user token obtained via a three-legged OAuth flow), use option.WithTokenSource:
//
//   config := &oauth2.Config{...}
//   // ...
//   token, err := config.Exchange(ctx, ...)
//   computeService, err := compute.NewService(ctx, option.WithTokenSource(config.TokenSource(ctx, token)))
func NewGoogleComputeService(endpoint string) *GoogleComputeService {
	opts := []option.ClientOption{}
	if endpoint != "" {
		config := &oauth2.Config{
			Endpoint: oauth2.Endpoint{
				AuthURL:  endpoint,
				TokenURL: endpoint,
			},
		}
		ctx := context.Background()
		token, err := config.Exchange(ctx, "dummy")
		if err != nil {
			log.Fatalf("Couldn't create dummy token for new Google compute service: %s", err)
		}
		opts = append(opts, option.WithEndpoint(endpoint), option.WithTokenSource(config.TokenSource(ctx, token)))
	}
	svc, err := compute.NewService(context.Background(), opts...)
	if err != nil {
		log.Fatalf("Unable to create new compute service: %s", err)
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
