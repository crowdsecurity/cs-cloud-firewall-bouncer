package cloudarmor

import (
	"context"

	"golang.org/x/oauth2"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

type GoogleComputeServiceIface interface {
	GetFirewallPolicy(project string, policyName string) (*compute.SecurityPolicy, error)
	AddRule(project string, policyName string, rule *compute.SecurityPolicyRule) (*compute.Operation, error)
	RemoveRule(project string, policyName string, rulePriority int64) (*compute.Operation, error)
	PatchRule(project string, policyName string, rule *compute.SecurityPolicyRule, rulePriority int64) (*compute.Operation, error)
	WaitOperation(project string, operation string) error
}

type GoogleComputeService struct {
	svc *compute.Service
}

// NewGoogleComputeService creates the compute service.
// The default endpoint can be overriden for testing purpose (to make calls to a mock server instead of the real Google servers).
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

func (s *GoogleComputeService) GetFirewallPolicy(project string, policyName string) (*compute.SecurityPolicy, error) {
	return s.svc.SecurityPolicies.Get(project, policyName).Do()
}

func (s *GoogleComputeService) AddRule(project string, policyName string, rule *compute.SecurityPolicyRule) (*compute.Operation, error) {
	return s.svc.SecurityPolicies.AddRule(project, policyName, rule).Do()
}

func (s *GoogleComputeService) RemoveRule(project string, policyName string, rulePriority int64) (*compute.Operation, error) {
	return s.svc.SecurityPolicies.RemoveRule(project, policyName).Priority(rulePriority).Do()
}

func (s *GoogleComputeService) PatchRule(project string, policyName string, rule *compute.SecurityPolicyRule, rulePriority int64) (*compute.Operation, error) {
	return s.svc.SecurityPolicies.PatchRule(project, policyName, rule).Priority(rulePriority).Do()
}

func (s *GoogleComputeService) WaitOperation(project string, operation string) error {
	_, err := s.svc.GlobalOperations.Wait(project, operation).Do()
	return err
}
