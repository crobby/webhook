package machineconfigs

import (
	"fmt"

	"github.com/rancher/webhook/pkg/admission"
	v1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	"github.com/rancher/webhook/pkg/resources/mutation"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

var gvr = schema.GroupVersionResource{
	Group:    "rke-machine-config.cattle.io",
	Version:  "v1",
	Resource: "*",
}

// Mutator implements admission.MutatingAdmissionWebhook.
type Mutator struct{}

// GVR returns the GroupVersionKind for this CRD.
func (m *Mutator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this mutator.
func (m *Mutator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create}
}

// MutatingWebhook returns the MutatingWebhook used for this CRD.
func (m *Mutator) MutatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) *admissionregistrationv1.MutatingWebhook {
	mutatingWebhook := admission.NewDefaultMutationWebhook(m, clientConfig, admissionregistrationv1.NamespacedScope)
	mutatingWebhook.SideEffects = admission.Ptr(admissionregistrationv1.SideEffectClassNoneOnDryRun)
	return mutatingWebhook
}

// Admit is the entrypoint for the mutator. Admit will return an error if it unable to process the request.
func (m *Mutator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	if request.DryRun != nil && *request.DryRun {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
	}

	listTrace := trace.New("machine config Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	config, err := v1.UnstructuredFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get object from request: %w", err)
	}
	response := &admissionv1.AdmissionResponse{}
	if err := mutation.SetCreatorIDAnnotation(request, response, request.Object, config.DeepCopy()); err != nil {
		return nil, fmt.Errorf("failed to set creatorIDAnnotation: %w", err)
	}
	response.Allowed = true
	return response, nil
}
