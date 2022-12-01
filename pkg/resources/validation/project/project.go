package project

import (
	"fmt"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/clients"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	v1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/utils/trace"
	"net/http"
	"time"
)

const (
	EnforceLabel = "pod-security.kubernetes.io/enforce"
	AuditLabel   = "pod-security.kubernetes.io/audit"
	WarnLabel    = "pod-security.kubernetes.io/warn"
)

var gvr = schema.GroupVersionResource{
	Version:  "v3",
	Resource: "projects",
	Group:    "management.cattle.io",
}

// Validator validates the namespace admission request
type Validator struct {
	sar authorizationv1.SubjectAccessReviewInterface
}

// NewValidator returns a new validator used for validation of namespace requests.
func NewValidator(clients *clients.Clients) *Validator {
	return &Validator{
		sar: clients.K8s.AuthorizationV1().SubjectAccessReviews(),
	}
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Update}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) *admissionregistrationv1.ValidatingWebhook {
	return admission.NewDefaultValidationWebhook(v, clientConfig, admissionregistrationv1.NamespacedScope)
}

// Admit is the entrypoint for the validator.
// Admit will return an error if it unable to process the request.
func (v *Validator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("Project Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	response := &admissionv1.AdmissionResponse{}

	oldns, ns, err := objectsv1.NamespaceOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		response.Result.Code = http.StatusBadRequest
		return response, fmt.Errorf("failed to decode namespace from request: %w", err)
	}

	if oldns == nil {
		return nil, nil
	}
	// Is the request attempting to modify the special PSA labels (enforce, warn, audit)
	// If it isn't, we're done
	// If it is, we then need to check to see if they should be allowed...only admin/restricted admin
	if !isUpdatingPSAConfig(oldns, ns) {
		response.Allowed = true
	}

	resp, err := v.sar.Create(request.Context, &v1.SubjectAccessReview{
		Spec: v1.SubjectAccessReviewSpec{
			ResourceAttributes: &v1.ResourceAttributes{
				Name:      ns.Namespace,
				Verb:      "updatepsa",
				Group:     "management.cattle.io",
				Version:   "v3",
				Resource:  "projects",
				Namespace: ns.Namespace,
			},
			User:   request.UserInfo.Username,
			Groups: request.UserInfo.Groups,
			UID:    request.UserInfo.UID,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return response, err
	}

	if resp.Status.Allowed {
		response.Allowed = true
	} else {
		response.Result = &metav1.Status{
			Status:  "Failure",
			Message: resp.Status.Reason,
			Reason:  metav1.StatusReasonUnauthorized,
			Code:    http.StatusForbidden,
		}
	}
	return response, nil
}

func isUpdatingPSAConfig(oldns *corev1.Namespace, ns *corev1.Namespace) bool {
	for _, label := range []string{EnforceLabel, AuditLabel, WarnLabel} {
		if oldns.Labels[label] != ns.Labels[label] {
			return true
		}
	}
	return false
}
