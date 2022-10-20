package projectpodsecuritytemplatebinding

import (
	"fmt"
	"github.com/rancher/webhook/pkg/clients"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/webhook"
	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/trace"
	"net/http"
	"strings"
	"time"
)

import (
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

func NewValidator(client *clients.Clients) webhook.Handler {
	return &projectPodSecurityTBValidator{
		sar: client.K8s.AuthorizationV1().SubjectAccessReviews(),
	}
}

type projectPodSecurityTBValidator struct {
	sar authorizationv1.SubjectAccessReviewInterface
}

func (c *projectPodSecurityTBValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("projectPodSecurityTBValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	// We need to check permission on the target project rather than the cluster level
	// so we fetch the psptpb and get the TargetProjectName to use that in our SAR
	psptpb, err := objectsv3.PodSecurityPolicyTemplateProjectBindingFromRequest(request)
	if err != nil {
		return fmt.Errorf("failed to decode PSPTPB from request: %w", err)
	}
	targetProject := strings.Split(psptpb.TargetProjectName, ":")[1]

	resp, err := c.sar.Create(request.Context, &v1.SubjectAccessReview{
		Spec: v1.SubjectAccessReviewSpec{
			ResourceAttributes: &v1.ResourceAttributes{
				Verb:      "update",
				Version:   "v3",
				Resource:  "podsecuritypolicytemplateprojectbindings",
				Group:     "management.cattle.io",
				Namespace: targetProject,
			},
			User:   request.UserInfo.Username,
			Groups: request.UserInfo.Groups,
			UID:    request.UserInfo.UID,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	if resp.Status.Allowed {
		response.Allowed = true
	} else {
		response.Result = &metav1.Status{
			Status:  "Failure",
			Message: resp.Status.Reason,
			Reason:  metav1.StatusReasonUnauthorized,
			Code:    http.StatusUnauthorized,
		}
	}
	return nil
}
