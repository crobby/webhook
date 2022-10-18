package token

import (
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"time"

	"github.com/rancher/webhook/pkg/patch"
	"github.com/rancher/wrangler/pkg/webhook"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/trace"
)

func NewMutator() webhook.Handler {
	return &mutator{}
}

type mutator struct{}

func (m *mutator) Admit(response *webhook.Response, request *webhook.Request) error {
	if request.DryRun != nil && *request.DryRun {
		response.Allowed = true
		return nil
	}

	listTrace := trace.New("token Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	token, err := tokenObject(request)
	if err != nil {
		return err
	}

	logrus.Debugf("[token-mutation] adding empty groupPrincipals[] token: %v", request.UserInfo.Username, token.Name)
	newToken := token.DeepCopy()

	if newToken.GroupPrincipals == nil {
		newToken.GroupPrincipals = make([]v3.Principal, 0)
		return patch.CreatePatch(token, newToken, response)
	} else {
		response.Allowed = true
		return nil
	}
}

func tokenObject(request *webhook.Request) (*v3.Token, error) {
	var token runtime.Object
	var err error
	if request.Operation == admissionv1.Delete {
		token, err = request.DecodeOldObject()
	} else {
		token, err = request.DecodeObject()
	}
	return token.(*v3.Token), err
}
