// Package integration holds the integration test for the webhook.
package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/rancher/lasso/pkg/client"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	provisioningv1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/wrangler/pkg/gvk"
	"github.com/rancher/wrangler/pkg/kubeconfig"
	"github.com/rancher/wrangler/pkg/schemes"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const testNamespace = "foo"

type IntegrationSuite struct {
	suite.Suite
	clientFactory client.SharedClientFactory
}

func TestIntegrationTest(t *testing.T) {
	suite.Run(t, new(IntegrationSuite))
}

func (m *IntegrationSuite) SetupSuite() {
	logrus.SetLevel(logrus.DebugLevel)
	kubeconfigPath := os.Getenv("KUBECONFIG")
	logrus.Infof("Setting up test with KUBECONFIG=%s", kubeconfigPath)
	restCfg, err := kubeconfig.GetNonInteractiveClientConfig(kubeconfigPath).ClientConfig()
	m.Require().NoError(err, "Failed to clientFactory config")
	m.clientFactory, err = client.NewSharedClientFactoryForConfig(restCfg)
	m.Require().NoError(err, "Failed to create clientFactory Interface")

	schemes.Register(v3.AddToScheme)
	schemes.Register(provisioningv1.AddToScheme)

	ns := &corev1.Namespace{
		ObjectMeta: v1.ObjectMeta{
			Name: testNamespace,
		},
	}
	m.createObj(ns, schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Namespace",
	})
}

func (m *IntegrationSuite) TearDownSuite() {
	ns := &corev1.Namespace{
		ObjectMeta: v1.ObjectMeta{
			Name: testNamespace,
		},
	}
	m.deleteObj(ns, schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Namespace",
	})
}

// Object is generic object to wrap runtime and metav1.
type Object interface {
	v1.Object
	runtime.Object
}
type endPointObjs[T Object] struct {
	invalidCreate  func() T
	validCreateObj T
	newObj         func() T
	invalidUpdate  func(obj T) T
	validUpdate    func(obj T) T
	invalidDelete  func() T
	validDelete    func() T
	gvk            schema.GroupVersionKind
}

func (m *IntegrationSuite) TestFeatureEndpoints() {
	newObj := func() *v3.Feature { return &v3.Feature{} }
	validCreateObj := &v3.Feature{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-feature",
		},
		Spec: v3.FeatureSpec{Value: Ptr(false)},
		Status: v3.FeatureStatus{
			LockedValue: Ptr(false),
			Description: "status description",
		},
	}
	invalidUpdate := func(created *v3.Feature) *v3.Feature {
		invalidUpdateObj := created.DeepCopy()
		invalidUpdateObj.Spec.Value = Ptr(true)
		return invalidUpdateObj
	}
	validUpdate := func(created *v3.Feature) *v3.Feature {
		validUpdateObj := created.DeepCopy()
		validUpdateObj.Status.Description = "Updated description"
		return validUpdateObj
	}
	validDelete := func() *v3.Feature {
		return validCreateObj
	}
	endPoints := &endPointObjs[*v3.Feature]{
		invalidCreate:  nil,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		invalidUpdate:  invalidUpdate,
		validUpdate:    validUpdate,
		validDelete:    validDelete,
	}
	validateEndpoints(m.T(), endPoints, m.clientFactory)
}

func (m *IntegrationSuite) TestGlobalRole() {
	newObj := func() *v3.GlobalRole { return &v3.GlobalRole{} }
	validCreateObj := &v3.GlobalRole{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-globalrole",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"GET", "WATCH"},
				APIGroups: []string{"v1"},
				Resources: []string{"pods"},
			},
		},
	}
	invalidCreate := func() *v3.GlobalRole {
		invalidCreate := validCreateObj.DeepCopy()
		if len(invalidCreate.Rules) != 0 {
			invalidCreate.Rules[0].Verbs = nil
		}
		return invalidCreate
	}
	invalidUpdate := func(created *v3.GlobalRole) *v3.GlobalRole {
		invalidUpdateObj := created.DeepCopy()
		if len(invalidUpdateObj.Rules) != 0 {
			invalidUpdateObj.Rules[0].Verbs = nil
		}
		return invalidUpdateObj
	}
	validUpdate := func(created *v3.GlobalRole) *v3.GlobalRole {
		validUpdateObj := created.DeepCopy()
		validUpdateObj.Description = "Updated description"
		return validUpdateObj
	}
	validDelete := func() *v3.GlobalRole {
		return validCreateObj
	}
	endPoints := &endPointObjs[*v3.GlobalRole]{
		invalidCreate:  invalidCreate,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		invalidUpdate:  invalidUpdate,
		validUpdate:    validUpdate,
		validDelete:    validDelete,
	}
	validateEndpoints(m.T(), endPoints, m.clientFactory)
}

func (m *IntegrationSuite) TestGlobalRoleBinding() {
	const grName = "grb-testgr"
	newObj := func() *v3.GlobalRoleBinding { return &v3.GlobalRoleBinding{} }
	validCreateObj := &v3.GlobalRoleBinding{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-globalrolebinding",
		},
		GlobalRoleName: grName,
	}
	invalidCreate := func() *v3.GlobalRoleBinding {
		invalidCreate := validCreateObj.DeepCopy()
		invalidCreate.GlobalRoleName = "foo"
		return invalidCreate
	}
	invalidUpdate := func(created *v3.GlobalRoleBinding) *v3.GlobalRoleBinding {
		invalidUpdateObj := created.DeepCopy()
		invalidUpdateObj.GlobalRoleName = "foo"
		return invalidUpdateObj
	}
	validUpdate := func(created *v3.GlobalRoleBinding) *v3.GlobalRoleBinding {
		validUpdateObj := created.DeepCopy()
		if validUpdateObj.Annotations == nil {
			validUpdateObj.Annotations = map[string]string{"foo": "bar"}
		} else {
			validUpdateObj.Annotations["foo"] = "bar"
		}
		return validUpdateObj
	}
	validDelete := func() *v3.GlobalRoleBinding {
		return validCreateObj
	}
	endPoints := &endPointObjs[*v3.GlobalRoleBinding]{
		invalidCreate:  invalidCreate,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		invalidUpdate:  invalidUpdate,
		validUpdate:    validUpdate,
		validDelete:    validDelete,
	}

	testGR := &v3.GlobalRole{
		ObjectMeta: v1.ObjectMeta{
			Name: grName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"GET", "WATCH"},
				APIGroups: []string{"v1"},
				Resources: []string{"pods"},
			},
		},
	}
	m.createObj(testGR, schema.GroupVersionKind{})
	validateEndpoints(m.T(), endPoints, m.clientFactory)
	m.deleteObj(testGR, schema.GroupVersionKind{})
}

func (m *IntegrationSuite) TestProjectRoleTemplateBinding() {
	const rtName = "rt-testprtb"
	newObj := func() *v3.ProjectRoleTemplateBinding { return &v3.ProjectRoleTemplateBinding{} }
	validCreateObj := &v3.ProjectRoleTemplateBinding{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-projectroletemplatebinding",
			Namespace: testNamespace,
		},
		UserName:         "bruce-wayne",
		RoleTemplateName: rtName,
		ProjectName:      "gotham:city",
	}
	invalidCreate := func() *v3.ProjectRoleTemplateBinding {
		invalidCreate := validCreateObj.DeepCopy()
		invalidCreate.RoleTemplateName = "foo"
		return invalidCreate
	}
	invalidUpdate := func(created *v3.ProjectRoleTemplateBinding) *v3.ProjectRoleTemplateBinding {
		invalidUpdateObj := created.DeepCopy()
		invalidUpdateObj.UserName = "daemon"
		return invalidUpdateObj
	}
	validUpdate := func(created *v3.ProjectRoleTemplateBinding) *v3.ProjectRoleTemplateBinding {
		validUpdateObj := created.DeepCopy()
		validUpdateObj.UserPrincipalName = "local://"
		return validUpdateObj
	}
	validDelete := func() *v3.ProjectRoleTemplateBinding {
		return validCreateObj
	}
	endPoints := &endPointObjs[*v3.ProjectRoleTemplateBinding]{
		invalidCreate:  invalidCreate,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		invalidUpdate:  invalidUpdate,
		validUpdate:    validUpdate,
		validDelete:    validDelete,
	}

	testRT := &v3.RoleTemplate{
		ObjectMeta: v1.ObjectMeta{
			Name: rtName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"GET", "WATCH"},
				APIGroups: []string{"v1"},
				Resources: []string{"pods"},
			},
		},
	}
	m.createObj(testRT, schema.GroupVersionKind{})
	validateEndpoints(m.T(), endPoints, m.clientFactory)
	m.deleteObj(testRT, schema.GroupVersionKind{})
}

func (m *IntegrationSuite) TestClusterRoleTemplateBinding() {
	const rtName = "rt-testcrtb"
	newObj := func() *v3.ClusterRoleTemplateBinding { return &v3.ClusterRoleTemplateBinding{} }
	validCreateObj := &v3.ClusterRoleTemplateBinding{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-clusterroletemplatebinding",
			Namespace: testNamespace,
		},
		UserName:         "bruce-wayne",
		RoleTemplateName: rtName,
		ClusterName:      "gotham",
	}
	invalidCreate := func() *v3.ClusterRoleTemplateBinding {
		invalidCreate := validCreateObj.DeepCopy()
		invalidCreate.RoleTemplateName = "foo"
		return invalidCreate
	}
	invalidUpdate := func(created *v3.ClusterRoleTemplateBinding) *v3.ClusterRoleTemplateBinding {
		invalidUpdateObj := created.DeepCopy()
		invalidUpdateObj.UserName = "daemon"
		return invalidUpdateObj
	}
	validUpdate := func(created *v3.ClusterRoleTemplateBinding) *v3.ClusterRoleTemplateBinding {
		validUpdateObj := created.DeepCopy()
		validUpdateObj.UserPrincipalName = "local://"
		return validUpdateObj
	}
	validDelete := func() *v3.ClusterRoleTemplateBinding {
		return validCreateObj
	}
	endPoints := &endPointObjs[*v3.ClusterRoleTemplateBinding]{
		invalidCreate:  invalidCreate,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		invalidUpdate:  invalidUpdate,
		validUpdate:    validUpdate,
		validDelete:    validDelete,
	}

	testRT := &v3.RoleTemplate{
		ObjectMeta: v1.ObjectMeta{
			Name: rtName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"GET", "WATCH"},
				APIGroups: []string{"v1"},
				Resources: []string{"pods"},
			},
		},
	}
	m.createObj(testRT, schema.GroupVersionKind{})
	validateEndpoints(m.T(), endPoints, m.clientFactory)
	m.deleteObj(testRT, schema.GroupVersionKind{})
}

func (m *IntegrationSuite) TestRoleTemplate() {
	newObj := func() *v3.RoleTemplate { return &v3.RoleTemplate{} }
	validCreateObj := &v3.RoleTemplate{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-roletemplate",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"GET", "WATCH"},
				APIGroups: []string{"v1"},
				Resources: []string{"pods"},
			},
		},
	}
	invalidCreate := func() *v3.RoleTemplate {
		invalidCreate := validCreateObj.DeepCopy()
		if len(invalidCreate.Rules) != 0 {
			invalidCreate.Rules[0].Verbs = nil
		}
		return invalidCreate
	}
	invalidUpdate := func(created *v3.RoleTemplate) *v3.RoleTemplate {
		invalidUpdateObj := created.DeepCopy()
		if len(invalidUpdateObj.Rules) != 0 {
			invalidUpdateObj.Rules[0].Verbs = nil
		}
		return invalidUpdateObj
	}
	validUpdate := func(created *v3.RoleTemplate) *v3.RoleTemplate {
		validUpdateObj := created.DeepCopy()
		validUpdateObj.Description = "Updated description"
		return validUpdateObj
	}
	validDelete := func() *v3.RoleTemplate {
		return validCreateObj
	}
	endPoints := &endPointObjs[*v3.RoleTemplate]{
		invalidCreate:  invalidCreate,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		invalidUpdate:  invalidUpdate,
		validUpdate:    validUpdate,
		validDelete:    validDelete,
	}
	validateEndpoints(m.T(), endPoints, m.clientFactory)
}

func (m *IntegrationSuite) TestProvisioningCluster() {
	newObj := func() *provisioningv1.Cluster { return &provisioningv1.Cluster{} }
	validCreateObj := &provisioningv1.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: testNamespace,
		},
	}
	invalidCreate := func() *provisioningv1.Cluster {
		invalidCreate := validCreateObj.DeepCopy()
		invalidCreate.Name = "local"
		return invalidCreate
	}
	invalidUpdate := func(created *provisioningv1.Cluster) *provisioningv1.Cluster {
		invalidUpdateObj := created.DeepCopy()
		invalidUpdateObj.Annotations = map[string]string{auth.CreatorIDAnn: "foobar"}
		return invalidUpdateObj
	}
	validUpdate := func(created *provisioningv1.Cluster) *provisioningv1.Cluster {
		validUpdateObj := created.DeepCopy()
		validUpdateObj.Spec.KubernetesVersion = "v1.25"
		return validUpdateObj
	}
	validDelete := func() *provisioningv1.Cluster {
		return validCreateObj
	}
	endPoints := &endPointObjs[*provisioningv1.Cluster]{
		invalidCreate:  invalidCreate,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		invalidUpdate:  invalidUpdate,
		validUpdate:    validUpdate,
		validDelete:    validDelete,
	}
	validateEndpoints(m.T(), endPoints, m.clientFactory)
}

func (m *IntegrationSuite) TestManagementCluster() {
	newObj := func() *v3.Cluster { return &v3.Cluster{} }
	validCreateObj := &v3.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-cluster",
		},
	}

	validDelete := func() *v3.Cluster {
		return validCreateObj
	}
	endPoints := &endPointObjs[*v3.Cluster]{
		invalidCreate:  nil,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		invalidUpdate:  nil,
		validUpdate:    nil,
		validDelete:    validDelete,
	}
	validateEndpoints(m.T(), endPoints, m.clientFactory)
}

func (m *IntegrationSuite) TestRKEMachineConfig() {
	objGVK := schema.GroupVersionKind{
		Group:   "rke-machine-config.cattle.io",
		Version: "v1",
		Kind:    "AzureConfig",
	}
	newObj := func() *unstructured.Unstructured { return &unstructured.Unstructured{} }
	validCreateObj := &unstructured.Unstructured{}
	validCreateObj.SetName("test-rke.machine")
	validCreateObj.SetNamespace(testNamespace)
	validCreateObj.SetGroupVersionKind(objGVK)
	invalidUpdate := func(created *unstructured.Unstructured) *unstructured.Unstructured {
		invalidUpdateObj := validCreateObj.DeepCopy()
		invalidUpdateObj.SetAnnotations(map[string]string{auth.CreatorIDAnn: "foobar"})
		return invalidUpdateObj
	}
	validUpdate := func(created *unstructured.Unstructured) *unstructured.Unstructured {
		validUpdateObj := created.DeepCopy()
		annotations := validUpdateObj.GetAnnotations()
		annotations["dark-knight"] = "batman"
		validUpdateObj.SetAnnotations(annotations)
		return validUpdateObj
	}
	validDelete := func() *unstructured.Unstructured {
		return validCreateObj
	}
	endPoints := &endPointObjs[*unstructured.Unstructured]{
		gvk:            objGVK,
		invalidCreate:  nil,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		invalidUpdate:  invalidUpdate,
		validUpdate:    validUpdate,
		validDelete:    validDelete,
	}
	validateEndpoints(m.T(), endPoints, m.clientFactory)
}

func validateEndpoints[T Object](t *testing.T, objs *endPointObjs[T], clientFactory client.SharedClientFactory) *client.Client {
	t.Helper()
	result := objs.newObj()
	objGVK := objs.gvk
	if objGVK.Empty() {
		var err error
		objGVK, err = gvk.Get(objs.validCreateObj)
		require.NoError(t, err, "failed to get GVK")
	}
	client, err := clientFactory.ForKind(objGVK)
	require.NoError(t, err, "Failed to create client")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if objs.invalidCreate != nil {
		invalidObj := objs.invalidCreate()
		err = client.Create(ctx, invalidObj.GetNamespace(), invalidObj, nil, v1.CreateOptions{})
		assert.Error(t, err, "No error returned during the creation of an invalid Object")
	}
	err = client.Create(ctx, objs.validCreateObj.GetNamespace(), objs.validCreateObj, result, v1.CreateOptions{})
	assert.NoError(t, err, "Error returned during the creation of a valid Object")
	if objs.invalidUpdate != nil {
		updatedObj := objs.invalidUpdate(result)
		patch, err := createPatch(result, updatedObj)
		assert.NoError(t, err, "Failed to create patch")
		err = client.Patch(ctx, updatedObj.GetNamespace(), updatedObj.GetName(), types.JSONPatchType, patch, result, v1.PatchOptions{})
		assert.Error(t, err, "No error returned during the update of an invalid Object")
	}
	if objs.validUpdate != nil {
		updatedObj := objs.validUpdate(result)
		patch, err := createPatch(result, updatedObj)
		assert.NoError(t, err, "Failed to create patch")
		err = client.Patch(ctx, updatedObj.GetNamespace(), updatedObj.GetName(), types.JSONPatchType, patch, result, v1.PatchOptions{})
		assert.NoError(t, err, "Error returned during the update of a valid Object")
	}
	if objs.invalidDelete != nil {
		deleteObj := objs.invalidDelete()
		err := client.Delete(ctx, deleteObj.GetNamespace(), deleteObj.GetName(), v1.DeleteOptions{})
		assert.Error(t, err, "No error returned during the update of an invalid Object")
	}
	if objs.validDelete != nil {
		deleteObj := objs.validDelete()
		err := client.Delete(ctx, deleteObj.GetNamespace(), deleteObj.GetName(), v1.DeleteOptions{})
		assert.NoError(t, err, "Error returned during the update of a valid Object")
	}

	return client
}

func Ptr[T any](val T) *T {
	return &val
}

func createPatch(oldObj, newObj any) ([]byte, error) {
	oldJSON, err := json.Marshal(oldObj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal old obj: %w", err)
	}
	newJSON, err := json.Marshal(newObj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal new obj: %w", err)
	}

	patch := admission.PatchResponseFromRaw(oldJSON, newJSON)

	patchJSON, err := json.Marshal(patch.Patches)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal patch: %w", err)
	}
	return patchJSON, nil
}

func (m *IntegrationSuite) deleteObj(obj Object, objGVK schema.GroupVersionKind) {
	if objGVK.Empty() {
		var err error
		objGVK, err = gvk.Get(obj)
		m.Require().NoError(err, "failed to get GVK")
	}
	client, err := m.clientFactory.ForKind(objGVK)
	m.Require().NoError(err, "failed to create client")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	err = client.Delete(ctx, obj.GetNamespace(), obj.GetName(), v1.DeleteOptions{})
	m.Require().NoError(err, "failed to delete obj")
}

func (m *IntegrationSuite) createObj(obj Object, objGVK schema.GroupVersionKind) {
	if objGVK.Empty() {
		var err error
		objGVK, err = gvk.Get(obj)
		m.Require().NoError(err, "failed to get GVK")
	}
	client, err := m.clientFactory.ForKind(objGVK)
	m.Require().NoError(err, "failed to create client")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	err = client.Create(ctx, obj.GetNamespace(), obj, nil, v1.CreateOptions{})
	m.Require().NoError(err, "failed to create obj")
}
