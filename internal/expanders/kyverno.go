// Copyright Contributors to the Open Cluster Management project
package expanders

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"open-cluster-management.io/policy-generator-plugin/internal/types"
)

type KyvernoPolicyExpander struct{}

const (
	kyvernoAPIVersion             = "kyverno.io/v1"
	kyvernoPolicyAPIVersion       = "policies.kyverno.io/v1"
	kyvernoPolicyReportAPIVersion = "wgpolicyk8s.io/v1alpha2"
	clusterPolicyReportKind       = "ClusterPolicyReport"
	namespacedPolicyReportKind    = "PolicyReport"
	kyvernoNamespaceScope         = "namespace"
	kyvernoClusterScope           = "cluster"
)

// kyvernoPolicyScopes defines all supported Kyverno policy kinds and their scopes.
var kyvernoPolicyScopes = map[string]string{
	// Legacy kinds (kyverno.io/v1)
	"ClusterPolicy": kyvernoClusterScope,
	"Policy":        kyvernoNamespaceScope,
	// New kinds (policies.kyverno.io/v1)
	"ValidatingPolicy":                kyvernoClusterScope,
	"MutatingPolicy":                  kyvernoClusterScope,
	"GeneratingPolicy":                kyvernoClusterScope,
	"ImageValidatingPolicy":           kyvernoClusterScope,
	"NamespacedValidatingPolicy":      kyvernoNamespaceScope,
	"NamespacedMutatingPolicy":        kyvernoNamespaceScope,
	"NamespacedGeneratingPolicy":      kyvernoNamespaceScope,
	"NamespacedImageValidatingPolicy": kyvernoNamespaceScope,
}

// isValidKyvernoKind checks if the apiVersion and kind represent a supported Kyverno policy.
func isValidKyvernoKind(apiVersion, kind string) bool {
	_, exists := kyvernoPolicyScopes[kind]
	if !exists {
		return false
	}

	if kind == "ClusterPolicy" || kind == "Policy" {
		return apiVersion == kyvernoAPIVersion
	}

	return apiVersion == kyvernoPolicyAPIVersion
}

// CanHandle determines if the manifest is a Kyverno policy that can be expanded.
func (k KyvernoPolicyExpander) CanHandle(manifest map[string]interface{}) bool {
	apiVersion, _, _ := unstructured.NestedString(manifest, "apiVersion")
	kind, _, _ := unstructured.NestedString(manifest, "kind")

	if !isValidKyvernoKind(apiVersion, kind) {
		return false
	}

	if n, _, _ := unstructured.NestedString(manifest, "metadata", "name"); n == "" {
		return false
	}

	return true
}

// Enabled determines if the policy configuration allows a Kyverno policy to be expanded.
func (k KyvernoPolicyExpander) Enabled(policyConf *types.PolicyConfig) bool {
	return policyConf.InformKyvernoPolicies
}

// Expand will generate additional policy templates for the Kyverno policy for auditing purposes
// through Open Cluster Management. This should be run after the CanHandle method.
func (k KyvernoPolicyExpander) Expand(
	manifest map[string]interface{}, severity string,
) []map[string]interface{} {
	templates := []map[string]interface{}{}
	policyName, _, _ := unstructured.NestedString(manifest, "metadata", "name")
	kind, _, _ := unstructured.NestedString(manifest, "kind")

	configPolicyName := "inform-kyverno-" + policyName

	// Determine report kind
	scope := kyvernoPolicyScopes[kind]
	reportKind := clusterPolicyReportKind

	if scope == kyvernoNamespaceScope {
		reportKind = namespacedPolicyReportKind
	}

	configurationPolicy := map[string]interface{}{
		"objectDefinition": map[string]interface{}{
			"apiVersion": configPolicyAPIVersion,
			"kind":       configPolicyKind,
			"metadata":   map[string]interface{}{"name": configPolicyName},
			"spec": map[string]interface{}{
				"namespaceSelector": map[string]interface{}{
					"exclude": []string{"kube-*"},
					"include": []string{"*"},
				},
				"remediationAction": "inform",
				"severity":          severity,
				"object-templates": []map[string]interface{}{
					{
						"complianceType": "mustnothave",
						"objectDefinition": map[string]interface{}{
							"apiVersion": kyvernoPolicyReportAPIVersion,
							"kind":       reportKind,
							"results": []map[string]interface{}{
								{
									"policy": policyName,
									"result": "fail",
								},
							},
						},
					},
				},
			},
		},
	}

	templates = append(templates, configurationPolicy)

	return templates
}
