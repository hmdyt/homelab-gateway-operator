/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VPSGatewaySpec defines the desired state of VPSGateway
type VPSGatewaySpec struct {
	// VPS defines the VPS server configuration
	// +kubebuilder:validation:Required
	VPS VPSConfig `json:"vps"`

	// FRP defines the frp client configuration
	// +kubebuilder:validation:Required
	FRP FRPConfig `json:"frp"`

	// Ingress defines the ingress configuration for routing traffic to the VPS
	// +optional
	Ingress IngressConfig `json:"ingress,omitempty"`

	// Egress defines the egress proxy configuration for routing traffic from the VPS
	// +optional
	Egress EgressConfig `json:"egress,omitempty"`
}

// VPSConfig defines the VPS server configuration
type VPSConfig struct {
	// Address is the IP address or hostname of the VPS
	// Must be a valid hostname (RFC 1123) or IPv4 address
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$|^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$`
	Address string `json:"address"`
}

// FRPConfig defines the frp client configuration
type FRPConfig struct {
	// Port is the frp server port
	// +optional
	// +kubebuilder:default=7000
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`

	// TokenSecretRef is a reference to a Secret containing the frp authentication token
	// The secret must contain a key "token" by default
	// +kubebuilder:validation:Required
	TokenSecretRef SecretReference `json:"tokenSecretRef"`

	// Image is the frpc container image
	// +optional
	// +kubebuilder:default="snowdreamtech/frpc:0.53.2"
	// +kubebuilder:validation:MinLength=1
	Image string `json:"image,omitempty"`
}

// SecretReference contains information to locate a secret
type SecretReference struct {
	// Name of the secret
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Key in the secret (defaults to "token")
	// +optional
	// +kubebuilder:default="token"
	Key string `json:"key,omitempty"`

	// Namespace of the secret (optional, defaults to VPSGateway's namespace)
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// IngressControllerConfig defines the Ingress Controller configuration
type IngressControllerConfig struct {
	// Enabled controls whether Traefik is managed by this operator
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// Image is the Traefik container image
	// +optional
	// +kubebuilder:default="traefik:v3.2"
	Image string `json:"image,omitempty"`

	// Replicas is the number of Traefik replicas
	// +optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	Replicas int32 `json:"replicas,omitempty"`
}

// IngressConfig defines the ingress configuration
type IngressConfig struct {
	// Enabled controls whether ingress resources should be created
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`

	// IngressClassName is the name of the IngressClass for Ingress matching
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	IngressClassName string `json:"ingressClassName"`

	// CustomDomains is a list of static domains to include in frpc config
	// These are merged with domains collected from Ingress resources
	// Supports wildcard domains like "*.example.com"
	// +optional
	CustomDomains []string `json:"customDomains,omitempty"`

	// Controller defines the Ingress Controller configuration
	// +optional
	Controller IngressControllerConfig `json:"controller,omitempty"`

	// TLS defines the TLS configuration for ingress
	// +optional
	TLS IngressTLSConfig `json:"tls,omitempty"`

	// DNS defines the DNS configuration for external-dns
	// +optional
	DNS DNSConfig `json:"dns,omitempty"`
}

// DNSConfig defines the DNS configuration for external-dns integration
type DNSConfig struct {
	// Enabled controls whether DNSEndpoint resources should be created
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`

	// TTL is the DNS record TTL in seconds
	// +optional
	// +kubebuilder:default=300
	// +kubebuilder:validation:Minimum=60
	TTL int64 `json:"ttl,omitempty"`
}

// IngressTLSConfig defines the TLS configuration for ingress
type IngressTLSConfig struct {
	// Enabled controls whether TLS should be enabled for ingress
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`

	// Issuer is the cert-manager Issuer name for generating TLS certificates
	// +optional
	// +kubebuilder:default="letsencrypt-prod"
	// +kubebuilder:validation:MinLength=1
	Issuer string `json:"issuer,omitempty"`
}

// EgressConfig defines the egress proxy configuration
type EgressConfig struct {
	// Enabled controls whether egress proxy should be configured
	// +optional
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// ProxyPort is the port for the egress proxy
	// +optional
	// +kubebuilder:default=3128
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	ProxyPort int32 `json:"proxyPort,omitempty"`

	// NoProxy is a list of hosts/domains that should bypass the proxy
	// +optional
	NoProxy []string `json:"noProxy,omitempty"`
}

// VPSGatewayPhase represents the current phase of the VPSGateway
// +kubebuilder:validation:Enum=Pending;Ready;Error
type VPSGatewayPhase string

const (
	// VPSGatewayPhasePending indicates the VPSGateway is being initialized
	VPSGatewayPhasePending VPSGatewayPhase = "Pending"
	// VPSGatewayPhaseReady indicates the VPSGateway is ready and operational
	VPSGatewayPhaseReady VPSGatewayPhase = "Ready"
	// VPSGatewayPhaseError indicates the VPSGateway has encountered an error
	VPSGatewayPhaseError VPSGatewayPhase = "Error"
)

// VPSGatewayStatus defines the observed state of VPSGateway
type VPSGatewayStatus struct {
	// Phase represents the current phase of the VPSGateway
	// +optional
	Phase VPSGatewayPhase `json:"phase,omitempty"`

	// Conditions represent the latest available observations of the VPSGateway's state
	// +optional
	// +listType=map
	// +listMapKey=type
	// +patchMergeKey=type
	// +patchStrategy=merge
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// FRPCReady indicates whether the frpc deployment is ready
	// +optional
	FRPCReady bool `json:"frpcReady,omitempty"`

	// IngressControllerReady indicates whether the Traefik deployment is ready
	// +optional
	IngressControllerReady bool `json:"ingressControllerReady,omitempty"`

	// EgressProxyReady indicates whether the egress proxy is ready
	// +optional
	EgressProxyReady bool `json:"egressProxyReady,omitempty"`

	// LastSyncTime is the last time the VPSGateway was successfully synced
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// ObservedGeneration is the generation observed by the controller
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// WatchedIngresses is the list of Ingresses currently watched by this VPSGateway
	// +optional
	WatchedIngresses []WatchedIngress `json:"watchedIngresses,omitempty"`
}

// WatchedIngress represents an Ingress being watched by the VPSGateway
type WatchedIngress struct {
	// Namespace of the Ingress
	Namespace string `json:"namespace"`

	// Name of the Ingress
	Name string `json:"name"`

	// Domains extracted from the Ingress rules
	Domains []string `json:"domains,omitempty"`
}

// Condition types for VPSGateway
const (
	// ConditionTypeReady indicates the overall readiness of the VPSGateway
	ConditionTypeReady = "Ready"
	// ConditionTypeFRPCReady indicates the frpc deployment is ready
	ConditionTypeFRPCReady = "FRPCReady"
	// ConditionTypeIngressControllerReady indicates the Traefik deployment is ready
	ConditionTypeIngressControllerReady = "IngressControllerReady"
	// ConditionTypeEgressProxyReady indicates the egress proxy is ready
	ConditionTypeEgressProxyReady = "EgressProxyReady"
	// ConditionTypeSecretFound indicates the token secret was found
	ConditionTypeSecretFound = "SecretFound"
)

// Condition reasons
const (
	// ReasonReconciling indicates the resource is being reconciled
	ReasonReconciling = "Reconciling"
	// ReasonAvailable indicates the resource is available
	ReasonAvailable = "Available"
	// ReasonDegraded indicates the resource is degraded
	ReasonDegraded = "Degraded"
	// ReasonSecretNotFound indicates the token secret was not found
	ReasonSecretNotFound = "SecretNotFound"
	// ReasonSecretKeyNotFound indicates the specified key was not found in the secret
	ReasonSecretKeyNotFound = "SecretKeyNotFound"
	// ReasonEgressDisabled indicates egress is disabled
	ReasonEgressDisabled = "EgressDisabled"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=vpsgw,categories=gateway
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="FRPC Ready",type=boolean,JSONPath=`.status.frpcReady`
// +kubebuilder:printcolumn:name="VPS Address",type=string,JSONPath=`.spec.vps.address`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VPSGateway is the Schema for the vpsgateways API
type VPSGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VPSGatewaySpec   `json:"spec,omitempty"`
	Status VPSGatewayStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VPSGatewayList contains a list of VPSGateway
type VPSGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VPSGateway `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VPSGateway{}, &VPSGatewayList{})
}
