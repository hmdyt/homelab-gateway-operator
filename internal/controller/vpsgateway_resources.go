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

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	gatewayv1alpha1 "github.com/hmdyt/homelab-gateway-operator/api/v1alpha1"
)

const (
	// Default values
	defaultSecretKey          = "token"
	defaultFRPCImage          = "snowdreamtech/frpc:0.53.2"
	defaultTraefikImage       = "traefik:v3.2"
	httpPort                  = 80
	httpsPort                 = 443
	traefikAdminPort          = 8080
	frpcUID             int64 = 1000
	traefikUID          int64 = 65532
)

// SecretKeyNotFoundError represents an error when a secret key is not found
type SecretKeyNotFoundError struct {
	Key        string
	SecretName string
}

func (e *SecretKeyNotFoundError) Error() string {
	return fmt.Sprintf("key %s not found in secret %s", e.Key, e.SecretName)
}

// Resource name generation helpers
func (r *VPSGatewayReconciler) getConfigMapName(gateway *gatewayv1alpha1.VPSGateway) string {
	return fmt.Sprintf("frpc-config-%s", gateway.Name)
}

func (r *VPSGatewayReconciler) getDeploymentName(gateway *gatewayv1alpha1.VPSGateway) string {
	return fmt.Sprintf("frpc-%s", gateway.Name)
}

func (r *VPSGatewayReconciler) getServiceName(gateway *gatewayv1alpha1.VPSGateway) string {
	return fmt.Sprintf("egress-proxy-%s", gateway.Name)
}

func (r *VPSGatewayReconciler) getIngressClassName(gateway *gatewayv1alpha1.VPSGateway) string {
	return getIngressClassName(gateway)
}

func (r *VPSGatewayReconciler) getTraefikDeploymentName(gateway *gatewayv1alpha1.VPSGateway) string {
	return fmt.Sprintf("traefik-%s", gateway.Name)
}

func (r *VPSGatewayReconciler) getTraefikServiceName(gateway *gatewayv1alpha1.VPSGateway) string {
	return fmt.Sprintf("traefik-%s", gateway.Name)
}

func (r *VPSGatewayReconciler) getTraefikConfigMapName(gateway *gatewayv1alpha1.VPSGateway) string {
	return fmt.Sprintf("traefik-config-%s", gateway.Name)
}

func (r *VPSGatewayReconciler) getTraefikServiceAddress(gateway *gatewayv1alpha1.VPSGateway) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local",
		r.getTraefikServiceName(gateway),
		r.getResourceNamespace(gateway))
}

// getResourceNamespace returns the namespace for deploying resources
// Since VPSGateway is namespace-scoped, all child resources are created in the same namespace
func (r *VPSGatewayReconciler) getResourceNamespace(gateway *gatewayv1alpha1.VPSGateway) string {
	return gateway.Namespace
}

// SecurityContext helpers
func getContainerSecurityContext() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr(false),
		RunAsNonRoot:             ptr(true),
		RunAsUser:                ptr(frpcUID),
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}
}

func getPodSecurityContext() *corev1.PodSecurityContext {
	return &corev1.PodSecurityContext{
		RunAsNonRoot: ptr(true),
		RunAsUser:    ptr(frpcUID),
		FSGroup:      ptr(frpcUID),
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}
}

// reconcileConfigMap creates or updates the frpc configuration ConfigMap
func (r *VPSGatewayReconciler) reconcileConfigMap(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) error {
	logger := log.FromContext(ctx)

	namespace := r.getResourceNamespace(gateway)
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.getConfigMapName(gateway),
			Namespace: namespace,
		},
	}

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, configMap, func() error {
		// Generate TOML configuration
		tomlConfig, err := r.generateFrpcConfig(ctx, gateway)
		if err != nil {
			return fmt.Errorf("failed to generate frpc config: %w", err)
		}

		// Set data
		if configMap.Data == nil {
			configMap.Data = make(map[string]string)
		}
		configMap.Data["frpc.toml"] = tomlConfig

		// Set labels
		configMap.Labels = r.getCommonLabels(gateway)

		// Set owner reference for automatic cleanup
		return controllerutil.SetControllerReference(gateway, configMap, r.Scheme)
	})

	if err != nil {
		logger.Error(err, "Failed to reconcile ConfigMap")
		return err
	}

	switch op {
	case controllerutil.OperationResultCreated:
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonConfigMapCreated,
			fmt.Sprintf("ConfigMap %s/%s created", namespace, configMap.Name))
		logger.Info("ConfigMap created", "name", configMap.Name, "namespace", namespace)
	case controllerutil.OperationResultUpdated:
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonConfigMapUpdated,
			fmt.Sprintf("ConfigMap %s/%s updated", namespace, configMap.Name))
		logger.Info("ConfigMap updated", "name", configMap.Name, "namespace", namespace)
	}

	return nil
}

// generateFrpcConfig generates TOML configuration for frpc
func (r *VPSGatewayReconciler) generateFrpcConfig(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) (string, error) {
	// Fetch token from secret
	token, err := r.getTokenFromSecret(ctx, gateway)
	if err != nil {
		return "", err
	}

	var builder strings.Builder

	// Basic configuration
	builder.WriteString(fmt.Sprintf("serverAddr = \"%s\"\n", gateway.Spec.VPS.Address))
	builder.WriteString(fmt.Sprintf("serverPort = %d\n\n", gateway.Spec.FRP.Port))
	builder.WriteString("[auth]\n")
	builder.WriteString(fmt.Sprintf("token = \"%s\"\n\n", token))

	// Collect all domains from watched Ingresses
	domains := r.collectDomainsFromIngresses(gateway)

	// Ingress proxies (if enabled and we have domains)
	if gateway.Spec.Ingress.Enabled && len(domains) > 0 {
		// Get Traefik service address (dynamic based on VPSGateway name)
		traefikServiceAddr := r.getTraefikServiceAddress(gateway)

		// HTTP proxy
		builder.WriteString("[[proxies]]\n")
		builder.WriteString("name = \"ingress-http\"\n")
		builder.WriteString("type = \"http\"\n")
		builder.WriteString(fmt.Sprintf("localIP = \"%s\"\n", traefikServiceAddr))
		builder.WriteString(fmt.Sprintf("localPort = %d\n", httpPort))
		builder.WriteString(fmt.Sprintf("customDomains = [%s]\n\n", r.formatDomainList(domains)))

		// HTTPS proxy
		builder.WriteString("[[proxies]]\n")
		builder.WriteString("name = \"ingress-https\"\n")
		builder.WriteString("type = \"https\"\n")
		builder.WriteString(fmt.Sprintf("localIP = \"%s\"\n", traefikServiceAddr))
		builder.WriteString(fmt.Sprintf("localPort = %d\n", httpsPort))
		builder.WriteString(fmt.Sprintf("customDomains = [%s]\n\n", r.formatDomainList(domains)))
	}

	// Egress visitor (if enabled)
	if gateway.Spec.Egress.Enabled {
		builder.WriteString("[[visitors]]\n")
		builder.WriteString("name = \"egress-visitor\"\n")
		builder.WriteString("type = \"stcp\"\n")
		builder.WriteString("serverName = \"egress-proxy\"\n")
		builder.WriteString("bindAddr = \"0.0.0.0\"\n")
		builder.WriteString(fmt.Sprintf("bindPort = %d\n", gateway.Spec.Egress.ProxyPort))
	}

	return builder.String(), nil
}

// collectDomainsFromIngresses collects all unique domains from watched Ingresses and customDomains
func (r *VPSGatewayReconciler) collectDomainsFromIngresses(gateway *gatewayv1alpha1.VPSGateway) []string {
	domainSet := make(map[string]struct{})

	// Collect from Ingress resources
	for _, ingress := range gateway.Status.WatchedIngresses {
		for _, domain := range ingress.Domains {
			domainSet[domain] = struct{}{}
		}
	}

	// Add static customDomains from spec
	for _, domain := range gateway.Spec.Ingress.CustomDomains {
		domainSet[domain] = struct{}{}
	}

	domains := make([]string, 0, len(domainSet))
	for domain := range domainSet {
		domains = append(domains, domain)
	}

	// Sort for deterministic output
	sort.Strings(domains)
	return domains
}

// formatDomainList formats a slice of domains for TOML array syntax
func (r *VPSGatewayReconciler) formatDomainList(domains []string) string {
	quoted := make([]string, len(domains))
	for i, domain := range domains {
		quoted[i] = fmt.Sprintf("\"%s\"", domain)
	}
	return strings.Join(quoted, ", ")
}

// getTokenFromSecret retrieves the token from the referenced secret
func (r *VPSGatewayReconciler) getTokenFromSecret(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) (string, error) {
	secret := &corev1.Secret{}
	secretName := types.NamespacedName{
		Name:      gateway.Spec.FRP.TokenSecretRef.Name,
		Namespace: gateway.Spec.FRP.TokenSecretRef.Namespace,
	}

	if err := r.Get(ctx, secretName, secret); err != nil {
		return "", err
	}

	key := gateway.Spec.FRP.TokenSecretRef.Key
	if key == "" {
		key = defaultSecretKey
	}

	tokenBytes, exists := secret.Data[key]
	if !exists {
		return "", &SecretKeyNotFoundError{Key: key, SecretName: secretName.Name}
	}

	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return "", fmt.Errorf("token in secret %s/%s is empty or contains only whitespace", secretName.Namespace, secretName.Name)
	}

	return token, nil
}

// reconcileDeployment creates or updates the frpc Deployment
func (r *VPSGatewayReconciler) reconcileDeployment(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) error {
	logger := log.FromContext(ctx)

	namespace := r.getResourceNamespace(gateway)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.getDeploymentName(gateway),
			Namespace: namespace,
		},
	}

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, deployment, func() error {
		labels := r.getCommonLabels(gateway)

		deployment.Labels = labels

		// Set replicas
		replicas := int32(1)
		deployment.Spec.Replicas = &replicas

		// Set selector
		deployment.Spec.Selector = &metav1.LabelSelector{
			MatchLabels: labels,
		}

		// Calculate ConfigMap hash to trigger pod restart on config changes
		configHash, err := r.getConfigMapHash(ctx, gateway)
		if err != nil {
			return fmt.Errorf("failed to get ConfigMap hash: %w", err)
		}

		// Prepare annotations with ConfigMap hash
		annotations := make(map[string]string)
		if configHash != "" {
			annotations["gateway.hmdyt.github.io/config-hash"] = configHash
		}

		// Set pod template
		deployment.Spec.Template = corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels:      labels,
				Annotations: annotations,
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "frpc",
						Image: r.getFrpcImage(gateway),
						Command: []string{
							"frpc",
							"-c",
							"/etc/frp/frpc.toml",
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "config",
								MountPath: "/etc/frp",
								ReadOnly:  true,
							},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("128Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("512Mi"),
							},
						},
						SecurityContext: getContainerSecurityContext(),
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								Exec: &corev1.ExecAction{
									Command: []string{"pgrep", "-x", "frpc"},
								},
							},
							InitialDelaySeconds: 10,
							PeriodSeconds:       30,
							TimeoutSeconds:      5,
							FailureThreshold:    3,
						},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								Exec: &corev1.ExecAction{
									Command: []string{"pgrep", "-x", "frpc"},
								},
							},
							InitialDelaySeconds: 5,
							PeriodSeconds:       10,
							TimeoutSeconds:      5,
							FailureThreshold:    3,
						},
					},
				},
				Volumes: []corev1.Volume{
					{
						Name: "config",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: r.getConfigMapName(gateway),
								},
							},
						},
					},
				},
				SecurityContext: getPodSecurityContext(),
			},
		}

		// Set owner reference for automatic cleanup
		return controllerutil.SetControllerReference(gateway, deployment, r.Scheme)
	})

	if err != nil {
		logger.Error(err, "Failed to reconcile Deployment")
		return err
	}

	switch op {
	case controllerutil.OperationResultCreated:
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonDeploymentCreated,
			fmt.Sprintf("Deployment %s/%s created", namespace, deployment.Name))
		logger.Info("Deployment created", "name", deployment.Name, "namespace", namespace)
	case controllerutil.OperationResultUpdated:
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonDeploymentUpdated,
			fmt.Sprintf("Deployment %s/%s updated", namespace, deployment.Name))
		logger.Info("Deployment updated", "name", deployment.Name, "namespace", namespace)
	}

	return nil
}

// getFrpcImage returns the frpc image from spec or default
func (r *VPSGatewayReconciler) getFrpcImage(gateway *gatewayv1alpha1.VPSGateway) string {
	if gateway.Spec.FRP.Image != "" {
		return gateway.Spec.FRP.Image
	}
	return defaultFRPCImage
}

// isDeploymentReady checks if the deployment is ready
func (r *VPSGatewayReconciler) isDeploymentReady(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) (bool, error) {
	deployment := &appsv1.Deployment{}
	deploymentName := types.NamespacedName{
		Name:      r.getDeploymentName(gateway),
		Namespace: r.getResourceNamespace(gateway),
	}

	if err := r.Get(ctx, deploymentName, deployment); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	// Check if deployment.Spec.Replicas is nil
	if deployment.Spec.Replicas == nil {
		return false, nil
	}

	// Check for deployment failure conditions
	for _, condition := range deployment.Status.Conditions {
		if condition.Type == appsv1.DeploymentProgressing {
			if condition.Status == corev1.ConditionFalse && condition.Reason == "ProgressDeadlineExceeded" {
				return false, fmt.Errorf("deployment %s has failed to progress: %s", deploymentName.Name, condition.Message)
			}
		}
		if condition.Type == appsv1.DeploymentReplicaFailure {
			if condition.Status == corev1.ConditionTrue {
				return false, fmt.Errorf("deployment %s has replica failure: %s", deploymentName.Name, condition.Message)
			}
		}
	}

	// Check if deployment has desired replicas available and ObservedGeneration is up to date
	if deployment.Status.ObservedGeneration == deployment.Generation &&
		deployment.Status.ReadyReplicas == *deployment.Spec.Replicas &&
		deployment.Status.Replicas == *deployment.Spec.Replicas &&
		deployment.Status.UpdatedReplicas == *deployment.Spec.Replicas {
		return true, nil
	}

	return false, nil
}

// reconcileService creates or updates the egress Service
func (r *VPSGatewayReconciler) reconcileService(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) error {
	logger := log.FromContext(ctx)

	namespace := r.getResourceNamespace(gateway)
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.getServiceName(gateway),
			Namespace: namespace,
		},
	}

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, service, func() error {
		labels := r.getCommonLabels(gateway)

		service.Labels = labels
		service.Spec.Selector = labels
		service.Spec.Type = corev1.ServiceTypeClusterIP

		// Set ports
		service.Spec.Ports = []corev1.ServicePort{
			{
				Name:       "egress",
				Port:       gateway.Spec.Egress.ProxyPort,
				TargetPort: intstr.FromInt(int(gateway.Spec.Egress.ProxyPort)),
				Protocol:   corev1.ProtocolTCP,
			},
		}

		// Set owner reference for automatic cleanup
		return controllerutil.SetControllerReference(gateway, service, r.Scheme)
	})

	if err != nil {
		logger.Error(err, "Failed to reconcile Service")
		return err
	}

	switch op {
	case controllerutil.OperationResultCreated:
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonServiceCreated,
			fmt.Sprintf("Service %s/%s created", namespace, service.Name))
		logger.Info("Service created", "name", service.Name, "namespace", namespace)
	case controllerutil.OperationResultUpdated:
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonServiceUpdated,
			fmt.Sprintf("Service %s/%s updated", namespace, service.Name))
		logger.Info("Service updated", "name", service.Name, "namespace", namespace)
	}

	return nil
}

// deleteServiceIfExists deletes the service if it exists
func (r *VPSGatewayReconciler) deleteServiceIfExists(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) error {
	service := &corev1.Service{}
	serviceName := types.NamespacedName{
		Name:      r.getServiceName(gateway),
		Namespace: r.getResourceNamespace(gateway),
	}

	err := r.Get(ctx, serviceName, service)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	return r.Delete(ctx, service)
}

// getCommonLabels returns common labels for all resources
func (r *VPSGatewayReconciler) getCommonLabels(gateway *gatewayv1alpha1.VPSGateway) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "frpc",
		"app.kubernetes.io/instance":   gateway.Name,
		"app.kubernetes.io/component":  "proxy-client",
		"app.kubernetes.io/part-of":    "homelab-gateway",
		"app.kubernetes.io/managed-by": "homelab-gateway-operator",
	}
}

// ptr returns a pointer to the value
func ptr[T any](v T) *T {
	return &v
}

// getConfigMapHash calculates the SHA256 hash of the ConfigMap data
func (r *VPSGatewayReconciler) getConfigMapHash(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) (string, error) {
	configMap := &corev1.ConfigMap{}
	configMapName := types.NamespacedName{
		Name:      r.getConfigMapName(gateway),
		Namespace: r.getResourceNamespace(gateway),
	}

	if err := r.Get(ctx, configMapName, configMap); err != nil {
		if apierrors.IsNotFound(err) {
			// ConfigMap doesn't exist yet, return empty hash
			return "", nil
		}
		return "", err
	}

	// Calculate hash of ConfigMap data
	h := sha256.New()
	if data, exists := configMap.Data["frpc.toml"]; exists {
		h.Write([]byte(data))
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// getTraefikImage returns the Traefik image from spec or default
func (r *VPSGatewayReconciler) getTraefikImage(gateway *gatewayv1alpha1.VPSGateway) string {
	if gateway.Spec.Ingress.Controller.Image != "" {
		return gateway.Spec.Ingress.Controller.Image
	}
	return defaultTraefikImage
}

// getTraefikReplicas returns the Traefik replicas from spec or default
func (r *VPSGatewayReconciler) getTraefikReplicas(gateway *gatewayv1alpha1.VPSGateway) int32 {
	if gateway.Spec.Ingress.Controller.Replicas > 0 {
		return gateway.Spec.Ingress.Controller.Replicas
	}
	return 1
}

// getTraefikLabels returns common labels for Traefik resources
func (r *VPSGatewayReconciler) getTraefikLabels(gateway *gatewayv1alpha1.VPSGateway) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "traefik",
		"app.kubernetes.io/instance":   gateway.Name,
		"app.kubernetes.io/component":  "ingress-controller",
		"app.kubernetes.io/part-of":    "homelab-gateway",
		"app.kubernetes.io/managed-by": "homelab-gateway-operator",
	}
}

// getTraefikSecurityContext returns the security context for Traefik container
func getTraefikSecurityContext() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr(false),
		RunAsNonRoot:             ptr(true),
		RunAsUser:                ptr(traefikUID),
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
		ReadOnlyRootFilesystem: ptr(true),
	}
}

// getTraefikPodSecurityContext returns the pod security context for Traefik
func getTraefikPodSecurityContext() *corev1.PodSecurityContext {
	return &corev1.PodSecurityContext{
		RunAsNonRoot: ptr(true),
		RunAsUser:    ptr(traefikUID),
		FSGroup:      ptr(traefikUID),
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}
}

// generateTraefikConfig generates YAML configuration for Traefik v3
func (r *VPSGatewayReconciler) generateTraefikConfig(gateway *gatewayv1alpha1.VPSGateway) string {
	ingressClassName := r.getIngressClassName(gateway)

	var builder strings.Builder

	// Entry points configuration
	builder.WriteString("entryPoints:\n")
	builder.WriteString("  web:\n")
	builder.WriteString("    address: \":80\"\n")
	builder.WriteString("    http:\n")
	builder.WriteString("      redirections:\n")
	builder.WriteString("        entryPoint:\n")
	builder.WriteString("          to: websecure\n")
	builder.WriteString("          scheme: https\n")
	builder.WriteString("  websecure:\n")
	builder.WriteString("    address: \":443\"\n")
	builder.WriteString("  traefik:\n")
	builder.WriteString("    address: \":8080\"\n")
	builder.WriteString("\n")

	// Kubernetes Ingress provider configuration
	builder.WriteString("providers:\n")
	builder.WriteString("  kubernetesIngress:\n")
	builder.WriteString(fmt.Sprintf("    ingressClass: %s\n", ingressClassName))
	builder.WriteString("    allowEmptyServices: true\n")
	builder.WriteString("\n")

	// API configuration (for dashboard)
	builder.WriteString("api:\n")
	builder.WriteString("  dashboard: true\n")
	builder.WriteString("  insecure: true\n")
	builder.WriteString("\n")

	// Ping configuration (for health checks)
	builder.WriteString("ping:\n")
	builder.WriteString("  entryPoint: traefik\n")
	builder.WriteString("\n")

	// Logging configuration
	builder.WriteString("log:\n")
	builder.WriteString("  level: INFO\n")

	return builder.String()
}

// reconcileTraefikConfigMap creates or updates the Traefik configuration ConfigMap
func (r *VPSGatewayReconciler) reconcileTraefikConfigMap(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) error {
	logger := log.FromContext(ctx)

	namespace := r.getResourceNamespace(gateway)
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.getTraefikConfigMapName(gateway),
			Namespace: namespace,
		},
	}

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, configMap, func() error {
		// Generate YAML configuration
		yamlConfig := r.generateTraefikConfig(gateway)

		// Set data
		if configMap.Data == nil {
			configMap.Data = make(map[string]string)
		}
		configMap.Data["traefik.yml"] = yamlConfig

		// Set labels
		configMap.Labels = r.getTraefikLabels(gateway)

		// Set owner reference for automatic cleanup
		return controllerutil.SetControllerReference(gateway, configMap, r.Scheme)
	})

	if err != nil {
		logger.Error(err, "Failed to reconcile Traefik ConfigMap")
		return err
	}

	switch op {
	case controllerutil.OperationResultCreated:
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonTraefikConfigMapCreated,
			fmt.Sprintf("Traefik ConfigMap %s/%s created", namespace, configMap.Name))
		logger.Info("Traefik ConfigMap created", "name", configMap.Name, "namespace", namespace)
	case controllerutil.OperationResultUpdated:
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonTraefikConfigMapUpdated,
			fmt.Sprintf("Traefik ConfigMap %s/%s updated", namespace, configMap.Name))
		logger.Info("Traefik ConfigMap updated", "name", configMap.Name, "namespace", namespace)
	}

	return nil
}

// getTraefikConfigMapHash calculates the SHA256 hash of the Traefik ConfigMap data
func (r *VPSGatewayReconciler) getTraefikConfigMapHash(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) (string, error) {
	configMap := &corev1.ConfigMap{}
	configMapName := types.NamespacedName{
		Name:      r.getTraefikConfigMapName(gateway),
		Namespace: r.getResourceNamespace(gateway),
	}

	if err := r.Get(ctx, configMapName, configMap); err != nil {
		if apierrors.IsNotFound(err) {
			return "", nil
		}
		return "", err
	}

	h := sha256.New()
	if data, exists := configMap.Data["traefik.yml"]; exists {
		h.Write([]byte(data))
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// reconcileTraefikDeployment creates or updates the Traefik Deployment
func (r *VPSGatewayReconciler) reconcileTraefikDeployment(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) error {
	logger := log.FromContext(ctx)

	namespace := r.getResourceNamespace(gateway)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.getTraefikDeploymentName(gateway),
			Namespace: namespace,
		},
	}

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, deployment, func() error {
		labels := r.getTraefikLabels(gateway)

		deployment.Labels = labels

		// Set replicas
		replicas := r.getTraefikReplicas(gateway)
		deployment.Spec.Replicas = &replicas

		// Set selector
		deployment.Spec.Selector = &metav1.LabelSelector{
			MatchLabels: labels,
		}

		// Calculate ConfigMap hash to trigger pod restart on config changes
		configHash, err := r.getTraefikConfigMapHash(ctx, gateway)
		if err != nil {
			return fmt.Errorf("failed to get Traefik ConfigMap hash: %w", err)
		}

		// Prepare annotations with ConfigMap hash
		annotations := make(map[string]string)
		if configHash != "" {
			annotations["gateway.hmdyt.github.io/traefik-config-hash"] = configHash
		}

		// Set pod template
		deployment.Spec.Template = corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels:      labels,
				Annotations: annotations,
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: r.getTraefikServiceAccountName(gateway),
				Containers: []corev1.Container{
					{
						Name:  "traefik",
						Image: r.getTraefikImage(gateway),
						Args: []string{
							"--configFile=/etc/traefik/traefik.yml",
						},
						Ports: []corev1.ContainerPort{
							{
								Name:          "web",
								ContainerPort: int32(httpPort),
								Protocol:      corev1.ProtocolTCP,
							},
							{
								Name:          "websecure",
								ContainerPort: int32(httpsPort),
								Protocol:      corev1.ProtocolTCP,
							},
							{
								Name:          "admin",
								ContainerPort: int32(traefikAdminPort),
								Protocol:      corev1.ProtocolTCP,
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "config",
								MountPath: "/etc/traefik",
								ReadOnly:  true,
							},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("128Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("512Mi"),
							},
						},
						SecurityContext: getTraefikSecurityContext(),
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/ping",
									Port: intstr.FromInt(traefikAdminPort),
								},
							},
							InitialDelaySeconds: 10,
							PeriodSeconds:       10,
							TimeoutSeconds:      5,
							FailureThreshold:    3,
						},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/ping",
									Port: intstr.FromInt(traefikAdminPort),
								},
							},
							InitialDelaySeconds: 5,
							PeriodSeconds:       5,
							TimeoutSeconds:      5,
							FailureThreshold:    3,
						},
					},
				},
				Volumes: []corev1.Volume{
					{
						Name: "config",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: r.getTraefikConfigMapName(gateway),
								},
							},
						},
					},
				},
				SecurityContext: getTraefikPodSecurityContext(),
			},
		}

		// Set owner reference for automatic cleanup
		return controllerutil.SetControllerReference(gateway, deployment, r.Scheme)
	})

	if err != nil {
		logger.Error(err, "Failed to reconcile Traefik Deployment")
		return err
	}

	switch op {
	case controllerutil.OperationResultCreated:
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonTraefikDeploymentCreated,
			fmt.Sprintf("Traefik Deployment %s/%s created", namespace, deployment.Name))
		logger.Info("Traefik Deployment created", "name", deployment.Name, "namespace", namespace)
	case controllerutil.OperationResultUpdated:
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonTraefikDeploymentUpdated,
			fmt.Sprintf("Traefik Deployment %s/%s updated", namespace, deployment.Name))
		logger.Info("Traefik Deployment updated", "name", deployment.Name, "namespace", namespace)
	}

	return nil
}

// getTraefikServiceAccountName returns the ServiceAccount name for Traefik
func (r *VPSGatewayReconciler) getTraefikServiceAccountName(gateway *gatewayv1alpha1.VPSGateway) string {
	return fmt.Sprintf("traefik-%s", gateway.Name)
}

// reconcileTraefikService creates or updates the Traefik Service
func (r *VPSGatewayReconciler) reconcileTraefikService(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) error {
	logger := log.FromContext(ctx)

	namespace := r.getResourceNamespace(gateway)
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.getTraefikServiceName(gateway),
			Namespace: namespace,
		},
	}

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, service, func() error {
		labels := r.getTraefikLabels(gateway)

		service.Labels = labels
		service.Spec.Selector = labels
		service.Spec.Type = corev1.ServiceTypeClusterIP

		// Set ports
		service.Spec.Ports = []corev1.ServicePort{
			{
				Name:       "web",
				Port:       int32(httpPort),
				TargetPort: intstr.FromString("web"),
				Protocol:   corev1.ProtocolTCP,
			},
			{
				Name:       "websecure",
				Port:       int32(httpsPort),
				TargetPort: intstr.FromString("websecure"),
				Protocol:   corev1.ProtocolTCP,
			},
		}

		// Set owner reference for automatic cleanup
		return controllerutil.SetControllerReference(gateway, service, r.Scheme)
	})

	if err != nil {
		logger.Error(err, "Failed to reconcile Traefik Service")
		return err
	}

	switch op {
	case controllerutil.OperationResultCreated:
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonTraefikServiceCreated,
			fmt.Sprintf("Traefik Service %s/%s created", namespace, service.Name))
		logger.Info("Traefik Service created", "name", service.Name, "namespace", namespace)
	case controllerutil.OperationResultUpdated:
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonTraefikServiceUpdated,
			fmt.Sprintf("Traefik Service %s/%s updated", namespace, service.Name))
		logger.Info("Traefik Service updated", "name", service.Name, "namespace", namespace)
	}

	return nil
}

// reconcileTraefikServiceAccount creates or updates the ServiceAccount for Traefik
func (r *VPSGatewayReconciler) reconcileTraefikServiceAccount(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) error {
	logger := log.FromContext(ctx)

	namespace := r.getResourceNamespace(gateway)
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.getTraefikServiceAccountName(gateway),
			Namespace: namespace,
		},
	}

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, sa, func() error {
		sa.Labels = r.getTraefikLabels(gateway)

		// Set owner reference for automatic cleanup
		return controllerutil.SetControllerReference(gateway, sa, r.Scheme)
	})

	if err != nil {
		logger.Error(err, "Failed to reconcile Traefik ServiceAccount")
		return err
	}

	switch op {
	case controllerutil.OperationResultCreated:
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonTraefikServiceAccountCreated,
			fmt.Sprintf("Traefik ServiceAccount %s/%s created", namespace, sa.Name))
		logger.Info("Traefik ServiceAccount created", "name", sa.Name, "namespace", namespace)
	case controllerutil.OperationResultUpdated:
		logger.Info("Traefik ServiceAccount updated", "name", sa.Name, "namespace", namespace)
	}

	return nil
}

// isTraefikReady checks if the Traefik deployment is ready
func (r *VPSGatewayReconciler) isTraefikReady(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) (bool, error) {
	deployment := &appsv1.Deployment{}
	deploymentName := types.NamespacedName{
		Name:      r.getTraefikDeploymentName(gateway),
		Namespace: r.getResourceNamespace(gateway),
	}

	if err := r.Get(ctx, deploymentName, deployment); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	if deployment.Spec.Replicas == nil {
		return false, nil
	}

	// Check for deployment failure conditions
	for _, condition := range deployment.Status.Conditions {
		if condition.Type == appsv1.DeploymentProgressing {
			if condition.Status == corev1.ConditionFalse && condition.Reason == "ProgressDeadlineExceeded" {
				return false, fmt.Errorf("traefik deployment %s has failed to progress: %s", deploymentName.Name, condition.Message)
			}
		}
		if condition.Type == appsv1.DeploymentReplicaFailure {
			if condition.Status == corev1.ConditionTrue {
				return false, fmt.Errorf("traefik deployment %s has replica failure: %s", deploymentName.Name, condition.Message)
			}
		}
	}

	// Check if deployment has desired replicas available
	if deployment.Status.ObservedGeneration == deployment.Generation &&
		deployment.Status.ReadyReplicas == *deployment.Spec.Replicas &&
		deployment.Status.Replicas == *deployment.Spec.Replicas &&
		deployment.Status.UpdatedReplicas == *deployment.Spec.Replicas {
		return true, nil
	}

	return false, nil
}

// deleteTraefikResourcesIfExists deletes all Traefik resources if they exist
func (r *VPSGatewayReconciler) deleteTraefikResourcesIfExists(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) error {
	namespace := r.getResourceNamespace(gateway)

	// Delete Service
	service := &corev1.Service{}
	serviceName := types.NamespacedName{
		Name:      r.getTraefikServiceName(gateway),
		Namespace: namespace,
	}
	if err := r.Get(ctx, serviceName, service); err == nil {
		if err := r.Delete(ctx, service); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}

	// Delete Deployment
	deployment := &appsv1.Deployment{}
	deploymentName := types.NamespacedName{
		Name:      r.getTraefikDeploymentName(gateway),
		Namespace: namespace,
	}
	if err := r.Get(ctx, deploymentName, deployment); err == nil {
		if err := r.Delete(ctx, deployment); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}

	// Delete ConfigMap
	configMap := &corev1.ConfigMap{}
	configMapName := types.NamespacedName{
		Name:      r.getTraefikConfigMapName(gateway),
		Namespace: namespace,
	}
	if err := r.Get(ctx, configMapName, configMap); err == nil {
		if err := r.Delete(ctx, configMap); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}

	// Delete ServiceAccount
	sa := &corev1.ServiceAccount{}
	saName := types.NamespacedName{
		Name:      r.getTraefikServiceAccountName(gateway),
		Namespace: namespace,
	}
	if err := r.Get(ctx, saName, sa); err == nil {
		if err := r.Delete(ctx, sa); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}

	return nil
}
