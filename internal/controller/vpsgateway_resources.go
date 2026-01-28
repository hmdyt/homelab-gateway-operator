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
	networkingv1 "k8s.io/api/networking/v1"
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
	defaultSecretKey            = "token"
	defaultFRPCImage            = "snowdreamtech/frpc:0.53.2"
	traefikServiceAddress       = "traefik.traefik.svc.cluster.local"
	httpPort                    = 80
	httpsPort                   = 443
	frpcUID               int64 = 1000
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

// getResourceNamespace returns the namespace for deploying frpc resources
func (r *VPSGatewayReconciler) getResourceNamespace(gateway *gatewayv1alpha1.VPSGateway) string {
	// Use the namespace from the Secret reference
	if gateway.Spec.FRP.TokenSecretRef.Namespace != "" {
		return gateway.Spec.FRP.TokenSecretRef.Namespace
	}
	return defaultFrpcNamespace
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

		// Note: Cannot set OwnerReference for cluster-scoped owner to namespace-scoped resource
		// The ConfigMap will be cleaned up via finalizer instead
		return nil
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
		// HTTP proxy
		builder.WriteString("[[proxies]]\n")
		builder.WriteString("name = \"ingress-http\"\n")
		builder.WriteString("type = \"http\"\n")
		builder.WriteString(fmt.Sprintf("localIP = \"%s\"\n", traefikServiceAddress))
		builder.WriteString(fmt.Sprintf("localPort = %d\n", httpPort))
		builder.WriteString(fmt.Sprintf("customDomains = [%s]\n\n", r.formatDomainList(domains)))

		// HTTPS proxy
		builder.WriteString("[[proxies]]\n")
		builder.WriteString("name = \"ingress-https\"\n")
		builder.WriteString("type = \"https\"\n")
		builder.WriteString(fmt.Sprintf("localIP = \"%s\"\n", traefikServiceAddress))
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

// collectDomainsFromIngresses collects all unique domains from watched Ingresses
func (r *VPSGatewayReconciler) collectDomainsFromIngresses(gateway *gatewayv1alpha1.VPSGateway) []string {
	domainSet := make(map[string]struct{})

	for _, ingress := range gateway.Status.WatchedIngresses {
		for _, domain := range ingress.Domains {
			domainSet[domain] = struct{}{}
		}
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

		// Note: Cannot set OwnerReference for cluster-scoped owner to namespace-scoped resource
		// The Deployment will be cleaned up via finalizer instead
		return nil
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

		// Note: Cannot set OwnerReference for cluster-scoped owner to namespace-scoped resource
		return nil
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

// reconcileIngressClass creates or updates the IngressClass for this VPSGateway
func (r *VPSGatewayReconciler) reconcileIngressClass(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) error {
	logger := log.FromContext(ctx)

	ingressClassName := r.getIngressClassName(gateway)
	ingressClass := &networkingv1.IngressClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: ingressClassName,
		},
	}

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, ingressClass, func() error {
		// Set labels
		ingressClass.Labels = map[string]string{
			"app.kubernetes.io/managed-by":  "homelab-gateway-operator",
			"app.kubernetes.io/instance":    gateway.Name,
			"gateway.hmdyt.github.io/owner": gateway.Name,
		}

		// Set the controller to a placeholder (we don't actually implement an Ingress controller)
		// The IngressClass is used to associate Ingresses with VPSGateway
		ingressClass.Spec.Controller = "gateway.hmdyt.github.io/vps-gateway"

		// Set annotations with VPS address for reference
		if ingressClass.Annotations == nil {
			ingressClass.Annotations = make(map[string]string)
		}
		ingressClass.Annotations["gateway.hmdyt.github.io/vps-address"] = gateway.Spec.VPS.Address

		// Set owner reference (both are cluster-scoped, so this works)
		return controllerutil.SetControllerReference(gateway, ingressClass, r.Scheme)
	})

	if err != nil {
		logger.Error(err, "Failed to reconcile IngressClass")
		return err
	}

	switch op {
	case controllerutil.OperationResultCreated:
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonIngressClassCreated,
			fmt.Sprintf("IngressClass %s created", ingressClass.Name))
		logger.Info("IngressClass created", "name", ingressClass.Name)
	case controllerutil.OperationResultUpdated:
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonIngressClassUpdated,
			fmt.Sprintf("IngressClass %s updated", ingressClass.Name))
		logger.Info("IngressClass updated", "name", ingressClass.Name)
	}

	return nil
}

// deleteIngressClassIfExists deletes the IngressClass if it exists
func (r *VPSGatewayReconciler) deleteIngressClassIfExists(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) error {
	ingressClass := &networkingv1.IngressClass{}
	ingressClassName := types.NamespacedName{
		Name: r.getIngressClassName(gateway),
	}

	err := r.Get(ctx, ingressClassName, ingressClass)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	return r.Delete(ctx, ingressClass)
}
