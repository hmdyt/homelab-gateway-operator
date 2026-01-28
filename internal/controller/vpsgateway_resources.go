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

func (r *VPSGatewayReconciler) getIngressName(gateway *gatewayv1alpha1.VPSGateway) string {
	return fmt.Sprintf("ingress-%s", gateway.Name)
}

func (r *VPSGatewayReconciler) getFrpcServiceName(gateway *gatewayv1alpha1.VPSGateway) string {
	return fmt.Sprintf("frpc-svc-%s", gateway.Name)
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

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.getConfigMapName(gateway),
			Namespace: gateway.Namespace,
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

		// Set owner reference for garbage collection
		return controllerutil.SetControllerReference(gateway, configMap, r.Scheme)
	})

	if err != nil {
		logger.Error(err, "Failed to reconcile ConfigMap")
		return err
	}

	if op == controllerutil.OperationResultCreated {
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonConfigMapCreated,
			fmt.Sprintf("ConfigMap %s created", configMap.Name))
		logger.Info("ConfigMap created", "name", configMap.Name)
	} else if op == controllerutil.OperationResultUpdated {
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonConfigMapUpdated,
			fmt.Sprintf("ConfigMap %s updated", configMap.Name))
		logger.Info("ConfigMap updated", "name", configMap.Name)
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

	// Ingress proxies (if enabled)
	if gateway.Spec.Ingress.Enabled && len(gateway.Spec.Ingress.Domains) > 0 {
		// HTTP proxy
		builder.WriteString("[[proxies]]\n")
		builder.WriteString("name = \"ingress-http\"\n")
		builder.WriteString("type = \"http\"\n")
		builder.WriteString(fmt.Sprintf("localIP = \"%s\"\n", traefikServiceAddress))
		builder.WriteString(fmt.Sprintf("localPort = %d\n", httpPort))
		builder.WriteString(fmt.Sprintf("customDomains = [%s]\n\n", r.formatDomainList(gateway.Spec.Ingress.Domains)))

		// HTTPS proxy
		builder.WriteString("[[proxies]]\n")
		builder.WriteString("name = \"ingress-https\"\n")
		builder.WriteString("type = \"https\"\n")
		builder.WriteString(fmt.Sprintf("localIP = \"%s\"\n", traefikServiceAddress))
		builder.WriteString(fmt.Sprintf("localPort = %d\n", httpsPort))
		builder.WriteString(fmt.Sprintf("customDomains = [%s]\n\n", r.formatDomainList(gateway.Spec.Ingress.Domains)))
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
		Namespace: gateway.Namespace,
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

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.getDeploymentName(gateway),
			Namespace: gateway.Namespace,
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

		// Set owner reference
		return controllerutil.SetControllerReference(gateway, deployment, r.Scheme)
	})

	if err != nil {
		logger.Error(err, "Failed to reconcile Deployment")
		return err
	}

	if op == controllerutil.OperationResultCreated {
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonDeploymentCreated,
			fmt.Sprintf("Deployment %s created", deployment.Name))
		logger.Info("Deployment created", "name", deployment.Name)
	} else if op == controllerutil.OperationResultUpdated {
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonDeploymentUpdated,
			fmt.Sprintf("Deployment %s updated", deployment.Name))
		logger.Info("Deployment updated", "name", deployment.Name)
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
		Namespace: gateway.Namespace,
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

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.getServiceName(gateway),
			Namespace: gateway.Namespace,
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

		// Set owner reference
		return controllerutil.SetControllerReference(gateway, service, r.Scheme)
	})

	if err != nil {
		logger.Error(err, "Failed to reconcile Service")
		return err
	}

	if op == controllerutil.OperationResultCreated {
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonServiceCreated,
			fmt.Sprintf("Service %s created", service.Name))
		logger.Info("Service created", "name", service.Name)
	} else if op == controllerutil.OperationResultUpdated {
		r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonServiceUpdated,
			fmt.Sprintf("Service %s updated", service.Name))
		logger.Info("Service updated", "name", service.Name)
	}

	return nil
}

// deleteServiceIfExists deletes the service if it exists
func (r *VPSGatewayReconciler) deleteServiceIfExists(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) error {
	service := &corev1.Service{}
	serviceName := types.NamespacedName{
		Name:      r.getServiceName(gateway),
		Namespace: gateway.Namespace,
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
		Namespace: gateway.Namespace,
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

// reconcileFrpcService creates or updates the frpc Service for Ingress routing
func (r *VPSGatewayReconciler) reconcileFrpcService(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) error {
	logger := log.FromContext(ctx)

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.getFrpcServiceName(gateway),
			Namespace: gateway.Namespace,
		},
	}

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, service, func() error {
		labels := r.getCommonLabels(gateway)

		service.Labels = labels
		service.Spec.Selector = labels
		service.Spec.Type = corev1.ServiceTypeClusterIP

		service.Spec.Ports = []corev1.ServicePort{
			{
				Name:       "http",
				Port:       int32(httpPort),
				TargetPort: intstr.FromInt(httpPort),
				Protocol:   corev1.ProtocolTCP,
			},
			{
				Name:       "https",
				Port:       int32(httpsPort),
				TargetPort: intstr.FromInt(httpsPort),
				Protocol:   corev1.ProtocolTCP,
			},
		}

		return controllerutil.SetControllerReference(gateway, service, r.Scheme)
	})

	if err != nil {
		logger.Error(err, "Failed to reconcile frpc Service")
		return err
	}

	if op == controllerutil.OperationResultCreated {
		logger.Info("frpc Service created", "name", service.Name)
	} else if op == controllerutil.OperationResultUpdated {
		logger.Info("frpc Service updated", "name", service.Name)
	}

	return nil
}

// reconcileIngress creates or updates the Ingress resource for each domain
func (r *VPSGatewayReconciler) reconcileIngress(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) error {
	logger := log.FromContext(ctx)

	// First, create the frpc service that the Ingress will route to
	if err := r.reconcileFrpcService(ctx, gateway); err != nil {
		return err
	}

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.getIngressName(gateway),
			Namespace: gateway.Namespace,
		},
	}

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, ingress, func() error {
		labels := r.getCommonLabels(gateway)
		ingress.Labels = labels

		// Set annotations for cert-manager if TLS is enabled
		if ingress.Annotations == nil {
			ingress.Annotations = make(map[string]string)
		}
		if gateway.Spec.Ingress.TLS.Enabled {
			ingress.Annotations["cert-manager.io/cluster-issuer"] = gateway.Spec.Ingress.TLS.Issuer
		}

		// Set IngressClassName
		ingressClassName := gateway.Spec.Ingress.IngressClassName
		ingress.Spec.IngressClassName = &ingressClassName

		// Build rules for each domain
		pathType := networkingv1.PathTypePrefix
		var rules []networkingv1.IngressRule
		var tlsHosts []string

		for _, domain := range gateway.Spec.Ingress.Domains {
			rules = append(rules, networkingv1.IngressRule{
				Host: domain,
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path:     "/",
								PathType: &pathType,
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: r.getFrpcServiceName(gateway),
										Port: networkingv1.ServiceBackendPort{
											Number: int32(httpPort),
										},
									},
								},
							},
						},
					},
				},
			})
			tlsHosts = append(tlsHosts, domain)
		}

		ingress.Spec.Rules = rules

		// Configure TLS if enabled
		if gateway.Spec.Ingress.TLS.Enabled && len(tlsHosts) > 0 {
			ingress.Spec.TLS = []networkingv1.IngressTLS{
				{
					Hosts:      tlsHosts,
					SecretName: fmt.Sprintf("%s-tls", gateway.Name),
				},
			}
		} else {
			ingress.Spec.TLS = nil
		}

		return controllerutil.SetControllerReference(gateway, ingress, r.Scheme)
	})

	if err != nil {
		logger.Error(err, "Failed to reconcile Ingress")
		return err
	}

	if op == controllerutil.OperationResultCreated {
		r.Recorder.Event(gateway, corev1.EventTypeNormal, "IngressCreated",
			fmt.Sprintf("Ingress %s created", ingress.Name))
		logger.Info("Ingress created", "name", ingress.Name)
	} else if op == controllerutil.OperationResultUpdated {
		r.Recorder.Event(gateway, corev1.EventTypeNormal, "IngressUpdated",
			fmt.Sprintf("Ingress %s updated", ingress.Name))
		logger.Info("Ingress updated", "name", ingress.Name)
	}

	return nil
}

// deleteIngressIfExists deletes the ingress and frpc service if they exist
func (r *VPSGatewayReconciler) deleteIngressIfExists(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) error {
	// Delete Ingress
	ingress := &networkingv1.Ingress{}
	ingressName := types.NamespacedName{
		Name:      r.getIngressName(gateway),
		Namespace: gateway.Namespace,
	}

	err := r.Get(ctx, ingressName, ingress)
	if err == nil {
		if err := r.Delete(ctx, ingress); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}

	// Delete frpc Service
	service := &corev1.Service{}
	serviceName := types.NamespacedName{
		Name:      r.getFrpcServiceName(gateway),
		Namespace: gateway.Namespace,
	}

	err = r.Get(ctx, serviceName, service)
	if err == nil {
		if err := r.Delete(ctx, service); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}

	return nil
}
