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
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	gatewayv1alpha1 "github.com/hmdyt/homelab-gateway-operator/api/v1alpha1"
)

const (
	// Finalizer name for cleanup
	vpsGatewayFinalizer = "gateway.hmdyt.github.io/finalizer"

	// Requeue durations
	requeueAfterError   = 1 * time.Minute
	requeueAfterSuccess = 10 * time.Minute

	// Event reasons
	EventReasonConfigMapCreated  = "ConfigMapCreated"
	EventReasonConfigMapUpdated  = "ConfigMapUpdated"
	EventReasonDeploymentCreated = "DeploymentCreated"
	EventReasonDeploymentUpdated = "DeploymentUpdated"
	EventReasonServiceCreated    = "ServiceCreated"
	EventReasonServiceUpdated    = "ServiceUpdated"
	EventReasonSecretNotFound    = "SecretNotFound"
	EventReasonReconcileError    = "ReconcileError"
	EventReasonReconcileSuccess  = "ReconcileSuccess"

	// Traefik event reasons
	EventReasonTraefikConfigMapCreated      = "TraefikConfigMapCreated"
	EventReasonTraefikConfigMapUpdated      = "TraefikConfigMapUpdated"
	EventReasonTraefikDeploymentCreated     = "TraefikDeploymentCreated"
	EventReasonTraefikDeploymentUpdated     = "TraefikDeploymentUpdated"
	EventReasonTraefikServiceCreated        = "TraefikServiceCreated"
	EventReasonTraefikServiceUpdated        = "TraefikServiceUpdated"
	EventReasonTraefikServiceAccountCreated = "TraefikServiceAccountCreated"
)

// VPSGatewayReconciler reconciles a VPSGateway object
type VPSGatewayReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=gateway.hmdyt.github.io,resources=vpsgateways,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gateway.hmdyt.github.io,resources=vpsgateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gateway.hmdyt.github.io,resources=vpsgateways/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile implements the main reconciliation logic
func (r *VPSGatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Starting reconciliation", "name", req.Name)

	// 1. Fetch VPSGateway resource (Namespace-scoped)
	gateway := &gatewayv1alpha1.VPSGateway{}
	if err := r.Get(ctx, req.NamespacedName, gateway); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("VPSGateway resource not found, ignoring")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get VPSGateway")
		return ctrl.Result{}, err
	}

	// 2. Handle deletion with finalizer
	if !gateway.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, gateway)
	}

	// 3. Add finalizer if not present
	if result, err, done := r.ensureFinalizer(ctx, gateway); done {
		return result, err
	}

	// 4. Initialize status if needed
	if gateway.Status.Phase == "" {
		gateway.Status.Phase = gatewayv1alpha1.VPSGatewayPhasePending
		if err := r.Status().Update(ctx, gateway); err != nil {
			return ctrl.Result{}, err
		}
	}

	// 5. Verify Secret exists (early validation)
	if result, err, done := r.reconcileSecret(ctx, gateway); done {
		return result, err
	}

	// 6. Reconcile Traefik resources
	if result, err, done := r.reconcileTraefikResources(ctx, gateway); done {
		return result, err
	}

	// 7. Collect domains from Ingresses and update status
	watchedIngresses, err := r.collectWatchedIngresses(ctx, gateway)
	if err != nil {
		logger.Error(err, "Failed to collect watched Ingresses")
	}
	gateway.Status.WatchedIngresses = watchedIngresses

	// 8. Reconcile ConfigMap (with domains from Ingresses)
	if err := r.reconcileConfigMap(ctx, gateway); err != nil {
		return r.handleReconcileError(ctx, gateway, "ConfigMapFailed", err)
	}

	// 9. Reconcile frpc Deployment
	if result, err, done := r.reconcileFRPCDeployment(ctx, gateway); done {
		return result, err
	}

	// 10. Reconcile Egress Service
	r.reconcileEgressService(ctx, gateway)

	// 11. Update final status to Ready
	return r.finishReconcile(ctx, gateway)
}

// ensureFinalizer adds finalizer if not present
func (r *VPSGatewayReconciler) ensureFinalizer(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) (ctrl.Result, error, bool) {
	if !controllerutil.ContainsFinalizer(gateway, vpsGatewayFinalizer) {
		controllerutil.AddFinalizer(gateway, vpsGatewayFinalizer)
		if err := r.Update(ctx, gateway); err != nil {
			log.FromContext(ctx).Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err, true
		}
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil, true
	}
	return ctrl.Result{}, nil, false
}

// reconcileSecret verifies Secret exists and is accessible
func (r *VPSGatewayReconciler) reconcileSecret(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) (ctrl.Result, error, bool) {
	_, err := r.getTokenFromSecret(ctx, gateway)
	if err != nil {
		if apierrors.IsNotFound(err) {
			notFoundErr := fmt.Errorf("secret %s not found in namespace %s",
				gateway.Spec.FRP.TokenSecretRef.Name, gateway.Spec.FRP.TokenSecretRef.Namespace)
			r.Recorder.Event(gateway, corev1.EventTypeWarning, EventReasonSecretNotFound, notFoundErr.Error())
			result, err := r.handleReconcileError(ctx, gateway, gatewayv1alpha1.ReasonSecretNotFound, notFoundErr)
			return result, err, true
		}
		var keyNotFoundErr *SecretKeyNotFoundError
		if errors.As(err, &keyNotFoundErr) {
			r.Recorder.Event(gateway, corev1.EventTypeWarning, "SecretKeyNotFound", err.Error())
			result, err := r.handleReconcileError(ctx, gateway, gatewayv1alpha1.ReasonSecretKeyNotFound, err)
			return result, err, true
		}
		result, err := r.handleReconcileError(ctx, gateway, "SecretVerificationFailed", err)
		return result, err, true
	}
	r.setCondition(gateway, gatewayv1alpha1.ConditionTypeSecretFound, metav1.ConditionTrue,
		"SecretFound", "Token secret found and accessible")
	return ctrl.Result{}, nil, false
}

// reconcileTraefikResources reconciles all Traefik-related resources
func (r *VPSGatewayReconciler) reconcileTraefikResources(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) (ctrl.Result, error, bool) {
	logger := log.FromContext(ctx)
	if gateway.Spec.Ingress.Enabled && gateway.Spec.Ingress.Controller.Enabled {
		if err := r.reconcileTraefikServiceAccount(ctx, gateway); err != nil {
			result, e := r.handleReconcileError(ctx, gateway, "TraefikServiceAccountFailed", err)
			return result, e, true
		}
		if err := r.reconcileTraefikClusterRole(ctx, gateway); err != nil {
			result, e := r.handleReconcileError(ctx, gateway, "TraefikClusterRoleFailed", err)
			return result, e, true
		}
		if err := r.reconcileTraefikClusterRoleBinding(ctx, gateway); err != nil {
			result, e := r.handleReconcileError(ctx, gateway, "TraefikClusterRoleBindingFailed", err)
			return result, e, true
		}
		if err := r.reconcileTraefikConfigMap(ctx, gateway); err != nil {
			result, e := r.handleReconcileError(ctx, gateway, "TraefikConfigMapFailed", err)
			return result, e, true
		}
		if err := r.reconcileTraefikDeployment(ctx, gateway); err != nil {
			result, e := r.handleReconcileError(ctx, gateway, "TraefikDeploymentFailed", err)
			return result, e, true
		}
		if err := r.reconcileTraefikService(ctx, gateway); err != nil {
			result, e := r.handleReconcileError(ctx, gateway, "TraefikServiceFailed", err)
			return result, e, true
		}
		traefikReady, err := r.isTraefikReady(ctx, gateway)
		if err != nil {
			result, e := r.handleReconcileError(ctx, gateway, "TraefikCheckFailed", err)
			return result, e, true
		}
		gateway.Status.IngressControllerReady = traefikReady
		if traefikReady {
			r.setCondition(gateway, gatewayv1alpha1.ConditionTypeIngressControllerReady, metav1.ConditionTrue,
				gatewayv1alpha1.ReasonAvailable, "Traefik deployment is ready")
		} else {
			r.setCondition(gateway, gatewayv1alpha1.ConditionTypeIngressControllerReady, metav1.ConditionFalse,
				gatewayv1alpha1.ReasonReconciling, "Traefik deployment is not yet ready")
		}
	} else {
		if err := r.deleteTraefikResourcesIfExists(ctx, gateway); err != nil {
			logger.Error(err, "Failed to delete Traefik resources")
		}
		gateway.Status.IngressControllerReady = false
		r.setCondition(gateway, gatewayv1alpha1.ConditionTypeIngressControllerReady, metav1.ConditionFalse,
			"IngressControllerDisabled", "Ingress controller is disabled")
	}
	return ctrl.Result{}, nil, false
}

// reconcileFRPCDeployment reconciles the frpc Deployment
func (r *VPSGatewayReconciler) reconcileFRPCDeployment(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) (ctrl.Result, error, bool) {
	if err := r.reconcileDeployment(ctx, gateway); err != nil {
		result, err := r.handleReconcileError(ctx, gateway, "DeploymentFailed", err)
		return result, err, true
	}
	deploymentReady, err := r.isDeploymentReady(ctx, gateway)
	if err != nil {
		result, err := r.handleReconcileError(ctx, gateway, "DeploymentCheckFailed", err)
		return result, err, true
	}
	gateway.Status.FRPCReady = deploymentReady
	if deploymentReady {
		r.setCondition(gateway, gatewayv1alpha1.ConditionTypeFRPCReady, metav1.ConditionTrue,
			gatewayv1alpha1.ReasonAvailable, "Deployment is ready with desired replicas")
	} else {
		r.setCondition(gateway, gatewayv1alpha1.ConditionTypeFRPCReady, metav1.ConditionFalse,
			gatewayv1alpha1.ReasonReconciling, "Deployment is not yet ready")
		if err := r.Status().Update(ctx, gateway); err != nil {
			return ctrl.Result{}, err, true
		}
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil, true
	}
	return ctrl.Result{}, nil, false
}

// reconcileEgressService reconciles the Egress Service
func (r *VPSGatewayReconciler) reconcileEgressService(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) {
	logger := log.FromContext(ctx)
	if gateway.Spec.Egress.Enabled {
		if err := r.reconcileService(ctx, gateway); err != nil {
			logger.Error(err, "Failed to reconcile egress service")
		}
		gateway.Status.EgressProxyReady = true
		r.setCondition(gateway, gatewayv1alpha1.ConditionTypeEgressProxyReady, metav1.ConditionTrue,
			gatewayv1alpha1.ReasonAvailable, "Egress service created and up-to-date")
	} else {
		if err := r.deleteServiceIfExists(ctx, gateway); err != nil {
			logger.Error(err, "Failed to delete service")
		}
		gateway.Status.EgressProxyReady = false
		r.setCondition(gateway, gatewayv1alpha1.ConditionTypeEgressProxyReady, metav1.ConditionFalse,
			gatewayv1alpha1.ReasonEgressDisabled, "Egress is disabled")
	}
}

// finishReconcile updates final status and returns
func (r *VPSGatewayReconciler) finishReconcile(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	gateway.Status.Phase = gatewayv1alpha1.VPSGatewayPhaseReady
	now := metav1.Now()
	gateway.Status.LastSyncTime = &now
	gateway.Status.ObservedGeneration = gateway.Generation
	r.setCondition(gateway, gatewayv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		EventReasonReconcileSuccess, "All resources are ready")

	if err := r.Status().Update(ctx, gateway); err != nil {
		logger.Error(err, "Failed to update status")
		return ctrl.Result{}, err
	}

	r.Recorder.Event(gateway, corev1.EventTypeNormal, EventReasonReconcileSuccess,
		"Successfully reconciled VPSGateway")
	logger.Info("Reconciliation complete", "phase", gateway.Status.Phase)

	return ctrl.Result{RequeueAfter: requeueAfterSuccess}, nil
}

// reconcileDelete handles cleanup when VPSGateway is deleted
func (r *VPSGatewayReconciler) reconcileDelete(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Handling deletion")

	if controllerutil.ContainsFinalizer(gateway, vpsGatewayFinalizer) {
		// Clean up cluster-scoped RBAC resources (they don't have OwnerReference)
		if err := r.deleteTraefikClusterRBACResources(ctx, gateway); err != nil {
			logger.Error(err, "Failed to delete Traefik cluster RBAC resources")
			return ctrl.Result{}, err
		}

		logger.Info("Cleanup complete, removing finalizer")

		controllerutil.RemoveFinalizer(gateway, vpsGatewayFinalizer)
		if err := r.Update(ctx, gateway); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// handleReconcileError updates status to Error and records event
func (r *VPSGatewayReconciler) handleReconcileError(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway, reason string, err error) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Error(err, "Reconciliation error", "reason", reason)

	gateway.Status.Phase = gatewayv1alpha1.VPSGatewayPhaseError
	r.setCondition(gateway, gatewayv1alpha1.ConditionTypeReady, metav1.ConditionFalse, reason, err.Error())

	if statusErr := r.Status().Update(ctx, gateway); statusErr != nil {
		logger.Error(statusErr, "Failed to update status after error")
	}

	r.Recorder.Event(gateway, corev1.EventTypeWarning, EventReasonReconcileError,
		fmt.Sprintf("%s: %v", reason, err))

	return ctrl.Result{RequeueAfter: requeueAfterError}, err
}

// setCondition updates or adds a condition to the status
func (r *VPSGatewayReconciler) setCondition(gateway *gatewayv1alpha1.VPSGateway, conditionType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&gateway.Status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		ObservedGeneration: gateway.Generation,
		Reason:             reason,
		Message:            message,
	})
}

// SetupWithManager sets up the controller with the Manager
func (r *VPSGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1alpha1.VPSGateway{}).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findGatewaysForSecret),
		).
		Watches(
			&networkingv1.Ingress{},
			handler.EnqueueRequestsFromMapFunc(r.findGatewaysForIngress),
		).
		Complete(r)
}

// findGatewaysForSecret maps Secret changes to VPSGateway reconcile requests
func (r *VPSGatewayReconciler) findGatewaysForSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)

	secret, ok := obj.(*corev1.Secret)
	if !ok {
		logger.Error(nil, "Expected Secret object", "type", fmt.Sprintf("%T", obj))
		return []reconcile.Request{}
	}

	// List all VPSGateways (Namespace-scoped)
	gatewayList := &gatewayv1alpha1.VPSGatewayList{}
	if err := r.List(ctx, gatewayList); err != nil {
		return []reconcile.Request{}
	}

	var requests []reconcile.Request
	for _, gateway := range gatewayList.Items {
		// Check if this Secret matches the VPSGateway's TokenSecretRef
		if gateway.Spec.FRP.TokenSecretRef.Name == secret.Name &&
			gateway.Spec.FRP.TokenSecretRef.Namespace == secret.Namespace {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      gateway.Name,
					Namespace: gateway.Namespace,
				},
			})
		}
	}

	return requests
}

// findGatewaysForIngress maps Ingress changes to VPSGateway reconcile requests
func (r *VPSGatewayReconciler) findGatewaysForIngress(ctx context.Context, obj client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)

	ingress, ok := obj.(*networkingv1.Ingress)
	if !ok {
		logger.Error(nil, "Expected Ingress object", "type", fmt.Sprintf("%T", obj))
		return []reconcile.Request{}
	}

	// Check if the Ingress has an IngressClassName
	if ingress.Spec.IngressClassName == nil {
		return []reconcile.Request{}
	}

	ingressClassName := *ingress.Spec.IngressClassName

	// List all VPSGateways to find one with matching IngressClassName
	gatewayList := &gatewayv1alpha1.VPSGatewayList{}
	if err := r.List(ctx, gatewayList); err != nil {
		logger.Error(err, "Failed to list VPSGateways")
		return []reconcile.Request{}
	}

	var requests []reconcile.Request
	for _, gateway := range gatewayList.Items {
		if getIngressClassName(&gateway) == ingressClassName {
			logger.V(1).Info("Ingress changed, triggering VPSGateway reconciliation",
				"ingress", ingress.Name, "namespace", ingress.Namespace,
				"vpsGateway", gateway.Name, "vpsGatewayNamespace", gateway.Namespace)
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      gateway.Name,
					Namespace: gateway.Namespace,
				},
			})
		}
	}

	return requests
}

// collectWatchedIngresses collects all Ingresses using this VPSGateway's IngressClass
func (r *VPSGatewayReconciler) collectWatchedIngresses(ctx context.Context, gateway *gatewayv1alpha1.VPSGateway) ([]gatewayv1alpha1.WatchedIngress, error) {
	ingressClassName := getIngressClassName(gateway)

	// List all Ingresses
	ingressList := &networkingv1.IngressList{}
	if err := r.List(ctx, ingressList); err != nil {
		return nil, err
	}

	watchedIngresses := make([]gatewayv1alpha1.WatchedIngress, 0, len(ingressList.Items))
	for _, ingress := range ingressList.Items {
		if ingress.Spec.IngressClassName == nil {
			continue
		}
		if *ingress.Spec.IngressClassName != ingressClassName {
			continue
		}

		// Extract domains from Ingress rules
		var domains []string
		for _, rule := range ingress.Spec.Rules {
			if rule.Host != "" {
				domains = append(domains, rule.Host)
			}
		}

		watchedIngresses = append(watchedIngresses, gatewayv1alpha1.WatchedIngress{
			Namespace: ingress.Namespace,
			Name:      ingress.Name,
			Domains:   domains,
		})
	}

	return watchedIngresses, nil
}
