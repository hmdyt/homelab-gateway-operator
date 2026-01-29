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
	"fmt"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	externaldnsv1alpha1 "sigs.k8s.io/external-dns/apis/v1alpha1"
	"sigs.k8s.io/external-dns/endpoint"

	gatewayv1alpha1 "github.com/hmdyt/homelab-gateway-operator/api/v1alpha1"
)

const (
	// Event reasons for Ingress reconciliation
	EventReasonDNSEndpointCreated  = "DNSEndpointCreated"
	EventReasonDNSEndpointUpdated  = "DNSEndpointUpdated"
	EventReasonCertificateCreated  = "CertificateCreated"
	EventReasonCertificateUpdated  = "CertificateUpdated"
	EventReasonDNSEndpointDeleted  = "DNSEndpointDeleted"
	EventReasonCertificateDeleted  = "CertificateDeleted"
	EventReasonIngressReconciled   = "IngressReconciled"
	EventReasonIngressReconcileErr = "IngressReconcileError"
)

// IngressReconciler reconciles Ingress objects with vps-gateway IngressClass
type IngressReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch
// +kubebuilder:rbac:groups=externaldns.k8s.io,resources=dnsendpoints,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete

// Reconcile handles Ingress resources with vps-gateway IngressClass
func (r *IngressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling Ingress", "namespace", req.Namespace, "name", req.Name)

	// 1. Fetch Ingress resource
	ingress := &networkingv1.Ingress{}
	if err := r.Get(ctx, req.NamespacedName, ingress); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Ingress resource not found, ignoring")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get Ingress")
		return ctrl.Result{}, err
	}

	// 2. Check if IngressClassName is specified
	if ingress.Spec.IngressClassName == nil {
		logger.V(1).Info("Ingress has no IngressClassName, skipping")
		return ctrl.Result{}, nil
	}

	ingressClassName := *ingress.Spec.IngressClassName

	// 3. Find the corresponding VPSGateway (across all namespaces)
	gateway, err := r.findVPSGatewayByIngressClassName(ctx, ingressClassName)
	if err != nil {
		logger.Error(err, "Failed to find VPSGateway")
		return ctrl.Result{}, err
	}
	if gateway == nil {
		logger.Info("VPSGateway not found for IngressClass", "ingressClassName", ingressClassName)
		return ctrl.Result{}, nil
	}

	// 4. Handle deletion
	if !ingress.DeletionTimestamp.IsZero() {
		// Resources with OwnerRef will be garbage collected automatically
		logger.Info("Ingress is being deleted, resources will be garbage collected")
		return ctrl.Result{}, nil
	}

	// 5. Extract domains from Ingress rules
	domains := r.extractDomainsFromIngress(ingress)
	if len(domains) == 0 {
		logger.Info("No domains found in Ingress rules")
		return ctrl.Result{}, nil
	}

	logger.Info("Processing Ingress", "domains", domains, "vpsGateway", gateway.Name)

	// 6. Reconcile DNSEndpoint (if DNS is enabled)
	if gateway.Spec.Ingress.DNS.Enabled {
		if err := r.reconcileDNSEndpoint(ctx, ingress, gateway, domains); err != nil {
			r.Recorder.Event(ingress, corev1.EventTypeWarning, EventReasonIngressReconcileErr,
				fmt.Sprintf("Failed to reconcile DNSEndpoint: %v", err))
			return ctrl.Result{}, err
		}
	} else {
		// Clean up DNSEndpoint if DNS is disabled
		if err := r.deleteDNSEndpointIfExists(ctx, ingress); err != nil {
			logger.Error(err, "Failed to delete DNSEndpoint")
		}
	}

	// 7. Reconcile Certificate (if TLS is enabled)
	if gateway.Spec.Ingress.TLS.Enabled {
		if err := r.reconcileCertificate(ctx, ingress, gateway, domains); err != nil {
			r.Recorder.Event(ingress, corev1.EventTypeWarning, EventReasonIngressReconcileErr,
				fmt.Sprintf("Failed to reconcile Certificate: %v", err))
			return ctrl.Result{}, err
		}
	} else {
		// Clean up Certificate if TLS is disabled
		if err := r.deleteCertificateIfExists(ctx, ingress); err != nil {
			logger.Error(err, "Failed to delete Certificate")
		}
	}

	// 8. Trigger VPSGateway reconciliation (for frpc ConfigMap update)
	// This is done by enqueueing a reconcile request for the VPSGateway
	// The VPSGatewayReconciler watches Ingresses and will be triggered automatically

	r.Recorder.Event(ingress, corev1.EventTypeNormal, EventReasonIngressReconciled,
		fmt.Sprintf("Successfully reconciled Ingress with domains: %v", domains))

	return ctrl.Result{}, nil
}

// extractDomainsFromIngress extracts all host domains from Ingress rules
func (r *IngressReconciler) extractDomainsFromIngress(ingress *networkingv1.Ingress) []string {
	domainSet := make(map[string]struct{})
	for _, rule := range ingress.Spec.Rules {
		if rule.Host != "" {
			domainSet[rule.Host] = struct{}{}
		}
	}

	domains := make([]string, 0, len(domainSet))
	for domain := range domainSet {
		domains = append(domains, domain)
	}
	return domains
}

// getDNSEndpointName generates the DNSEndpoint name for an Ingress
func (r *IngressReconciler) getDNSEndpointName(ingress *networkingv1.Ingress) string {
	return fmt.Sprintf("%s-%s-dns", ingress.Namespace, ingress.Name)
}

// getCertificateName generates the Certificate name for an Ingress
func (r *IngressReconciler) getCertificateName(ingress *networkingv1.Ingress) string {
	return fmt.Sprintf("%s-%s-cert", ingress.Namespace, ingress.Name)
}

// getTLSSecretName generates the TLS secret name for an Ingress
func (r *IngressReconciler) getTLSSecretName(ingress *networkingv1.Ingress) string {
	return fmt.Sprintf("%s-tls", ingress.Name)
}

// reconcileDNSEndpoint creates or updates the DNSEndpoint for the Ingress
func (r *IngressReconciler) reconcileDNSEndpoint(ctx context.Context, ingress *networkingv1.Ingress, gateway *gatewayv1alpha1.VPSGateway, domains []string) error {
	logger := log.FromContext(ctx)

	dnsEndpoint := &externaldnsv1alpha1.DNSEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.getDNSEndpointName(ingress),
			Namespace: ingress.Namespace,
		},
	}

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, dnsEndpoint, func() error {
		// Set labels
		dnsEndpoint.Labels = map[string]string{
			"app.kubernetes.io/managed-by":  "homelab-gateway-operator",
			"app.kubernetes.io/created-for": fmt.Sprintf("%s-%s", ingress.Namespace, ingress.Name),
		}

		// Get TTL from VPSGateway config
		ttl := gateway.Spec.Ingress.DNS.TTL
		if ttl == 0 {
			ttl = 300 // default
		}

		// Build endpoints for each domain
		endpoints := make([]*endpoint.Endpoint, 0, len(domains))
		for _, domain := range domains {
			endpoints = append(endpoints, &endpoint.Endpoint{
				DNSName:    domain,
				RecordType: endpoint.RecordTypeA,
				RecordTTL:  endpoint.TTL(ttl),
				Targets:    endpoint.Targets{gateway.Spec.VPS.Address},
			})
		}
		dnsEndpoint.Spec.Endpoints = endpoints

		// Set owner reference to Ingress for garbage collection
		return controllerutil.SetControllerReference(ingress, dnsEndpoint, r.Scheme)
	})

	if err != nil {
		logger.Error(err, "Failed to reconcile DNSEndpoint")
		return err
	}

	switch op {
	case controllerutil.OperationResultCreated:
		r.Recorder.Event(ingress, corev1.EventTypeNormal, EventReasonDNSEndpointCreated,
			fmt.Sprintf("DNSEndpoint %s created", dnsEndpoint.Name))
		logger.Info("DNSEndpoint created", "name", dnsEndpoint.Name)
	case controllerutil.OperationResultUpdated:
		r.Recorder.Event(ingress, corev1.EventTypeNormal, EventReasonDNSEndpointUpdated,
			fmt.Sprintf("DNSEndpoint %s updated", dnsEndpoint.Name))
		logger.Info("DNSEndpoint updated", "name", dnsEndpoint.Name)
	}

	return nil
}

// deleteDNSEndpointIfExists deletes the DNSEndpoint if it exists
func (r *IngressReconciler) deleteDNSEndpointIfExists(ctx context.Context, ingress *networkingv1.Ingress) error {
	dnsEndpoint := &externaldnsv1alpha1.DNSEndpoint{}
	name := types.NamespacedName{
		Name:      r.getDNSEndpointName(ingress),
		Namespace: ingress.Namespace,
	}

	err := r.Get(ctx, name, dnsEndpoint)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	return r.Delete(ctx, dnsEndpoint)
}

// reconcileCertificate creates or updates the Certificate for the Ingress
func (r *IngressReconciler) reconcileCertificate(ctx context.Context, ingress *networkingv1.Ingress, gateway *gatewayv1alpha1.VPSGateway, domains []string) error {
	logger := log.FromContext(ctx)

	certificate := &certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.getCertificateName(ingress),
			Namespace: ingress.Namespace,
		},
	}

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, certificate, func() error {
		// Set labels
		certificate.Labels = map[string]string{
			"app.kubernetes.io/managed-by":  "homelab-gateway-operator",
			"app.kubernetes.io/created-for": fmt.Sprintf("%s-%s", ingress.Namespace, ingress.Name),
		}

		// Set spec
		certificate.Spec.SecretName = r.getTLSSecretName(ingress)
		certificate.Spec.DNSNames = domains
		certificate.Spec.IssuerRef = cmmeta.ObjectReference{
			Name: gateway.Spec.Ingress.TLS.Issuer,
			Kind: "ClusterIssuer",
		}

		// Set owner reference to Ingress for garbage collection
		return controllerutil.SetControllerReference(ingress, certificate, r.Scheme)
	})

	if err != nil {
		logger.Error(err, "Failed to reconcile Certificate")
		return err
	}

	switch op {
	case controllerutil.OperationResultCreated:
		r.Recorder.Event(ingress, corev1.EventTypeNormal, EventReasonCertificateCreated,
			fmt.Sprintf("Certificate %s created", certificate.Name))
		logger.Info("Certificate created", "name", certificate.Name)
	case controllerutil.OperationResultUpdated:
		r.Recorder.Event(ingress, corev1.EventTypeNormal, EventReasonCertificateUpdated,
			fmt.Sprintf("Certificate %s updated", certificate.Name))
		logger.Info("Certificate updated", "name", certificate.Name)
	}

	return nil
}

// deleteCertificateIfExists deletes the Certificate if it exists
func (r *IngressReconciler) deleteCertificateIfExists(ctx context.Context, ingress *networkingv1.Ingress) error {
	certificate := &certmanagerv1.Certificate{}
	name := types.NamespacedName{
		Name:      r.getCertificateName(ingress),
		Namespace: ingress.Namespace,
	}

	err := r.Get(ctx, name, certificate)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	return r.Delete(ctx, certificate)
}

// SetupWithManager sets up the controller with the Manager
func (r *IngressReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1.Ingress{}).
		// Use GenerationChangedPredicate to avoid reconcile loops caused by status-only updates.
		// Without this predicate, external-dns and cert-manager status updates would trigger
		// Ingress reconciliation, causing an infinite loop.
		Owns(&externaldnsv1alpha1.DNSEndpoint{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Owns(&certmanagerv1.Certificate{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(
			&gatewayv1alpha1.VPSGateway{},
			handler.EnqueueRequestsFromMapFunc(r.findIngressesForVPSGateway),
		).
		Complete(r)
}

// findIngressesForVPSGateway maps VPSGateway changes to Ingress reconcile requests
func (r *IngressReconciler) findIngressesForVPSGateway(ctx context.Context, obj client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)

	gateway, ok := obj.(*gatewayv1alpha1.VPSGateway)
	if !ok {
		logger.Error(nil, "Expected VPSGateway object", "type", fmt.Sprintf("%T", obj))
		return []reconcile.Request{}
	}

	// Find the IngressClass name for this VPSGateway
	ingressClassName := getIngressClassName(gateway)

	// List all Ingresses across all namespaces that use this IngressClass
	ingressList := &networkingv1.IngressList{}
	if err := r.List(ctx, ingressList); err != nil {
		logger.Error(err, "Failed to list Ingresses")
		return []reconcile.Request{}
	}

	var requests []reconcile.Request
	for _, ingress := range ingressList.Items {
		if ingress.Spec.IngressClassName != nil && *ingress.Spec.IngressClassName == ingressClassName {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      ingress.Name,
					Namespace: ingress.Namespace,
				},
			})
		}
	}

	logger.V(1).Info("Found Ingresses for VPSGateway", "vpsGateway", gateway.Name, "count", len(requests))
	return requests
}

// findVPSGatewayByIngressClassName searches for a VPSGateway across all namespaces
// that matches the given IngressClass name
func (r *IngressReconciler) findVPSGatewayByIngressClassName(ctx context.Context, ingressClassName string) (*gatewayv1alpha1.VPSGateway, error) {
	gatewayList := &gatewayv1alpha1.VPSGatewayList{}
	if err := r.List(ctx, gatewayList); err != nil {
		return nil, err
	}

	for i := range gatewayList.Items {
		gw := &gatewayList.Items[i]
		if getIngressClassName(gw) == ingressClassName {
			return gw, nil
		}
	}

	return nil, nil
}

// getIngressClassName returns the IngressClass name for a VPSGateway
func getIngressClassName(gateway *gatewayv1alpha1.VPSGateway) string {
	return gateway.Spec.Ingress.IngressClassName
}
