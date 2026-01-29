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
	"testing"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	externaldnsv1alpha1 "sigs.k8s.io/external-dns/apis/v1alpha1"
)

// TestCertificateStatusUpdateShouldNotTriggerReconcile tests that Certificate status-only
// updates should NOT trigger Ingress reconciliation.
//
// Bug context: When cert-manager updates Certificate status (conditions, renewalTime, etc.),
// these changes should not trigger Ingress reconciliation. Without the GenerationChangedPredicate,
// every status update triggers reconciliation, causing an infinite loop.
func TestCertificateStatusUpdateShouldNotTriggerReconcile(t *testing.T) {
	// This predicate should be used in SetupWithManager for Owns(&Certificate{})
	pred := predicate.GenerationChangedPredicate{}

	// Create a Certificate with generation 1
	oldCert := &certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-cert",
			Namespace:  "test-ns",
			Generation: 1,
		},
		Spec: certmanagerv1.CertificateSpec{
			SecretName: "test-secret",
			DNSNames:   []string{"test.example.com"},
			IssuerRef: cmmeta.ObjectReference{
				Name: "letsencrypt-prod",
				Kind: "ClusterIssuer",
			},
		},
	}

	// Simulate cert-manager updating only the status (generation remains the same)
	newCertWithStatusOnly := oldCert.DeepCopy()
	newCertWithStatusOnly.Status = certmanagerv1.CertificateStatus{
		Conditions: []certmanagerv1.CertificateCondition{
			{
				Type:   certmanagerv1.CertificateConditionReady,
				Status: cmmeta.ConditionTrue,
			},
		},
	}

	updateEvent := event.UpdateEvent{
		ObjectOld: oldCert,
		ObjectNew: newCertWithStatusOnly,
	}

	// The predicate should return false for status-only updates (same generation)
	shouldReconcile := pred.Update(updateEvent)
	if shouldReconcile {
		t.Errorf("GenerationChangedPredicate should return false for status-only Certificate update, got true")
	}

	// Now test that spec changes (which increment generation) DO trigger reconcile
	newCertWithSpecChange := oldCert.DeepCopy()
	newCertWithSpecChange.Generation = 2 // Spec change increments generation
	newCertWithSpecChange.Spec.DNSNames = []string{"test.example.com", "new.example.com"}

	specChangeEvent := event.UpdateEvent{
		ObjectOld: oldCert,
		ObjectNew: newCertWithSpecChange,
	}

	shouldReconcileSpecChange := pred.Update(specChangeEvent)
	if !shouldReconcileSpecChange {
		t.Errorf("GenerationChangedPredicate should return true for spec change (generation change), got false")
	}
}

// TestDNSEndpointStatusUpdateShouldNotTriggerReconcile tests that DNSEndpoint status-only
// updates should NOT trigger Ingress reconciliation.
func TestDNSEndpointStatusUpdateShouldNotTriggerReconcile(t *testing.T) {
	pred := predicate.GenerationChangedPredicate{}

	oldEndpoint := &externaldnsv1alpha1.DNSEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-dns",
			Namespace:  "test-ns",
			Generation: 1,
		},
	}

	// Simulate external-dns updating only the status
	newEndpointWithStatusOnly := oldEndpoint.DeepCopy()
	newEndpointWithStatusOnly.Status = externaldnsv1alpha1.DNSEndpointStatus{
		ObservedGeneration: 1,
	}

	updateEvent := event.UpdateEvent{
		ObjectOld: oldEndpoint,
		ObjectNew: newEndpointWithStatusOnly,
	}

	shouldReconcile := pred.Update(updateEvent)
	if shouldReconcile {
		t.Errorf("GenerationChangedPredicate should return false for status-only DNSEndpoint update, got true")
	}
}

// TestPredicateAllowsCreateAndDelete tests that the predicate still allows
// Create and Delete events, which are needed for proper controller operation.
func TestPredicateAllowsCreateAndDelete(t *testing.T) {
	pred := predicate.GenerationChangedPredicate{}

	cert := &certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-cert",
			Namespace:  "test-ns",
			Generation: 1,
		},
	}

	// Create event should be allowed
	createEvent := event.CreateEvent{
		Object: cert,
	}
	if !pred.Create(createEvent) {
		t.Errorf("GenerationChangedPredicate should return true for Create event, got false")
	}

	// Delete event should be allowed
	deleteEvent := event.DeleteEvent{
		Object: cert,
	}
	if !pred.Delete(deleteEvent) {
		t.Errorf("GenerationChangedPredicate should return true for Delete event, got false")
	}
}

// TestDefaultOwnsBehaviorCausesInfiniteLoop demonstrates that without
// GenerationChangedPredicate, the default Owns() behavior would trigger
// reconciliation on every status update, causing an infinite loop.
//
// This test verifies the BUG: Default predicate triggers on ALL changes.
func TestDefaultOwnsBehaviorCausesInfiniteLoop(t *testing.T) {
	// Default Owns() uses ResourceVersionChangedPredicate which triggers on ANY change
	// We simulate this by checking that status-only updates still pass the filter
	defaultPred := predicate.ResourceVersionChangedPredicate{}

	oldCert := &certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "test-cert",
			Namespace:       "test-ns",
			Generation:      1,
			ResourceVersion: "1000",
		},
	}

	// Status-only update changes resourceVersion but not generation
	newCertWithStatusOnly := oldCert.DeepCopy()
	newCertWithStatusOnly.ResourceVersion = "1001" // Changed by API server on status update
	newCertWithStatusOnly.Status = certmanagerv1.CertificateStatus{
		Conditions: []certmanagerv1.CertificateCondition{
			{
				Type:   certmanagerv1.CertificateConditionReady,
				Status: cmmeta.ConditionTrue,
			},
		},
	}

	updateEvent := event.UpdateEvent{
		ObjectOld: oldCert,
		ObjectNew: newCertWithStatusOnly,
	}

	// BUG: Default predicate returns true for status-only updates
	// This causes infinite reconcile loop when cert-manager updates Certificate status
	triggersReconcile := defaultPred.Update(updateEvent)
	if !triggersReconcile {
		t.Errorf("Default ResourceVersionChangedPredicate should return true for status-only update (this demonstrates the bug)")
	}

	// With GenerationChangedPredicate, status-only updates are filtered out
	fixedPred := predicate.GenerationChangedPredicate{}
	triggersReconcileFixed := fixedPred.Update(updateEvent)
	if triggersReconcileFixed {
		t.Errorf("GenerationChangedPredicate should return false for status-only update (this is the fix)")
	}
}
