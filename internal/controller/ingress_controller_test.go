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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	externaldnsv1alpha1 "sigs.k8s.io/external-dns/apis/v1alpha1"

	gatewayv1alpha1 "github.com/hmdyt/homelab-gateway-operator/api/v1alpha1"
)

var _ = Describe("Ingress Controller", func() {
	const (
		timeout  = time.Second * 30
		interval = time.Millisecond * 250
	)

	Context("When creating an Ingress with vps-gateway IngressClass", func() {
		const (
			vpsGatewayName   = "ingress-test-gateway"
			secretName       = "ingress-test-frp-token"
			secretNamespace  = "vps-gateway-system"
			ingressName      = "test-app-ingress"
			ingressNamespace = "vps-gateway-system"
			vpsAddress       = "192.168.1.200"
			testDomain       = "myapp.example.com"
		)

		var ingressClassName string

		BeforeEach(func() {
			ingressClassName = "vps-gateway-" + vpsGatewayName

			// Create the Secret first
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: secretNamespace,
				},
				StringData: map[string]string{
					"token": "test-token-value",
				},
			}
			Expect(k8sClient.Create(ctx, secret)).Should(Succeed())

			// Create the VPSGateway (namespace-scoped)
			gateway := &gatewayv1alpha1.VPSGateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      vpsGatewayName,
					Namespace: secretNamespace,
				},
				Spec: gatewayv1alpha1.VPSGatewaySpec{
					VPS: gatewayv1alpha1.VPSConfig{
						Address: vpsAddress,
					},
					FRP: gatewayv1alpha1.FRPConfig{
						Port: 7000,
						TokenSecretRef: gatewayv1alpha1.SecretReference{
							Name:      secretName,
							Namespace: secretNamespace,
							Key:       "token",
						},
					},
					Ingress: gatewayv1alpha1.IngressConfig{
						Enabled:          true,
						IngressClassName: ingressClassName,
						TLS: gatewayv1alpha1.IngressTLSConfig{
							Enabled: true,
							Issuer:  "letsencrypt-prod",
						},
						DNS: gatewayv1alpha1.DNSConfig{
							Enabled: true,
							TTL:     300,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())

			// Wait for VPSGateway to be ready (no IngressClass is created by operator anymore)
			Eventually(func() bool {
				gw := &gatewayv1alpha1.VPSGateway{}
				err := k8sClient.Get(ctx, types.NamespacedName{Name: vpsGatewayName, Namespace: secretNamespace}, gw)
				return err == nil
			}, timeout, interval).Should(BeTrue())
		})

		AfterEach(func() {
			// Clean up Ingress
			ingress := &networkingv1.Ingress{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: ingressName, Namespace: ingressNamespace}, ingress)
			if err == nil {
				Expect(k8sClient.Delete(ctx, ingress)).Should(Succeed())
			}

			// Clean up VPSGateway (namespace-scoped)
			gateway := &gatewayv1alpha1.VPSGateway{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: vpsGatewayName, Namespace: secretNamespace}, gateway)
			if err == nil {
				Expect(k8sClient.Delete(ctx, gateway)).Should(Succeed())
			}

			// Clean up Secret
			secret := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, secret)
			if err == nil {
				Expect(k8sClient.Delete(ctx, secret)).Should(Succeed())
			}

			// Wait for cleanup
			time.Sleep(time.Second)
		})

		It("should create DNSEndpoint when DNS is enabled", func() {
			// Skip if external-dns CRD is not installed
			Skip("Skipping: external-dns CRD (DNSEndpoint) is not installed in envtest")

			By("Creating an Ingress with vps-gateway IngressClass")
			pathType := networkingv1.PathTypePrefix
			ingress := &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ingressName,
					Namespace: ingressNamespace,
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: &ingressClassName,
					Rules: []networkingv1.IngressRule{
						{
							Host: testDomain,
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/",
											PathType: &pathType,
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "test-service",
													Port: networkingv1.ServiceBackendPort{
														Number: 80,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, ingress)).Should(Succeed())

			By("Checking if DNSEndpoint is created")
			dnsEndpoint := &externaldnsv1alpha1.DNSEndpoint{}
			dnsEndpointName := ingressNamespace + "-" + ingressName + "-dns"
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      dnsEndpointName,
					Namespace: ingressNamespace,
				}, dnsEndpoint)
			}, timeout, interval).Should(Succeed())

			Expect(dnsEndpoint.Spec.Endpoints).To(HaveLen(1))
			Expect(dnsEndpoint.Spec.Endpoints[0].DNSName).To(Equal(testDomain))
			Expect(dnsEndpoint.Spec.Endpoints[0].Targets).To(ContainElement(vpsAddress))
			Expect(dnsEndpoint.Spec.Endpoints[0].RecordType).To(Equal("A"))
		})

		It("should create Certificate when TLS is enabled", func() {
			// Skip if cert-manager CRD is not installed
			Skip("Skipping: cert-manager CRD (Certificate) is not installed in envtest")

			By("Creating an Ingress with vps-gateway IngressClass")
			pathType := networkingv1.PathTypePrefix
			ingress := &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ingressName,
					Namespace: ingressNamespace,
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: &ingressClassName,
					Rules: []networkingv1.IngressRule{
						{
							Host: testDomain,
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/",
											PathType: &pathType,
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "test-service",
													Port: networkingv1.ServiceBackendPort{
														Number: 80,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, ingress)).Should(Succeed())

			By("Checking if Certificate is created")
			certificate := &certmanagerv1.Certificate{}
			certificateName := ingressNamespace + "-" + ingressName + "-cert"
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      certificateName,
					Namespace: ingressNamespace,
				}, certificate)
			}, timeout, interval).Should(Succeed())

			Expect(certificate.Spec.DNSNames).To(ContainElement(testDomain))
			Expect(certificate.Spec.IssuerRef.Name).To(Equal("letsencrypt-prod"))
			Expect(certificate.Spec.IssuerRef.Kind).To(Equal("ClusterIssuer"))
		})

		It("should update VPSGateway status with watched Ingresses", func() {
			By("Creating an Ingress with vps-gateway IngressClass")
			pathType := networkingv1.PathTypePrefix
			ingress := &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ingressName,
					Namespace: ingressNamespace,
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: &ingressClassName,
					Rules: []networkingv1.IngressRule{
						{
							Host: testDomain,
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/",
											PathType: &pathType,
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "test-service",
													Port: networkingv1.ServiceBackendPort{
														Number: 80,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, ingress)).Should(Succeed())

			By("Checking VPSGateway status.watchedIngresses")
			gateway := &gatewayv1alpha1.VPSGateway{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: vpsGatewayName, Namespace: secretNamespace}, gateway)
				if err != nil {
					return false
				}
				for _, watched := range gateway.Status.WatchedIngresses {
					if watched.Name == ingressName && watched.Namespace == ingressNamespace {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			// Verify domain is in watched ingresses
			var found bool
			for _, watched := range gateway.Status.WatchedIngresses {
				if watched.Name == ingressName {
					Expect(watched.Domains).To(ContainElement(testDomain))
					found = true
					break
				}
			}
			Expect(found).To(BeTrue())
		})

		It("should include domain in frpc ConfigMap", func() {
			By("Creating an Ingress with vps-gateway IngressClass")
			pathType := networkingv1.PathTypePrefix
			ingress := &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ingressName,
					Namespace: ingressNamespace,
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: &ingressClassName,
					Rules: []networkingv1.IngressRule{
						{
							Host: testDomain,
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/",
											PathType: &pathType,
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "test-service",
													Port: networkingv1.ServiceBackendPort{
														Number: 80,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, ingress)).Should(Succeed())

			By("Checking if domain is in ConfigMap")
			configMap := &corev1.ConfigMap{}
			configMapName := "frpc-config-" + vpsGatewayName
			Eventually(func() string {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      configMapName,
					Namespace: secretNamespace,
				}, configMap)
				if err != nil {
					return ""
				}
				frpcConfig, ok := configMap.Data["frpc.toml"]
				if !ok {
					return ""
				}
				return frpcConfig
			}, timeout, interval).Should(ContainSubstring(testDomain))
		})
	})
})
