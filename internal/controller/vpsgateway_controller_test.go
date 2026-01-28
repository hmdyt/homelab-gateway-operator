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

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	gatewayv1alpha1 "github.com/hmdyt/homelab-gateway-operator/api/v1alpha1"
)

var _ = Describe("VPSGateway Controller", func() {
	const (
		timeout  = time.Second * 30
		interval = time.Millisecond * 250
	)

	Context("When creating a VPSGateway", func() {
		const (
			vpsGatewayName   = "test-gateway"
			secretName       = "test-frp-token"
			secretNamespace  = "vps-gateway-system"
			vpsAddress       = "192.168.1.100"
			ingressClassName = "vps-gateway-test-gateway"
		)

		BeforeEach(func() {
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
		})

		AfterEach(func() {
			// Clean up VPSGateway
			gateway := &gatewayv1alpha1.VPSGateway{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: vpsGatewayName}, gateway)
			if err == nil {
				Expect(k8sClient.Delete(ctx, gateway)).Should(Succeed())
			}

			// Clean up Secret
			secret := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, secret)
			if err == nil {
				Expect(k8sClient.Delete(ctx, secret)).Should(Succeed())
			}

			// Clean up IngressClass
			ingressClass := &networkingv1.IngressClass{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: ingressClassName}, ingressClass)
			if err == nil {
				Expect(k8sClient.Delete(ctx, ingressClass)).Should(Succeed())
			}
		})

		It("should create IngressClass when ingress is enabled", func() {
			By("Creating a VPSGateway")
			gateway := &gatewayv1alpha1.VPSGateway{
				ObjectMeta: metav1.ObjectMeta{
					Name: vpsGatewayName,
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
						Enabled: true,
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

			By("Checking if IngressClass is created")
			ingressClass := &networkingv1.IngressClass{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: ingressClassName}, ingressClass)
			}, timeout, interval).Should(Succeed())

			Expect(ingressClass.Spec.Controller).To(Equal("traefik.io/ingress-controller"))
			Expect(ingressClass.Annotations["gateway.hmdyt.github.io/vps-address"]).To(Equal(vpsAddress))

			By("Checking VPSGateway has IngressClassReady condition")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: vpsGatewayName}, gateway)
				if err != nil {
					return false
				}
				for _, cond := range gateway.Status.Conditions {
					if cond.Type == gatewayv1alpha1.ConditionTypeIngressClassReady && cond.Status == metav1.ConditionTrue {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
		})

		It("should create ConfigMap in the secret namespace", func() {
			By("Creating a VPSGateway")
			gateway := &gatewayv1alpha1.VPSGateway{
				ObjectMeta: metav1.ObjectMeta{
					Name: vpsGatewayName,
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
						Enabled: true,
					},
				},
			}
			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())

			By("Checking if ConfigMap is created")
			configMap := &corev1.ConfigMap{}
			configMapName := "frpc-config-" + vpsGatewayName
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      configMapName,
					Namespace: secretNamespace,
				}, configMap)
			}, timeout, interval).Should(Succeed())

			Expect(configMap.Data).To(HaveKey("frpc.toml"))
			Expect(configMap.Data["frpc.toml"]).To(ContainSubstring(vpsAddress))
			Expect(configMap.Data["frpc.toml"]).To(ContainSubstring("serverPort = 7000"))
		})
	})
})
