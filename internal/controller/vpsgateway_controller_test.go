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
			vpsGatewayName  = "test-gateway"
			secretName      = "test-frp-token"
			secretNamespace = "vps-gateway-system"
			vpsAddress      = "192.168.1.100"
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
			// Clean up VPSGateway (namespace-scoped)
			gateway := &gatewayv1alpha1.VPSGateway{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: vpsGatewayName, Namespace: secretNamespace}, gateway)
			if err == nil {
				Expect(k8sClient.Delete(ctx, gateway)).Should(Succeed())
			}

			// Clean up Secret
			secret := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, secret)
			if err == nil {
				Expect(k8sClient.Delete(ctx, secret)).Should(Succeed())
			}
		})

		It("should create ConfigMap in the same namespace as VPSGateway", func() {
			By("Creating a VPSGateway")
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
						IngressClassName: "vps-gateway",
					},
				},
			}
			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())

			By("Checking if ConfigMap is created in the same namespace")
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

			By("Checking if ConfigMap has ownerReference to VPSGateway")
			Expect(configMap.OwnerReferences).To(HaveLen(1))
			Expect(configMap.OwnerReferences[0].Name).To(Equal(vpsGatewayName))
			Expect(configMap.OwnerReferences[0].Kind).To(Equal("VPSGateway"))
		})
	})

	Context("When creating a VPSGateway with customDomains", func() {
		const (
			vpsGatewayName  = "test-gateway-custom"
			secretName      = "test-frp-token-custom"
			secretNamespace = "vps-gateway-system"
			vpsAddress      = "192.168.1.101"
		)

		BeforeEach(func() {
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
			gateway := &gatewayv1alpha1.VPSGateway{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: vpsGatewayName, Namespace: secretNamespace}, gateway)
			if err == nil {
				Expect(k8sClient.Delete(ctx, gateway)).Should(Succeed())
			}

			secret := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, secret)
			if err == nil {
				Expect(k8sClient.Delete(ctx, secret)).Should(Succeed())
			}
		})

		It("should include customDomains in frpc config", func() {
			By("Creating a VPSGateway with customDomains")
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
						IngressClassName: "vps-gateway-custom",
						CustomDomains: []string{
							"*.yhmd.dev",
							"*.coder.yhmd.dev",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())

			By("Checking if ConfigMap includes customDomains")
			configMap := &corev1.ConfigMap{}
			configMapName := "frpc-config-" + vpsGatewayName
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      configMapName,
					Namespace: secretNamespace,
				}, configMap)
			}, timeout, interval).Should(Succeed())

			Expect(configMap.Data).To(HaveKey("frpc.toml"))
			Expect(configMap.Data["frpc.toml"]).To(ContainSubstring("*.yhmd.dev"))
			Expect(configMap.Data["frpc.toml"]).To(ContainSubstring("*.coder.yhmd.dev"))
		})

		It("should deduplicate domains within customDomains", func() {
			By("Creating a VPSGateway with duplicate customDomains")
			gateway := &gatewayv1alpha1.VPSGateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      vpsGatewayName + "-dedup",
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
						IngressClassName: "vps-gateway-dedup",
						CustomDomains: []string{
							"example.com",
							"example.com", // duplicate in customDomains
							"test.example.com",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())

			// Clean up this gateway as well
			defer func() {
				gw := &gatewayv1alpha1.VPSGateway{}
				err := k8sClient.Get(ctx, types.NamespacedName{Name: vpsGatewayName + "-dedup", Namespace: secretNamespace}, gw)
				if err == nil {
					Expect(k8sClient.Delete(ctx, gw)).Should(Succeed())
				}
			}()

			By("Checking if ConfigMap deduplicates domains")
			configMap := &corev1.ConfigMap{}
			configMapName := "frpc-config-" + vpsGatewayName + "-dedup"
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      configMapName,
					Namespace: secretNamespace,
				}, configMap)
			}, timeout, interval).Should(Succeed())

			Expect(configMap.Data).To(HaveKey("frpc.toml"))
			// Domains should be sorted and deduplicated
			config := configMap.Data["frpc.toml"]
			Expect(config).To(ContainSubstring(`customDomains = ["example.com", "test.example.com"]`))
		})
	})
})
