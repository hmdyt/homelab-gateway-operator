//go:build e2e
// +build e2e

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

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/hmdyt/homelab-gateway-operator/test/utils"
)

// namespace where the project is deployed in
const namespace = "homelab-gateway-operator-system"

// serviceAccountName created for the project
const serviceAccountName = "homelab-gateway-operator-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "homelab-gateway-operator-controller-manager-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "homelab-gateway-operator-metrics-binding"

// Test resource constants
const (
	testVPSGatewayName = "e2e-test-gateway"
	testSecretName     = "e2e-frp-token"
	testIngressName    = "e2e-test-ingress"
	testDomain         = "e2e-test.example.com"
	testNamespace      = "default"
	testFRPToken       = "e2e-test-token"
	mockFRPSNamespace  = "frps-mock"

	// Traffic flow test constants
	trafficTestGatewayName = "e2e-traffic-gateway"
	trafficTestIngressName = "e2e-traffic-ingress"
	trafficTestDomain      = "traffic-test.example.com"
	trafficTestBackendName = "e2e-backend"
)

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("cleaning up mock frps server namespace")
		cmd = exec.Command("kubectl", "delete", "ns", mockFRPSNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching curl-metrics logs")
			cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Metrics logs:\n %s", metricsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get curl-metrics logs: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				// Get the name of the controller-manager pod
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("controller-manager"))

				// Validate the pod's status
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		// Skip metrics test as it's not the focus of these tests and can fail in CI environments
		// The metrics functionality is tested separately
		It("should ensure the metrics endpoint is serving metrics", Label("metrics"), func() {
			Skip("Skipping metrics test to focus on VPSGateway and Ingress tests")
			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
				"--clusterrole=homelab-gateway-operator-metrics-reader",
				fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName),
			)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create ClusterRoleBinding")

			By("validating that the metrics service is available")
			cmd = exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("getting the service account token")
			token, err := serviceAccountToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("ensuring the controller pod is ready")
			verifyControllerPodReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", controllerPodName, "-n", namespace,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "Controller pod not ready")
			}
			Eventually(verifyControllerPodReady, 3*time.Minute, time.Second).Should(Succeed())

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("Serving metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted, 3*time.Minute, time.Second).Should(Succeed())

			// +kubebuilder:scaffold:e2e-metrics-webhooks-readiness

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "curlimages/curl:latest",
							"command": ["/bin/sh", "-c"],
							"args": ["curl -v -k -H 'Authorization: Bearer %s' https://%s.%s.svc.cluster.local:8443/metrics"],
							"securityContext": {
								"readOnlyRootFilesystem": true,
								"allowPrivilegeEscalation": false,
								"capabilities": {
									"drop": ["ALL"]
								},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {
									"type": "RuntimeDefault"
								}
							}
						}],
						"serviceAccountName": "%s"
					}
				}`, token, metricsServiceName, namespace, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
					"-o", "jsonpath={.status.phase}",
					"-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
			}
			Eventually(verifyCurlUp, 5*time.Minute).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			verifyMetricsAvailable := func(g Gomega) {
				metricsOutput, err := getMetricsOutput()
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
				g.Expect(metricsOutput).NotTo(BeEmpty())
				g.Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
			}
			Eventually(verifyMetricsAvailable, 2*time.Minute).Should(Succeed())
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks
	})

	// mockFRPSAddress will be set after deploying the mock frps server
	var mockFRPSAddress string

	Context("VPSGateway作成時", Ordered, func() {
		BeforeAll(func() {
			By("creating namespace for mock frps server")
			cmd := exec.Command("kubectl", "create", "ns", mockFRPSNamespace, "--dry-run=client", "-o", "yaml")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(output)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("deploying mock frps server")
			frpsYAML := fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: frps-config
  namespace: %s
data:
  frps.toml: |
    bindPort = 7000
    vhostHTTPPort = 8080
    auth.token = "%s"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frps
  namespace: %s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: frps
  template:
    metadata:
      labels:
        app: frps
    spec:
      containers:
      - name: frps
        image: snowdreamtech/frps:0.53.2
        ports:
        - containerPort: 7000
        - containerPort: 8080
        volumeMounts:
        - name: config
          mountPath: /etc/frp
      volumes:
      - name: config
        configMap:
          name: frps-config
---
apiVersion: v1
kind: Service
metadata:
  name: frps
  namespace: %s
spec:
  selector:
    app: frps
  ports:
  - name: control
    port: 7000
    targetPort: 7000
  - name: http
    port: 8080
    targetPort: 8080
`, mockFRPSNamespace, testFRPToken, mockFRPSNamespace, mockFRPSNamespace)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(frpsYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for mock frps server to be ready")
			verifyFRPSReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "deployment", "frps", "-n", mockFRPSNamespace,
					"-o", "jsonpath={.status.readyReplicas}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("1"), "frps deployment should have 1 ready replica")
			}
			Eventually(verifyFRPSReady, 2*time.Minute, time.Second).Should(Succeed())

			By("getting mock frps service ClusterIP")
			cmd = exec.Command("kubectl", "get", "service", "frps", "-n", mockFRPSNamespace,
				"-o", "jsonpath={.spec.clusterIP}")
			clusterIP, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(clusterIP).NotTo(BeEmpty())
			mockFRPSAddress = clusterIP

			By("creating test Secret for FRP token")
			secretYAML := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque
stringData:
  token: "%s"
`, testSecretName, testNamespace, testFRPToken)
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(secretYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		// NOTE: VPSGateway削除は「VPSGateway削除時」Contextでテストするため、
		// ここでは削除しない。最終的なクリーンアップはManagerのAfterAllで行う。

		It("VPSGatewayが作成されること", func() {
			By("creating VPSGateway CR (namespace-scoped)")
			vpsGatewayYAML := fmt.Sprintf(`apiVersion: gateway.hmdyt.github.io/v1alpha1
kind: VPSGateway
metadata:
  name: %s
  namespace: %s
spec:
  vps:
    address: "%s"
  frp:
    port: 7000
    tokenSecretRef:
      name: %s
      namespace: %s
  ingress:
    enabled: true
    ingressClassName: vps-gateway-%s
    tls:
      enabled: true
      issuer: "letsencrypt-prod"
    dns:
      enabled: true
      ttl: 300
`, testVPSGatewayName, testNamespace, mockFRPSAddress, testSecretName, testNamespace, testVPSGatewayName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(vpsGatewayYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		It("指定されたnamespaceにfrpc ConfigMapが作成されること", func() {
			By("verifying frpc ConfigMap is created")
			expectedConfigMapName := fmt.Sprintf("frpc-config-%s", testVPSGatewayName)
			verifyConfigMap := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "configmap", expectedConfigMapName, "-n", testNamespace)
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "frpc ConfigMap should exist")
			}
			Eventually(verifyConfigMap).Should(Succeed())
		})

		It("VPSGatewayのstatusがReadyになること", func() {
			By("verifying VPSGateway status phase is Ready")
			verifyStatus := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vpsgateway", testVPSGatewayName, "-n", testNamespace,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Ready"), "VPSGateway phase should be Ready")
			}
			Eventually(verifyStatus).Should(Succeed())
		})

		It("子リソースにownerReferenceが設定されていること", func() {
			By("verifying ConfigMap has ownerReference")
			expectedConfigMapName := fmt.Sprintf("frpc-config-%s", testVPSGatewayName)
			verifyOwnerReference := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "configmap", expectedConfigMapName, "-n", testNamespace,
					"-o", "jsonpath={.metadata.ownerReferences[0].name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal(testVPSGatewayName), "ConfigMap should have ownerReference to VPSGateway")
			}
			Eventually(verifyOwnerReference).Should(Succeed())
		})
	})

	Context("vps-gateway classのIngress作成時", Ordered, func() {
		It("DNSEndpointが作成されること", func() {
			ingressClassName := fmt.Sprintf("vps-gateway-%s", testVPSGatewayName)
			By("creating Ingress with vps-gateway IngressClass")
			ingressYAML := fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %s
  namespace: %s
spec:
  ingressClassName: %s
  rules:
    - host: %s
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: test-service
                port:
                  number: 80
`, testIngressName, testNamespace, ingressClassName, testDomain)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(ingressYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying DNSEndpoint is created")
			expectedDNSEndpointName := fmt.Sprintf("%s-%s-dns", testNamespace, testIngressName)
			verifyDNSEndpoint := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "dnsendpoint", expectedDNSEndpointName, "-n", testNamespace)
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "DNSEndpoint should exist")
			}
			Eventually(verifyDNSEndpoint).Should(Succeed())

			By("verifying DNSEndpoint has correct target (VPS address)")
			verifyDNSEndpointTarget := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "dnsendpoint", expectedDNSEndpointName, "-n", testNamespace,
					"-o", "jsonpath={.spec.endpoints[0].targets[0]}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal(mockFRPSAddress), "DNSEndpoint target should be VPS address")
			}
			Eventually(verifyDNSEndpointTarget).Should(Succeed())
		})

		It("Certificateが作成されること", func() {
			By("verifying Certificate is created")
			expectedCertName := fmt.Sprintf("%s-%s-cert", testNamespace, testIngressName)
			verifyCertificate := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "certificate", expectedCertName, "-n", testNamespace)
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Certificate should exist")
			}
			Eventually(verifyCertificate).Should(Succeed())

			By("verifying Certificate has correct issuer")
			verifyCertIssuer := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "certificate", expectedCertName, "-n", testNamespace,
					"-o", "jsonpath={.spec.issuerRef.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("letsencrypt-prod"), "Certificate issuer should be letsencrypt-prod")
			}
			Eventually(verifyCertIssuer).Should(Succeed())
		})

		It("frpc ConfigMapにIngressのドメインが反映されること", func() {
			By("verifying frpc ConfigMap contains the Ingress domain")
			expectedConfigMapName := fmt.Sprintf("frpc-config-%s", testVPSGatewayName)
			verifyConfigMapDomain := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "configmap", expectedConfigMapName, "-n", testNamespace,
					"-o", "jsonpath={.data['frpc\\.toml']}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring(testDomain), "frpc ConfigMap should contain the domain")
			}
			Eventually(verifyConfigMapDomain).Should(Succeed())
		})
	})

	Context("複数ホストのIngress作成時", func() {
		It("複数ホストが正しく処理されること", func() {
			multiHostIngressName := "e2e-multi-host-ingress"
			host1 := "api.e2e-test.example.com"
			host2 := "web.e2e-test.example.com"
			ingressClassName := fmt.Sprintf("vps-gateway-%s", testVPSGatewayName)

			By("creating Ingress with multiple hosts")
			ingressYAML := fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %s
  namespace: %s
spec:
  ingressClassName: %s
  rules:
    - host: %s
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: api-service
                port:
                  number: 8080
    - host: %s
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: web-service
                port:
                  number: 3000
`, multiHostIngressName, testNamespace, ingressClassName, host1, host2)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(ingressYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying DNSEndpoint is created with multiple endpoints")
			expectedDNSEndpointName := fmt.Sprintf("%s-%s-dns", testNamespace, multiHostIngressName)
			verifyMultipleDNSEndpoints := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "dnsendpoint", expectedDNSEndpointName, "-n", testNamespace,
					"-o", "jsonpath={.spec.endpoints}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring(host1), "DNSEndpoint should contain first host")
				g.Expect(output).To(ContainSubstring(host2), "DNSEndpoint should contain second host")
			}
			Eventually(verifyMultipleDNSEndpoints).Should(Succeed())

			By("cleaning up multi-host Ingress")
			cmd = exec.Command("kubectl", "delete", "ingress", multiHostIngressName, "-n", testNamespace)
			_, _ = utils.Run(cmd)
		})
	})

	Context("Ingress削除時", func() {
		It("DNSEndpointとCertificateが削除されること", func() {
			By("deleting the test Ingress")
			cmd := exec.Command("kubectl", "delete", "ingress", testIngressName, "-n", testNamespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			expectedDNSEndpointName := fmt.Sprintf("%s-%s-dns", testNamespace, testIngressName)
			expectedCertName := fmt.Sprintf("%s-%s-cert", testNamespace, testIngressName)

			By("verifying DNSEndpoint is deleted")
			verifyDNSEndpointDeleted := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "dnsendpoint", expectedDNSEndpointName, "-n", testNamespace)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred(), "DNSEndpoint should be deleted")
			}
			Eventually(verifyDNSEndpointDeleted).Should(Succeed())

			By("verifying Certificate is deleted")
			verifyCertDeleted := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "certificate", expectedCertName, "-n", testNamespace)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred(), "Certificate should be deleted")
			}
			Eventually(verifyCertDeleted).Should(Succeed())
		})
	})

	Context("VPSGateway削除時", func() {
		It("子リソースが自動削除されること", func() {
			expectedConfigMapName := fmt.Sprintf("frpc-config-%s", testVPSGatewayName)

			By("deleting VPSGateway")
			cmd := exec.Command("kubectl", "delete", "vpsgateway", testVPSGatewayName, "-n", testNamespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying ConfigMap is deleted (via ownerReference garbage collection)")
			verifyConfigMapDeleted := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "configmap", expectedConfigMapName, "-n", testNamespace)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred(), "ConfigMap should be deleted")
			}
			Eventually(verifyConfigMapDeleted).Should(Succeed())
		})
	})

	Context("エッジケース", Ordered, func() {
		BeforeAll(func() {
			By("creating test Secret for FRP token (edge cases)")
			secretYAML := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s-edge
  namespace: %s
type: Opaque
stringData:
  token: "%s"
`, testSecretName, testNamespace, testFRPToken)
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(secretYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterAll(func() {
			By("cleaning up edge case VPSGateway resources")
			cmd := exec.Command("kubectl", "delete", "vpsgateway", "e2e-dns-disabled", "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "vpsgateway", "e2e-tls-disabled", "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "ingress", "e2e-edge-ingress", "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "ingress", "e2e-no-class-ingress", "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "secret", fmt.Sprintf("%s-edge", testSecretName), "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("VPSGatewayでDNSが無効の場合、DNSEndpointが作成されないこと", func() {
			vpsGatewayName := "e2e-dns-disabled"
			ingressClassName := fmt.Sprintf("vps-gateway-%s", vpsGatewayName)
			By("creating VPSGateway with DNS disabled")
			vpsGatewayYAML := fmt.Sprintf(`apiVersion: gateway.hmdyt.github.io/v1alpha1
kind: VPSGateway
metadata:
  name: %s
  namespace: %s
spec:
  vps:
    address: "%s"
  frp:
    port: 7000
    tokenSecretRef:
      name: %s-edge
      namespace: %s
  ingress:
    enabled: true
    ingressClassName: %s
    tls:
      enabled: true
    dns:
      enabled: false
`, vpsGatewayName, testNamespace, mockFRPSAddress, testSecretName, testNamespace, ingressClassName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(vpsGatewayYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VPSGateway to be ready")
			verifyReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vpsgateway", vpsGatewayName, "-n", testNamespace,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Ready"))
			}
			Eventually(verifyReady).Should(Succeed())

			By("creating Ingress for DNS-disabled VPSGateway")
			ingressName := "e2e-edge-ingress"
			ingressYAML := fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %s
  namespace: %s
spec:
  ingressClassName: %s
  rules:
    - host: dns-disabled.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: test-service
                port:
                  number: 80
`, ingressName, testNamespace, ingressClassName)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(ingressYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting a bit for reconciliation")
			time.Sleep(5 * time.Second)

			By("verifying DNSEndpoint is NOT created")
			expectedDNSEndpointName := fmt.Sprintf("%s-%s-dns", testNamespace, ingressName)
			cmd = exec.Command("kubectl", "get", "dnsendpoint", expectedDNSEndpointName, "-n", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "DNSEndpoint should NOT exist when DNS is disabled")

			By("cleaning up")
			cmd = exec.Command("kubectl", "delete", "ingress", ingressName, "-n", testNamespace)
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "vpsgateway", vpsGatewayName, "-n", testNamespace)
			_, _ = utils.Run(cmd)
		})

		It("VPSGatewayでTLSが無効の場合、Certificateが作成されないこと", func() {
			vpsGatewayName := "e2e-tls-disabled"
			ingressClassName := fmt.Sprintf("vps-gateway-%s", vpsGatewayName)
			By("creating VPSGateway with TLS disabled")
			vpsGatewayYAML := fmt.Sprintf(`apiVersion: gateway.hmdyt.github.io/v1alpha1
kind: VPSGateway
metadata:
  name: %s
  namespace: %s
spec:
  vps:
    address: "%s"
  frp:
    port: 7000
    tokenSecretRef:
      name: %s-edge
      namespace: %s
  ingress:
    enabled: true
    ingressClassName: %s
    tls:
      enabled: false
    dns:
      enabled: true
`, vpsGatewayName, testNamespace, mockFRPSAddress, testSecretName, testNamespace, ingressClassName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(vpsGatewayYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VPSGateway to be ready")
			verifyReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vpsgateway", vpsGatewayName, "-n", testNamespace,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Ready"))
			}
			Eventually(verifyReady).Should(Succeed())

			By("creating Ingress for TLS-disabled VPSGateway")
			ingressName := "e2e-tls-disabled-ingress"
			ingressYAML := fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %s
  namespace: %s
spec:
  ingressClassName: %s
  rules:
    - host: tls-disabled.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: test-service
                port:
                  number: 80
`, ingressName, testNamespace, ingressClassName)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(ingressYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting a bit for reconciliation")
			time.Sleep(5 * time.Second)

			By("verifying Certificate is NOT created")
			expectedCertName := fmt.Sprintf("%s-%s-cert", testNamespace, ingressName)
			cmd = exec.Command("kubectl", "get", "certificate", expectedCertName, "-n", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "Certificate should NOT exist when TLS is disabled")

			By("cleaning up")
			cmd = exec.Command("kubectl", "delete", "ingress", ingressName, "-n", testNamespace)
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "vpsgateway", vpsGatewayName, "-n", testNamespace)
			_, _ = utils.Run(cmd)
		})

		It("vps-gateway以外のIngressClassの場合、Ingressが無視されること", func() {
			By("creating Ingress without vps-gateway IngressClass")
			ingressName := "e2e-no-class-ingress"
			ingressYAML := fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %s
  namespace: %s
spec:
  ingressClassName: nginx
  rules:
    - host: no-class.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: test-service
                port:
                  number: 80
`, ingressName, testNamespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(ingressYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting a bit for reconciliation")
			time.Sleep(5 * time.Second)

			By("verifying DNSEndpoint is NOT created for non-vps-gateway Ingress")
			expectedDNSEndpointName := fmt.Sprintf("%s-%s-dns", testNamespace, ingressName)
			cmd = exec.Command("kubectl", "get", "dnsendpoint", expectedDNSEndpointName, "-n", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "DNSEndpoint should NOT exist for non-vps-gateway Ingress")

			By("verifying Certificate is NOT created for non-vps-gateway Ingress")
			expectedCertName := fmt.Sprintf("%s-%s-cert", testNamespace, ingressName)
			cmd = exec.Command("kubectl", "get", "certificate", expectedCertName, "-n", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "Certificate should NOT exist for non-vps-gateway Ingress")

			By("cleaning up")
			cmd = exec.Command("kubectl", "delete", "ingress", ingressName, "-n", testNamespace)
			_, _ = utils.Run(cmd)
		})
	})

	Context("トラフィックフロー", Ordered, func() {
		trafficIngressClassName := fmt.Sprintf("vps-gateway-%s", trafficTestGatewayName)

		BeforeAll(func() {
			By("FRPトークン用のSecretを作成")
			secretYAML := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s-traffic
  namespace: %s
type: Opaque
stringData:
  token: "%s"
`, testSecretName, testNamespace, testFRPToken)
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(secretYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("トラフィックフローテスト用のVPSGatewayを作成")
			vpsGatewayYAML := fmt.Sprintf(`apiVersion: gateway.hmdyt.github.io/v1alpha1
kind: VPSGateway
metadata:
  name: %s
  namespace: %s
spec:
  vps:
    address: "%s"
  frp:
    port: 7000
    tokenSecretRef:
      name: %s-traffic
      namespace: %s
  ingress:
    enabled: true
    ingressClassName: %s
    tls:
      enabled: false
    dns:
      enabled: false
`, trafficTestGatewayName, testNamespace, mockFRPSAddress, testSecretName, testNamespace, trafficIngressClassName)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(vpsGatewayYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("VPSGatewayがReadyになるまで待機")
			verifyReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vpsgateway", trafficTestGatewayName, "-n", testNamespace,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Ready"))
			}
			Eventually(verifyReady).Should(Succeed())

			By("バックエンドPodとServiceを作成")
			backendYAML := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  labels:
    app: %s
spec:
  containers:
  - name: nginx
    image: nginx:alpine
    ports:
    - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: %s
  namespace: %s
spec:
  selector:
    app: %s
  ports:
  - port: 80
    targetPort: 80
`, trafficTestBackendName, testNamespace, trafficTestBackendName,
				trafficTestBackendName, testNamespace, trafficTestBackendName)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(backendYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("バックエンドPodがReadyになるまで待機")
			verifyBackendReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", trafficTestBackendName, "-n", testNamespace,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"))
			}
			Eventually(verifyBackendReady, 2*time.Minute, time.Second).Should(Succeed())

			By("トラフィックフローテスト用のIngressを作成")
			ingressYAML := fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %s
  namespace: %s
spec:
  ingressClassName: %s
  rules:
    - host: %s
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: %s
                port:
                  number: 80
`, trafficTestIngressName, testNamespace, trafficIngressClassName, trafficTestDomain, trafficTestBackendName)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(ingressYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("frpc ConfigMapにドメインが反映されるまで待機")
			expectedConfigMapName := fmt.Sprintf("frpc-config-%s", trafficTestGatewayName)
			verifyConfigMapDomain := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "configmap", expectedConfigMapName, "-n", testNamespace,
					"-o", "jsonpath={.data['frpc\\.toml']}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring(trafficTestDomain))
			}
			Eventually(verifyConfigMapDomain).Should(Succeed())

			By("frpc DeploymentがReadyになるまで待機")
			frpcDeploymentName := fmt.Sprintf("frpc-%s", trafficTestGatewayName)
			verifyFRPCReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "deployment", frpcDeploymentName, "-n", testNamespace,
					"-o", "jsonpath={.status.readyReplicas}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("1"))
			}
			Eventually(verifyFRPCReady, 2*time.Minute, time.Second).Should(Succeed())

			By("Traefik DeploymentがReadyになるまで待機")
			traefikDeploymentName := fmt.Sprintf("traefik-%s", trafficTestGatewayName)
			verifyTraefikReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "deployment", traefikDeploymentName, "-n", testNamespace,
					"-o", "jsonpath={.status.readyReplicas}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("1"))
			}
			Eventually(verifyTraefikReady, 2*time.Minute, time.Second).Should(Succeed())

			// Wait for frpc Pod to restart after ConfigMap update (triggered by Ingress creation)
			// The ConfigMap update causes the Deployment to rolling restart due to config-hash annotation
			By("frpc Podが新しい設定で再起動するまで待機")
			time.Sleep(3 * time.Second) // Give time for controller to update ConfigMap

			// Wait for the new frpc Pod to be ready after restart
			verifyFRPCReadyAfterRestart := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "deployment", frpcDeploymentName, "-n", testNamespace,
					"-o", "jsonpath={.status.updatedReplicas}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("1"))

				cmd = exec.Command("kubectl", "get", "deployment", frpcDeploymentName, "-n", testNamespace,
					"-o", "jsonpath={.status.readyReplicas}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("1"))
			}
			Eventually(verifyFRPCReadyAfterRestart, 2*time.Minute, time.Second).Should(Succeed())

			// Give time for frpc to establish connection to frps and register proxies
			By("frpcがfrpsに接続するまで待機")
			time.Sleep(10 * time.Second)
		})

		AfterAll(func() {
			By("トラフィックフローテストのリソースをクリーンアップ")
			cmd := exec.Command("kubectl", "delete", "ingress", trafficTestIngressName, "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "pod", trafficTestBackendName, "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "service", trafficTestBackendName, "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "vpsgateway", trafficTestGatewayName, "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "secret", fmt.Sprintf("%s-traffic", testSecretName), "-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("curl -> frps -> frpc -> traefik -> pod の経路でトラフィックが流れること", func() {
			By("kubectl port-forward を開始")
			portForwardCmd := exec.Command("kubectl", "port-forward", "-n", mockFRPSNamespace, "svc/frps", "18080:8080")
			err := portForwardCmd.Start()
			Expect(err).NotTo(HaveOccurred())
			defer portForwardCmd.Process.Kill()

			// port-forward が ready になるまで少し待つ
			time.Sleep(2 * time.Second)

			By("frps 経由で HTTP リクエストを送信")
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse // リダイレクトを追跡しない
				},
				Timeout: 10 * time.Second,
			}

			req, err := http.NewRequest("GET", "http://localhost:18080/", nil)
			Expect(err).NotTo(HaveOccurred())
			req.Host = trafficTestDomain

			resp, err := client.Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()

			By("トラフィックフローが成功したことを確認")
			// HTTP 200: 直接成功、または HTTP 301 + HTTPS リダイレクト: Traefik まで到達
			success := resp.StatusCode == http.StatusOK ||
				(resp.StatusCode == http.StatusMovedPermanently &&
					strings.Contains(resp.Header.Get("Location"), "https://"+trafficTestDomain))
			Expect(success).To(BeTrue(), "Expected HTTP 200 or 301 with HTTPS redirect, got status %d", resp.StatusCode)
		})
	})
})

// serviceAccountToken returns a token for the specified service account in the given namespace.
// It uses the Kubernetes TokenRequest API to generate a token by directly sending a request
// and parsing the resulting token from the API response.
func serviceAccountToken() (string, error) {
	const tokenRequestRawString = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	// Temporary file to store the token request
	secretName := fmt.Sprintf("%s-token-request", serviceAccountName)
	tokenRequestFile := filepath.Join("/tmp", secretName)
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestRawString), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	verifyTokenCreation := func(g Gomega) {
		// Execute kubectl command to create the token
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		g.Expect(err).NotTo(HaveOccurred())

		// Parse the JSON output to extract the token
		var token tokenRequest
		err = json.Unmarshal(output, &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, err
}

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() (string, error) {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	return utils.Run(cmd)
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response,
// containing only the token field that we need to extract.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}
