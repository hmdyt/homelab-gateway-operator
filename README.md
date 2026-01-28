# homelab-gateway-operator

Kubernetes Operator for managing VPS Gateway with frp (Fast Reverse Proxy) for homelab environments.

## 概要

このオペレーターは、グローバル IP を持たないホームラボ Kubernetes クラスタが VPS を経由してインターネットと通信するための frp クライアントを自動管理します。

### 主な機能

- **VPSGateway CRD**: VPS と frp の設定を宣言的に管理
- **自動リソース生成**: frpc ConfigMap, Deployment, Service を自動作成
- **Ingress サポート**: Traefik などの Ingress Controller への自動ルーティング
- **Egress サポート**: VPS 経由の Egress プロキシ設定

## クイックスタート

### 前提条件

- Go version v1.24.6+
- Kubernetes v1.11.3+ クラスタ
- kubectl version v1.11.3+
- VPS with frps (frp server) running

### インストール

1. **CRD をインストール**

```sh
make install
```

2. **Operator をローカル実行（開発用）**

```sh
make run
```

または

3. **Operator をクラスタにデプロイ**

```sh
# イメージをビルドしてプッシュ
make docker-build docker-push IMG=<your-registry>/homelab-gateway-operator:tag

# デプロイ
make deploy IMG=<your-registry>/homelab-gateway-operator:tag
```

### 使用方法

1. **frp 認証トークン用の Secret を作成**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: frp-token
type: Opaque
stringData:
  token: "your-frp-server-token"
```

```sh
kubectl apply -f config/samples/secret_frp-token.yaml
```

2. **VPSGateway リソースを作成**

```yaml
apiVersion: gateway.hmdyt.github.io/v1alpha1
kind: VPSGateway
metadata:
  name: my-gateway
spec:
  vps:
    address: "203.0.113.1"  # あなたの VPS の IP アドレス

  frp:
    port: 7000
    tokenSecretRef:
      name: frp-token

  ingress:
    enabled: true
    domains:
      - "*.example.com"

  egress:
    enabled: false  # 必要に応じて true に
```

```sh
kubectl apply -f config/samples/gateway_v1alpha1_vpsgateway.yaml
```

3. **状態を確認**

```sh
kubectl get vpsgw
kubectl describe vpsgw my-gateway
```

### 生成されるリソース

VPSGateway を作成すると、以下のリソースが自動的に生成されます:

- **ConfigMap** (`frpc-config-<name>`): frp クライアント設定 (TOML)
- **Deployment** (`frpc-<name>`): frpc コンテナを実行
- **Service** (`egress-proxy-<name>`): Egress が有効な場合のみ

すべてのリソースには OwnerReference が設定されており、VPSGateway を削除すると自動的にクリーンアップされます。

## 設定オプション

### VPSGateway Spec

```yaml
spec:
  vps:
    address: string          # 必須: VPS の IP アドレスまたはホスト名
    namespace: string        # オプション: リソースを作成する namespace (デフォルト: CR と同じ)

  frp:
    port: int32             # オプション: frp サーバーポート (デフォルト: 7000)
    tokenSecretRef:
      name: string          # 必須: トークンを含む Secret の名前
      key: string           # オプション: Secret 内のキー (デフォルト: "token")
    image: string           # オプション: frpc イメージ (デフォルト: "snowdreamtech/frpc:0.53.2")

  ingress:
    enabled: bool           # オプション: Ingress を有効化 (デフォルト: true)
    domains: []string       # 必須 (enabled が true の場合): ルーティングするドメインリスト
    ingressClassName: string # オプション: IngressClass 名 (デフォルト: "traefik")
    tls:
      enabled: bool         # オプション: TLS を有効化 (デフォルト: true)
      issuer: string        # オプション: cert-manager Issuer 名 (デフォルト: "letsencrypt-prod")

  egress:
    enabled: bool           # オプション: Egress プロキシを有効化 (デフォルト: false)
    proxyPort: int32        # オプション: プロキシポート (デフォルト: 3128)
    noProxy: []string       # オプション: プロキシをバイパスするホストリスト
```

### VPSGateway Status

```yaml
status:
  phase: string                 # Pending | Ready | Error
  frpcReady: bool               # frpc Deployment の準備状態
  egressProxyReady: bool        # Egress Service の準備状態
  lastSyncTime: timestamp       # 最後の同期時刻
  observedGeneration: int64     # 観測された世代番号
  conditions: []Condition       # 詳細な状態情報
```

## 開発

### テスト

```sh
# ユニットテスト
make test

# E2E テスト
make test-e2e
```

### Lint

```sh
make lint
```

### コード生成

```sh
# DeepCopy メソッドを生成
make generate

# CRD マニフェストを生成
make manifests
```

## アンインストール

```sh
# CRD を削除
make uninstall

# Operator をアンデプロイ
make undeploy
```

