# Claude Code 開発ガイド

## 開発環境

このプロジェクトは nix 環境を使用しています。全てのコマンドは `nix develop` シェル内で実行してください。

```bash
nix develop -c <command>
```

## コマンド一覧

### ビルド
```bash
nix develop -c go build ./...
```

### テスト
```bash
# ユニットテスト
nix develop -c make test

# E2E テスト
nix develop -c make test-2e2
```

### コード生成
```bash
# DeepCopy コード生成
nix develop -c make generate

# CRD マニフェスト生成
nix develop -c make manifests
```
