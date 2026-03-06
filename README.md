> **Status: Work in Progress** - 現在開発中です。

# trivy-ssvc

Trivyの脆弱性スキャン結果にSSVCで優先度付けして、差分をSlackに通知するCLIツールです。

## なぜこれが必要か

Dependabotのアラートが大量に溜まって、どれから対応すればいいかわからなくなっていませんか？

CVSSスコアは「脆弱性の深刻度」であって「あなたが今すぐ対応すべきか」の判断基準にはなりません。

このツールはSSVC（Stakeholder-Specific Vulnerability Categorization）を使って、あなたの環境に合わせた優先度付けを自動で行います。

## できること

- Trivyのスキャン結果（JSON）を読み込む
- SSVCで優先度付け（Immediate / Out-of-cycle / Scheduled / Defer）
- 前回のスキャン結果と差分を比較
- 新しい脆弱性が見つかったらSlackに通知
- 脆弱性が解消されたらSlackに通知
- 通知がそのまま証跡として残る

## 既存ツールとの違い

| ツール     | 複数エコシステム対応 | 優先度付け         | チーム共有 | 無料 |
| ---------- | -------------------- | ------------------ | ---------- | ---- |
| npm audit  | Node.jsのみ          | CVSSのみ           | -          | 無料 |
| Dependabot | 複数対応             | CVSSのみ           | GitHub上   | 無料 |
| yamory     | 複数対応             | トリアージ機能あり | あり       | 有料 |
| trivy-ssvc | 複数対応             | SSVC               | Slack      | 無料 |

## 前提条件

[Trivy](https://trivy.dev/latest/getting-started/installation/) がインストールされている必要があります。

```bash
# macOS
brew install trivy

# Linux
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

## インストール

GitHubの[Releases](https://github.com/yuhkisan/trivy-ssvc/releases)からバイナリをダウンロードしてください。

```bash
# Linux (amd64)
curl -L https://github.com/yuhkisan/trivy-ssvc/releases/latest/download/trivy-ssvc-linux-amd64 -o trivy-ssvc
chmod +x trivy-ssvc
sudo mv trivy-ssvc /usr/local/bin/

# macOS (arm64)
curl -L https://github.com/yuhkisan/trivy-ssvc/releases/latest/download/trivy-ssvc-darwin-arm64 -o trivy-ssvc
chmod +x trivy-ssvc
sudo mv trivy-ssvc /usr/local/bin/
```

## 使い方

### 1. Trivyでスキャンする

```bash
trivy fs ./ --format json --output vulns.json
```

### 2. SSVCステータスを付与する

```bash
# 初回
trivy-ssvc \
  --vulns vulns.json \
  --system-exposure open \
  --safety-impact negligible \
  --mission-impact degraded \
  --save-state ssvc-state.json

# 2回目以降（差分検出）
trivy-ssvc \
  --vulns vulns.json \
  --system-exposure open \
  --safety-impact negligible \
  --mission-impact degraded \
  --previous-state ssvc-state.json \
  --save-state ssvc-state.json \
  --slack-webhook https://hooks.slack.com/... \
  --threshold immediate
```

## 引数

### 必須

| 引数                | 説明                                                                    |
| ------------------- | ----------------------------------------------------------------------- |
| `--vulns`           | Trivyのスキャン結果ファイルのパス（JSON形式）                           |
| `--system-exposure` | システムの露出度（`open` / `controlled` / `small`）                     |
| `--safety-impact`   | 安全への影響（`negligible` / `marginal` / `critical` / `catastrophic`） |
| `--mission-impact`  | 業務への影響（`minimal` / `degraded` / `failed`）                       |

### オプション

| 引数               | デフォルト  | 説明                                           |
| ------------------ | ----------- | ---------------------------------------------- |
| `--previous-state` | なし        | 前回のスキャン結果ファイルのパス（差分検出用） |
| `--save-state`     | なし        | 今回のスキャン結果の保存先パス                 |
| `--slack-webhook`  | なし        | Slack Webhook URL                              |
| `--threshold`      | `immediate` | Slack通知する最低優先度                        |
| `--output`         | `table`     | 出力形式（`table` / `json`）                   |

## SSVCの変数について

よくわからない場合は以下を参考にしてください。

| ケース                           | system-exposure | safety-impact | mission-impact |
| -------------------------------- | --------------- | ------------- | -------------- |
| インターネット公開のWebサービス  | `open`          | `negligible`  | `degraded`     |
| 社内ツール                       | `controlled`    | `negligible`  | `minimal`      |
| 医療・自動車など安全に関わる製品 | `controlled`    | `critical`    | `degraded`     |

## Slackの通知例

```
[新規] CVE-2026-XXXX | openssl 1.1.1 | Immediate
対応を検討してください。

[解決] CVE-2026-XXXX | openssl 1.1.1
脆弱性が解消されました。
```

## GitHub Actionsとして使う

### セットアップ

**1. SlackのWebhook URLを取得する**

Slackの App設定からIncoming Webhookを発行してください。

**2. GitHub SecretsにWebhook URLを登録する**

リポジトリの `Settings` -> `Secrets and variables` -> `Actions` -> `New repository secret`

- Name: `SLACK_WEBHOOK`
- Value: SlackのWebhook URL

**3. ワークフローファイルを作成する**

`.github/workflows/ssvc-scan.yml` を作成して以下を貼り付けてください。

```yaml
name: SSVC Scan
on:
  schedule:
    - cron: "0 9 * * *" # 毎日9時に実行
  workflow_dispatch: # 手動実行も可能

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Trivy
        run: |
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

      - name: Scan with Trivy
        run: trivy fs ./ --format json --output vulns.json

      - name: Install trivy-ssvc
        run: |
          curl -L https://github.com/yuhkisan/trivy-ssvc/releases/latest/download/trivy-ssvc-linux-amd64 -o trivy-ssvc
          chmod +x trivy-ssvc
          sudo mv trivy-ssvc /usr/local/bin/

      - name: Apply SSVC
        run: |
          trivy-ssvc \
            --vulns vulns.json \
            --system-exposure open \
            --safety-impact negligible \
            --mission-impact degraded \
            --previous-state ssvc-state.json \
            --save-state ssvc-state.json \
            --slack-webhook ${{ secrets.SLACK_WEBHOOK }} \
            --threshold immediate
```

**以上です。**

### プライベートリポジトリの場合

`trivy fs` に `--token` オプションでGitHubトークンを渡してください。

```yaml
      - name: Scan with Trivy
        run: trivy fs ./ --format json --output vulns.json --token ${{ secrets.GITHUB_TOKEN }}
```

## 仕組み

```
毎日スケジュール実行
  ↓
trivy fs でスキャン → vulns.json
  ↓
trivy-ssvc が vulns.json を読み込みSSVCで優先度計算
  ↓
前回結果（ssvc-state.json）と差分比較
  ↓
新しいImmediate → Slackに通知
解決したImmediate → Slackに通知
  ↓
今回の結果をssvc-state.jsonに保存
```

## ライセンス

MIT
