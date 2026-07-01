# AWS WAF JavaScript Integrations ハンズオン
## テーマ：ログインAPIへの直接アクセス(スクリプト攻撃想定)をJS統合で防ぐ

**想定時間**: 30〜40分
**シナリオ**: 漏洩ID/PWリストを使った総当たり攻撃(クレデンシャルスタッフィング)を想定し、
正規のログインページ(JS統合済み)を経由しない直接リクエスト(curl等)をATP + JS Integrationsで検知・遮断する。

---

## 全体構成

```
[ブラウザ] --(JS統合: challenge.js)--> [API Gateway] --> [Lambda(疑似ログインAPI)]
                                            ↑
                                       [WAF Web ACL + ATPルール]

[curl(直接POST)] --(トークン無し)--> [API Gateway] → WAFがブロック/Challenge
```

---

## Step 1: 疑似ログインAPI(Lambda)を作成

コンソールで Lambda 関数を新規作成(ランタイム: Python 3.12)。

```python
import json

def handler(event, context):
    # 検証ロジックは持たず、常に成功を返すモック
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"message": "login ok (mock)"})
    }
```

---

## Step 2: API Gateway (REST API) を作成

1. API Gateway コンソールで **REST API** を新規作成(リージョン)
2. リソース `/login` を作成し、メソッド `POST` を追加
3. 統合タイプ: Lambda関数(Step 1で作成したもの)を指定
4. デプロイ(例: ステージ名 `prod`)
5. 発行されたエンドポイントURLを控える
   例: `https://xxxx.execute-api.ap-northeast-1.amazonaws.com/prod/login`

---

## Step 3: WAF Web ACL を作成し、API Gatewayに関連付け

1. WAFコンソールで **Web ACL** を新規作成
   - リソースタイプ: リージョンリソース(REST APIのステージ)
   - 保護対象: Step 2のAPI Gatewayステージを選択
2. **ルールを追加 → マネージドルールグループを追加**
   - `Account takeover prevention (ATP)` を選択して追加

---

## Step 4: ATP(AWSManagedRulesATPRuleSet)の設定

ルールグループ追加時、詳細設定画面で以下を入力:

| 項目 | 値 |
|---|---|
| Login path | `/prod/login` |
| Payload type | JSON |
| Username field | `/username` |
| Password field | `/password` |

- **Override all rule actions** を一時的に `Count` に設定しておくと、
  最初はブロックせず挙動確認(ラベル付与)のみ行える(検証用)
- 慣れてきたら `Block` (デフォルト動作)に変更して実際に遮断させる

Web ACLを保存し、反映を待つ(数分程度)。

---

## Step 5: JavaScript Integration の設定・取得

1. WAFコンソール → 対象Web ACL → **Application integration** タブ
2. **Intelligent threat integration** の設定を有効化
3. 表示される `Integration URL` (challenge.jsの読み込み元)を控える
   例: `https://xxxx.token.awswaf.com/xxxx/challenge.js`

---

## Step 6: ログインHTML(JS統合あり)を作成し、Amplify Hostingで公開

`login.html` は `file://` で直接開くと動作しない(WAFトークンはドメイン単位でCookie発行されるため、
origin が `null` になる file:// では正しく発行・送信されない)。
そこで **AWS Amplify Hosting** の手動デプロイ(Gitリポジトリ不要)でホスティングする。

### 6-1. login.htmlを作成

ローカルPCに `login.html` として保存する。

```html
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>ログイン(JS統合あり)</title>
  <!-- Step5で取得したIntegration URLに置き換える -->
  <script src="https://xxxx.token.awswaf.com/xxxx/challenge.js" defer></script>
</head>
<body>
  <h2>ログイン(JS統合あり)</h2>
  <input id="username" placeholder="username" value="test@example.com"><br>
  <input id="password" type="password" placeholder="password" value="password123"><br>
  <button onclick="login()">ログイン</button>
  <pre id="result"></pre>

  <script>
    const API_URL = "https://xxxx.execute-api.ap-northeast-1.amazonaws.com/prod/login"; // Step2のURLに置き換え

    async function login() {
      const body = JSON.stringify({
        username: document.getElementById("username").value,
        password: document.getElementById("password").value
      });

      // AwsWafIntegration.fetch がWAFトークンを自動付与してリクエストする
      const res = await AwsWafIntegration.fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: body
      });

      const text = await res.text();
      document.getElementById("result").textContent =
        `Status: ${res.status}\n${text}`;
    }
  </script>
</body>
</html>
```

### 6-2. zip化してAmplify Hostingへ手動デプロイ

Amplifyの「Deploy without Git」はフォルダのドラッグ&ドロップ機能に不具合報告があるため、
`.zip` ファイルでのアップロードを推奨。

```bash
zip login-site.zip login.html
```

1. Amplifyコンソール → **Create new app** → **Deploy without Git** → **Next**
2. App name(例: `waf-js-atp-demo`)、Branch name(例: `demo`)を入力
3. Method: **Drag and drop** → `login-site.zip` を選択
4. **Save and deploy** で数十秒〜数分待つ
5. 発行されたURLを控える(例: `https://demo.xxxxxxxxxx.amplifyapp.com`)

### 6-3. WAF側でToken domainにAmplifyのドメインを追加

1. WAFコンソール → 対象Web ACL → **Application integration** タブ → **Token domain list**
2. Amplifyで発行されたドメイン(例: `demo.xxxxxxxxxx.amplifyapp.com`)を追加して保存
   - これを設定しないと、challenge.jsがこのドメイン向けの有効なトークンを発行できない

### 確認ポイント
- Amplifyで発行されたURL(`https://xxxx.amplifyapp.com/login.html`)にブラウザでアクセス
- ページを開いた時点で、裏で `challenge.js` がサイレントチャレンジを実行(ユーザー操作は不要)
- 「ログイン」ボタンを押すと `AwsWafIntegration.fetch` がトークンを自動付与してAPIに送信
- レスポンスが `200 login ok (mock)` になれば成功(WAFを通過)

---

## Step 7: JS統合なし(curl直接POST)で比較

```bash
curl -i -X POST "https://xxxx.execute-api.ap-northeast-1.amazonaws.com/prod/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"test@example.com","password":"password123"}'
```

### 期待される挙動
- **ATPをBlockモードにしている場合**: `403 Forbidden` が返る(トークン無しのためブロック)
- **Countモードの場合**: `200`は返るが、CloudWatchログ上でATP関連ラベル
  (`awswaf:managed:aws:atp:...`)が付与されているのが確認できる

---

## Step 8: CloudWatchメトリクス/ログで結果を確認

1. WAFコンソール → 対象Web ACL → **Logging and metrics** タブ
2. サンプルWebリクエストで以下を比較
   - Step6(ブラウザ+JS統合)のリクエスト → WAFトークンあり、ATPルールを通過
   - Step7(curl直接)のリクエスト → トークン無し、ATP関連ラベルが付与 / ブロック

ログを有効化していれば、CloudWatch Logsで以下のようなラベルが確認できる:
```
awswaf:managed:aws:atp:...
```

---

## まとめ(振り返りポイント)

| 観点 | JS統合あり(ブラウザ経由) | JS統合なし(curl直接) |
|---|---|---|
| WAFトークン | あり | なし |
| ユーザー操作 | 不要(サイレント) | - |
| ATP判定 | 通過しやすい | ブロック/ラベル付与 |
| 想定する防御対象 | - | クレデンシャルスタッフィング/スクリプト攻撃 |

**ポイント**: WAFが見ているのは「ブラウザかどうか」ではなく「JSチャレンジ(人間らしさの証明)を通過したか」。
curlが弾かれるのは、curlがJS実行能力を持たずトークンを取得できないことの結果である。

---

## 後片付け(コスト発生防止)

- Amplify Hosting アプリ(Step6で作成)を削除
- WAF Web ACL を削除(または API Gatewayから関連付け解除)
- API Gateway REST API を削除
- Lambda関数を削除

ATPルールグループ自体は使用量ベースの課金なので、放置してもリクエストが無ければ大きな費用は発生しないが、
検証後は忘れずに削除しておくことを推奨。
