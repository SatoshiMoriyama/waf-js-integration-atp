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

### つまづきポイント: ATPだけでは「トークン無し」を単体でブロックしない

ATP(`AWSManagedRulesATPRuleSet`)を`Block`モードにしても、curlで1回叩くだけでは
**403にならず200が返ってくる**。これはATPの各ルールの検知条件が以下のようなもので、
「トークンが無いこと」自体を単体でブロックする条件が存在しないため
(ルール一覧の根拠: [AWS WAF Fraud Control account takeover prevention (ATP) rule group](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-atp.html))。

- `VolumetricIpHigh` / `VolumetricSession`: 同一IP・同一セッションからの高頻度リクエスト
- `AttributeCompromisedCredentials`: 送信された認証情報が漏洩クレデンシャルDBに一致
- `AttributeUsernameTraversal` / `AttributePasswordTraversal`: ID/PWを変えながらの総当たり
- `SignalMissingCredential`: リクエストボディにusername/passwordフィールドが無い

つまりATPは「ブルートフォースや漏洩クレデンシャルの利用」を検知するルールであり、
「JS統合を経由したか(トークンの有無)」を判定するルールではない。

**対処**: ATPが付与するトークン状態ラベル`awswaf:managed:token:absent`
(ラベルの根拠: [Types of token labels in AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/waf-tokens-labeling.html))
にマッチするカスタムルールを、ATPの後(優先度を下げて)追加し、明示的にブロックする。
この対処自体もAWS公式が推奨する方法(詳細はStep6の実験セクションを参照)。

```ts
// ATP: priority 0, overrideAction: none (ブルートフォース・漏洩クレデンシャル検知)
// カスタムルール: priority 1, トークン欠如(token:absent)ラベルでBlock
{
  name: 'BlockMissingTokenRule',
  priority: 1,
  action: { block: {} },
  statement: {
    labelMatchStatement: { scope: 'LABEL', key: 'awswaf:managed:token:absent' },
  },
  ...
}
```

**ATPとカスタムルールは併用が正解**(どちらか一方だけでは不十分)。役割が異なる。

- カスタムルールが守るもの: 「JS統合を経由したか」の1点(トークンの有無)
- ATPが守るもの: トークンの有無に関係なく、ブルートフォースや漏洩クレデンシャルの利用
  (ヘッドレスブラウザ等でトークンを正規取得しつつ総当たりするケースはカスタムルールだけでは防げない)

コスト削減のためにATPを外してカスタムルールのみにする選択肢もあるが、
それだと今回のシナリオの核心である「漏洩クレデンシャルを使ったブルートフォース」への
防御力が無くなるため非推奨。

### つまづきポイント: CloudFormation(CDK)でのManagedRuleGroupConfigsの構造

CDKで`managedRuleGroupConfigs`を1つのオブジェクトにまとめて書くと、デプロイ時に
以下のエラーになる。

```
Error reason: EXACTLY_ONE_CONDITION_REQUIRED, field: MANAGED_RULE_GROUP_CONFIG,
parameter: ManagedRuleGroupConfig (Service: Wafv2, Status Code: 400, ...)
```

`ManagedRuleGroupConfigs`は配列の各要素に**条件を1つだけ**含める必要がある
(構造の根拠: [AWS::WAFv2::WebACL ManagedRuleGroupStatement](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-wafv2-webacl-managedrulegroupstatement.md)の設定例)。
NG例(1つのオブジェクトに複数フィールド):

```ts
managedRuleGroupConfigs: [
  {
    loginPath: '/prod/login',
    payloadType: 'JSON',
    usernameField: { identifier: '/username' },
    passwordField: { identifier: '/password' },
  },
],
```

OK例(要素ごとに1条件):

```ts
managedRuleGroupConfigs: [
  { loginPath: '/prod/login' },
  { payloadType: 'JSON' },
  { usernameField: { identifier: '/username' } },
  { passwordField: { identifier: '/password' } },
],
```

---

## Step 5: JavaScript Integration の設定・取得

**つまづきポイント**: 「Web ACLの詳細画面の中にApplication integrationタブがある」わけではない。
**WAFコンソールの左ナビゲーションペインに「Application integration」という独立した項目がある**ので、
そこから遷移する
(手順の根拠: [Accessing the AWS WAF client application integration APIs](https://docs.aws.amazon.com/waf/latest/developerguide/waf-application-integration-location-in-console.html))。

1. WAFコンソール(https://console.aws.amazon.com/wafv2/homev2)を開く
2. 左ナビゲーションペインから **Application integration** を選択(Web ACLの中のタブではない)
3. **Intelligent threat integration** タブを選択
4. ATP等を使っているWeb ACL(`waf-js-atp-login-web-acl`)が一覧に出ているので選択
5. 表示される `Integration URL` (challenge.jsの読み込み元スクリプトタグ)を控える
   例:
   ```html
   <script type="text/javascript" src="https://xxxx.ap-northeast-1.sdk.awswaf.com/xxxx/yyyy/challenge.js" defer></script>
   ```

---

## Step 6: ログインHTML(JS統合あり)を作成し、Amplify Hostingで公開

`login.html` は `file://` で直接開くと動作しない(WAFトークンはドメイン単位でCookie発行されるため、
origin が `null` になる file:// では正しく発行・送信されない)。
そこで **AWS Amplify Hosting** の手動デプロイ(Gitリポジトリ不要)でホスティングする。

### 6-1. index.htmlを作成

`packages/login-front/index.html` として作成済み(challenge.jsのURL、API_URLは後で置き換える)。

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
cd packages/login-front
zip login-site.zip index.html
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
   - 仕様の根拠: [Specifying token domains and domain lists in AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/waf-tokens-domains.html) —
     「Token domain listを指定しない場合、WAFは保護対象リソースのドメインのトークンのみ受理する」

### 確認ポイント
- Amplifyで発行されたURL(`https://xxxx.amplifyapp.com/`)にブラウザでアクセス
- ページを開いた時点で、裏で `challenge.js` がサイレントチャレンジを実行(ユーザー操作は不要)
- 「ログイン」ボタンを押すと `AwsWafIntegration.fetch` がトークンを自動付与してAPIに送信
- レスポンスが `200 login ok (mock)` になれば成功(WAFを通過)

### 補足: WAFトークン(`x-aws-waf-token`)の中身と有効期限

`AwsWafIntegration.fetch`が自動付与するトークンは、リクエストヘッダー
`x-aws-waf-token`として送信される。ブラウザの開発者ツール(Network タブ)や
`aws-waf-token`Cookie(Application/Storageタブ)で実際の値を確認できる。

**トークンの構造(概形)**

```
<セッションID(UUID)>:<短いメタデータ>:<暗号化されたペイロード>
```

例(ダミー値):
```
xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx:AQoAxxxxxxxxAAAA:<base64っぽい暗号化データ>
```

暗号化ペイロードの中身自体は非公開だが、[AWS公式ドキュメント](https://docs.aws.amazon.com/waf/latest/developerguide/waf-tokens-details.html)
によると以下の情報が含まれるとされている。

- silent challengeへの最新の成功応答のタイムスタンプ
- CAPTCHAへの最新の成功応答のタイムスタンプ(CAPTCHAを使っている場合のみ)
- クライアントの識別子や、自動化の兆候・ブラウザ設定の不整合などの信号
  (個人を特定できない形で収集される)
- **JS統合SDK使用時は、マウス移動・キー入力・ページ上のフォーム操作といった
  インタラクティビティ情報もパッシブに収集され、トークンに含まれる**
  (別ヘッダーや別リクエストで送るのではなく、暗号化されたトークン本体に
  エンコードされる)

AWSはセキュリティ上の理由で、トークンの内容や暗号化プロセスの完全な説明は提供していない。

**有効期限(immunity time)**

[公式ドキュメント](https://docs.aws.amazon.com/waf/latest/developerguide/waf-tokens-immunity-times.html)によると:

- Web ACLのデフォルト設定は**300秒(5分)**。challenge immunity timeの最小値も300秒
  (CAPTCHA immunity timeの最小値は60秒、両者とも最大は3日)
- 免除期間内は同じトークンが再利用される(毎リクエストごとに変わるわけではない)
- 実際に2回連続でヘッダーを確認したところ、**完全に同一の値**だった(immunity time内だったため)
- immunity timeが切れると、裏で自動的に再チャレンジが走り、新しいトークンに切り替わる
  (セッションID部分も含めて変わる)
- immunity timeはWeb ACL単位、または個別のCAPTCHA/Challengeルール単位で変更可能

**注意**: このトークンは実際のブラウザセッションに紐づく値であり、有効期限内であれば
リプレイ(再利用)して正規のリクエストとしてWAFを通過させることが技術的に可能。
ブログや資料等で実際の値を掲載する場合は、末尾を省略するかダミー値に置き換えること。

### 実験: トークンをcurlに手動で付けて再送(リプレイ)してみる

ブラウザで発行された`x-aws-waf-token`の値をコピーし、curlのヘッダーに手動でセットして
送信するとどうなるか実験した。

**1回目: 期限切れのトークンを使用 → 失敗(403)**

会話中で少し時間が経ってから貼り付けたトークンで試したところ、`403 Forbidden`が返った。
おそらくimmunity time(デフォルト5分)を過ぎて`rejected:expired`扱いになったため。

**2回目: 取得直後の新鮮なトークンを使用 → 成功(200)**

```bash
curl -i -X POST "https://xxxx.execute-api.ap-northeast-1.amazonaws.com/prod/login" \
  -H "Content-Type: application/json" \
  -H "x-aws-waf-token: <ブラウザから取得した直後のトークン>" \
  -d '{"username":"test@example.com","password":"password123"}'
```
```
HTTP/2 200
{"message": "login ok (mock) for test@example.com"}
```

**分かったこと**: WAFトークンの検証で見ているのは「有効期限内かどうか」であり、
送信元がブラウザかcurlかというクライアントの種類そのものではない。
つまりATPが守っているのは「JS実行環境でchallenge.jsを完走してトークンを
取得する能力があるか」であり、一度取得したトークンさえあれば、その後の送信手段
(ブラウザ、curl、スクリプト等)は問われない。

これは[公式ドキュメント](https://docs.aws.amazon.com/waf/latest/developerguide/waf-tokens-block-missing-tokens.html)でも裏付けられている仕様。
「`AWSManagedRulesATPRuleSet`は`rejected`(トークンはあるが無効)ラベルのリクエストは
自動でブロックするが、`absent`(トークンが無い)ラベルのリクエストは自動でブロックしない」
と明記されている。つまりATP単体では「トークン無し」を捌けない設計であり、
本ハンズオンで`BlockMissingTokenRule`を別途追加したのは公式が推奨する対処と一致する。

これは実運用上の重要な含意でもある。攻撃者がブラウザ操作(または自動化ブラウザ)で
一度トークンを取得できれば、その後は非ブラウザのツールでリプレイして
大量リクエストを送ることも理論上可能。この対策は主にATP側のボリューム攻撃検知
(`VolumetricIpHigh`/`VolumetricSession`)やトークンのブラウザフィンガープリント
チェックが担っている
(根拠: [How AWS WAF uses tokens](https://docs.aws.amazon.com/waf/latest/developerguide/waf-tokens-usage.html) —
「ATPの高頻度・長時間セッション検知ルールは、有効かつchallengeタイムスタンプが
期限切れでないトークンを要求する」)。JS統合はあくまで「入口のハードルを上げる」
対策であり、それ単体で全てのリプレイ攻撃を防ぐわけではない。

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

### 実際の検証結果

ATP + `BlockMissingTokenRule`(トークン欠如ブロックのカスタムルール)を併用した状態での実測。

**ブラウザ経由(JS統合あり、Amplify Hosting)**
```
[OK] Status: 200
{"message": "login ok (mock) for test@example.com"}
```

**curl直接POST(トークン無し)**
```bash
curl -i -X POST "https://kq2oc5ecbe.execute-api.ap-northeast-1.amazonaws.com/prod/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"test@example.com","password":"password123"}'
```
```
HTTP/2 403
content-type: application/json
x-amzn-errortype: ForbiddenException
{"message":"Forbidden"}
```

想定どおり、JS統合を経由したブラウザからのリクエストは`200`で通過し、
トークンを持たないcurlの直接リクエストは`403`でブロックされることを確認できた。

---

## Step 8: CloudWatchメトリクス/ログで結果を確認

1. WAFコンソール → 対象Web ACL → **Logging and metrics** タブ
2. サンプルWebリクエストで以下を比較
   - Step6(ブラウザ+JS統合)のリクエスト → WAFトークンあり、ATPルールを通過
   - Step7(curl直接)のリクエスト → トークン無し、ATP関連ラベルが付与 / ブロック

ログを有効化していれば、CloudWatch Logsで以下のようなラベルが確認できる
(ラベル一覧の根拠: [AWS WAF Fraud Control account takeover prevention (ATP) rule group](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-atp.html)):
```
awswaf:managed:aws:atp:...
```

### 実際のメトリクス確認結果

CloudWatchメトリクス(`AWS/WAFV2`名前空間)をCLIで確認したところ、
過去2時間で以下のようにルールごとのブロック数が分かれた。

| ルール | ブロック数(過去2時間) | 内容 |
|---|---|---|
| `ATPRule` | 43件 | `VolumetricIpHigh`(同一IPからの高頻度アクセス)による検知 |
| `BlockMissingTokenRule` | 2件 | curlでのトークン無し直接アクセス |

**気づきポイント**: `ATPRule`のブロックはすべて`VolumetricIpHigh`によるもので、
`get-sampled-requests`で確認すると**ブラウザ経由(Referer付き、Amplify Hostingのドメイン)の
リクエストも含めてブロックされていた**。これは検証作業中に同一IPから短時間に
繰り返しアクセスしたことでATPのボリューム攻撃検知(10分間に20リクエスト超)に
引っかかったため。

つまりATPは「JS統合の有無」に関係なく、**頻度が高すぎれば正規のブラウザ経由の
アクセスもブロックする**。これは実運用でも起こりうる挙動で、通常利用のユーザーが
誤ってブロックされる可能性(過検知)も考慮した閾値設計・監視が必要になる。

サンプルリクエストの取得コマンド例:
```bash
aws wafv2 get-sampled-requests \
  --web-acl-arn "arn:aws:wafv2:<region>:<account>:regional/webacl/<name>/<id>" \
  --rule-metric-name ATPRule --scope REGIONAL \
  --time-window StartTime=<ISO8601>,EndTime=<ISO8601> \
  --max-items 5
```

---

## まとめ(振り返りポイント)

### 前提: これはアプリケーション認証の代替ではない

今回のログインAPIは検証ロジックを持たない完全なモック(常に`200`を返す)である。
WAF/ATP/JS統合が担っているのは、あくまで**ネットワークの入口(エッジ)での一次フィルタ**
であり、本来アプリケーション側に必要な認証機構の代替にはならない。

```
[WAF + ATP + JS統合]  ← 今回のハンズオンの範囲(エッジでの一次フィルタ)
        ↓
[アプリケーション認証: パスワードハッシュ、JWT/セッション、MFA、ロックアウト等]  ← 本来必須の層
```

本来の実装であれば以下のような要素が必要になり、これらはWAFでは代替できない。

- パスワードのハッシュ化・照合(bcrypt等)
- ログイン成功時のJWT/セッショントークン発行と、以降のAPIでの検証
- ログイン失敗回数の制限(アカウントロックアウト)。ATPの`VolumetricSession`等と役割は
  重なるが、WAFだけに依存せずアプリ側にも持たせるのが望ましい
- MFA(多要素認証)。クレデンシャルスタッフィング対策として最も効果が高い
  (漏洩したID/PWだけでは突破できなくなる)
- レートリミット(API Gateway Usage Plan/Throttling、アプリ側でのIP/ユーザー単位の制限)

WAF側だけで完結すると誤解すると、認証ロジック自体を疎かにする危険な設計判断に
つながりかねない。今回の検証(トークンのリプレイが成立した点も含む)からも、
JS統合単体で全ての攻撃を防げるわけではないことが分かる。

### 検証結果のまとめ

| 観点 | JS統合あり(ブラウザ経由) | JS統合なし(curl直接) |
|---|---|---|
| WAFトークン | あり | なし |
| ユーザー操作 | 不要(サイレント) | - |
| ATP判定 | 通過しやすい | ブロック/ラベル付与 |
| 想定する防御対象 | - | クレデンシャルスタッフィング/スクリプト攻撃 |

**ポイント**: WAFが見ているのは「ブラウザかどうか」ではなく「JSチャレンジ(人間らしさの証明)を通過したか」。
curlが弾かれるのは、curlがJS実行能力を持たずトークンを取得できないことの結果である。

**ただし**、取得済みのトークンをcurlに手動で付与すればWAFを通過できることも確認した
(Step6の実験を参照)。つまりJS統合は「トークンを取得する能力(JS実行環境)があるか」
までしか見ておらず、取得後のトークンの使い回し(リプレイ)自体は別の仕組み
(有効期限、ATPのボリューム検知等)で補完する必要がある。JS統合は防御の1層目として
「入口のコストを上げる」ものであり、単純な自動化攻撃には非常に有効だが、
本気で回避しようとする攻撃者(ヘッドレスブラウザ+トークン再利用)には単体では不十分。
ATPの他の検知ロジック(ボリューム攻撃、漏洩クレデンシャル一致)との併用が実用上必須。

---

## 後片付け(コスト発生防止)

- Amplify Hosting アプリ(Step6で作成)を削除
- WAF Web ACL を削除(または API Gatewayから関連付け解除)
- API Gateway REST API を削除
- Lambda関数を削除

ATPルールグループ自体は使用量ベースの課金なので、放置してもリクエストが無ければ大きな費用は発生しないが、
検証後は忘れずに削除しておくことを推奨。
