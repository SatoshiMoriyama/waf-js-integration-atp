import * as path from 'node:path';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import * as cdk from 'aws-cdk-lib/core';
import type { Construct } from 'constructs';

export class LoginApiStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // 疑似ログインAPI(検証ロジックは持たず、常に成功を返すモック)
    const loginFunction = new lambda.Function(this, 'LoginFunction', {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(
        path.join(__dirname, '..', '..', 'login-api'),
      ),
    });

    const api = new apigateway.RestApi(this, 'LoginApi', {
      restApiName: 'waf-js-atp-login-api',
      deployOptions: {
        stageName: 'prod',
      },
      defaultCorsPreflightOptions: {
        // Amplify Hosting(別オリジン)からのfetchを許可するためCORSを有効化
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: ['POST', 'OPTIONS'],
        allowHeaders: ['Content-Type', 'x-aws-waf-token'],
      },
    });

    const loginResource = api.root.addResource('login');
    loginResource.addMethod(
      'POST',
      new apigateway.LambdaIntegration(loginFunction),
    );

    new cdk.CfnOutput(this, 'LoginApiUrl', {
      value: `${api.url}login`,
      description: 'ログインAPIのエンドポイントURL',
    });

    // ATP(Account Takeover Prevention)マネージドルールグループ
    // overrideActionを{ none: {} }にすることでルールグループ本来のBlock動作になる
    // (トークン無しのcurl等を403でブロックする)。挙動確認だけしたい場合は{ count: {} }に戻す。
    const webAcl = new wafv2.CfnWebACL(this, 'LoginWebAcl', {
      name: 'waf-js-atp-login-web-acl',
      scope: 'REGIONAL',
      defaultAction: { allow: {} },
      // Amplify Hosting(challenge.jsを読み込むページのホストドメイン)向けに
      // 有効なWAFトークンを発行できるようにするための設定。
      // これが無いと、challenge.jsが取得したトークンがこのWeb ACLでは受理されない。
      tokenDomains: ['main.dgpzwsaakidam.amplifyapp.com'],
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: 'LoginWebAcl',
      },
      rules: [
        {
          name: 'ATPRule',
          priority: 0,
          overrideAction: { none: {} },
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesATPRuleSet',
              // AWSManagedRulesATPRuleSetプロパティにネストする形式が現在の推奨(旧フラット形式は非推奨)。
              // 参考: https://docs.aws.amazon.com/waf/latest/developerguide/waf-tokens-block-missing-tokens.html
              managedRuleGroupConfigs: [
                {
                  awsManagedRulesAtpRuleSet: {
                    loginPath: '/prod/login',
                    requestInspection: {
                      payloadType: 'JSON',
                      usernameField: { identifier: '/username' },
                      passwordField: { identifier: '/password' },
                    },
                  },
                },
              ],
            },
          },
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: 'ATPRule',
          },
        },
        {
          // ATPはボリューム攻撃や漏洩クレデンシャルの一致等を検知するルールで、
          // 「トークンが無い」だけでは単体でブロックしない。
          // そこでATPが付与するトークン状態ラベル(token:absent)にマッチしたら
          // 明示的にブロックし、JS統合なし(curl等)のリクエストを拒否する。
          // ログインパス・POSTメソッドへの絞り込みはAWS公式サンプルに合わせたもの
          // (ATPルールグループの評価スコープと一致させ、他エンドポイントへの誤爆を防ぐため)。
          name: 'BlockMissingTokenRule',
          priority: 1,
          action: { block: {} },
          statement: {
            andStatement: {
              statements: [
                {
                  labelMatchStatement: {
                    scope: 'LABEL',
                    key: 'awswaf:managed:token:absent',
                  },
                },
                {
                  byteMatchStatement: {
                    searchString: '/prod/login',
                    fieldToMatch: { uriPath: {} },
                    textTransformations: [{ priority: 0, type: 'NONE' }],
                    positionalConstraint: 'STARTS_WITH',
                  },
                },
                {
                  byteMatchStatement: {
                    searchString: 'POST',
                    fieldToMatch: { method: {} },
                    textTransformations: [{ priority: 0, type: 'NONE' }],
                    positionalConstraint: 'EXACTLY',
                  },
                },
              ],
            },
          },
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: 'BlockMissingTokenRule',
          },
        },
      ],
    });

    new wafv2.CfnWebACLAssociation(this, 'LoginWebAclAssociation', {
      resourceArn: api.deploymentStage.stageArn,
      webAclArn: webAcl.attrArn,
    });
  }
}
