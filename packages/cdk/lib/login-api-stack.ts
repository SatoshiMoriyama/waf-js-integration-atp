import * as path from 'node:path';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as lambda from 'aws-cdk-lib/aws-lambda';
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
  }
}
