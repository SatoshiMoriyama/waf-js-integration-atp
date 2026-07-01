import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { LoginApiStack } from '../lib/login-api-stack';

describe('LoginApiStack', () => {
  test('スナップショットテスト', () => {
    const app = new cdk.App();
    const stack = new LoginApiStack(app, 'TestStack');
    const template = Template.fromStack(stack);

    expect(template.toJSON()).toMatchSnapshot();
  });
});
