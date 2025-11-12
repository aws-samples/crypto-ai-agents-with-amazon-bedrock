// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import { getConfig, EnvironmentConfig } from '../../utils/environment';

const config: EnvironmentConfig = getConfig();

const region = config.region;
const accountId = config.accountId;
const kbRoleName = config.kbRoleName;
const bucketName = config.bucketName;

export class KbRoleStack extends cdk.Stack {
  public readonly kbRole: iam.Role;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Create KB Role
    this.kbRole = new iam.Role(this, 'KB_Role', {
      roleName: kbRoleName,
      assumedBy: new iam.ServicePrincipal('bedrock.amazonaws.com', {
        conditions: {
          StringEquals: { 'aws:SourceAccount': accountId },
          ArnLike: { 'aws:SourceArn': `arn:aws:bedrock:${region}:${accountId}:knowledge-base/*` },
        },
      }),
    });
    
    // Apply removal policy to ensure role is deleted with stack
    this.kbRole.applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);

    // Add inline policies
    this.kbRole.addToPolicy(new iam.PolicyStatement({
      sid: 'BedrockInvokeModelStatement',
      effect: iam.Effect.ALLOW,
      actions: ['bedrock:InvokeModel'],
      resources: [`arn:aws:bedrock:${region}::foundation-model/*`],
    }));

    this.kbRole.addToPolicy(new iam.PolicyStatement({
      sid: 'OpenSearchServerlessAPIAccessAllStatement',
      effect: iam.Effect.ALLOW,
      actions: ['aoss:APIAccessAll'],
      resources: [`arn:aws:aoss:${region}:${accountId}:collection/*`],
    }));

    this.kbRole.addToPolicy(new iam.PolicyStatement({
      sid: 'S3ListBucketStatement',
      effect: iam.Effect.ALLOW,
      actions: ['s3:ListBucket'],
      resources: [`arn:aws:s3:::${bucketName}`],
    }));

    this.kbRole.addToPolicy(new iam.PolicyStatement({
      sid: 'S3GetObjectStatement',
      effect: iam.Effect.ALLOW,
      actions: ['s3:GetObject'],
      resources: [`arn:aws:s3:::${bucketName}/*`],
    }));

    // Create SSM parameter
    const kbRoleArnParameter = new ssm.StringParameter(this, 'kbRoleArn', {
      parameterName: '/e2e-rag/kbRoleArn',
      stringValue: this.kbRole.roleArn,
    });
    
    // Apply removal policy to ensure parameter is deleted with stack
    kbRoleArnParameter.applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
  }
}