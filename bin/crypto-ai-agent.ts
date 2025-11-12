#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import * as dotenv from 'dotenv';
dotenv.config();

import * as cdk from 'aws-cdk-lib';
import { AwsSolutionsChecks, NagSuppressions } from 'cdk-nag';
import { CryptoAIAgentSupervisorStack } from '../lib/crypto-ai-agent-supervisor-stack';
import { KbRoleStack } from '../lib/knowledge-base-news-stack/kb-role-stack';
import { OpenSearchServerlessInfraStack } from '../lib/knowledge-base-news-stack/oss-infra-stack';
import { KbInfraStack } from '../lib/knowledge-base-news-stack/kb-infra-stack';
import { BlockchainDataAgentStack } from '../lib/knowledge-base-blockchain-data-stack';
import { getConfig } from '../utils/environment';

const app = new cdk.App();

// Load configuration from .env
const config = getConfig();

// Define environment for all stacks
const env = {
  account: config.accountId,
  region: config.region
};

// ### Create KnowledgeBase to ingest blockchain news
// Borrows from https://github.com/aws-samples/amazon-bedrock-samples/tree/main/rag/knowledge-bases/features-examples/04-infrastructure/e2e_rag_using_bedrock_kb_cdk
// Create IAM role for e2e RAG
const kbRoleStack = new KbRoleStack(app, 'KbRoleStack', { env });

// Setup OSS
const openSearchServerlessInfraStack = new OpenSearchServerlessInfraStack(app, 'OpenSearchServerlessInfraStack', { env });
openSearchServerlessInfraStack.node.addDependency(kbRoleStack);
// Create Knowledgebase and datasource
const kbInfraStack = new KbInfraStack(app, 'KbInfraStack', { env });
kbInfraStack.node.addDependency(openSearchServerlessInfraStack);

// ### Create an agent to query historic blockchain data
const blockchainDataAgentStack = new BlockchainDataAgentStack(app, 'BlockchainDataAgentStack', { env });
blockchainDataAgentStack.node.addDependency(kbInfraStack);

// ### Create AI Agent
const cryptoAIAgentSupervisorStack = new CryptoAIAgentSupervisorStack(app, 'CryptoAIAgentSupervisorStack', 
  { 
    env,
    description: 'Crypto AI Agent Supervisor stack (uksb-tg4glnwleb)',
    knowledgeBase: kbInfraStack.knowledgeBase 
  }
);
cryptoAIAgentSupervisorStack.node.addDependency(blockchainDataAgentStack);

cdk.Aspects.of(app).add(new AwsSolutionsChecks())

NagSuppressions.addStackSuppressions(kbRoleStack, [
  { id: 'AwsSolutions-IAM5', reason: 'Permission to read CF stack is restrictive enough' },
], true);

NagSuppressions.addStackSuppressions(openSearchServerlessInfraStack, [
  { id: 'AwsSolutions-IAM5', reason: 'Permission to read CF stack is restrictive enough' },
  { id: 'AwsSolutions-L1', reason: 'Stack dependencies have been tested with Python 3.12' },
], true);

NagSuppressions.addStackSuppressions(kbInfraStack, [
  { id: 'AwsSolutions-IAM4', reason: 'AWSLambdaBasicExecutionRole, AWSLambdaVPCAccessExecutionRole are restrictive roles' },
  { id: 'AwsSolutions-IAM5', reason: 'Permission to read CF stack is restrictive enough' },
], true);

NagSuppressions.addStackSuppressions(blockchainDataAgentStack, [
  { id: 'AwsSolutions-IAM4', reason: 'AWSLambdaBasicExecutionRole, AWSLambdaVPCAccessExecutionRole are restrictive roles' },
  { id: 'AwsSolutions-IAM5', reason: 'Permission to read CF stack is restrictive enough' },
  { id: 'AwsSolutions-S1', reason: 'S3 Bucket server access logs not required for this solution' },
  { id: 'AwsSolutions-L1', reason: 'web3py dependency requires Python 3.12' },
], true);

NagSuppressions.addStackSuppressions(cryptoAIAgentSupervisorStack, [
  { id: 'AwsSolutions-IAM4', reason: 'AWSLambdaBasicExecutionRole, AWSLambdaVPCAccessExecutionRole are restrictive roles' },
  { id: 'AwsSolutions-IAM5', reason: 'Permission to read CF stack is restrictive enough' },
], true);