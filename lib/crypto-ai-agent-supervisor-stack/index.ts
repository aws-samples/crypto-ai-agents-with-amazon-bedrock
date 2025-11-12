// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as ecrAssets from 'aws-cdk-lib/aws-ecr-assets';
import { bedrock as bedrockGenAIConstructs} from '@cdklabs/generative-ai-cdk-constructs';
import * as path from 'path';
import { getConfig, EnvironmentConfig } from '../../utils/environment';
const config: EnvironmentConfig = getConfig();

interface CryptoAIAgentSupervisorStackProps extends cdk.StackProps {
  knowledgeBase: bedrockGenAIConstructs.VectorKnowledgeBase;
}

export class CryptoAIAgentSupervisorStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: CryptoAIAgentSupervisorStackProps) {
    super(scope, id, props);

    // Create KMS wallet
    const kmsWallet = new cdk.aws_kms.Key(this, 'KmsWallet', {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      alias: 'crypto-ai-agent-wallet',
      keySpec: cdk.aws_kms.KeySpec.ECC_SECG_P256K1, // Use secp256k1 curve for Ethereum compatibility
      keyUsage: cdk.aws_kms.KeyUsage.SIGN_VERIFY
    });

    const guardrail = new bedrockGenAIConstructs.Guardrail(this, 'bedrockGuardrails', {
      name: 'agent-guardrail',
      description: 'Guardrails to protect against malicious use of the agent.',
    });

    guardrail.addDeniedTopicFilter(bedrockGenAIConstructs.Topic.POLITICAL_ADVICE);
    guardrail.addWordFilter('steal');
    guardrail.addWordFilter('rugpull');

    // We use cross region inference to improve inference performance
    const cris = bedrockGenAIConstructs.CrossRegionInferenceProfile.fromConfig({
      geoRegion: bedrockGenAIConstructs.CrossRegionInferenceProfileRegion.EU,
      model: bedrockGenAIConstructs.BedrockFoundationModel.AMAZON_NOVA_PRO_V1,
    });
    
    const agent = new bedrockGenAIConstructs.Agent(this, 'Agent', {
      name: 'CryptoAI_Supervisor_Agent',
      foundationModel: cris,
      shouldPrepareAgent: true,
      userInputEnabled: true,
      instruction: `
      Role: You are a Crypto AI Agent. You have access to an Ethereum Virtual Machine compatible blockchain and can query it and send transactions from your own wallet. You can query the blockchain for information and perform actions such as sending transactions. You have access to a knowledge base that contains current blockchain news. You have access to a wallet that you can use to send transactions to the blockchain. Use the Action Group to interact with the blockchain.
      
      These are the functions you can invoke:
      sendTx - send a transaction to the blockchain
      estimateGas - estimate the gas cost of a transaction
      getBalance - get the balance of a wallet
      getCryptoPrice - get the price of a cryptocurrency token
      investAdviceMetric - get investment advice
      getWalletAddress - get your own wallet's address
      `,
    });
    
    agent.addGuardrail(guardrail);

    const agentAlias = new bedrockGenAIConstructs.AgentAlias(this, 'AgentAlias', {
      aliasName: 'CryptoAIAgent',
      agent: agent,
      description: 'Initial alias'
    });

    agent.addKnowledgeBase(props.knowledgeBase);

    // Validate that BLOCKCHAIN_RPC_URL is provided
    if (!config.blockchainRPCURL) {
      throw new Error('BLOCKCHAIN_RPC_URL environment variable is required');
    }

    const lambdaEnvironment = {
      BLOCKCHAIN_RPC_URL: config.blockchainRPCURL,
      COINGECKO_API_KEY: config.coinGeckoAPIKey,
      ...(config.unstoppableDomainsAddress && {
        UNSTOPPABLE_DOMAINS_ADDRESS: config.unstoppableDomainsAddress
      }),
    };

    const actionGroupInvestmentAdviceFunction = new lambda.DockerImageFunction(this, 'InvestmentAdviceActionGroupFunction', {
      code: lambda.DockerImageCode.fromImageAsset(path.join(__dirname, 'lambda'), {
        cmd: ['index.lambda_handler'],
        platform: ecrAssets.Platform.LINUX_AMD64,
      }),
      timeout: cdk.Duration.seconds(300),
      environment: lambdaEnvironment,
      memorySize: 512
    });

    const actionGroupWalletManagerFunction = new lambda.DockerImageFunction(this, 'WalletManagerActionGroupFunction', {
      code: lambda.DockerImageCode.fromImageAsset(path.join(__dirname, 'lambda'), {
        cmd: ['index.lambda_handler'],
        platform: ecrAssets.Platform.LINUX_AMD64,
      }),
      timeout: cdk.Duration.seconds(300),
      environment: lambdaEnvironment,
      memorySize: 512
    });

    // This will grant all required permissions including DescribeKey
    kmsWallet.grant(actionGroupWalletManagerFunction, 
      'kms:DescribeKey',
      'kms:Encrypt',
      'kms:Decrypt',
      'kms:GetPublicKey',
      'kms:Sign'
    );

    kmsWallet.grant(actionGroupInvestmentAdviceFunction,
      'kms:DescribeKey',
      'kms:Encrypt',
      'kms:Decrypt',
      'kms:GetPublicKey',
      'kms:Sign'
    );

    const actionGroupInvestmentAdvice = new bedrockGenAIConstructs.AgentActionGroup({
        name: 'investment_advice',
        description: 'Get investment advice and get token prices',
        executor: bedrockGenAIConstructs.ActionGroupExecutor.fromlambdaFunction(actionGroupInvestmentAdviceFunction),
        enabled: true,
        functionSchema: {
          functions: [{
            "description": "This function is used to get investment advice",
            "name": "investAdviceMetric",
            "parameters": {}
          },
          {
            "description": "This function is used to get the price of crypto tokens",
            "name": "getCryptoPrice",
            "parameters": {
                "token": {
                  "type": "string",
                  "description": "The token for which to get the price of",
                  "required": true
                },
            }
          },
        ]
        }
    });

    const actionGroupWalletManagement = new bedrockGenAIConstructs.AgentActionGroup({
        name: 'wallet_management',
        description: 'Queries the wallet address, gets wallet token balances, and sends ether to a specified address',
        executor: bedrockGenAIConstructs.ActionGroupExecutor.fromlambdaFunction(actionGroupWalletManagerFunction),
        enabled: true,
        functionSchema: {
          functions: [{
            "description": "This function is used to lend assets on-chain and query individual address balances",
            "name": "getBalance",
            "parameters": {
                "walletAddress": {
                  "type": "string",
                  "description": "The address for which to query the balance. This can be a wallet address or an ENS name such as vitalik.eth",
                  "required": true
                },
            }
          },
          {
            "description": "This function is used to estimate the gas required for a payment transaction",
            "name": "estimateGas",
            "parameters": {}
          },
          {
            "description": "This function is used to send transactions to the blockchain. It returns a transaction hash which should be returned to the user",
            "name": "sendTx",
            "requireConfirmation": "ENABLED",
            "parameters": {
                "amount": {
                  "type": "number",
                  "description": "The amount of the currency to send",
                  "required": true
                },
                "receiver": {
                  "type": "string",
                  "description": "The wallet address to send the transaction to",
                  "required": true
                },
            }
          },
          {
            "description": "This function is used to get the agent's wallet address",
            "name": "getWalletAddress",
            "parameters": {}
          }]
        }
      });

      agent.addActionGroup(actionGroupWalletManagement);
      agent.addActionGroup(actionGroupInvestmentAdvice);

      // Output the Agent ID and Agent Alias ID for easy access
      new cdk.CfnOutput(this, 'AgentId', {
        value: agent.agentId,
        description: 'Bedrock Agent ID for CryptoAI Supervisor Agent',
        exportName: 'CryptoAIAgentId',
      });

      new cdk.CfnOutput(this, 'AgentAliasId', {
        value: agentAlias.aliasId,
        description: 'Bedrock Agent Alias ID for CryptoAI Supervisor Agent',
        exportName: 'CryptoAIAgentAliasId',
      });

      new cdk.CfnOutput(this, 'KmsWalletKeyId', {
        value: kmsWallet.keyId,
        description: 'KMS Key ID for the crypto wallet',
        exportName: 'CryptoAIWalletKeyId',
      });

  }
}

