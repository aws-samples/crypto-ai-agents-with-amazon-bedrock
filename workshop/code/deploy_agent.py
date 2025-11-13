import boto3
import os

client = boto3.client('bedrock-agentcore-control',
                      region_name=os.environ["AWS_REGION"])

response = client.create_agent_runtime(
    agentRuntimeName='strands_agent',
    agentRuntimeArtifact={
        'containerConfiguration': {
            'containerUri': f'{os.environ["AWS_ACCOUNT_ID"]}.dkr.ecr.{os.environ["AWS_REGION"]}.amazonaws.com/web3-strands-agent:latest'
        }
    },
    networkConfiguration={"networkMode": "PUBLIC"},
    roleArn=f'arn:aws:iam::{os.environ["AWS_ACCOUNT_ID"]}:role/Web3AgentCoreExecutionRole'
)

print(f"Agent Runtime created successfully!")
print(f"Agent Runtime ARN: {response['agentRuntimeArn']}")
print(f"Status: {response['status']}")
