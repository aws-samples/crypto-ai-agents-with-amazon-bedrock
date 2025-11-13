import boto3
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def update_agent_runtime_role_for_agent_invoke():
    """Update IAM role to include Bedrock Agent invocation permissions."""
    
    iam = boto3.client('iam')
    role_name = 'Web3AgentCoreExecutionRole'
    
    # Additional policy for Agent-to-Agent communication
    agent_invoke_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "bedrock:InvokeAgent",
                    "bedrock:GetAgent",
                    "bedrock:ListAgents"
                ],
                "Resource": "*",
                "Sid": "BedrockAgentInvocation"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "kms:Decrypt",
                    "kms:DescribeKey",
                    "kms:GetPublicKey"
                ],
                "Resource": "*",
                "Sid": "KMSAccess"
            }
        ]
    }
    
    try:
        # Create and attach agent invoke policy
        policy_response = iam.create_policy(
            PolicyName=f'{role_name}AgentInvokePolicy',
            PolicyDocument=json.dumps(agent_invoke_policy),
            Description='Agent invocation policy for Web3 Bedrock AgentCore agents'
        )
        
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_response['Policy']['Arn']
        )
        
        logger.info(f"Attached agent invoke policy: {policy_response['Policy']['Arn']}")
        return policy_response['Policy']['Arn']
        
    except iam.exceptions.EntityAlreadyExistsException:
        logger.info(f"📁 Agent invoke policy already exists")
        # Get existing policy ARN
        account_id = boto3.client('sts').get_caller_identity()['Account']
        policy_arn = f"arn:aws:iam::{account_id}:policy/{role_name}AgentInvokePolicy"
        return policy_arn
    except Exception as e:
        logger.error(f"Error updating role: {e}")
        raise

if __name__ == "__main__":
    policy_arn = update_agent_runtime_role_for_agent_invoke()
    print(f"Agent Invoke Policy ARN: {policy_arn}")
