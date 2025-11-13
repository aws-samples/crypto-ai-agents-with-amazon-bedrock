import boto3
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def update_agent_runtime_role_for_memory():
    """Update IAM role to include AgentCore Memory permissions."""
    
    iam = boto3.client('iam')
    role_name = 'Web3AgentCoreExecutionRole'
    
    # Additional policy for Memory service
    memory_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "bedrock-agentcore:CreateMemory",
                    "bedrock-agentcore:GetMemory",
                    "bedrock-agentcore:ListMemories",
                    "bedrock-agentcore:DeleteMemory",
                    "bedrock-agentcore:CreateEvent",
                    "bedrock-agentcore:GetEvent",
                    "bedrock-agentcore:ListEvents"
                ],
                "Resource": "*",
                "Sid": "AgentCoreMemoryAccess"
            }
        ]
    }
    
    try:
        # Create and attach memory policy
        policy_response = iam.create_policy(
            PolicyName=f'{role_name}MemoryPolicy',
            PolicyDocument=json.dumps(memory_policy),
            Description='Memory service policy for Web3 Bedrock AgentCore agents'
        )
        
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_response['Policy']['Arn']
        )
        
        logger.info(f"Attached memory policy: {policy_response['Policy']['Arn']}")
        return policy_response['Policy']['Arn']
        
    except iam.exceptions.EntityAlreadyExistsException:
        logger.info(f"📁 Memory policy already exists")
        # Get existing policy ARN
        account_id = boto3.client('sts').get_caller_identity()['Account']
        policy_arn = f"arn:aws:iam::{account_id}:policy/{role_name}MemoryPolicy"
        return policy_arn
    except Exception as e:
        logger.error(f"Error updating role: {e}")
        raise

if __name__ == "__main__":
    policy_arn = update_agent_runtime_role_for_memory()
    print(f"Memory Policy ARN: {policy_arn}")
