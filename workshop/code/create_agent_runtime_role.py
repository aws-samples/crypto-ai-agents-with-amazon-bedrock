import boto3
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_agent_runtime_role():
    """Create IAM role for Bedrock AgentCore runtime with Web3 permissions."""
    
    iam = boto3.client('iam')
    role_name = 'Web3AgentCoreExecutionRole'
    
    # Trust policy
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "bedrock-agentcore.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    
    # Execution policy with Web3 agent permissions
    execution_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream",
                    "bedrock:InvokeAgent"
                ],
                "Resource": "*",
                "Sid": "BedrockAccess"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "bedrock-agentcore:*"
                ],
                "Resource": "*",
                "Sid": "AgentCoreAccess"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage"
                ],
                "Resource": "*",
                "Sid": "ECRAccess"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "xray:PutTraceSegments",
                    "xray:PutTelemetryRecords"
                ],
                "Resource": "*",
                "Sid": "XRayTracing"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": "*",
                "Sid": "CloudWatchLogging"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ssm:GetParameter",
                    "ssm:PutParameter",
                    "ssm:DeleteParameter"
                ],
                "Resource": "arn:aws:ssm:*:*:parameter/web3-agent/*",
                "Sid": "SSMParameterAccess"
            },
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
        # Create role
        role_response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description='Execution role for Web3 Bedrock AgentCore agents'
        )
        
        # Create and attach policy
        policy_response = iam.create_policy(
            PolicyName=f'{role_name}Policy',
            PolicyDocument=json.dumps(execution_policy),
            Description='Execution policy for Web3 Bedrock AgentCore agents'
        )
        
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_response['Policy']['Arn']
        )
        
        logger.info(f"Created role: {role_response['Role']['Arn']}")
        return role_response['Role']['Arn']
        
    except iam.exceptions.EntityAlreadyExistsException:
        role_response = iam.get_role(RoleName=role_name)
        logger.info(f"📁 Role already exists: {role_response['Role']['Arn']}")
        return role_response['Role']['Arn']

if __name__ == "__main__":
    role_arn = create_agent_runtime_role()
    print(f"Role ARN: {role_arn}")
