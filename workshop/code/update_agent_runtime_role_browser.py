import boto3
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def update_agent_runtime_role_for_browser():
    """Update IAM role to include AgentCore Browser Tool permissions."""
    
    iam = boto3.client('iam')
    role_name = 'Web3AgentCoreExecutionRole'
    
    # Additional policy for Browser Tool
    browser_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "bedrock-agentcore:CreateBrowserSession",
                    "bedrock-agentcore:GetBrowserSession",
                    "bedrock-agentcore:DeleteBrowserSession",
                    "bedrock-agentcore:ExecuteBrowserAction"
                ],
                "Resource": "*",
                "Sid": "AgentCoreBrowserAccess"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "bedrock:InvokeModel"
                ],
                "Resource": "arn:aws:bedrock:*::foundation-model/amazon.nova-pro-v1:0",
                "Sid": "NovaModelAccess"
            }
        ]
    }
    
    try:
        # Create and attach browser policy
        policy_response = iam.create_policy(
            PolicyName=f'{role_name}BrowserPolicy',
            PolicyDocument=json.dumps(browser_policy),
            Description='Browser tool policy for Web3 Bedrock AgentCore agents'
        )
        
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_response['Policy']['Arn']
        )
        
        logger.info(f"Attached browser policy: {policy_response['Policy']['Arn']}")
        return policy_response['Policy']['Arn']
        
    except iam.exceptions.EntityAlreadyExistsException:
        logger.info(f"📁 Browser policy already exists")
        # Get existing policy ARN
        account_id = boto3.client('sts').get_caller_identity()['Account']
        policy_arn = f"arn:aws:iam::{account_id}:policy/{role_name}BrowserPolicy"
        return policy_arn
    except Exception as e:
        logger.error(f"Error updating role: {e}")
        raise

if __name__ == "__main__":
    policy_arn = update_agent_runtime_role_for_browser()
    print(f"Browser Policy ARN: {policy_arn}")
