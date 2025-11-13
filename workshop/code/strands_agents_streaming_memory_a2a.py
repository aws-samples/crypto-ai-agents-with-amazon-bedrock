import asyncio
import os
import logging
import boto3
import uuid
from datetime import datetime
from strands import Agent, tool
from bedrock_agentcore import BedrockAgentCoreApp

from bedrock_agentcore.memory import MemoryClient
from botocore.exceptions import ClientError
from memory import LongTermMemoryHooks

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

region = os.getenv("AWS_REGION", "us-east-1")
user_id = "user_001"
session_id = str(uuid.uuid4())
memory_id = os.environ["MEMORY_ID"]
memory_client = MemoryClient(region_name=region)
memory_hooks = LongTermMemoryHooks(memory_id, memory_client, user_id, session_id)
version = "Agent with Memory and Trasaction Management Agent - v0.0.1"
bedrock_agent_runtime_client = boto3.client("bedrock-agent-runtime",
                                            region_name=region)

@tool
def invoke_bedrock_agent(prompt: str) -> dict:
    """Invoke a Bedrock Agent Runtime Agent with the given payload."""
    try:
        response = bedrock_agent_runtime_client.invoke_agent(
            agentId="ZSZGSBPYSZ",
            agentAliasId="IXREV3KVVN",
            sessionId=session_id,
            inputText=prompt,
        )   

        completion = ""

        for event in response.get("completion"):
            chunk = event["chunk"]
            completion += chunk["bytes"].decode()

    except Exception as e:
        logger.error(f"invoking bedrock agent causes error: {e}")
        return {"error": str(e)}

    return completion

@tool
def get_version() -> dict:
    """Return the version of the agent."""
    return {"version": version}


app = BedrockAgentCoreApp()
agent = Agent(
    tools=[invoke_bedrock_agent, get_version],
    system_prompt=f"""You are a coordinator agent that routes requests to specialized blockchain agents.
        
        AVAILABLE TOOLS:
        - invoke_bedrock_agent: Delegates requests to a specialized Bedrock agent for blockchain operations
          * Parameter: prompt (string) - The user's request to forward to the blockchain agent
        - get_version: Returns the current version of this coordinator agent
        
        ROUTING LOGIC:
        Use invoke_bedrock_agent for:
        - Wallet operations (send, check balance, get address)
        - Current cryptocurrency prices
        - Investment advice
        - Transaction cost estimates
        - Historical blockchain data queries
        
        Use get_version for:
        - Version information requests
        
        EXAMPLE REQUESTS FOR invoke_bedrock_agent:
        - "Send 0.1 ETH to vitalik.eth"
        - "What's my current balance?"
        - "What's the price of Bitcoin right now?"
        - "Should I invest in crypto now?"
        - "What's my wallet address?"
        - "How much gas will this cost?"
        
        Today's date: {datetime.today().strftime('%Y-%m-%d')}
        Be friendly and professional.""",
    # hooks=[memory_hooks],
    state={"actor_id": user_id, "session_id": session_id, "version": version},
    model="us.anthropic.claude-sonnet-4-20250514-v1:0",
)


@app.entrypoint
async def agent_invocation(payload):
    """Handler for agent invocation"""
    stream = agent.stream_async(payload["prompt"])
    async for event in stream:
        if "data" in event:
            yield event["data"]

        if "tool_use" in event:
            tool_info = event["tool_use"]
            tool_name = tool_info.get("name", "Unknown")
            tool_input = tool_info.get("input", {})

            # Format the tool call as a special marker that can be easily detected by the client
            yield f"\n\n<tool_call>\n"
            yield f"name: {tool_name}\n"
            yield f"params: {tool_input}\n"
            yield f"</tool_call>\n\n"

if __name__ == "__main__":
    app.run()
