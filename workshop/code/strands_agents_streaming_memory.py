import asyncio
import os
import logging
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
version = "Agent with Memory v0.0.1"

@tool
def get_version() -> dict:
    """Return the version of the agent."""
    return {"version": version}

app = BedrockAgentCoreApp()

agent = Agent(
    tools=[get_version],
    system_prompt=f"""You are a helpful personal assistant with long-term memory capabilities.
        
        You can help with:
        - General questions about blockchain
        - Remembering user preferences and past conversations
        - Personal task management
        
        AVAILABLE TOOLS:
        - get_version: Returns the current version of this agent
        
        Your memory system automatically stores and retrieves conversation context.
        When users ask about past conversations or their preferences, recall from memory.
        
        Today's date: {datetime.today().strftime('%Y-%m-%d')}
        Be friendly and professional.""",
    hooks=[memory_hooks],
    state={"actor_id": user_id, "session_id": session_id},
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

        # Check for current_tool_use in chunk (which appears in delta updates)
        # elif "current_tool_use" in event:
        #     tool_info = event["current_tool_use"]
        #     tool_name = tool_info.get('name', 'Unknown')
        #     tool_input = tool_info.get('input', {})
        #     tool_id = tool_info.get('toolUseId', '')

        #     # Format the tool call as a special marker
        #     yield f"\n\n<tool_call>\n"
        #     yield f"name: {tool_name}\n"
        #     yield f"id: {tool_id}\n"
        #     yield f"params: {tool_input}\n"


if __name__ == "__main__":
    app.run()
