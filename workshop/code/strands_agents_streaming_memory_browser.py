import asyncio
import os
import logging
import uuid
from datetime import datetime
from strands import Agent, tool
from bedrock_agentcore import BedrockAgentCoreApp
from bedrock_agentcore.memory import MemoryClient
from botocore.exceptions import ClientError
from playwright.sync_api import sync_playwright, Playwright, BrowserType
from bedrock_agentcore.tools.browser_client import browser_session
from langchain_aws import ChatBedrock
from memory import LongTermMemoryHooks

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

region = os.getenv("AWS_REGION", "us-east-1")
user_id = "user_001"
session_id = str(uuid.uuid4())
memory_id = os.environ["MEMORY_ID"]
memory_client = MemoryClient(region_name=region)
memory_hooks = LongTermMemoryHooks(memory_id, memory_client, user_id, session_id)
version = "Agent with Memory and Browser v0.0.1"

def get_coin_data_with_browser(playwright: Playwright, coin: str) -> str:
    """Get cryptocurrency market data using browser"""
    with browser_session(os.environ.get("AWS_REGION", "us-east-1")) as client:
        ws_url, headers = client.generate_ws_headers()
        chromium: BrowserType = playwright.chromium
        browser = chromium.connect_over_cdp(ws_url, headers=headers)

        try:
            context = browser.contexts[0] if browser.contexts else browser.new_context()
            page = context.pages[0] if context.pages else context.new_page()
            page.goto(f"https://coinmarketcap.com/currencies/{coin}")
            content = page.inner_text("body")

            llm = ChatBedrock(model_id="eu.amazon.nova-pro-v1:0", region_name=os.environ.get("AWS_REGION", "us-east-1"))
            prompt = "Extract cryptocurrency coin price and key information, key news for {} from this page content. Be concise:\n\n{}".format(coin, content[:3000])
            result = llm.invoke(prompt).content
            logger.info(f"llm result for {coin}: {result}")

            return result

        finally:
            if not page.is_closed():
                page.close()
            browser.close()

@tool
def get_version() -> dict:
    """Return the version of the agent."""
    return {"version": version}

@tool
def get_coin_data(coin: str) -> str:
    """Get cryptocurrency data for a given symbol"""
    try:
        with sync_playwright() as p:
            return get_coin_data_with_browser(p, coin)
    except Exception as e:
        logger.error(f"Error getting data for {coin}: {str(e)}")
        return f"Error getting data for {coin}: {str(e)}"
app = BedrockAgentCoreApp()
agent = Agent(
    tools=[get_coin_data, get_version],
    system_prompt=f"""You're an expert market intelligence analyst with deep expertise in financial markets, business strategy, and economic trends. You have advanced long-term memory capabilities to store and recall financial interests for each user you work with.

    PURPOSE:
    - Provide real-time cryptocurrency market analysis
    - Maintain long-term financial profiles for each user
    - Store and recall investment preferences, risk tolerance, and financial goals
    - Build ongoing professional relationships through comprehensive memory
        
    AVAILABLE TOOLS:
    - get_coin_data: Retrieves current cryptocurrency prices, changes, and market data
      * Parameter: coin (string) - Full coin name (e.g., "bitcoin" not "btc", "ethereum" not "eth")
    - get_version: Returns the current version of this agent

    WORKFLOW:
    1. Identify user and recall their cryptocurrency preferences from memory
    2. For market data requests, use get_coin_data with the full coin name
    3. Store user preferences and conversation context in memory for future interactions

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

if __name__ == "__main__":
    app.run()
