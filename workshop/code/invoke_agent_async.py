#!/usr/bin/env python3
import boto3
import json
import uuid
import os
from datetime import datetime
from rich.console import Console

console = Console()

class AgentChat:
    def __init__(self):
        # Initialize the Bedrock AgentCore client
        self.agent_core_client = boto3.client("bedrock-agentcore",
                                                region_name=os.environ["AWS_REGION"])
        self.agent_runtime_arn = os.environ["AGENT_RUNTIME_ARN"]
        # Generate a unique session ID for this chat session
        self.session_id = (
            str(uuid.uuid4()).replace("-", "")[:40] + "f"
        )
        

        print("Web3 Strands Agent Chat Interface")
        print("=" * 50)
        print(f"Session ID: {self.session_id}")
        print("Type 'quit', 'exit', or 'bye' to end the chat")
        print("=" * 50)

    def extract_text_from_response(self, response_data):
        """Extract text from the expected response format"""
        try:
            if isinstance(response_data, dict):
                # Navigate the expected structure: output.message.content[0].text
                output = response_data.get("output", {})
                message = output.get("message", {})
                content = message.get("content", [])

                if content and isinstance(content, list) and len(content) > 0:
                    first_content = content[0]
                    if isinstance(first_content, dict) and "text" in first_content:
                        return first_content["text"]

            return None
        except (KeyError, IndexError, TypeError):
            return None

    def stream_response(self, response):
        if "text/event-stream" in response.get("contentType", ""):
            complete_text = ""
            for line in response["response"].iter_lines(chunk_size=1):
                if line:
                    line = line.decode("utf-8")
                    if line.startswith("data: "):
                        json_chunk = line[6:]
                        try:
                            parsed_chunk = json.loads(json_chunk)
                            if isinstance(parsed_chunk, str):
                                text_chunk = parsed_chunk
                            else:
                                text_chunk = json.dumps(
                                    parsed_chunk, ensure_ascii=False
                                )
                                text_chunk += "\n\n"
                            console.print(text_chunk, end="")
                            # print(text_chunk, end="")
                            complete_text += text_chunk
                        except json.JSONDecodeError:
                            console.print(json_chunk)
                            # print(json_chunk)
                            continue
            console.print()
            return {}

        elif response.get("contentType") == "application/json":
            # Handle standard JSON response
            content = []
            for chunk in response.get("response", []):
                content.append(chunk.decode("utf-8"))

            try:
                response_data = json.loads("".join(content))
                text = self.extract_text_from_response(response_data)
                if text:
                    print(text, end="", flush=True)
                    response_text = text
            except json.JSONDecodeError:
                pass

        else:
            # For other content types, try to extract from the response object
            text = self.extract_text_from_response(response)
            if text:
                print(text, end="", flush=True)
                response_text = text

        return response_text

    def send_message(self, user_input):
        """Send a message to the agent and stream the response"""
        try:
            # Prepare the payload
            payload = json.dumps(
                {
                    "prompt": user_input
                }
            )

            # Invoke the agent
            response = self.agent_core_client.invoke_agent_runtime(
                agentRuntimeArn=self.agent_runtime_arn,
                runtimeSessionId=self.session_id,
                payload=payload,
                qualifier="DEFAULT",
            )

            # Stream the response
            return self.stream_response(response)

        except Exception as e:
            print(f"\n Error: {e}")
            return None

    def chat_loop(self):
        """Main chat loop"""
        try:
            while True:
                # Get user input
                try:
                    user_input = input("\n You: ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\n\nGoodbye!")
                    break

                # Check for exit commands
                if user_input.lower() in ["quit", "exit", "bye", "q"]:
                    print("Goodbye!")
                    break

                # Skip empty input
                if not user_input:
                    continue

                # Send message and get response
                print("Agent: ", end="", flush=True)
                response = self.send_message(user_input)

                if response is None:
                    print("Sorry, I couldn't process your request. Please try again.")

        except KeyboardInterrupt:
            print("\n\nChat interrupted. Goodbye!")


def main():
    """Main function to start the chat interface"""
    chat = AgentChat()
    chat.chat_loop()


if __name__ == "__main__":
    main()
