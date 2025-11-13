from strands.hooks import AfterInvocationEvent, HookProvider, HookRegistry, MessageAddedEvent
import re
import logging
from bedrock_agentcore.memory import MemoryClient

logger = logging.getLogger(__name__)
logging.getLogger().setLevel(logging.ERROR) # Set the logging level to ERROR

class LongTermMemoryHooks(HookProvider):
    """Memory hooks for long-term memory agent"""

    def __init__(
        self, memory_id: str, client: MemoryClient, actor_id: str, session_id: str
    ):
        self.memory_id = memory_id
        self.client = client
        self.actor_id = actor_id
        self.session_id = session_id
        self.namespaces = {
            i["type"]: i["namespaces"][0]
            for i in self.client.get_memory_strategies(self.memory_id)
        }

    def retrieve_user_context(self, event: MessageAddedEvent):
        """Retrieve user context before processing support query"""
        logger.info("Start to retrieve user context...")
        messages = event.agent.messages
        if (
            messages[-1]["role"] == "user"
            and "toolResult" not in messages[-1]["content"][0]
        ):
            user_query = messages[-1]["content"][0]["text"]

            try:
                all_context = []

                for context_type, namespace in self.namespaces.items():
                    # *** AGENTCORE MEMORY USAGE *** - Retrieve customer context from each namespace
                    memories = self.client.retrieve_memories(
                        memory_id=self.memory_id,
                        namespace=namespace.format(actorId=self.actor_id, sessionId=""),
                        query=user_query,
                        top_k=3,
                    )
                    # Post-processing: Format memories into context strings
                    for memory in memories:
                        if isinstance(memory, dict):
                            content = memory.get("content", {})
                            if isinstance(content, dict):
                                text = content.get("text", "").strip()
                                if text:
                                    all_context.append(
                                        f"[{context_type.upper()}] {text}"
                                    )

                # Inject user context into the query
                if all_context:
                    context_text = "\n".join(all_context)
                    original_text = messages[-1]["content"][0]["text"]
                    messages[-1]["content"][0][
                        "text"
                    ] = f"User Context: {context_text}\n\n User Query: {original_text}"
                    logger.info(f"Retrieved {len(all_context)} user context items")

            except Exception as e:
                logger.error(f"Failed to retrieve user context: {e}")

    def save_conversation(self, event: AfterInvocationEvent):
        """Save user interaction after agent response"""
        try:
            messages = event.agent.messages
            if len(messages) >= 2 and messages[-1]["role"] == "assistant":
                # Get last user query and agent response
                user_query = None
                agent_response = None

                for msg in reversed(messages):
                    if msg["role"] == "assistant" and not agent_response:
                        output_message = msg["content"][0]["text"]
                        agent_response = re.sub(r'<thinking>.*?</thinking>', '', output_message, flags=re.DOTALL).strip()

                    elif (
                        msg["role"] == "user"
                        and not user_query
                        and "toolResult" not in msg["content"][0]
                    ):
                        input_prompt = msg["content"][0]["text"]
                        user_query = re.sub(r'User Context:.*? User Query: ', '', input_prompt, flags=re.DOTALL).strip()
                        break

                if user_query and agent_response:
                    # *** AGENTCORE MEMORY USAGE *** - Save the support interaction
                    self.client.create_event(
                        memory_id=self.memory_id,
                        actor_id=self.actor_id,
                        session_id=self.session_id,
                        messages=[
                            (user_query, "USER"),
                            (agent_response, "ASSISTANT"),
                        ],
                    )
                    logger.info(f"Saved support interaction to memory")

        except Exception as e:
            logger.error(f"Failed to save support interaction: {e}")

    def register_hooks(self, registry: HookRegistry) -> None:
        """Register user support memory hooks"""
        registry.add_callback(MessageAddedEvent, self.retrieve_user_context)
        registry.add_callback(AfterInvocationEvent, self.save_conversation)
        logger.info("User support memory hooks registered")
