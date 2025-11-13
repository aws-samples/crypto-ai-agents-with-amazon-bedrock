from bedrock_agentcore.memory import MemoryClient
from bedrock_agentcore.memory.constants import StrategyType
from botocore.exceptions import ClientError
import os
import boto3

memory_client = MemoryClient(region_name=os.environ["AWS_REGION"])
memory_name = "Web3AnalystMemory"

try:
    memory = memory_client.create_memory_and_wait(
        name=memory_name,
        description="Memory for sample agent conversations",
        strategies=[
            {
                StrategyType.SUMMARY.value: {
                    "name": "SessionSummarizer",
                    "namespaces": ["sample-agent/summaries/{actorId}/{sessionId}"]
                }
            },
            {
                StrategyType.USER_PREFERENCE.value: {
                    "name": "UserPreferences",
                    "description": "Captures user preferences and behavior",
                    "namespaces": ["sample-agent/preferences/{actorId}"],
                }
            },
            {
                StrategyType.SEMANTIC.value: {
                    "name": "FactExtractor",
                    "description": "Stores facts from conversations",
                    "namespaces": ["sample-agent/semantic/{actorId}/"],
                }
            },
        ],
        event_expiry_days=7, # Memories expire after 7 days
    )
    memory_id = memory.get('id') # The memory_id will be used in following operations
    print(f"✅ Memory ID: {memory_id}")
except ClientError as e:
    print(f"❌ ERROR: {e}")
    if e.response['Error']['Code'] == 'ValidationException' and "already exists" in str(e):
        # If memory already exists, retrieve its ID
        memories = memory_client.list_memories()
        memory_id = next((m['id'] for m in memories if m['id'].startswith(memory_name)), None)
        print(f"Memory already exists. Using existing memory ID: {memory_id}")
except Exception as e:
    # Show any errors during memory creation
    print(f"❌ ERROR: {e}")
    import traceback
    traceback.print_exc()
    # Cleanup on error - delete the memory if it was partially created
    if memory_id:
        try:
            memory_client.delete_memory_and_wait(memory_id=memory_id)
            print(f"Cleaned up memory: {memory_id}")
        except Exception as cleanup_error:
            print(f"Failed to clean up memory: {cleanup_error}")