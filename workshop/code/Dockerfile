FROM ghcr.io/astral-sh/uv:python3.11-bookworm-slim
WORKDIR /app

# Configure UV for container environment
ENV UV_SYSTEM_PYTHON=1 UV_COMPILE_BYTECODE=1

# Copy requirements and install dependencies
COPY requirements.txt requirements.txt
RUN uv pip install -r requirements.txt

# Install AWS OpenTelemetry for observability
RUN uv pip install aws-opentelemetry-distro>=0.10.1

# Set AWS region environment variables
ENV AWS_REGION=us-east-1

# Signal that this is running in Docker for host binding logic
ENV DOCKER_CONTAINER=1

# MemoryID
ENV MEMORY_ID="Web3AnalystMemory-0OZZp7Doxi"

# Create non-root user for security
RUN useradd -m -u 1000 bedrock_agentcore
USER bedrock_agentcore

# Expose ports for agent communication
EXPOSE 8080
EXPOSE 8000

# Copy entire project (respecting .dockerignore)
COPY . .

# Default command - can be overridden for different agent types
CMD ["opentelemetry-instrument", "python", "-m", "strands_agents_streaming_memory"]
