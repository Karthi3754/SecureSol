# Multi-stage build for analyzer service
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    nodejs \
    npm \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# Install Solidity compiler
RUN curl -fsSL https://github.com/ethereum/solidity/releases/download/v0.8.19/solc-static-linux -o /usr/local/bin/solc \
    && chmod +x /usr/local/bin/solc

# Create working directory
WORKDIR /app

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install security analysis tools
RUN pip install slither-analyzer mythril

# Install Echidna (Haskell-based fuzzer)
RUN curl -fsSL https://github.com/crytic/echidna/releases/download/v2.2.1/echidna-2.2.1-Ubuntu-18.04.tar.gz -o echidna.tar.gz \
    && tar -xzf echidna.tar.gz \
    && mv echidna /usr/local/bin/ \
    && rm echidna.tar.gz \
    || echo "Warning: Echidna installation failed, fuzzing will use fallback mode"

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs models temp

# Create initial ML models if they don't exist
RUN python models/create_initial_models.py

# Set proper permissions
RUN chmod +x app.py

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

# Expose port
EXPOSE 8001

# Command to run the application
CMD ["python", "app.py"]
