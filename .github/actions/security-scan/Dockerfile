FROM node:20-alpine

# Install required tools
RUN apk add --no-cache \
    curl \
    bash \
    jq \
    git \
    docker-cli

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install GitHub CLI
RUN apk add --no-cache github-cli

# Create app directory
WORKDIR /action

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production 2>/dev/null || npm install --only=production

# Copy action source files
COPY src/ ./src/
COPY entrypoint.sh ./

# Make entrypoint executable
RUN chmod +x entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/action/entrypoint.sh"]
