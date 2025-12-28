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

# Create non-root user for security
RUN addgroup -g 1000 scanner && \
    adduser -u 1000 -G scanner -s /bin/sh -D scanner

# Create app directory
WORKDIR /action

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production 2>/dev/null || npm install --only=production

# Copy action source files
COPY src/ ./src/
COPY entrypoint.sh ./

# Make entrypoint executable and set ownership
RUN chmod +x entrypoint.sh && \
    chown -R scanner:scanner /action

# Switch to non-root user
USER scanner

# Set entrypoint
ENTRYPOINT ["/action/entrypoint.sh"]
