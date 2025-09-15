# Tools Container - Pre-install all penetration testing tools
FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Create tools directory
RUN mkdir -p /opt/tools

# Install basic dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    python3 \
    python3-pip \
    golang-go \
    nodejs \
    npm \
    unzip \
    build-essential \
    libssl-dev \
    ca-certificates \
    apt-transport-https \
    software-properties-common \
    dnsutils \
    masscan \
    nmap \
    nikto \
    && rm -rf /var/lib/apt/lists/*

# Set Go environment
ENV GOPATH=/opt/tools/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

# Install tool installation script
COPY install_tools.sh /install_tools.sh
RUN chmod +x /install_tools.sh

WORKDIR /opt/tools

CMD ["/bin/bash"]