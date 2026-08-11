#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
NC='\033[0m' 
BOLD='\033[1m'

echo -e "${GREEN}${BOLD}=== APTCP-SOCKS Tunnel Installer ===${NC}"

# 1. Dependency check
for cmd in git docker openssl; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd is not installed. Please install it before running this script."
        exit 1
    fi
done

# Check for docker compose vs docker-compose
if docker compose version > /dev/null 2>&1; then
    DOCKER_CMD="docker compose"
elif docker-compose version > /dev/null 2>&1; then
    DOCKER_CMD="docker-compose"
else
    echo "Error: Neither 'docker compose' nor 'docker-compose' found."
    echo "Please install the Docker Compose plugin."
    exit 1
fi

# 2. Cloning repository
REPO_URL="https://github.com/Doctorgth/APTCP-SOCKS.git"
PROJECT_DIR="APTCP-SOCKS"

if [ -d "$PROJECT_DIR" ]; then
    echo "Directory $PROJECT_DIR already exists. Using existing one."
    cd "$PROJECT_DIR" || exit
else
    echo "Cloning repository..."
    git clone "$REPO_URL"
    cd "$PROJECT_DIR" || exit
fi

# 3. User Input
echo -e "\n${BOLD}--- Configuration Setup ---${NC}"

read -p "Enter port for APTCP server [default 1080]: " USER_PORT
USER_PORT=${USER_PORT:-1080}

read -p "Enter username [default default]: " USER_NAME
USER_NAME=${USER_NAME:-default}

read -p "Enter password [default default]: " USER_PASS
USER_PASS=${USER_PASS:-default}

read -p "Generate TLS certificate for encryption? (y/n) [default n]: " TLS_CHOICE
TLS_CHOICE=${TLS_CHOICE:-n}

# 4. Prepare config files
cp server/config.json.example server/config.json
cp server/users.jsonl.example server/users.jsonl

# 5. Apply settings
# Create users.jsonl
echo "{\"username\": \"$USER_NAME\", \"password\": \"$USER_PASS\"}" > server/users.jsonl

# Build config.json
cat <<EOF > server/config.json
{
  "aptcp_host": "0.0.0.0",
  "aptcp_port": $USER_PORT,
  "auth_enabled": true,
  "users_file": "server/users.jsonl",
  "timeout": 30
EOF

if [[ "$TLS_CHOICE" =~ ^[Yy]$ ]]; then
    echo "Generating self-signed certificate..."
    openssl req -x509 -newkey rsa:4096 -keyout server/key.pem -out server/cert.pem -days 365 -nodes -subj "/CN=aptcp-server" 2>/dev/null
    
    cat <<EOF >> server/config.json
,
  "tls_enabled": true,
  "tls_cert": "server/cert.pem",
  "tls_key": "server/key.pem"
}
EOF
    # Uncomment volumes in docker-compose.yml
    sed -i 's|# - ./server/cert.pem|- ./server/cert.pem|g' docker-compose.yml
    sed -i 's|# - ./server/key.pem|- ./server/key.pem|g' docker-compose.yml
    # Update port mapping in docker-compose.yml
    sed -i "s|\"1080:1080\"|\"$USER_PORT:$USER_PORT\"|g" docker-compose.yml
    echo "TLS enabled and certificates created."
else
    # Update port mapping even if TLS is disabled
    sed -i "s|\"1080:1080\"|\"$USER_PORT:$USER_PORT\"|g" docker-compose.yml
    echo "}" >> server/config.json
    echo "TLS disabled."
fi

# 6. Final Instructions
echo -e "\n${GREEN}${BOLD}=== Installation Complete! ===${NC}"
echo -e "${BOLD}Your credentials:${NC}"
echo "Username: $USER_NAME"
echo "Password: $USER_PASS"
echo "Port:     $USER_PORT"
if [[ "$TLS_CHOICE" =~ ^[Yy]$ ]]; then
    echo "TLS:      Enabled (Download server/cert.pem for your client)"
fi

echo -e "\n${BOLD}Management Commands:${NC}"
echo -e "Start server:       ${GREEN}$DOCKER_CMD up -d --build${NC}"
echo -e "Stop server:        ${GREEN}$DOCKER_CMD down${NC}"
echo -e "View logs:          ${GREEN}$DOCKER_CMD logs -f${NC}"
echo -e "Rebuild:            ${GREEN}$DOCKER_CMD up -d --build --force-recreate${NC}"

echo -e "\n${BOLD}File locations:${NC}"
echo "Config:  ./server/config.json"
echo "Users:   ./server/users.jsonl"

echo -e "\nTo start now, run:"
echo -e "${GREEN}cd $PROJECT_DIR && $DOCKER_CMD up -d --build${NC}"