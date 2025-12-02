#!/bin/bash
# Helper script to setup Keycloak and Girder OIDC integration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
KEYCLOAK_URL="${KEYCLOAK_URL:-https://localhost:8443}"
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
REALM_NAME="${REALM_NAME:-girder}"
CLIENT_ID="${CLIENT_ID:-girder}"
REDIRECT_URI="${REDIRECT_URI:-http://localhost:8080/api/v1/oidc/callback}"
TEST_USER="${TEST_USER:-testuser}"
TEST_PASSWORD="${TEST_PASSWORD:-testpass123}"
TEST_EMAIL="${TEST_EMAIL:-test@example.com}"

echo -e "${YELLOW}================================================${NC}"
echo -e "${YELLOW}Girder OIDC Setup Script${NC}"
echo -e "${YELLOW}================================================${NC}"
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python 3 is required but not installed${NC}"
    exit 1
fi

# Check if requests is installed
python3 -c "import requests" 2>/dev/null || {
    echo -e "${YELLOW}Installing Python requests library...${NC}"
    pip install requests
}

# Run the setup script
echo -e "${YELLOW}Starting Keycloak setup...${NC}"
echo ""

python3 "$(dirname "$0")/setup_keycloak.py" \
    --keycloak-url "$KEYCLOAK_URL" \
    --admin-user "$KEYCLOAK_ADMIN" \
    --admin-password "$KEYCLOAK_ADMIN_PASSWORD" \
    --realm-name "$REALM_NAME" \
    --client-id "$CLIENT_ID" \
    --redirect-uri "$REDIRECT_URI" \
    --test-user "$TEST_USER" \
    --test-password "$TEST_PASSWORD" \
    --test-email "$TEST_EMAIL"

echo ""
echo -e "${GREEN}✓ Setup complete!${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Create a Girder admin account at: http://localhost:8080"
echo "2. Go to Admin Panel → OIDC/Keycloak Configuration"
echo "3. Enter the following settings:"
echo "   - Keycloak URL: $KEYCLOAK_URL"
echo "   - Keycloak Realm: $REALM_NAME"
echo "   - Client ID: $CLIENT_ID"
echo "   - Client Secret: $CLIENT_SECRET"
echo "4. Check 'Enable OIDC' and save"
echo "5. Test login at http://localhost:8080/#!/login"
echo ""
echo -e "${YELLOW}Test Credentials:${NC}"
echo "Username: $TEST_USER"
echo "Password: $TEST_PASSWORD"
echo ""
