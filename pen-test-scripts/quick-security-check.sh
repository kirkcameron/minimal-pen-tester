#!/usr/bin/env bash
# Quick Security Check for minimal-server-mail
# Fast security assessment for production environments

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TARGET_URL="$1"

if [[ -z "$TARGET_URL" ]]; then
    echo "Usage: $0 <TARGET_URL>"
    echo "Example: $0 https://example.com/contact"
    exit 1
fi

# Ensure URL ends with /
if [[ ! "$TARGET_URL" =~ /$ ]]; then
    TARGET_URL="${TARGET_URL}/"
fi

echo -e "${YELLOW}🔍 Quick Security Check: $TARGET_URL${NC}"
echo ""

# Quick tests
echo "Testing direct access..."
mail_response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL"mail.php)
config_response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL"config.php)
htaccess_response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL".htaccess)

# Results
# For mail.php: 404 (not found) or 500 (requires POST) = SECURE, 200 (accessible) = VULNERABLE
if [[ "$mail_response" == "404" ]] || [[ "$mail_response" == "500" ]]; then
    echo -e "${GREEN}✅ mail.php: SECURE ($mail_response)${NC}"
else
    echo -e "${RED}❌ mail.php: VULNERABLE ($mail_response)${NC}"
fi

if [[ "$config_response" == "404" ]]; then
    echo -e "${GREEN}✅ config.php: SECURE (404)${NC}"
else
    echo -e "${RED}❌ config.php: VULNERABLE ($config_response)${NC}"
fi

# Check .htaccess - must be 404 OR 200 without actual .htaccess content
if [[ "$htaccess_response" == "404" ]] || ([[ "$htaccess_response" == "200" ]] && ! curl -s "$TARGET_URL".htaccess | grep -q "RewriteRule\|DirectoryIndex\|Options"); then
    echo -e "${GREEN}✅ .htaccess: SECURE ($htaccess_response)${NC}"
else
    echo -e "${RED}❌ .htaccess: VULNERABLE ($htaccess_response)${NC}"
fi

echo ""
# Check if all tests are actually secure (not just 404)
mail_secure=false
config_secure=false
htaccess_secure=false

# mail.php is secure if 404 or 500
if [[ "$mail_response" == "404" ]] || [[ "$mail_response" == "500" ]]; then
    mail_secure=true
fi

# config.php is secure if 404
if [[ "$config_response" == "404" ]]; then
    config_secure=true
fi

# .htaccess is secure if 404 OR 200 without actual content
if [[ "$htaccess_response" == "404" ]] || ([[ "$htaccess_response" == "200" ]] && ! curl -s "$TARGET_URL".htaccess | grep -q "RewriteRule\|DirectoryIndex\|Options"); then
    htaccess_secure=true
fi

if [[ "$mail_secure" == "true" && "$config_secure" == "true" && "$htaccess_secure" == "true" ]]; then
    echo -e "${GREEN}🎉 All security checks passed!${NC}"
else
    echo -e "${RED}⚠️  Security issues found. Run full penetration test for details.${NC}"
fi
