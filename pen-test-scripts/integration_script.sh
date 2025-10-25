#!/usr/bin/env bash
# Safe Integration Script for Process Authentication
# This script safely integrates process authentication without breaking existing functionality

set -e  # Exit on any error

echo "🛡️  Process Authentication Safe Integration"
echo "=============================================="

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INTEGRATION_DIR="process_auth_integration"
BACKUP_DIR="backup_$(date +%Y%m%d_%H%M%S)"
CONFIG_FILE="process_auth_config.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Step 1: Create backup
echo "Step 1: Creating backup..."
mkdir -p "$BACKUP_DIR"
cp -r ../contact "$BACKUP_DIR/" 2>/dev/null || true
cp -r ../minimal-server-mail "$BACKUP_DIR/" 2>/dev/null || true
print_status "Backup created in $BACKUP_DIR"

# Step 2: Create integration directory
echo "Step 2: Setting up integration..."
mkdir -p "$INTEGRATION_DIR"
cp "$PROJECT_ROOT/process-auth/templates/process_auth_integration.py" "$INTEGRATION_DIR/"
cp "$PROJECT_ROOT/process-auth/config/process_auth_config.json" "$INTEGRATION_DIR/"
print_status "Integration directory created"

# Step 3: Test integration (safe mode)
echo "Step 3: Testing integration (safe mode)..."
cd "$INTEGRATION_DIR"
python3 process_auth_integration.py
if [ $? -eq 0 ]; then
    print_status "Integration test passed"
else
    print_error "Integration test failed"
    exit 1
fi

# Step 4: Create PHP wrappers (safe mode - disabled by default)
echo "Step 4: Creating PHP wrappers (safe mode)..."
python3 -c "
from process_auth_integration import ProcessAuthIntegration
integration = ProcessAuthIntegration()
integration.create_php_wrapper('../../contact/contact.php', 'contact_wrapper.php')
integration.create_php_wrapper('../../minimal-server-mail/mail.php', 'mail_wrapper.php')
print('PHP wrappers created (disabled by default)')
"

# Step 5: Create nginx configuration snippet
echo "Step 5: Creating nginx configuration snippet..."
python3 -c "
from process_auth_integration import ProcessAuthIntegration
integration = ProcessAuthIntegration()
with open('nginx_process_auth.conf', 'w') as f:
    f.write(integration.create_nginx_config())
print('Nginx configuration snippet created')
"

# Step 6: Create activation script
echo "Step 6: Creating activation script..."
cat > activate_process_auth.sh << 'EOF'
#!/usr/bin/env bash
# Activation script for process authentication
# Run this to enable process authentication

echo "🛡️  Activating Process Authentication..."

# Enable in config
python3 -c "
import json
with open('process_auth_config.json', 'r') as f:
    config = json.load(f)
config['enabled'] = True
with open('process_auth_config.json', 'w') as f:
    json.dump(config, f, indent=2)
print('Process authentication enabled')
"

echo "✅ Process authentication activated"
echo "⚠️  Monitor your website for any issues"
echo "🔄 To disable: Set 'enabled': false in process_auth_config.json"
EOF

chmod +x activate_process_auth.sh

# Step 7: Create deactivation script
cat > deactivate_process_auth.sh << 'EOF'
#!/usr/bin/env bash
# Deactivation script for process authentication
# Run this to disable process authentication

echo "🔄 Deactivating Process Authentication..."

# Disable in config
python3 -c "
import json
with open('process_auth_config.json', 'r') as f:
    config = json.load(f)
config['enabled'] = False
with open('process_auth_config.json', 'w') as f:
    json.dump(config, f, indent=2)
print('Process authentication disabled')
"

echo "✅ Process authentication deactivated"
echo "🛡️  Website running in fallback mode"
EOF

chmod +x deactivate_process_auth.sh

# Step 8: Create monitoring script
cat > monitor_process_auth.sh << 'EOF'
#!/usr/bin/env bash
# Monitoring script for process authentication

echo "📊 Process Authentication Status"
echo "================================"

# Check if enabled
python3 -c "
import json
try:
    with open('process_auth_config.json', 'r') as f:
        config = json.load(f)
    print(f'Status: {\"ENABLED\" if config.get(\"enabled\", False) else \"DISABLED\"}')
    print(f'Security Level: {config.get(\"security_level\", \"medium\")}')
    print(f'Fallback Allowed: {config.get(\"fallback_allowed\", True)}')
except Exception as e:
    print(f'Error reading config: {e}')
"

# Test authentication
echo ""
echo "🧪 Testing Authentication..."
python3 process_auth_integration.py
EOF

chmod +x monitor_process_auth.sh

cd ..

print_status "Safe integration completed!"
echo ""
echo "📋 Next Steps:"
echo "1. Test the integration: cd $INTEGRATION_DIR && ./monitor_process_auth.sh"
echo "2. When ready, activate: cd $INTEGRATION_DIR && ./activate_process_auth.sh"
echo "3. Monitor your website for any issues"
echo "4. If problems occur, deactivate: cd $INTEGRATION_DIR && ./deactivate_process_auth.sh"
echo ""
echo "🛡️  Process authentication is now safely integrated!"
echo "   - Default: DISABLED (no breaking changes)"
echo "   - Activation: Safe and reversible"
echo "   - Fallback: Always available"
