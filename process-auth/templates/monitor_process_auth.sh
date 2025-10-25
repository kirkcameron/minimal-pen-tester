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
