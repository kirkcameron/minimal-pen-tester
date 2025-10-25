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
