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
