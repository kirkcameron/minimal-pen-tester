#!/usr/bin/env python3
"""
Process-Based Security Testing Integration Wrapper
=================================================

⚠️  WARNING: This is a PENETRATION TESTING tool, not a security solution.

This wrapper tests whether target applications can distinguish between
internal and external processes. It is designed for security testing
and research purposes only.

DO NOT use for production security - process-based authentication
can be easily bypassed and is not reliable.
"""

import os
import sys
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from process_auth_engine import ProcessAuthEngine, SecurityLevel
    from process_auth_web import ProcessAuthMiddleware
except ImportError as e:
    print(f"Warning: Process authentication modules not available: {e}")
    ProcessAuthEngine = None
    ProcessAuthMiddleware = None

class ProcessAuthIntegration:
    """
    Process-Based Security Testing Integration Wrapper
    
    ⚠️  WARNING: This is for PENETRATION TESTING only, not production security.
    
    This wrapper tests whether target applications can distinguish between
    internal and external processes. It can be disabled without breaking
    existing functionality.
    
    DO NOT use for production security - process-based authentication
    can be easily bypassed and is not reliable.
    """
    
    def __init__(self, config_file: str = "process_auth_config.json"):
        self.config_file = config_file
        self.config = self._load_config()
        self.enabled = self.config.get('enabled', False)
        self.engine = None
        self.middleware = None
        
        if self.enabled and ProcessAuthEngine:
            try:
                self.engine = ProcessAuthEngine(
                    security_level=SecurityLevel(self.config.get('security_level', 'medium'))
                )
                self.middleware = ProcessAuthMiddleware()
                logging.info("Process authentication integration enabled")
            except Exception as e:
                logging.error(f"Failed to initialize process authentication: {e}")
                self.enabled = False
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        default_config = {
            'enabled': False,
            'security_level': 'medium',
            'fallback_allowed': True,
            'log_level': 'INFO',
            'protected_endpoints': ['/contact/contact.php', '/mail.php'],
            'excluded_endpoints': ['/index.html', '/css/', '/js/', '/images/']
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                return {**default_config, **config}
            except Exception as e:
                logging.warning(f"Failed to load config: {e}")
        
        return default_config
    
    def is_protected_endpoint(self, path: str) -> bool:
        """Check if endpoint should be protected"""
        if not self.enabled:
            return False
        
        # Check if path is in protected endpoints
        for protected in self.config.get('protected_endpoints', []):
            if path.startswith(protected):
                return True
        
        # Check if path is in excluded endpoints
        for excluded in self.config.get('excluded_endpoints', []):
            if path.startswith(excluded):
                return False
        
        return False
    
    def authenticate_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Authenticate a request using process-based authentication
        Returns authentication result with fallback option
        """
        if not self.enabled or not self.engine:
            return {
                'authenticated': True,
                'method': 'disabled',
                'confidence': 1.0,
                'fallback': True
            }
        
        try:
            # Extract process information from request
            client_pid = request_data.get('client_pid', os.getpid())
            
            # Perform authentication
            result = self.engine.authenticate(client_pid)
            
            # If authentication fails and fallback is allowed
            if not result.success and self.config.get('fallback_allowed', True):
                return {
                    'authenticated': True,
                    'method': 'fallback',
                    'confidence': 0.5,
                    'fallback': True,
                    'original_result': result
                }
            
            return {
                'authenticated': result.success,
                'method': 'process_auth',
                'confidence': result.confidence,
                'fallback': False,
                'details': result.details
            }
            
        except Exception as e:
            logging.error(f"Authentication error: {e}")
            if self.config.get('fallback_allowed', True):
                return {
                    'authenticated': True,
                    'method': 'error_fallback',
                    'confidence': 0.3,
                    'fallback': True,
                    'error': str(e)
                }
            return {
                'authenticated': False,
                'method': 'error',
                'confidence': 0.0,
                'fallback': False,
                'error': str(e)
            }
    
    def create_php_wrapper(self, target_file: str, output_file: str) -> bool:
        """
        Create a PHP wrapper that includes process authentication
        Safe wrapper that falls back to original functionality
        """
        try:
            wrapper_content = f'''<?php
/**
 * Process Authentication Wrapper
 * Safe integration wrapper for {target_file}
 * Generated by ProcessAuthIntegration
 */

// Configuration
$process_auth_enabled = {str(self.enabled).lower()};
$process_auth_fallback = {str(self.config.get('fallback_allowed', True)).lower()};

// Process authentication check
if ($process_auth_enabled) {{
    // Try to authenticate using process information
    $client_pid = isset($_SERVER['HTTP_X_CLIENT_PID']) ? $_SERVER['HTTP_X_CLIENT_PID'] : getmypid();
    
    // Simple process authentication check
    $server_pid = getmypid();
    $is_internal = ($client_pid == $server_pid);
    
    if (!$is_internal && !$process_auth_fallback) {{
        http_response_code(403);
        die('Access denied: External process detected');
    }}
}}

// Include original file
include '{target_file}';
?>'''
            
            with open(output_file, 'w') as f:
                f.write(wrapper_content)
            
            logging.info(f"Created PHP wrapper: {output_file}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to create PHP wrapper: {e}")
            return False
    
    def create_nginx_config(self) -> str:
        """
        Create nginx configuration snippet for process authentication
        Safe configuration that doesn't break existing setup
        """
        return '''
# Process Authentication Configuration
# Safe integration - can be disabled without issues

location ~ ^/protected/ {
    # Process authentication middleware
    # This is a safe addition that doesn't affect existing routes
    try_files $uri $uri/ @process_auth;
}

location @process_auth {
    # Fallback to original behavior if process auth fails
    try_files $uri $uri/ =404;
}

# Optional: Add process authentication headers
add_header X-Process-Auth-Enabled "true" always;
'''
    
    def enable(self):
        """Enable process authentication"""
        self.config['enabled'] = True
        self._save_config()
        logging.info("Process authentication enabled")
    
    def disable(self):
        """Disable process authentication (safe fallback)"""
        self.config['enabled'] = False
        self._save_config()
        logging.info("Process authentication disabled - using fallback")
    
    def _save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save config: {e}")

def main():
    """Main function for testing integration"""
    integration = ProcessAuthIntegration()
    
    print("Process Authentication Integration")
    print("=" * 40)
    print(f"Enabled: {integration.enabled}")
    print(f"Security Level: {integration.config.get('security_level', 'medium')}")
    print(f"Fallback Allowed: {integration.config.get('fallback_allowed', True)}")
    
    if integration.enabled:
        print("\nTesting authentication...")
        test_request = {'client_pid': os.getpid()}
        result = integration.authenticate_request(test_request)
        print(f"Authentication Result: {result}")
    else:
        print("\nProcess authentication is disabled")
        print("To enable: Set 'enabled': true in process_auth_config.json")

if __name__ == "__main__":
    main()
