#!/usr/bin/env python3
"""
Process-Based Authentication Web Integration
===========================================

Generic web server integration for process-based authentication.
Supports multiple web frameworks and server types.

Author: Process Auth Team
License: MIT
"""

import os
import sys
import json
import time
import logging
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import threading
import subprocess
import psutil

from process_auth_engine import ProcessAuthEngine, AuthMethod, SecurityLevel, AuthResult

logger = logging.getLogger(__name__)

@dataclass
class WebAuthConfig:
    """Configuration for web authentication"""
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    allowed_methods: List[AuthMethod] = None
    cache_timeout: int = 300
    max_attempts: int = 5
    rate_limit_window: int = 60
    enable_logging: bool = True
    trusted_ips: List[str] = None
    
    def __post_init__(self):
        if self.allowed_methods is None:
            self.allowed_methods = [AuthMethod.COMBINED]
        if self.trusted_ips is None:
            self.trusted_ips = ['127.0.0.1', '::1']

class ProcessAuthMiddleware:
    """
    Generic middleware for process-based authentication
    
    Can be integrated with any web framework or server.
    """
    
    def __init__(self, config: WebAuthConfig = None):
        self.config = config or WebAuthConfig()
        self.auth_engine = ProcessAuthEngine(self.config.security_level)
        self.rate_limiter = {}
        self.attempt_log = []
        
        logger.info("ProcessAuthMiddleware initialized")
    
    def get_client_pid(self, request_info: Dict[str, Any]) -> Optional[int]:
        """
        Extract client PID from request information
        
        This is the key method - we need to get the PID of the
        process making the request. This varies by server type.
        """
        # Method 1: From custom header (if client sets it)
        pid_header = request_info.get('headers', {}).get('X-Client-PID')
        if pid_header:
            try:
                return int(pid_header)
            except ValueError:
                pass
        
        # Method 2: From process information (for local requests)
        client_ip = request_info.get('client_ip', '')
        if client_ip in self.config.trusted_ips:
            # For localhost requests, try to find the process
            return self._find_client_process(request_info)
        
        # Method 3: From connection information
        return self._extract_pid_from_connection(request_info)
    
    def _find_client_process(self, request_info: Dict[str, Any]) -> Optional[int]:
        """Find the client process for localhost requests"""
        try:
            # Get current connections
            connections = psutil.net_connections(kind='inet')
            client_ip = request_info.get('client_ip', '')
            client_port = request_info.get('client_port', 0)
            
            for conn in connections:
                if (conn.laddr.ip == client_ip and 
                    conn.laddr.port == client_port and 
                    conn.pid):
                    return conn.pid
        except Exception as e:
            logger.debug(f"Could not find client process: {e}")
        
        return None
    
    def _extract_pid_from_connection(self, request_info: Dict[str, Any]) -> Optional[int]:
        """Extract PID from connection information"""
        # This is server-specific and would need to be implemented
        # based on the web server being used
        return None
    
    def check_rate_limit(self, client_ip: str) -> bool:
        """Check if client is rate limited"""
        now = time.time()
        window_start = now - self.config.rate_limit_window
        
        # Clean old entries
        self.rate_limiter[client_ip] = [
            attempt for attempt in self.rate_limiter.get(client_ip, [])
            if attempt > window_start
        ]
        
        # Check if over limit
        attempts = len(self.rate_limiter.get(client_ip, []))
        if attempts >= self.config.max_attempts:
            return False
        
        # Add current attempt
        if client_ip not in self.rate_limiter:
            self.rate_limiter[client_ip] = []
        self.rate_limiter[client_ip].append(now)
        
        return True
    
    def authenticate_request(self, request_info: Dict[str, Any]) -> AuthResult:
        """
        Authenticate a web request using process-based authentication
        
        Args:
            request_info: Dictionary containing request information
                - client_ip: Client IP address
                - client_port: Client port
                - headers: Request headers
                - method: HTTP method
                - path: Request path
                - query: Query parameters
        
        Returns:
            AuthResult: Authentication result
        """
        client_ip = request_info.get('client_ip', '')
        client_port = request_info.get('client_port', 0)
        
        # Check rate limiting
        if not self.check_rate_limit(client_ip):
            return AuthResult(
                success=False,
                method=AuthMethod.COMBINED,
                confidence=0.0,
                details={'error': 'Rate limited'},
                timestamp=time.time(),
                server_pid=self.auth_engine.server_pid,
                client_pid=0
            )
        
        # Get client PID
        client_pid = self.get_client_pid(request_info)
        if not client_pid:
            return AuthResult(
                success=False,
                method=AuthMethod.COMBINED,
                confidence=0.0,
                details={'error': 'Could not determine client PID'},
                timestamp=time.time(),
                server_pid=self.auth_engine.server_pid,
                client_pid=0
            )
        
        # Perform authentication
        auth_method = self.config.allowed_methods[0] if self.config.allowed_methods else AuthMethod.COMBINED
        result = self.auth_engine.authenticate(client_pid, auth_method)
        
        # Log attempt
        if self.config.enable_logging:
            self._log_auth_attempt(request_info, result)
        
        return result
    
    def _log_auth_attempt(self, request_info: Dict[str, Any], result: AuthResult):
        """Log authentication attempt"""
        log_entry = {
            'timestamp': result.timestamp,
            'client_ip': request_info.get('client_ip', ''),
            'client_port': request_info.get('client_port', 0),
            'method': request_info.get('method', ''),
            'path': request_info.get('path', ''),
            'client_pid': result.client_pid,
            'success': result.success,
            'confidence': result.confidence,
            'details': result.details
        }
        
        logger.info(f"Web auth attempt: {json.dumps(log_entry)}")
        self.attempt_log.append(log_entry)
    
    def is_authenticated(self, request_info: Dict[str, Any]) -> bool:
        """Simple authentication check"""
        result = self.authenticate_request(request_info)
        return result.success
    
    def get_auth_result(self, request_info: Dict[str, Any]) -> AuthResult:
        """Get detailed authentication result"""
        return self.authenticate_request(request_info)

class ProcessAuthHTTPServer(HTTPServer):
    """HTTP Server with process-based authentication"""
    
    def __init__(self, server_address, RequestHandlerClass, auth_config: WebAuthConfig = None):
        super().__init__(server_address, RequestHandlerClass)
        self.auth_middleware = ProcessAuthMiddleware(auth_config)
        logger.info(f"ProcessAuthHTTPServer started on {server_address}")

class ProcessAuthRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler with process-based authentication"""
    
    def __init__(self, *args, **kwargs):
        self.auth_middleware = None
        super().__init__(*args, **kwargs)
    
    def set_auth_middleware(self, middleware: ProcessAuthMiddleware):
        """Set authentication middleware"""
        self.auth_middleware = middleware
    
    def do_GET(self):
        """Handle GET requests with authentication"""
        if not self._authenticate_request():
            return
        
        # Process authenticated request
        self._handle_authenticated_request()
    
    def do_POST(self):
        """Handle POST requests with authentication"""
        if not self._authenticate_request():
            return
        
        # Process authenticated request
        self._handle_authenticated_request()
    
    def _authenticate_request(self) -> bool:
        """Authenticate the request"""
        if not self.auth_middleware:
            # No authentication configured
            return True
        
        # Extract request information
        request_info = {
            'client_ip': self.client_address[0],
            'client_port': self.client_address[1],
            'headers': dict(self.headers),
            'method': self.command,
            'path': self.path,
            'query': parse_qs(urlparse(self.path).query)
        }
        
        # Perform authentication
        result = self.auth_middleware.authenticate_request(request_info)
        
        if not result.success:
            self._send_auth_error(result)
            return False
        
        return True
    
    def _send_auth_error(self, result: AuthResult):
        """Send authentication error response"""
        self.send_response(403)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        error_response = {
            'error': 'Authentication failed',
            'details': result.details,
            'confidence': result.confidence,
            'timestamp': result.timestamp
        }
        
        self.wfile.write(json.dumps(error_response).encode())
    
    def _handle_authenticated_request(self):
        """Handle authenticated request"""
        # This is where you'd implement your actual request handling
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        response = {
            'message': 'Authenticated request processed',
            'timestamp': time.time(),
            'path': self.path,
            'method': self.command
        }
        
        self.wfile.write(json.dumps(response).encode())

def create_auth_server(host: str = 'localhost', port: int = 8080, 
                      config: WebAuthConfig = None) -> ProcessAuthHTTPServer:
    """Create a process-authenticated HTTP server"""
    
    class AuthHandler(ProcessAuthRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.set_auth_middleware(ProcessAuthMiddleware(config))
    
    server = ProcessAuthHTTPServer((host, port), AuthHandler, config)
    return server

def run_auth_server(host: str = 'localhost', port: int = 8080, 
                   config: WebAuthConfig = None):
    """Run a process-authenticated HTTP server"""
    
    server = create_auth_server(host, port, config)
    logger.info(f"Starting process-authenticated server on {host}:{port}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        server.shutdown()

# Flask integration example
try:
    from flask import Flask, request, jsonify, abort
    from functools import wraps
    
    def create_flask_app_with_auth(config: WebAuthConfig = None) -> Flask:
        """Create Flask app with process-based authentication"""
        
        app = Flask(__name__)
        auth_middleware = ProcessAuthMiddleware(config)
        
        def require_auth(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                # Extract request information
                request_info = {
                    'client_ip': request.remote_addr,
                    'client_port': request.environ.get('REMOTE_PORT', 0),
                    'headers': dict(request.headers),
                    'method': request.method,
                    'path': request.path,
                    'query': request.args
                }
                
                # Authenticate request
                result = auth_middleware.authenticate_request(request_info)
                
                if not result.success:
                    abort(403, description=f"Authentication failed: {result.details}")
                
                return f(*args, **kwargs)
            return decorated_function
        
        @app.route('/')
        @require_auth
        def index():
            return jsonify({'message': 'Authenticated access granted'})
        
        @app.route('/api/status')
        @require_auth
        def status():
            return jsonify(auth_middleware.auth_engine.get_server_info())
        
        return app
    
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

# Django integration example
try:
    from django.http import JsonResponse
    from django.views.decorators.csrf import csrf_exempt
    from django.conf import settings
    
    class ProcessAuthMiddleware:
        """Django middleware for process-based authentication"""
        
        def __init__(self, get_response):
            self.get_response = get_response
            self.auth_middleware = ProcessAuthMiddleware()
        
        def __call__(self, request):
            # Extract request information
            request_info = {
                'client_ip': request.META.get('REMOTE_ADDR', ''),
                'client_port': request.META.get('REMOTE_PORT', 0),
                'headers': dict(request.META),
                'method': request.method,
                'path': request.path,
                'query': request.GET
            }
            
            # Authenticate request
            result = self.auth_middleware.authenticate_request(request_info)
            
            if not result.success:
                return JsonResponse({
                    'error': 'Authentication failed',
                    'details': result.details
                }, status=403)
            
            response = self.get_response(request)
            return response
    
    DJANGO_AVAILABLE = True
except ImportError:
    DJANGO_AVAILABLE = False

# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create configuration
    config = WebAuthConfig(
        security_level=SecurityLevel.MEDIUM,
        allowed_methods=[AuthMethod.COMBINED],
        enable_logging=True
    )
    
    # Run server
    run_auth_server('localhost', 8080, config)
