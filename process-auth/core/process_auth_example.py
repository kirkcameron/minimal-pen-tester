#!/usr/bin/env python3
"""
Process-Based Authentication Example Implementation
================================================

Production-ready example of how to implement process-based authentication
in a real web application.

Author: Process Auth Team
License: MIT
"""

import os
import sys
import json
import time
import logging
from typing import Dict, List, Optional, Any
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import threading

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from process_auth_engine import ProcessAuthEngine, AuthMethod, SecurityLevel, AuthResult
from process_auth_web import ProcessAuthMiddleware, WebAuthConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ProcessAuthExampleHandler(BaseHTTPRequestHandler):
    """Example HTTP handler with process-based authentication"""
    
    def __init__(self, *args, **kwargs):
        self.auth_middleware = None
        super().__init__(*args, **kwargs)
    
    def set_auth_middleware(self, middleware: ProcessAuthMiddleware):
        """Set authentication middleware"""
        self.auth_middleware = middleware
    
    def do_GET(self):
        """Handle GET requests"""
        if not self._authenticate_request():
            return
        
        # Handle authenticated GET request
        if self.path == '/':
            self._handle_home()
        elif self.path == '/status':
            self._handle_status()
        elif self.path == '/api/server-info':
            self._handle_server_info()
        else:
            self._handle_not_found()
    
    def do_POST(self):
        """Handle POST requests"""
        if not self._authenticate_request():
            return
        
        # Handle authenticated POST request
        if self.path == '/api/send-mail':
            self._handle_send_mail()
        elif self.path == '/api/process-data':
            self._handle_process_data()
        else:
            self._handle_not_found()
    
    def _authenticate_request(self) -> bool:
        """Authenticate the request using process-based authentication"""
        if not self.auth_middleware:
            # No authentication configured - allow all requests
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
        
        # Log successful authentication
        logger.info(f"Authenticated request from PID {result.client_pid} with confidence {result.confidence:.2f}")
        return True
    
    def _send_auth_error(self, result: AuthResult):
        """Send authentication error response"""
        self.send_response(403)
        self.send_header('Content-Type', 'application/json')
        self.send_header('X-Auth-Error', 'Process authentication failed')
        self.end_headers()
        
        error_response = {
            'error': 'Authentication failed',
            'message': 'Process-based authentication failed',
            'details': result.details,
            'confidence': result.confidence,
            'timestamp': result.timestamp,
            'server_pid': result.server_pid,
            'client_pid': result.client_pid
        }
        
        self.wfile.write(json.dumps(error_response, indent=2).encode())
    
    def _handle_home(self):
        """Handle home page request"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Process-Based Authentication Example</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .container { max-width: 800px; margin: 0 auto; }
                .success { color: green; }
                .info { background: #f0f0f0; padding: 20px; border-radius: 5px; }
                .form { margin: 20px 0; }
                input, textarea { width: 100%; padding: 10px; margin: 5px 0; }
                button { background: #007cba; color: white; padding: 10px 20px; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Process-Based Authentication Example</h1>
                <p class="success">✅ Successfully authenticated using process-based authentication!</p>
                
                <div class="info">
                    <h3>How it works:</h3>
                    <p>This server uses process-based authentication to verify that requests come from legitimate processes.</p>
                    <p>Only processes with proper system-level relationships to the server can access these endpoints.</p>
                </div>
                
                <div class="form">
                    <h3>Test Mail Sending (Authenticated)</h3>
                    <form id="mailForm">
                        <input type="text" name="name" placeholder="Your Name" required>
                        <input type="email" name="email" placeholder="Your Email" required>
                        <textarea name="message" placeholder="Your Message" rows="4" required></textarea>
                        <button type="submit">Send Mail</button>
                    </form>
                </div>
                
                <div class="form">
                    <h3>Test Data Processing (Authenticated)</h3>
                    <form id="dataForm">
                        <input type="text" name="data" placeholder="Data to process" required>
                        <button type="submit">Process Data</button>
                    </form>
                </div>
                
                <p><a href="/status">View Server Status</a> | <a href="/api/server-info">View Server Info</a></p>
            </div>
            
            <script>
                document.getElementById('mailForm').addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const formData = new FormData(e.target);
                    const response = await fetch('/api/send-mail', {
                        method: 'POST',
                        body: formData
                    });
                    const result = await response.json();
                    alert(JSON.stringify(result, null, 2));
                });
                
                document.getElementById('dataForm').addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const formData = new FormData(e.target);
                    const response = await fetch('/api/process-data', {
                        method: 'POST',
                        body: formData
                    });
                    const result = await response.json();
                    alert(JSON.stringify(result, null, 2));
                });
            </script>
        </body>
        </html>
        """
        
        self.wfile.write(html_content.encode())
    
    def _handle_status(self):
        """Handle status request"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        status = {
            'status': 'online',
            'timestamp': time.time(),
            'process_auth': 'enabled',
            'server_pid': os.getpid(),
            'uptime': time.time() - self.server.start_time if hasattr(self, 'server') else 0
        }
        
        self.wfile.write(json.dumps(status, indent=2).encode())
    
    def _handle_server_info(self):
        """Handle server info request"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        if self.auth_middleware:
            server_info = self.auth_middleware.auth_engine.get_server_info()
        else:
            server_info = {'error': 'Authentication middleware not configured'}
        
        self.wfile.write(json.dumps(server_info, indent=2).encode())
    
    def _handle_send_mail(self):
        """Handle mail sending request"""
        # Parse form data
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        # Simple form parsing
        form_data = {}
        for pair in post_data.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                form_data[key] = value
        
        # Simulate mail sending
        mail_result = {
            'success': True,
            'message': 'Mail sent successfully',
            'details': {
                'name': form_data.get('name', ''),
                'email': form_data.get('email', ''),
                'message': form_data.get('message', ''),
                'timestamp': time.time(),
                'process_auth': 'verified'
            }
        }
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(mail_result, indent=2).encode())
    
    def _handle_process_data(self):
        """Handle data processing request"""
        # Parse form data
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        # Simple form parsing
        form_data = {}
        for pair in post_data.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                form_data[key] = value
        
        # Simulate data processing
        data = form_data.get('data', '')
        processed_data = {
            'original': data,
            'processed': data.upper(),
            'length': len(data),
            'timestamp': time.time(),
            'process_auth': 'verified'
        }
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(processed_data, indent=2).encode())
    
    def _handle_not_found(self):
        """Handle 404 requests"""
        self.send_response(404)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        error_response = {
            'error': 'Not found',
            'message': 'The requested resource was not found',
            'path': self.path,
            'timestamp': time.time()
        }
        
        self.wfile.write(json.dumps(error_response, indent=2).encode())
    
    def log_message(self, format, *args):
        """Override log message to include process authentication info"""
        if self.auth_middleware:
            logger.info(f"Request: {format % args} (Auth: Process-based)")
        else:
            logger.info(f"Request: {format % args} (Auth: None)")

class ProcessAuthExampleServer(HTTPServer):
    """Example server with process-based authentication"""
    
    def __init__(self, server_address, RequestHandlerClass, auth_config: WebAuthConfig = None):
        super().__init__(server_address, RequestHandlerClass)
        self.auth_middleware = ProcessAuthMiddleware(auth_config)
        self.start_time = time.time()
        logger.info(f"ProcessAuthExampleServer started on {server_address}")
        logger.info(f"Server PID: {os.getpid()}")
        logger.info(f"Security level: {auth_config.security_level.value if auth_config else 'None'}")

def create_example_server(host: str = 'localhost', port: int = 8080, 
                         security_level: SecurityLevel = SecurityLevel.MEDIUM) -> ProcessAuthExampleServer:
    """Create an example server with process-based authentication"""
    
    class AuthHandler(ProcessAuthExampleHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.set_auth_middleware(ProcessAuthMiddleware(WebAuthConfig(security_level=security_level)))
    
    server = ProcessAuthExampleServer((host, port), AuthHandler, 
                                    WebAuthConfig(security_level=security_level))
    return server

def run_example_server(host: str = 'localhost', port: int = 8080, 
                      security_level: SecurityLevel = SecurityLevel.MEDIUM):
    """Run the example server"""
    
    server = create_example_server(host, port, security_level)
    logger.info(f"Starting process-authenticated example server on {host}:{port}")
    logger.info(f"Security level: {security_level.value}")
    logger.info(f"Access the server at: http://{host}:{port}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        server.shutdown()

# Example usage and testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Process-Based Authentication Example Server')
    parser.add_argument('--host', default='localhost', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind to')
    parser.add_argument('--security-level', choices=['low', 'medium', 'high', 'paranoid'], 
                       default='medium', help='Security level')
    
    args = parser.parse_args()
    
    # Convert security level string to enum
    security_levels = {
        'low': SecurityLevel.LOW,
        'medium': SecurityLevel.MEDIUM,
        'high': SecurityLevel.HIGH,
        'paranoid': SecurityLevel.PARANOID
    }
    
    security_level = security_levels[args.security_level]
    
    # Run server
    run_example_server(args.host, args.port, security_level)
