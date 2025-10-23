#!/usr/bin/env python3
"""
Red Team Agent - Main Application Entry Point
"""

import os
from app import create_app

# Get configuration from environment
config_name = os.getenv('FLASK_ENV', 'development')

# Create Flask application
app = create_app(config_name)

if __name__ == '__main__':
    # Run the application
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', 5000))
    debug = config_name == 'development'
    
    print(f"""
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║              RED TEAM AGENT - STARTING                   ║
    ║                                                          ║
    ║  Environment: {config_name:<40}  ║
    ║  Host: {host:<49}  ║
    ║  Port: {port:<49}  ║
    ║                                                          ║
    ║  API Documentation:                                      ║
    ║  http://{host}:{port}/                             ║
    ║                                                          ║
    ║  ⚠️  IMPORTANT SECURITY NOTICE                           ║
    ║  Always ensure you have proper authorization before      ║
    ║  conducting security assessments.                        ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    app.run(host=host, port=port, debug=debug)