"""
Firewall Bypass Testing Routes

CRITICAL WARNING: These endpoints provide network probing and firewall bypass testing.
Use ONLY for authorized security testing with explicit written permission.

Unauthorized port scanning and network probing is illegal.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging

from .modules.firewall_bypass_simple import FirewallBypassTester

logger = logging.getLogger(__name__)

firewall_bypass_bp = Blueprint('firewall_bypass', __name__)


@firewall_bypass_bp.route('/firewall_bypass', methods=['POST'])
@jwt_required()
def test_firewall_bypass_basic():
    """
    Test basic firewall bypass using TCP connection (legacy endpoint).

    Request body:
    {
        "target_ip": "192.168.1.1",
        "target_port": 80
    }

    Returns:
        JSON response with test results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_ip = data.get('target_ip')
        target_port = data.get('target_port')

        if not target_ip or not target_port:
            return jsonify({
                "status": "error",
                "message": "Missing required fields: target_ip, target_port"
            }), 400

        # Validate port
        try:
            target_port = int(target_port)
            if not (1 <= target_port <= 65535):
                return jsonify({
                    "status": "error",
                    "message": "Port must be between 1 and 65535"
                }), 400
        except ValueError:
            return jsonify({
                "status": "error",
                "message": "Invalid port number"
            }), 400

        logger.warning(f"⚠️  FIREWALL BYPASS TEST by user: {user_id}")
        logger.warning(f"Target: {target_ip}:{target_port}")

        tester = FirewallBypassTester()
        result = tester.test_tcp_connection(target_ip, target_port)

        # Format response for backward compatibility
        if result.get("success"):
            return jsonify({
                "status": "success",
                "response": result.get("response", "")
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": result.get("error", "Connection failed")
            }), 400

    except Exception as e:
        logger.error(f"Error in firewall bypass endpoint: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@firewall_bypass_bp.route('/firewall_bypass/tcp', methods=['POST'])
@jwt_required()
def test_tcp_connection():
    """
    Test TCP connection to target.

    Request body:
    {
        "target_ip": "192.168.1.1",
        "target_port": 80,
        "payload": "GET / HTTP/1.1\r\n\r\n",  // Optional
        "timeout": 5  // Optional
    }

    Returns:
        JSON response with test results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_ip = data.get('target_ip')
        target_port = data.get('target_port')
        payload = data.get('payload')
        timeout = data.get('timeout', 5)

        if not target_ip or not target_port:
            return jsonify({
                "status": "error",
                "message": "Missing required fields: target_ip, target_port"
            }), 400

        # Validate port
        try:
            target_port = int(target_port)
            if not (1 <= target_port <= 65535):
                return jsonify({
                    "status": "error",
                    "message": "Port must be between 1 and 65535"
                }), 400
        except ValueError:
            return jsonify({
                "status": "error",
                "message": "Invalid port number"
            }), 400

        logger.warning(f"TCP connection test by user: {user_id}, target: {target_ip}:{target_port}")

        # Convert payload to bytes if provided
        payload_bytes = payload.encode() if payload else None

        tester = FirewallBypassTester()
        result = tester.test_tcp_connection(target_ip, target_port, payload_bytes, timeout)

        return jsonify({
            "status": "success",
            **result
        }), 200

    except Exception as e:
        logger.error(f"Error in TCP connection test: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@firewall_bypass_bp.route('/firewall_bypass/udp', methods=['POST'])
@jwt_required()
def test_udp_connection():
    """
    Test UDP connection to target.

    Request body:
    {
        "target_ip": "192.168.1.1",
        "target_port": 53,
        "payload": "test",  // Optional
        "timeout": 5  // Optional
    }

    Returns:
        JSON response with test results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_ip = data.get('target_ip')
        target_port = data.get('target_port')
        payload = data.get('payload')
        timeout = data.get('timeout', 5)

        if not target_ip or not target_port:
            return jsonify({
                "status": "error",
                "message": "Missing required fields: target_ip, target_port"
            }), 400

        # Validate port
        try:
            target_port = int(target_port)
            if not (1 <= target_port <= 65535):
                return jsonify({
                    "status": "error",
                    "message": "Port must be between 1 and 65535"
                }), 400
        except ValueError:
            return jsonify({
                "status": "error",
                "message": "Invalid port number"
            }), 400

        logger.warning(f"UDP connection test by user: {user_id}, target: {target_ip}:{target_port}")

        # Convert payload to bytes if provided
        payload_bytes = payload.encode() if payload else None

        tester = FirewallBypassTester()
        result = tester.test_udp_connection(target_ip, target_port, payload_bytes, timeout)

        return jsonify({
            "status": "success",
            **result
        }), 200

    except Exception as e:
        logger.error(f"Error in UDP connection test: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@firewall_bypass_bp.route('/firewall_bypass/port_scan', methods=['POST'])
@jwt_required()
def port_scan():
    """
    Scan multiple ports on target.

    Request body:
    {
        "target_ip": "192.168.1.1",
        "ports": [80, 443, 22, 21],  // List of ports to scan
        "timeout": 2  // Optional
    }

    Returns:
        JSON response with scan results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_ip = data.get('target_ip')
        ports = data.get('ports', [])
        timeout = data.get('timeout', 2)

        if not target_ip:
            return jsonify({
                "status": "error",
                "message": "Missing required field: target_ip"
            }), 400

        if not ports or not isinstance(ports, list):
            return jsonify({
                "status": "error",
                "message": "Missing or invalid 'ports' array"
            }), 400

        # Limit number of ports
        if len(ports) > 100:
            return jsonify({
                "status": "error",
                "message": "Maximum 100 ports allowed per scan"
            }), 400

        # Validate all ports
        try:
            ports = [int(p) for p in ports]
            if not all(1 <= p <= 65535 for p in ports):
                return jsonify({
                    "status": "error",
                    "message": "All ports must be between 1 and 65535"
                }), 400
        except ValueError:
            return jsonify({
                "status": "error",
                "message": "Invalid port number in list"
            }), 400

        logger.warning(f"⚠️  PORT SCAN by user: {user_id}, target: {target_ip}, ports: {len(ports)}")

        tester = FirewallBypassTester()
        result = tester.port_scan(target_ip, ports, timeout)

        return jsonify({
            "status": "success",
            **result
        }), 200

    except Exception as e:
        logger.error(f"Error in port scan: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@firewall_bypass_bp.route('/firewall_bypass/common_ports', methods=['POST'])
@jwt_required()
def scan_common_ports():
    """
    Scan common ports on target.

    Request body:
    {
        "target_ip": "192.168.1.1"
    }

    Returns:
        JSON response with scan results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_ip = data.get('target_ip')

        if not target_ip:
            return jsonify({
                "status": "error",
                "message": "Missing required field: target_ip"
            }), 400

        logger.warning(f"⚠️  COMMON PORTS SCAN by user: {user_id}, target: {target_ip}")

        tester = FirewallBypassTester()
        result = tester.test_common_ports(target_ip)

        return jsonify({
            "status": "success",
            **result
        }), 200

    except Exception as e:
        logger.error(f"Error in common ports scan: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@firewall_bypass_bp.route('/firewall_bypass/techniques/source_port', methods=['POST'])
@jwt_required()
def test_source_port_manipulation():
    """
    Test firewall bypass using source port manipulation.

    Request body:
    {
        "target_ip": "192.168.1.1",
        "target_port": 80,
        "source_ports": [53, 80, 443]  // Optional
    }

    Returns:
        JSON response with test results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_ip = data.get('target_ip')
        target_port = data.get('target_port')
        source_ports = data.get('source_ports')

        if not target_ip or not target_port:
            return jsonify({
                "status": "error",
                "message": "Missing required fields: target_ip, target_port"
            }), 400

        # Validate port
        try:
            target_port = int(target_port)
            if not (1 <= target_port <= 65535):
                return jsonify({
                    "status": "error",
                    "message": "Port must be between 1 and 65535"
                }), 400
        except ValueError:
            return jsonify({
                "status": "error",
                "message": "Invalid port number"
            }), 400

        logger.warning(f"Source port manipulation test by user: {user_id}, target: {target_ip}:{target_port}")

        tester = FirewallBypassTester()
        result = tester.test_source_port_manipulation(target_ip, target_port, source_ports)

        return jsonify({
            "status": "success",
            **result
        }), 200

    except Exception as e:
        logger.error(f"Error in source port manipulation test: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@firewall_bypass_bp.route('/firewall_bypass/techniques/protocol', methods=['POST'])
@jwt_required()
def test_protocol_switching():
    """
    Test firewall bypass by switching protocols.

    Request body:
    {
        "target_ip": "192.168.1.1",
        "protocols": ["tcp", "udp"]  // Optional
    }

    Returns:
        JSON response with test results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_ip = data.get('target_ip')
        protocols = data.get('protocols')

        if not target_ip:
            return jsonify({
                "status": "error",
                "message": "Missing required field: target_ip"
            }), 400

        logger.warning(f"Protocol switching test by user: {user_id}, target: {target_ip}")

        tester = FirewallBypassTester()
        result = tester.test_protocol_switching(target_ip, protocols)

        return jsonify({
            "status": "success",
            **result
        }), 200

    except Exception as e:
        logger.error(f"Error in protocol switching test: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@firewall_bypass_bp.route('/firewall_bypass/techniques/all', methods=['POST'])
@jwt_required()
def test_all_techniques():
    """
    Test all firewall bypass techniques.

    Request body:
    {
        "target_ip": "192.168.1.1",
        "target_port": 80
    }

    Returns:
        JSON response with results from all techniques
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_ip = data.get('target_ip')
        target_port = data.get('target_port')

        if not target_ip or not target_port:
            return jsonify({
                "status": "error",
                "message": "Missing required fields: target_ip, target_port"
            }), 400

        # Validate port
        try:
            target_port = int(target_port)
            if not (1 <= target_port <= 65535):
                return jsonify({
                    "status": "error",
                    "message": "Port must be between 1 and 65535"
                }), 400
        except ValueError:
            return jsonify({
                "status": "error",
                "message": "Invalid port number"
            }), 400

        logger.warning(f"⚠️  ALL FIREWALL BYPASS TECHNIQUES by user: {user_id}, target: {target_ip}:{target_port}")

        tester = FirewallBypassTester()
        result = tester.test_all_techniques(target_ip, target_port)

        return jsonify({
            "status": "success",
            **result
        }), 200

    except Exception as e:
        logger.error(f"Error testing all techniques: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@firewall_bypass_bp.route('/firewall_bypass/check_port', methods=['POST'])
@jwt_required()
def check_port_status():
    """
    Check if a specific port is open, closed, or filtered.

    Request body:
    {
        "target_ip": "192.168.1.1",
        "target_port": 80,
        "timeout": 5  // Optional
    }

    Returns:
        JSON response with port status
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_ip = data.get('target_ip')
        target_port = data.get('target_port')
        timeout = data.get('timeout', 5)

        if not target_ip or not target_port:
            return jsonify({
                "status": "error",
                "message": "Missing required fields: target_ip, target_port"
            }), 400

        # Validate port
        try:
            target_port = int(target_port)
            if not (1 <= target_port <= 65535):
                return jsonify({
                    "status": "error",
                    "message": "Port must be between 1 and 65535"
                }), 400
        except ValueError:
            return jsonify({
                "status": "error",
                "message": "Invalid port number"
            }), 400

        logger.info(f"Port status check by user: {user_id}, target: {target_ip}:{target_port}")

        tester = FirewallBypassTester()
        port_status = tester.check_port_status(target_ip, target_port, timeout)

        return jsonify({
            "status": "success",
            "target_ip": target_ip,
            "target_port": target_port,
            "port_status": port_status
        }), 200

    except Exception as e:
        logger.error(f"Error checking port status: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500
