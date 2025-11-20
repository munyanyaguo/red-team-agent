"""
Firewall Bypass Testing Module

IMPORTANT: This tool should only be used for:
- Authorized penetration testing engagements
- Network security assessments with proper authorization
- Testing firewall configurations you own or have permission to test
- Security research in isolated environments

Unauthorized port scanning and network probing is illegal and unethical.
"""

import logging
import socket
import struct
import time
from typing import Dict, Any, List, Optional, Tuple
import select

logger = logging.getLogger(__name__)


class FirewallBypassTester:
    """
    Tests various firewall bypass techniques for security assessments.

    IMPORTANT: Only use for authorized security testing.
    """

    def __init__(self):
        self.default_timeout = 5
        self.max_payload_size = 4096

    def test_tcp_connection(self, target_ip: str, target_port: int,
                           payload: bytes = None, timeout: int = None) -> Dict[str, Any]:
        """
        Test basic TCP connection to target.

        Args:
            target_ip: Target IP address
            target_port: Target port number
            payload: Optional payload to send
            timeout: Connection timeout in seconds

        Returns:
            Dictionary with test results
        """
        logger.warning(f"Testing TCP connection: {target_ip}:{target_port}")

        timeout = timeout or self.default_timeout
        payload = payload or b'Hello, world'

        try:
            # Create TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            # Attempt connection
            start_time = time.time()
            sock.connect((target_ip, target_port))
            connect_time = time.time() - start_time

            logger.info(f"TCP connection successful: {target_ip}:{target_port}")

            # Send payload
            sock.sendall(payload)

            # Try to receive response
            try:
                response = sock.recv(self.max_payload_size)
                response_text = response.decode('utf-8', errors='ignore')
            except socket.timeout:
                response_text = ""
            except Exception as e:
                response_text = f"Error receiving: {str(e)}"

            sock.close()

            return {
                "success": True,
                "technique": "tcp_connection",
                "target_ip": target_ip,
                "target_port": target_port,
                "port_open": True,
                "connect_time": connect_time,
                "payload_sent": payload.decode('utf-8', errors='ignore'),
                "response": response_text,
                "bypassed": True
            }

        except socket.timeout:
            logger.warning(f"TCP connection timeout: {target_ip}:{target_port}")
            return {
                "success": False,
                "technique": "tcp_connection",
                "target_ip": target_ip,
                "target_port": target_port,
                "port_open": False,
                "error": "Connection timeout",
                "bypassed": False
            }

        except ConnectionRefusedError:
            logger.warning(f"TCP connection refused: {target_ip}:{target_port}")
            return {
                "success": False,
                "technique": "tcp_connection",
                "target_ip": target_ip,
                "target_port": target_port,
                "port_open": False,
                "error": "Connection refused",
                "bypassed": False
            }

        except Exception as e:
            logger.error(f"TCP connection error: {e}")
            return {
                "success": False,
                "technique": "tcp_connection",
                "target_ip": target_ip,
                "target_port": target_port,
                "error": str(e),
                "bypassed": False
            }
        finally:
            try:
                sock.close()
            except:
                pass

    def test_udp_connection(self, target_ip: str, target_port: int,
                           payload: bytes = None, timeout: int = None) -> Dict[str, Any]:
        """
        Test UDP connection to target.

        Args:
            target_ip: Target IP address
            target_port: Target port number
            payload: Optional payload to send
            timeout: Connection timeout in seconds

        Returns:
            Dictionary with test results
        """
        logger.warning(f"Testing UDP connection: {target_ip}:{target_port}")

        timeout = timeout or self.default_timeout
        payload = payload or b'Hello, world'

        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)

            # Send payload
            sock.sendto(payload, (target_ip, target_port))

            logger.info(f"UDP packet sent: {target_ip}:{target_port}")

            # Try to receive response
            try:
                response, addr = sock.recvfrom(self.max_payload_size)
                response_text = response.decode('utf-8', errors='ignore')
                port_open = True
            except socket.timeout:
                response_text = "No response (UDP is connectionless)"
                port_open = None  # Can't determine with UDP
            except Exception as e:
                response_text = f"Error receiving: {str(e)}"
                port_open = None

            sock.close()

            return {
                "success": True,
                "technique": "udp_connection",
                "target_ip": target_ip,
                "target_port": target_port,
                "port_open": port_open,
                "payload_sent": payload.decode('utf-8', errors='ignore'),
                "response": response_text,
                "bypassed": True
            }

        except Exception as e:
            logger.error(f"UDP connection error: {e}")
            return {
                "success": False,
                "technique": "udp_connection",
                "target_ip": target_ip,
                "target_port": target_port,
                "error": str(e),
                "bypassed": False
            }
        finally:
            try:
                sock.close()
            except:
                pass

    def port_scan(self, target_ip: str, ports: List[int],
                 timeout: int = None) -> Dict[str, Any]:
        """
        Scan multiple ports on target.

        Args:
            target_ip: Target IP address
            ports: List of ports to scan
            timeout: Connection timeout per port

        Returns:
            Dictionary with scan results
        """
        logger.warning(f"Port scanning: {target_ip}, Ports: {len(ports)}")

        timeout = timeout or 2  # Shorter timeout for scanning
        open_ports = []
        closed_ports = []
        filtered_ports = []

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)

                result = sock.connect_ex((target_ip, port))

                if result == 0:
                    # Port is open
                    open_ports.append(port)
                    logger.info(f"Port {port} is OPEN")
                else:
                    # Port is closed
                    closed_ports.append(port)

                sock.close()

            except socket.timeout:
                # Port is filtered (no response)
                filtered_ports.append(port)
            except Exception as e:
                logger.error(f"Error scanning port {port}: {e}")
                filtered_ports.append(port)

        return {
            "success": True,
            "technique": "port_scan",
            "target_ip": target_ip,
            "total_ports_scanned": len(ports),
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "filtered_ports": filtered_ports,
            "open_count": len(open_ports),
            "bypassed": len(open_ports) > 0
        }

    def test_common_ports(self, target_ip: str) -> Dict[str, Any]:
        """
        Scan common ports on target.

        Args:
            target_ip: Target IP address

        Returns:
            Dictionary with scan results
        """
        logger.warning(f"Scanning common ports: {target_ip}")

        # Common ports
        common_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            143,   # IMAP
            443,   # HTTPS
            445,   # SMB
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            5900,  # VNC
            8080,  # HTTP Alt
            8443,  # HTTPS Alt
        ]

        return self.port_scan(target_ip, common_ports, timeout=2)

    def test_fragmented_packets(self, target_ip: str, target_port: int) -> Dict[str, Any]:
        """
        Test firewall bypass using fragmented packets.
        Note: This requires raw socket access (root/admin privileges).

        Args:
            target_ip: Target IP address
            target_port: Target port number

        Returns:
            Dictionary with test results
        """
        logger.warning(f"Testing fragmented packets: {target_ip}:{target_port}")

        try:
            # This is a simplified version - full implementation would require scapy
            # or raw socket programming which requires root privileges

            # For now, test if we can connect normally
            result = self.test_tcp_connection(target_ip, target_port)

            return {
                "success": True,
                "technique": "fragmented_packets",
                "target_ip": target_ip,
                "target_port": target_port,
                "note": "Full packet fragmentation requires root privileges and raw sockets",
                "basic_connection": result.get("success", False),
                "bypassed": result.get("success", False)
            }

        except Exception as e:
            logger.error(f"Fragmented packet test error: {e}")
            return {
                "success": False,
                "technique": "fragmented_packets",
                "error": str(e),
                "bypassed": False
            }

    def test_source_port_manipulation(self, target_ip: str, target_port: int,
                                     source_ports: List[int] = None) -> Dict[str, Any]:
        """
        Test firewall bypass by manipulating source port.
        Some firewalls trust traffic from specific ports (53, 80, 443, etc.).

        Args:
            target_ip: Target IP address
            target_port: Target port number
            source_ports: List of source ports to try

        Returns:
            Dictionary with test results
        """
        logger.warning(f"Testing source port manipulation: {target_ip}:{target_port}")

        source_ports = source_ports or [53, 80, 443, 8080]
        results = []

        for src_port in source_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.default_timeout)

                # Bind to specific source port
                try:
                    sock.bind(('', src_port))
                    bind_success = True
                except PermissionError:
                    # Ports below 1024 require root/admin
                    bind_success = False
                    results.append({
                        "source_port": src_port,
                        "error": "Permission denied (requires root for ports < 1024)",
                        "bypassed": False
                    })
                    sock.close()
                    continue

                # Attempt connection
                result = sock.connect_ex((target_ip, target_port))

                if result == 0:
                    results.append({
                        "source_port": src_port,
                        "connected": True,
                        "bypassed": True
                    })
                    logger.info(f"Connection successful from source port {src_port}")
                else:
                    results.append({
                        "source_port": src_port,
                        "connected": False,
                        "bypassed": False
                    })

                sock.close()

            except Exception as e:
                logger.error(f"Error with source port {src_port}: {e}")
                results.append({
                    "source_port": src_port,
                    "error": str(e),
                    "bypassed": False
                })

        return {
            "success": True,
            "technique": "source_port_manipulation",
            "target_ip": target_ip,
            "target_port": target_port,
            "source_ports_tested": results,
            "bypassed": any(r.get("bypassed", False) for r in results)
        }

    def test_protocol_switching(self, target_ip: str, protocols: List[str] = None) -> Dict[str, Any]:
        """
        Test firewall bypass by switching protocols.

        Args:
            target_ip: Target IP address
            protocols: List of protocols to test

        Returns:
            Dictionary with test results
        """
        logger.warning(f"Testing protocol switching: {target_ip}")

        protocols = protocols or ['tcp', 'udp']
        results = []

        # Test common protocol/port combinations
        test_cases = [
            ('tcp', 80),    # HTTP
            ('tcp', 443),   # HTTPS
            ('tcp', 22),    # SSH
            ('tcp', 21),    # FTP
            ('udp', 53),    # DNS
            ('udp', 161),   # SNMP
        ]

        for protocol, port in test_cases:
            if protocol == 'tcp':
                result = self.test_tcp_connection(target_ip, port, timeout=2)
            else:
                result = self.test_udp_connection(target_ip, port, timeout=2)

            results.append({
                "protocol": protocol,
                "port": port,
                "success": result.get("success", False),
                "bypassed": result.get("bypassed", False)
            })

        return {
            "success": True,
            "technique": "protocol_switching",
            "target_ip": target_ip,
            "protocols_tested": results,
            "bypassed": any(r.get("bypassed", False) for r in results)
        }

    def test_all_techniques(self, target_ip: str, target_port: int) -> Dict[str, Any]:
        """
        Test all firewall bypass techniques.

        Args:
            target_ip: Target IP address
            target_port: Target port number

        Returns:
            Dictionary with results from all techniques
        """
        logger.warning(f"Testing all firewall bypass techniques: {target_ip}:{target_port}")

        results = {
            "target_ip": target_ip,
            "target_port": target_port,
            "techniques": []
        }

        # Test TCP connection
        tcp_result = self.test_tcp_connection(target_ip, target_port)
        results["techniques"].append(tcp_result)

        # Test UDP connection
        udp_result = self.test_udp_connection(target_ip, target_port)
        results["techniques"].append(udp_result)

        # Test source port manipulation
        src_port_result = self.test_source_port_manipulation(target_ip, target_port)
        results["techniques"].append(src_port_result)

        # Test fragmented packets
        frag_result = self.test_fragmented_packets(target_ip, target_port)
        results["techniques"].append(frag_result)

        # Determine if any technique succeeded
        results["any_bypassed"] = any(
            t.get("bypassed", False) for t in results["techniques"]
        )

        results["successful_techniques"] = sum(
            1 for t in results["techniques"] if t.get("bypassed", False)
        )

        results["total_techniques"] = len(results["techniques"])

        return results

    def check_port_status(self, target_ip: str, target_port: int,
                         timeout: int = None) -> str:
        """
        Check if a port is open, closed, or filtered.

        Args:
            target_ip: Target IP address
            target_port: Target port number
            timeout: Connection timeout

        Returns:
            String: "open", "closed", or "filtered"
        """
        timeout = timeout or self.default_timeout

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            result = sock.connect_ex((target_ip, target_port))
            sock.close()

            if result == 0:
                return "open"
            else:
                return "closed"

        except socket.timeout:
            return "filtered"
        except Exception:
            return "filtered"
