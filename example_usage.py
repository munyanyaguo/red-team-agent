#!/usr/bin/env python3
"""
Example Usage Script - Red Team Agent
This demonstrates how to use the Red Team Agent programmatically
"""

import requests
import json
import time
from datetime import datetime, timezone # Added timezone import

# Configuration
BASE_URL = "http://localhost:5000/api"
TEST_TARGET = "testphp.vulnweb.com"  # Safe test target

class RedTeamAgentClient:
    """Simple client for interacting with Red Team Agent API"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
    
    def _request(self, method: str, endpoint: str, **kwargs):
        """Make API request"""
        url = f"{self.base_url}{endpoint}"
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response.json()
    
    def create_engagement(self, name: str, client: str, targets: list):
        """Create a new engagement"""
        data = {
            "name": name,
            "client": client,
            "type": "internal",
            "scope": targets
        }
        return self._request("POST", "/engagements", json=data)
    
    def run_full_scan(self, target: str, engagement_id: int):
        """Run full security assessment"""
        data = {
            "target": target,
            "engagement_id": engagement_id
        }
        return self._request("POST", "/scan/full", json=data)
    
    def get_findings(self, engagement_id: int):
        """Get all findings for an engagement"""
        return self._request("GET", f"/findings?engagement_id={engagement_id}")
    
    def generate_report(self, engagement_id: int, report_type: str = "technical"):
        """Generate a report"""
        data = {
            "engagement_id": engagement_id,
            "report_type": report_type
        }
        return self._request("POST", "/reports/generate", json=data)
    
    def get_stats(self):
        """Get overall statistics"""
        return self._request("GET", "/stats")


def print_section(title: str):
    """Print a formatted section header"""
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60 + "\n")


def main():
    """Main example workflow"""
    
    print("""
    ╔══════════════════════════════════════════════════════╗
    ║                                                      ║
    ║         RED TEAM AGENT - EXAMPLE USAGE              ║
    ║                                                      ║
    ║  This script demonstrates a complete workflow       ║
    ║  using a safe test target.                          ║
    ║                                                      ║
    ╚══════════════════════════════════════════════════════╝
    ")
    
    # Initialize client
    client = RedTeamAgentClient(BASE_URL)
    
    try:
        # Step 1: Create Engagement
        print_section("STEP 1: Creating Engagement")
        
        engagement = client.create_engagement(
            name=f"Example Assessment - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}", # Use UTC
            client="Example Corp",
            targets=[TEST_TARGET]
        )
        
        engagement_id = engagement['engagement']['id']
        print(f"✓ Created engagement with ID: {engagement_id}")
        print(f"  Name: {engagement['engagement']['name']}")
        print(f"  Client: {engagement['engagement']['client']}")
        
        # Step 2: Run Full Scan
        print_section("STEP 2: Running Full Security Assessment")
        print(f"Target: {TEST_TARGET}")
        print("This will take a few minutes...")
        print("\nPhases:")
        print("  1. Reconnaissance (gathering information)")
        print("  2. Vulnerability Scanning (finding issues)")
        print("  3. AI Analysis (intelligent assessment)")
        
        scan_result = client.run_full_scan(TEST_TARGET, engagement_id)
        
        print("\n✓ Scan completed!")
        
        # Display reconnaissance results
        if 'recon' in scan_result['results']:
            recon = scan_result['results']['recon']
            print(f"\n  Reconnaissance Summary:")
            print(f"    - Target Type: {recon.get('target_type', 'unknown')}")
            if recon.get('ip_address'):
                print(f"    - IP Address: {recon['ip_address']}")
            if recon.get('port_scan', {}).get('open_ports'):
                print(f"    - Open Ports: {len(recon['port_scan']['open_ports'])}")
            if recon.get('technologies'):
                print(f"    - Technologies Detected: {len(recon['technologies'])}")
        
        # Display vulnerability summary
        if 'vulnerabilities' in scan_result['results']:
            vulns = scan_result['results']['vulnerabilities']
            findings = vulns.get('findings', [])
            print(f"\n  Vulnerability Summary:")
            print(f"    - Total Findings: {len(findings)}")
            
            # Count by severity
            severity_count = {}
            for finding in findings:
                sev = finding.get('severity', 'unknown')
                severity_count[sev] = severity_count.get(sev, 0) + 1
            
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if severity in severity_count:
                    print(f"    - {severity.title()}: {severity_count[severity]}")
        
        # Display AI Analysis
        if 'ai_analysis' in scan_result['results']:
            print(f"\n  AI Analysis:")
            ai = scan_result['results']['ai_analysis']
            
            if 'recon' in ai and 'risk_level' in ai['recon']:
                print(f"    - Risk Level: {ai['recon']['risk_level']}")
            
            if 'vulnerabilities' in ai and 'executive_summary' in ai['vulnerabilities']:
                summary = ai['vulnerabilities']['executive_summary']
                # Print first 200 chars
                print(f"    - Summary: {summary[:200]}...")
        
        # Step 3: Get Detailed Findings
        print_section("STEP 3: Retrieving Detailed Findings")
        
        findings_response = client.get_findings(engagement_id)
        findings = findings_response['findings']
        
        print(f"Total findings: {len(findings)}")
        
        # Show top 5 findings
        if findings:
            print("\nTop Findings:")
            for i, finding in enumerate(findings[:5], 1):
                print(f"\n  {i}. {finding['title']}")
                print(f"     Severity: {finding['severity'].upper()}")
                print(f"     Description: {finding['description'][:100]}...")
        
        # Step 4: Generate Reports
        print_section("STEP 4: Generating Reports")
        
        report_types = ['executive', 'technical', 'remediation']
        
        for report_type in report_types:
            print(f"Generating {report_type} report...")
            report = client.generate_report(engagement_id, report_type)
            
            if report['success']:
                print(f"  ✓ {report_type.title()} report generated")
                print(f"    File: {report['report']['file_path']}")
            
            time.sleep(1)  # Brief pause between reports
        
        # Step 5: Get Statistics
        print_section("STEP 5: System Statistics")
        
        stats = client.get_stats()
        
        if stats['success']:
            s = stats['stats']
            print("Engagements:")
            print(f"  - Total: {s['engagements']['total']}")
            print(f"  - Active: {s['engagements']['active']}")
            print(f"  - Completed: {s['engagements']['completed']}")
            
            print("\nFindings:")
            print(f"  - Total: {s['findings']['total']}")
            print(f"  - Critical: {s['findings']['critical']}")
            print(f"  - High: {s['findings']['high']}")
            print(f"  - Medium: {s['findings']['medium']}")
            print(f"  - Low: {s['findings']['low']}")
            
            print(f"\nReports Generated: {s['reports']['total']}")
        
        # Summary
        print_section("SUMMARY")
        print(f"✓ Engagement created (ID: {engagement_id})")
        print(f"✓ Full assessment completed on {TEST_TARGET}")
        print(f"✓ {len(findings)} findings identified")
        print(f"✓ {len(report_types)} reports generated")
        print("\nReports are available in the 'reports/' directory")
        print("You can view them with:")
        print(f"  ls -lh reports/")
        
        print("\n" + "="*60)
        print("  Example completed successfully! 🎉")
        print("="*60 + "\n")
        
    except requests.exceptions.ConnectionError:
        print("\n❌ ERROR: Cannot connect to Red Team Agent API")
        print("Make sure the server is running:")
        print("  python run.py")
        
    except requests.exceptions.HTTPError as e:
        print(f"\n❌ HTTP Error: {e}")
        print(f"Response: {e.response.text}")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()