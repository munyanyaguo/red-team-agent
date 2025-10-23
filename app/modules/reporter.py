import os
import json
import logging
from datetime import datetime, timezone # Added timezone
from typing import Dict, List, Any
from jinja2 import Template
import markdown

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generate security assessment reports"""
    
    def __init__(self, reports_dir: str):
        self.reports_dir = reports_dir
        os.makedirs(reports_dir, exist_ok=True)
    
    def generate_report(self, engagement_data: Dict[str, Any], 
                       report_type: str = 'technical') -> str:
        """
        Generate a security report
        report_type: executive, technical, remediation
        """
        logger.info(f"Generating {report_type} report for engagement {engagement_data.get('name')}")
        
        try:
            if report_type == 'executive':
                return self._generate_executive_report(engagement_data)
            elif report_type == 'technical':
                return self._generate_technical_report(engagement_data)
            elif report_type == 'remediation':
                return self._generate_remediation_report(engagement_data)
            else:
                logger.error(f"Unknown report type: {report_type}", exc_info=True)
                return None
        except Exception as e:
            logger.error(f"Error generating {report_type} report: {e}", exc_info=True)
            return None
    
    def _generate_executive_report(self, data: Dict[str, Any]) -> str:
        """Generate executive summary report"""
        
        template_content = """# Executive Summary
## Security Assessment Report

**Client:** {{ client }}  
**Engagement:** {{ name }}  
**Date:** {{ date }}  
**Assessment Period:** {{ start_date }} to {{ end_date }}

---

## Overview

{{ executive_summary }}

## Key Statistics

- **Total Findings:** {{ total_findings }}
- **Critical Issues:** {{ critical_count }}
- **High Risk Issues:** {{ high_count }}
- **Medium Risk Issues:** {{ medium_count }}
- **Low Risk Issues:** {{ low_count }}

## Risk Level: {{ overall_risk }}

{{ risk_explanation }}

## Top Critical Issues

{% for finding in critical_findings %}
### {{ loop.index }}. {{ finding.title }}
**Severity:** {{ finding.severity | upper }}  
**Impact:** {{ finding.description }}

---
{% endfor %}

## Recommendations

{% for rec in recommendations %}
{{ loop.index }}. {{ rec }}
{% endfor %}

## Conclusion

{{ conclusion }}

---

*This report is confidential and intended solely for the use of {{ client }}*
"""
        
        template = Template(template_content)
        
        # Prepare data
        report_data = {
            'client': data.get('client', 'Unknown'),
            'name': data.get('name', 'Security Assessment'),
            'date': datetime.now(timezone.utc).strftime('%Y-%m-%d'), # Use UTC
            'start_date': data.get('start_date', 'N/A'),
            'end_date': data.get('end_date', 'N/A'),
            'executive_summary': data.get('ai_analysis', {}).get('executive_summary', 
                'A comprehensive security assessment was conducted on the specified targets.'),
            'total_findings': len(data.get('findings', [])),
            'critical_count': len([f for f in data.get('findings', []) if f.get('severity') == 'critical']),
            'high_count': len([f for f in data.get('findings', []) if f.get('severity') == 'high']),
            'medium_count': len([f for f in data.get('findings', []) if f.get('severity') == 'medium']),
            'low_count': len([f for f in data.get('findings', []) if f.get('severity') == 'low']),
            'overall_risk': data.get('ai_analysis', {}).get('risk_level', 'Medium'),
            'risk_explanation': data.get('ai_analysis', {}).get('risk_reasoning', 
                'Multiple vulnerabilities were identified that require attention.'),
            'critical_findings': [f for f in data.get('findings', []) if f.get('severity') in ['critical', 'high']][:5],
            'recommendations': data.get('ai_analysis', {}).get('remediation_plan', [
                'Address critical vulnerabilities immediately',
                'Implement security best practices',
                'Conduct regular security assessments',
                'Provide security training to staff'
            ]),
            'conclusion': 'The assessment has identified several areas requiring attention. Immediate action on critical issues is recommended.'
        }
        
        # Render template
        markdown_content = template.render(**report_data)
        
        # Save report
        filename = f"executive_report_{data.get('id', 'unknown')}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.md" # Use UTC
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(markdown_content)
        
        logger.info(f"Executive report saved to {filepath}")
        return filepath
    
    def _generate_technical_report(self, data: Dict[str, Any]) -> str:
        """Generate detailed technical report"""
        
        template_content = """# Technical Security Assessment Report

## Engagement Information

**Client:** {{ client }}  
**Engagement ID:** {{ engagement_id }}  
**Assessment Type:** {{ engagement_type }}  
**Date:** {{ date }}  
**Assessor:** Red Team Agent

---

## Scope

{{ scope_description }}

**Targets Assessed:**
{% for target in targets %}
- {{ target.type }}: `{{ target.value }}`
{% endfor %}

---

## Methodology

This assessment utilized the following approach:

1. **Reconnaissance** - Information gathering and attack surface mapping
2. **Vulnerability Scanning** - Automated and manual vulnerability identification
3. **Exploitation** - Proof-of-concept validation of critical vulnerabilities
4. **Analysis** - AI-powered risk assessment and impact analysis
5. **Reporting** - Documentation of findings and recommendations

---

## Executive Summary

{{ executive_summary }}

---

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | {{ critical_count }} |
| High | {{ high_count }} |
| Medium | {{ medium_count }} |
| Low | {{ low_count }} |
| Info | {{ info_count }} |

**Total Findings:** {{ total_findings }}

---

## Detailed Findings

{% for finding in findings %}
### Finding #{{ loop.index }}: {{ finding.title }}

**Severity:** {{ finding.severity | upper }}  
**CWE:** {{ finding.cwe | default('N/A') }}  
**CVE:** {{ finding.cve_id | default('N/A') }}  
**Status:** {{ finding.status }}

#### Description
{{ finding.description }}

#### Affected Target
{% if finding.url %}
- **URL:** {{ finding.url }}
{% endif %}
{% if finding.target_id %}
- **Target ID:** {{ finding.target_id }}
{% endif %}

#### Impact
{{ finding.impact | default('This vulnerability could be exploited to compromise system security.') }}

#### Reproduction Steps
{{ finding.reproduction_steps | default('See description for details.') }}

#### Remediation
{{ finding.remediation }}

#### Evidence
{% if finding.evidence %}
{{ finding.evidence }}
{% else %}
No additional evidence provided.
{% endif %}

---

{% endfor %}

## Reconnaissance Results

### DNS Information
{% if dns_info %}
{{ dns_info }}
{% else %}
No DNS information gathered.
{% endif %}

### Open Ports & Services
{% if port_scan %}
{{ port_scan }}
{% else %}
No port scan data available.
{% endif %}

### Technologies Detected
{% if technologies %}
{% for tech in technologies %}
- **{{ tech.name }}** ({{ tech.category }}) - Confidence: {{ tech.confidence }}
{% endfor %}
{% else %}
No technologies detected.
{% endif %}

---

## AI Analysis

### Attack Surface
{{ attack_surface }}

### Priority Targets
{{ priority_targets }}

### Recommended Next Steps
{{ next_steps }}

---

## Risk Assessment

**Overall Risk Level:** {{ overall_risk }}

{{ risk_reasoning }}

---

## Recommendations

### Immediate Actions (Critical/High)
{% for rec in immediate_actions %}
{{ loop.index }}. {{ rec }}
{% endfor %}

### Short-term Actions (Medium)
{% for rec in short_term_actions %}
{{ loop.index }}. {{ rec }}
{% endfor %}

### Long-term Improvements (Low)
{% for rec in long_term_actions %}
{{ loop.index }}. {{ rec }}
{% endfor %}

---

## Appendix

### Tools Used
- Nmap - Port scanning
- Custom reconnaissance tools
            AI-powered analysis (Claude)
- Vulnerability scanners

### References
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE Database: https://cwe.mitre.org/
- CVE Database: https://cve.mitre.org/

---

*Report Generated: {{ date }}*  
*This document is confidential and should be treated as sensitive information.*
"""
        
        template = Template(template_content)
        
        # Prepare comprehensive data
        findings = data.get('findings', [])
        
        report_data = {
            'client': data.get('client', 'Unknown'),
            'engagement_id': data.get('id', 'N/A'),
            'engagement_type': data.get('engagement_type', 'Security Assessment'),
            'date': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), # Use UTC
            'scope_description': data.get('scope', 'Assessment scope as defined in engagement'),
            'targets': data.get('targets', []),
            'executive_summary': data.get('ai_analysis', {}).get('executive_summary', 
                'A security assessment was performed on the specified targets.'),
            'total_findings': len(findings),
            'critical_count': len([f for f in findings if f.get('severity') == 'critical']),
            'high_count': len([f for f in findings if f.get('severity') == 'high']),
            'medium_count': len([f for f in findings if f.get('severity') == 'medium']),
            'low_count': len([f for f in findings if f.get('severity') == 'low']),
            'info_count': len([f for f in findings if f.get('severity') == 'info']),
            'findings': findings,
            'dns_info': self._format_dns_info(data.get('recon_data', {}).get('dns_info', {})),
            'port_scan': self._format_port_scan(data.get('recon_data', {}).get('port_scan', {})),
            'technologies': data.get('recon_data', {}).get('technologies', []),
            'attack_surface': data.get('ai_analysis', {}).get('attack_surface', 'See findings above.'),
            'priority_targets': self._format_list(data.get('ai_analysis', {}).get('priority_targets', [])),
            'next_steps': self._format_list(data.get('ai_analysis', {}).get('next_steps', [])),
            'overall_risk': data.get('ai_analysis', {}).get('risk_level', 'Medium'),
            'risk_reasoning': data.get('ai_analysis', {}).get('risk_reasoning', 
                'Multiple vulnerabilities identified requiring remediation.'),
            'immediate_actions': self._categorize_actions(findings, 'immediate'),
            'short_term_actions': self._categorize_actions(findings, 'short_term'),
            'long_term_actions': self._categorize_actions(findings, 'long_term')
        }
        
        # Render template
        markdown_content = template.render(**report_data)
        
        # Save report
        filename = f"technical_report_{data.get('id', 'unknown')}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.md" # Use UTC
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(markdown_content)
        
        logger.info(f"Technical report saved to {filepath}")
        return filepath
    
    def _generate_remediation_report(self, data: Dict[str, Any]) -> str:
        """Generate remediation-focused report"""
        
        template_content = """# Security Remediation Guide

## Engagement: {{ name }}
**Client:** {{ client }}  
**Date:** {{ date }}

---

## Remediation Priority Matrix

This guide provides a prioritized approach to addressing identified security issues.

### Critical Priority (Fix Immediately - 0-7 days)

{% for finding in critical_findings %}
#### {{ loop.index }}. {{ finding.title }}

**Severity:** CRITICAL  
**Affected Asset:** {{ finding.url | default('See technical report') }}

**Issue:**
{{ finding.description }}

**Fix:**
{{ finding.remediation }}

**Validation:**
After implementing the fix:
1. Re-test the affected component
2. Verify the vulnerability is no longer present
3. Document the changes made

---
{% endfor %}

### High Priority (Fix Within 30 days)

{% for finding in high_findings %}
#### {{ loop.index }}. {{ finding.title }}

**Issue:** {{ finding.description }}  
**Fix:** {{ finding.remediation }}

---
{% endfor %}

### Medium Priority (Fix Within 90 days)

{% for finding in medium_findings %}
- **{{ finding.title }}**: {{ finding.remediation }}
{% endfor %}

### Low Priority (Fix Within 6 months)

{% for finding in low_findings %}
- **{{ finding.title }}**: {{ finding.remediation }}
{% endfor %}

---

## Implementation Checklist

{% for category, items in checklist.items() %}
### {{ category }}
{% for item in items %}
- [ ] {{ item }}
{% endfor %}

{% endfor %}

## Security Best Practices

### General Recommendations
1. Implement a regular patch management process
2. Enable security logging and monitoring
3. Conduct security awareness training
4. Perform regular security assessments
5. Implement a security incident response plan

### Web Application Security
1. Use HTTPS everywhere with valid certificates
2. Implement all security headers (CSP, HSTS, etc.)
3. Validate and sanitize all user inputs
4. Use parameterized queries to prevent SQL injection
5. Implement proper session management

### Network Security
1. Follow principle of least privilege
2. Segment networks appropriately
3. Use strong authentication mechanisms
4. Keep all systems and software up to date
5. Monitor network traffic for anomalies

---

## Verification Testing

After implementing fixes, perform the following verification:

{% for finding in all_findings %}
### {{ finding.title }}
**Test Method:** {{ finding.verification | default('Re-run vulnerability scan') }}

{% endfor %}

---

## Support Resources

- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- CWE Database: https://cwe.mitre.org/
- NIST Security Guidelines: https://www.nist.gov/cybersecurity

---

*This remediation guide should be treated as confidential information.*
"""
        
        template = Template(template_content)
        
        findings = data.get('findings', [])
        
        report_data = {
            'name': data.get('name', 'Security Assessment'),
            'client': data.get('client', 'Unknown'),
            'date': datetime.now(timezone.utc).strftime('%Y-%m-%d'), # Use UTC
            'critical_findings': [f for f in findings if f.get('severity') == 'critical'],
            'high_findings': [f for f in findings if f.get('severity') == 'high'],
            'medium_findings': [f for f in findings if f.get('severity') == 'medium'],
            'low_findings': [f for f in findings if f.get('severity') == 'low'],
            'all_findings': findings,
            'checklist': self._generate_checklist(findings)
        }
        
        # Render template
        markdown_content = template.render(**report_data)
        
        # Save report
        filename = f"remediation_guide_{data.get('id', 'unknown')}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.md" # Use UTC
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(markdown_content)
        
        logger.info(f"Remediation guide saved to {filepath}")
        return filepath
    
    def _format_dns_info(self, dns_data: Dict) -> str:
        """Format DNS information for report"""
        if not dns_data:
            return "No DNS data available"
        
        output = []
        for record_type, records in dns_data.items():
            if records:
                output.append(f"**{record_type} Records:**")
                for record in records:
                    output.append(f"- {record}")
                output.append("")
        
        return "\n".join(output) if output else "No DNS records found"
    
    def _format_port_scan(self, port_data: Dict) -> str:
        """Format port scan results"""
        if not port_data or 'open_ports' not in port_data:
            return "No port scan data available"
        
        output = ["**Open Ports:**\n"]
        output.append("| Port | Service | Version |")
        output.append("|------|---------|---------|")
        
        for port in port_data.get('open_ports', []):
            service_info = port_data.get('services', {}).get(port, {})
            name = service_info.get('name', 'unknown')
            version = service_info.get('version', 'N/A')
            output.append(f"| {port} | {name} | {version} |")
        
        return "\n".join(output)
    
    def _format_list(self, items: Any) -> str: # Changed type hint to Any
        """Format list items, ensuring consistent list output."""
        if items is None:
            return "None specified"
        
        if isinstance(items, str):
            # If it's a single string, treat it as a list with one item
            return f"- {items}"
        
        try:
            # Try to iterate if it's a list-like object
            return "\n".join([f"- {item}" for item in items])
        except TypeError:
            # If not iterable, just return its string representation
            return f"- {str(items)}"
    
    def _categorize_actions(self, findings: List[Dict], category: str) -> List[str]:
        """Categorize remediation actions by urgency"""
        actions = []
        
        if category == 'immediate':
            critical = [f for f in findings if f.get('severity') in ['critical', 'high']]
            actions = [f"{f.get('title')}: {f.get('remediation', 'Address this vulnerability')}" 
                      for f in critical[:5]]
        elif category == 'short_term':
            medium = [f for f in findings if f.get('severity') == 'medium']
            actions = [f"{f.get('title')}: {f.get('remediation', 'Address this vulnerability')}" 
                      for f in medium[:5]]
        elif category == 'long_term':
            low = [f for f in findings if f.get('severity') in ['low', 'info']]
            actions = [f"{f.get('title')}: {f.get('remediation', 'Address this vulnerability')}" 
                      for f in low[:5]]
        
        return actions if actions else ['No actions in this category']
    
    def _generate_checklist(self, findings: List[Dict]) -> Dict[str, List[str]]:
        """Generate implementation checklist"""
        checklist = {
            'Immediate Actions': [],
            'Security Headers': [],
            'Authentication & Access': [],
            'Data Protection': [],
            'Monitoring & Logging': []
        }
        
        # Analyze findings and add to appropriate categories
        for finding in findings:
            title = finding.get('title', '')
            
            if 'header' in title.lower():
                checklist['Security Headers'].append(f"Fix: {title}")
            elif 'authentication' in title.lower() or 'password' in title.lower():
                checklist['Authentication & Access'].append(f"Fix: {title}")
            elif 'ssl' in title.lower() or 'tls' in title.lower() or 'https' in title.lower():
                checklist['Data Protection'].append(f"Fix: {title}")
            elif finding.get('severity') in ['critical', 'high']:
                checklist['Immediate Actions'].append(f"Fix: {title}")
        
        # Add general items
        checklist['Monitoring & Logging'].extend([
            'Enable security logging',
            'Set up monitoring alerts',
            'Review logs regularly'
        ])
        
        return {k: v for k, v in checklist.items() if v}
    
    def generate_json_report(self, data: Dict[str, Any]) -> str:
        """Generate machine-readable JSON report"""
        filename = f"report_{data.get('id', 'unknown')}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json" # Use UTC
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info(f"JSON report saved to {filepath}")
        return filepath
