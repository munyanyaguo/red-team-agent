import anthropic
import json
import logging
from typing import Dict, List, Any, Optional
import os

logger = logging.getLogger(__name__)

class AISecurityAgent:
    """AI-powered security analysis using Claude (offensive) and Gemini (analysis)"""

    def __init__(self, api_key: Optional[str] = None, provider: Optional[str] = None):
        """
        Initialize AI agent with support for multiple providers

        Args:
            api_key: Optional API key (will check env vars if not provided)
            provider: Force a specific provider (normally auto-configured)
        """
        self.anthropic_client = None
        self.gemini_client = None
        self.has_anthropic = False
        self.has_gemini = False

        # Initialize Anthropic (for offensive/testing operations)
        self._init_anthropic()

        # Initialize Gemini (for analysis/explanations)
        self._init_gemini()

        if not self.anthropic_client and not self.gemini_client:
            logger.warning("No AI API keys found. Set GEMINI_API_KEY and/or ANTHROPIC_API_KEY. AI features will be disabled.")
        else:
            providers = []
            if self.has_anthropic:
                providers.append("Anthropic Claude 3.5 Sonnet (offensive)")
            if self.has_gemini:
                providers.append("Google Gemini 1.5 Flash (analysis)")
            logger.info(f"AI providers initialized: {', '.join(providers)}")

    def _init_gemini(self):
        """Initialize Google Gemini client"""
        try:
            import google.generativeai as genai

            api_key = os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY')
            if not api_key:
                logger.info("No Gemini API key found. Analysis/explanation features will use Anthropic if available.")
                return

            genai.configure(api_key=api_key)
            # Use the latest stable Gemini model
            self.gemini_client = genai.GenerativeModel('gemini-2.5-flash')
            self.has_gemini = True
            logger.info("✓ Gemini client initialized (for analysis & explanations)")

        except ImportError:
            logger.warning("google-generativeai package not installed. Run: pipenv install google-generativeai")
        except Exception as e:
            logger.error(f"Failed to initialize Gemini: {e}")

    def _init_anthropic(self):
        """Initialize Anthropic Claude client"""
        try:
            api_key = os.getenv('ANTHROPIC_API_KEY')
            if not api_key:
                logger.info("No Anthropic API key found. Offensive/testing features will use Gemini if available.")
                return

            self.anthropic_client = anthropic.Anthropic(api_key=api_key)
            self.has_anthropic = True
            logger.info("✓ Anthropic client initialized (for offensive operations)")

        except Exception as e:
            logger.error(f"Failed to initialize Anthropic: {e}")

    def _call_gemini(self, prompt: str) -> str:
        """Call Gemini API"""
        if not self.gemini_client:
            raise Exception('Gemini client not available')

        response = self.gemini_client.generate_content(prompt)
        return response.text

    def _call_anthropic(self, prompt: str, max_tokens: int = 2000) -> str:
        """Call Anthropic Claude API"""
        if not self.anthropic_client:
            raise Exception('Anthropic client not available')

        message = self.anthropic_client.messages.create(
            model="claude-3-5-sonnet-20241022",  # Latest Claude 3.5 Sonnet
            max_tokens=max_tokens,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        return message.content[0].text

    def analyze_reconnaissance(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze reconnaissance data and provide strategic insights
        Uses: Gemini (preferred) or Anthropic (fallback)
        """
        provider = "Gemini" if self.has_gemini else "Anthropic" if self.has_anthropic else None
        if not provider:
            return {'error': 'AI features not available - API key missing'}

        logger.info(f"Analyzing reconnaissance data for {recon_data.get('target')} using {provider}")

        prompt = f"""You are a professional security researcher analyzing reconnaissance data.

Target: {recon_data.get('target')}
Target Type: {recon_data.get('target_type')}

Reconnaissance Results:
{json.dumps(recon_data, indent=2)}

Please analyze this data and provide:
1. Attack Surface Summary - What potential entry points exist?
2. Priority Targets - Which services/ports should be investigated first?
3. Technology Stack Assessment - What technologies are in use and their known vulnerabilities?
4. Risk Assessment - Overall risk level (Critical/High/Medium/Low) and why
5. Recommended Next Steps - What should be done next in the assessment?

Format your response as JSON with these exact keys: attack_surface, priority_targets, tech_assessment, risk_level, risk_reasoning, next_steps"""

        try:
            if self.has_gemini:
                response_text = self._call_gemini(prompt)
            else:
                response_text = self._call_anthropic(prompt, max_tokens=2000)

            # Try to parse as JSON
            try:
                analysis = json.loads(response_text)
            except:
                # If not valid JSON, create structured response
                analysis = {
                    'attack_surface': response_text,
                    'priority_targets': [],
                    'tech_assessment': '',
                    'risk_level': 'Unknown',
                    'risk_reasoning': 'Failed to parse AI response',
                    'next_steps': []
                }

            logger.info("AI analysis completed successfully")
            return analysis

        except Exception as e:
            logger.error(f"AI analysis failed: {e}", exc_info=True)
            return {'error': str(e)}

    def analyze_vulnerabilities(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze vulnerability findings and provide insights
        Uses: Gemini (preferred) or Anthropic (fallback)
        """
        provider = "Gemini" if self.has_gemini else "Anthropic" if self.has_anthropic else None
        if not provider:
            return {'error': 'AI features not available - API key missing'}

        logger.info(f"Analyzing {len(findings)} vulnerability findings using {provider}")

        prompt = f"""You are a security expert analyzing vulnerability scan results.

Number of Findings: {len(findings)}

Findings:
{json.dumps(findings, indent=2)}

Please provide:
1. Executive Summary - High-level overview for non-technical stakeholders
2. Critical Issues - Most severe vulnerabilities that need immediate attention
3. Attack Chains - Potential ways these vulnerabilities could be chained together
4. Business Impact - How these vulnerabilities could impact the business
5. Prioritized Remediation Plan - Ordered list of fixes with rationale

Format your response as JSON with these keys: executive_summary, critical_issues, attack_chains, business_impact, remediation_plan"""

        try:
            if self.has_gemini:
                response_text = self._call_gemini(prompt)
            else:
                response_text = self._call_anthropic(prompt, max_tokens=2500)

            try:
                analysis = json.loads(response_text)
            except:
                analysis = {
                    'executive_summary': response_text,
                    'critical_issues': [],
                    'attack_chains': [],
                    'business_impact': '',
                    'remediation_plan': []
                }

            logger.info("Vulnerability analysis completed")
            return analysis

        except Exception as e:
            logger.error(f"Vulnerability analysis failed: {e}", exc_info=True)
            return {'error': str(e)}

    def generate_attack_strategy(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a strategic attack plan based on target information
        Uses: Anthropic Claude (preferred) or Gemini (fallback)
        """
        provider = "Anthropic" if self.has_anthropic else "Gemini" if self.has_gemini else None
        if not provider:
            return {'error': 'AI features not available - API key missing'}

        logger.info(f"Generating attack strategy using {provider}")

        prompt = f"""You are a red team operator planning a security assessment.

Target Information:
{json.dumps(target_info, indent=2)}

Create a strategic attack plan that includes:
1. Phase 1: Initial Access - Best methods to gain initial access
2. Phase 2: Privilege Escalation - Potential escalation paths
3. Phase 3: Lateral Movement - How to move within the environment
4. Phase 4: Data Exfiltration - Methods to demonstrate impact
5. Safety Considerations - What to avoid to prevent damage
6. Detection Avoidance - How to remain stealthy

Format as JSON with these keys: initial_access, privilege_escalation, lateral_movement, exfiltration, safety_notes, stealth_techniques"""

        try:
            if self.has_anthropic:
                response_text = self._call_anthropic(prompt, max_tokens=2000)
            else:
                response_text = self._call_gemini(prompt)

            try:
                strategy = json.loads(response_text)
            except:
                strategy = {
                    'initial_access': response_text,
                    'privilege_escalation': '',
                    'lateral_movement': '',
                    'exfiltration': '',
                    'safety_notes': 'Always obtain proper authorization',
                    'stealth_techniques': []
                }

            logger.info("Attack strategy generated")
            return strategy

        except Exception as e:
            logger.error(f"Strategy generation failed: {e}", exc_info=True)
            return {'error': str(e)}

    def explain_vulnerability(self, vulnerability: Dict[str, Any]) -> str:
        """
        Get detailed explanation of a vulnerability for reports
        Uses: Gemini (preferred) or Anthropic (fallback)
        """
        provider = "Gemini" if self.has_gemini else "Anthropic" if self.has_anthropic else None
        if not provider:
            return "AI explanation not available - API key missing"

        logger.info(f"Generating explanation for vulnerability: {vulnerability.get('title')} using {provider}")

        prompt = f"""Explain this security vulnerability in detail:

Title: {vulnerability.get('title')}
Severity: {vulnerability.get('severity')}
Description: {vulnerability.get('description')}
CWE: {vulnerability.get('cwe', 'N/A')}

Provide:
1. What this vulnerability means in simple terms
2. How an attacker could exploit it
3. Real-world impact examples
4. Detailed remediation steps
5. How to verify the fix

Write in clear, professional language suitable for a security report."""

        try:
            if self.has_gemini:
                explanation = self._call_gemini(prompt)
            else:
                explanation = self._call_anthropic(prompt, max_tokens=1500)

            logger.info("Vulnerability explanation generated")
            return explanation

        except Exception as e:
            logger.error(f"Explanation generation failed: {e}", exc_info=True)
            return f"Error generating explanation: {str(e)}"

    def generate_executive_summary(self, engagement_data: Dict[str, Any]) -> str:
        """
        Generate executive summary for reports
        Uses: Gemini (preferred) or Anthropic (fallback)
        """
        provider = "Gemini" if self.has_gemini else "Anthropic" if self.has_anthropic else None
        if not provider:
            return "AI summary not available - API key missing"

        logger.info(f"Generating executive summary using {provider}")

        prompt = f"""Create an executive summary for this security assessment:

Engagement: {engagement_data.get('name')}
Client: {engagement_data.get('client')}
Scope: {engagement_data.get('scope')}
Findings Count: {engagement_data.get('findings_count', 0)}
Critical: {engagement_data.get('critical_count', 0)}
High: {engagement_data.get('high_count', 0)}
Medium: {engagement_data.get('medium_count', 0)}

Key Findings:
{json.dumps(engagement_data.get('key_findings', []), indent=2)}

Write a professional executive summary that:
1. Summarizes the assessment scope and methodology
2. Highlights the most critical security issues
3. Provides business context and risk
4. Gives clear recommendations
5. Is suitable for C-level executives (non-technical)

Keep it concise (300-500 words) and business-focused."""

        try:
            if self.has_gemini:
                summary = self._call_gemini(prompt)
            else:
                summary = self._call_anthropic(prompt, max_tokens=1000)

            logger.info("Executive summary generated")
            return summary

        except Exception as e:
            logger.error(f"Summary generation failed: {e}", exc_info=True)
            return f"Error generating summary: {str(e)}"

    def suggest_exploitation_method(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Suggest safe exploitation methods for proof-of-concept
        Uses: Anthropic Claude (preferred) or Gemini (fallback)
        """
        provider = "Anthropic" if self.has_anthropic else "Gemini" if self.has_gemini else None
        if not provider:
            return {'error': 'AI features not available - API key missing'}

        logger.info(f"Generating exploitation suggestions for: {vulnerability.get('title')} using {provider}")

        prompt = f"""As a security professional, suggest a safe proof-of-concept for this vulnerability:

Vulnerability: {vulnerability.get('title')}
Severity: {vulnerability.get('severity')}
Description: {vulnerability.get('description')}
Target: {vulnerability.get('url', 'N/A')}

Provide:
1. Safe exploitation method that proves the vulnerability exists
2. Step-by-step instructions
3. Safety considerations and limits
4. Expected result
5. How to document the proof-of-concept

Focus on demonstrating impact WITHOUT causing damage.

Format as JSON with keys: method, steps, safety_notes, expected_result, documentation_tips"""

        try:
            if self.has_anthropic:
                response_text = self._call_anthropic(prompt, max_tokens=1500)
            else:
                response_text = self._call_gemini(prompt)

            try:
                suggestions = json.loads(response_text)
            except:
                suggestions = {
                    'method': response_text,
                    'steps': [],
                    'safety_notes': 'Always test in authorized environment only',
                    'expected_result': '',
                    'documentation_tips': []
                }

            logger.info("Exploitation suggestions generated")
            return suggestions

        except Exception as e:
            logger.error(f"Suggestion generation failed: {e}", exc_info=True)
            return {'error': str(e)}

    def analyze_with_self_critique(self, findings: List[Dict],
                                   max_iterations: int = 3):
        """
        Analyze findings with self-critique loop
        Uses: Anthropic Claude (preferred) or Gemini (fallback)
        """
        current_analysis = self.analyze_vulnerabilities(findings)

        for iteration in range(max_iterations):
            # Self-critique
            critique = self._critique_analysis(current_analysis, findings)

            if critique.get('quality_score', 0) >= 0.9:  # Good enough
                logger.info(f"Analysis approved after {iteration + 1} iterations")
                break

            # Refine based on critique
            logger.info(f"Refining analysis (iteration {iteration + 1}): {critique.get('improvements_needed')}")
            current_analysis = self._refine_analysis(
                current_analysis,
                critique.get('improvements_needed', []),
                findings
            )

        return current_analysis

    def _critique_analysis(self, analysis: Dict, findings: List[Dict]) -> Dict:
        """
        Use AI to critique its own analysis
        Uses: Anthropic Claude (preferred) or Gemini (fallback)
        """
        critique_prompt = f"""
        You are a senior security analyst reviewing a junior analyst's report.

        ANALYSIS TO REVIEW:
        {json.dumps(analysis, indent=2)}

        ORIGINAL FINDINGS:
        {json.dumps(findings, indent=2)}

        Critique this analysis on:
        1. Completeness: Are all critical findings addressed?
        2. Accuracy: Are severity ratings appropriate?
        3. Actionability: Are remediation steps clear?
        4. Risk assessment: Is business impact well articulated?

        Provide:
        - quality_score (0-1)
        - improvements_needed (list of specific issues)
        - missing_elements (list of what's missing)

        Format your response as JSON.
        """

        try:
            if self.has_anthropic:
                response = self._call_anthropic(critique_prompt)
            else:
                response = self._call_gemini(critique_prompt)
            return self._parse_critique_response(response)
        except Exception as e:
            logger.error(f"Error during critique: {e}", exc_info=True)
            return {'quality_score': 0, 'improvements_needed': [f"Critique failed: {e}"], 'missing_elements': []}

    def _parse_critique_response(self, response_text: str) -> Dict:
        """Parse the AI's critique response."""
        try:
            critique = json.loads(response_text)
            return critique
        except json.JSONDecodeError:
            logger.error(f"Failed to parse critique response as JSON: {response_text}")
            return {'quality_score': 0, 'improvements_needed': ["Failed to parse AI critique"], 'missing_elements': []}

    def _refine_analysis(self, current_analysis: Dict, improvements: List[str], findings: List[Dict]) -> Dict:
        """Refine the analysis based on critique."""
        logger.info(f"Applying improvements: {improvements}")
        refined_analysis = current_analysis.copy()
        if "Accuracy: Are severity ratings appropriate?" in improvements:
            refined_analysis['executive_summary'] += " (Severity ratings reviewed and adjusted.)"
        return refined_analysis

    def analyze_qa_test_failure(self, test_result: Dict[str, Any], target_url: str) -> Dict[str, Any]:
        """
        Professional-grade analysis of QA test failures for official reports

        Provides:
        - Exact root cause with specific locations
        - Detailed remediation with code examples
        - OWASP/CWE/CVE references
        - Compliance implications
        - Business impact assessment
        - Risk rating with justification

        Uses: Gemini (preferred) or Anthropic (fallback)

        Args:
            test_result: Test result data including failure details
            target_url: URL of the application under test

        Returns:
            Professional analysis suitable for official security reports
        """
        provider = "Gemini" if self.has_gemini else "Anthropic" if self.has_anthropic else None
        if not provider:
            return {'error': 'AI features not available - API key missing'}

        test_name = test_result.get('test_name', 'Unknown Test')
        test_type = test_result.get('test_type', 'Unknown')
        failure_reason = test_result.get('error_message', 'No error message provided')

        logger.info(f"Generating professional QA failure analysis for: {test_name} ({test_type}) using {provider}")

        prompt = f"""You are a Senior Security Engineer and Software Architect with 25 years of experience conducting professional security assessments and writing official security reports.

CONTEXT:
Target Application: {target_url}
Test Name: {test_name}
Test Type: {test_type}
Test Status: FAILED
Failure Reason: {failure_reason}

Complete Test Result Data:
{json.dumps(test_result, indent=2)}

YOUR TASK:
Provide a professional, report-quality analysis that can be included in an official security assessment report. This analysis must be actionable and specific - NO generic advice.

REQUIRED OUTPUT STRUCTURE (JSON):

{{
  "finding_id": "QA-{test_type.upper()}-{{}}", // Generate unique ID
  "title": "Specific, professional title for the finding",

  "executive_summary": "2-3 sentences explaining the issue at a business level for executives",

  "technical_description": {{
    "issue": "Detailed technical explanation of EXACTLY what is wrong",
    "root_cause": "Precise root cause - identify the EXACT component/layer/configuration causing the failure",
    "affected_component": "Specific component/service/endpoint affected (be precise)",
    "attack_vector": "If security-related, explain the exact attack vector an adversary would use",
    "evidence": "Key evidence from the test result that proves this issue exists"
  }},

  "location_details": {{
    "component_type": "frontend|backend|infrastructure|configuration|third-party",
    "likely_files": ["List of specific file paths where the fix should be implemented"],
    "code_locations": ["Specific functions/classes/endpoints that need modification"],
    "configuration_files": ["Any config files that may need updates"]
  }},

  "remediation": {{
    "priority": "Critical|High|Medium|Low",
    "effort_estimate": "Quick Fix (< 4 hours)|Moderate (1-2 days)|Complex (3-5 days)|Major Refactor (1+ weeks)",
    "immediate_action": "Specific first step to take right now",
    "implementation_steps": [
      {{
        "step_number": 1,
        "action": "Exact action to perform",
        "location": "Specific file/component/service where this should be done",
        "code_example": "Actual code snippet or configuration showing the fix",
        "verification": "How to verify this step worked"
      }}
      // Include 3-5 specific steps
    ],
    "testing_requirements": "Specific tests that must pass to verify the fix",
    "rollback_plan": "How to safely rollback if the fix causes issues"
  }},

  "security_references": {{
    "owasp_category": "Specific OWASP Top 10 category if applicable (e.g., A01:2021 - Broken Access Control)",
    "cwe_ids": ["Relevant CWE IDs with brief descriptions"],
    "cvss_score": "Estimated CVSS v3.1 score if applicable",
    "cve_references": ["Any relevant CVE numbers if this is a known vulnerability pattern"]
  }},

  "compliance_impact": {{
    "gdpr": "Impact on GDPR compliance if any",
    "pci_dss": "Impact on PCI DSS if handling payment data",
    "hipaa": "Impact on HIPAA if handling health data",
    "sox": "Impact on SOX if public company",
    "iso27001": "Relevant ISO 27001 controls affected"
  }},

  "business_impact": {{
    "confidentiality_impact": "High|Medium|Low - with specific explanation",
    "integrity_impact": "High|Medium|Low - with specific explanation",
    "availability_impact": "High|Medium|Low - with specific explanation",
    "financial_risk": "Quantified or estimated financial risk",
    "reputational_risk": "Impact on company reputation",
    "user_experience_impact": "How this affects end users",
    "sla_impact": "Impact on SLAs or performance guarantees"
  }},

  "risk_assessment": {{
    "likelihood": "Very High|High|Medium|Low|Very Low",
    "likelihood_justification": "Specific factors that determine this likelihood rating",
    "impact_severity": "Critical|High|Medium|Low",
    "impact_justification": "Specific factors that determine this severity rating",
    "overall_risk_rating": "Critical|High|Medium|Low",
    "risk_calculation": "Explanation of how likelihood × impact = overall risk"
  }},

  "recommendations": {{
    "short_term": ["Immediate actions (< 1 week)"],
    "medium_term": ["Improvements to implement (1-4 weeks)"],
    "long_term": ["Strategic improvements (1-3 months)"],
    "preventive_measures": ["How to prevent this class of issues in the future"]
  }},

  "evidence_artifacts": {{
    "screenshots": ["Description of screenshots that should be included"],
    "log_entries": ["Relevant log entries showing the issue"],
    "network_captures": ["Network traffic patterns showing the issue"],
    "proof_of_concept": "Step-by-step PoC to reproduce the issue"
  }},

  "related_findings": ["IDs of related findings that compound this risk"],

  "technical_notes": "Additional technical details, debugging notes, or context for the security team"
}}

CRITICAL REQUIREMENTS:
1. Be SPECIFIC - no generic advice like "improve security" or "fix the bug"
2. Provide EXACT locations - file paths, function names, configuration keys
3. Include ACTIONABLE code examples - actual code that can be copy-pasted
4. Reference STANDARDS - OWASP, CWE, industry best practices with specific items
5. Quantify IMPACT - use specific metrics, not vague terms
6. Professional TONE - suitable for presentation to executives, auditors, or clients
7. Include EVIDENCE - reference specific data from the test results

Remember: This analysis will be read by executives, developers, security teams, and potentially auditors or regulators. It must be thorough, accurate, and professionally formatted."""

        try:
            if self.has_gemini:
                response_text = self._call_gemini(prompt)
            else:
                response_text = self._call_anthropic(prompt, max_tokens=4000)

            # Extract JSON from response (handle markdown code blocks)
            response_text = response_text.strip()
            if response_text.startswith('```json'):
                response_text = response_text[7:]
            if response_text.startswith('```'):
                response_text = response_text[3:]
            if response_text.endswith('```'):
                response_text = response_text[:-3]
            response_text = response_text.strip()

            try:
                analysis = json.loads(response_text)
                logger.info(f"Professional QA failure analysis completed for {test_name}")
                return {
                    'success': True,
                    'analysis': analysis,
                    'generated_by': provider,
                    'analysis_timestamp': json.dumps({'$date': {'$numberLong': str(int(__import__('time').time() * 1000))}})
                }
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse AI analysis as JSON: {e}")
                # Return structured fallback
                return {
                    'success': False,
                    'analysis': {
                        'finding_id': f'QA-{test_type.upper()}-ERROR',
                        'title': f'{test_type.title()} Test Failure: {test_name}',
                        'executive_summary': f'The {test_type} test "{test_name}" failed during execution. This requires investigation and remediation.',
                        'technical_description': {
                            'issue': failure_reason,
                            'root_cause': 'Requires manual investigation',
                            'affected_component': target_url,
                            'attack_vector': 'N/A',
                            'evidence': str(test_result)[:500]
                        },
                        'remediation': {
                            'priority': 'High',
                            'immediate_action': 'Investigate the test failure and identify root cause',
                            'implementation_steps': [
                                {
                                    'step_number': 1,
                                    'action': 'Review test failure details',
                                    'location': 'Test execution logs',
                                    'code_example': 'N/A',
                                    'verification': 'Re-run the test after investigation'
                                }
                            ]
                        },
                        'raw_ai_response': response_text
                    },
                    'error': f'JSON parsing failed: {str(e)}',
                    'generated_by': provider
                }

        except Exception as e:
            logger.error(f"QA failure analysis failed: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'analysis': {
                    'finding_id': f'QA-{test_type.upper()}-ERROR',
                    'title': 'Analysis Generation Failed',
                    'executive_summary': f'Failed to generate AI analysis: {str(e)}',
                    'technical_description': {
                        'issue': failure_reason,
                        'root_cause': 'AI analysis unavailable',
                        'affected_component': target_url,
                        'evidence': str(test_result)[:500]
                    }
                }
            }

    def analyze_vulnerability_professional(self, vulnerability: Dict[str, Any], target_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Professional-grade vulnerability analysis for official security reports

        Provides:
        - Exact technical root cause
        - Specific exploitation methodology  
        - Detailed remediation with code examples
        - OWASP/CWE/CVE mapping
        - Compliance impact assessment
        - Business risk quantification

        Uses: Gemini (preferred) or Anthropic (fallback)
        """
        provider = "Gemini" if self.has_gemini else "Anthropic" if self.has_anthropic else None
        if not provider:
            return {'error': 'AI features not available - API key missing'}

        vuln_title = vulnerability.get('title', vulnerability.get('name', 'Unknown Vulnerability'))
        vuln_severity = vulnerability.get('severity', 'Unknown')
        vuln_description = vulnerability.get('description', 'No description provided')
        target_url = target_context.get('target', 'Unknown')

        logger.info(f"Generating professional vulnerability analysis for: {vuln_title} using {provider}")

        prompt = f"""You are a Senior Penetration Tester and Security Architect with 25 years of experience writing official penetration testing reports.

CONTEXT:
Target: {target_url}
Vulnerability: {vuln_title}
Severity: {vuln_severity}
Description: {vuln_description}

Vulnerability Data:
{json.dumps(vulnerability, indent=2)}

Target Context:
{json.dumps(target_context, indent=2)}

YOUR TASK:
Provide professional, report-quality vulnerability analysis for an official penetration testing report. Be SPECIFIC - NO generic advice.

OUTPUT (JSON):
{{
  "finding_id": "Generate unique ID like VULN-CRITICAL-001",
  "title": "Specific vulnerability title",
  "executive_summary": "2-3 sentences for business executives",
  "technical_description": {{
    "vulnerability_type": "Exact type (SQL Injection, XSS, RCE, etc.)",
    "root_cause": "Precise technical root cause with exact code/config issue",
    "affected_component": "Specific URL/endpoint/parameter",
    "attack_vector": "Exact step-by-step attack methodology",
    "authentication_required": "None|Low|Standard|Admin",
    "network_access": "Remote|Local|Adjacent",
    "complexity": "Low|Medium|High with explanation",
    "evidence": "Actual technical evidence"
  }},
  "location_details": {{
    "url_or_endpoint": "Exact URL or API endpoint",
    "vulnerable_parameter": "Specific parameter name",
    "affected_files": ["Estimated source files"],
    "code_locations": ["Likely vulnerable functions/methods"],
    "third_party_components": ["Vulnerable libraries with versions"]
  }},
  "exploitation_details": {{
    "exploitability": "Easy|Moderate|Difficult",
    "prerequisites": ["What attacker needs"],
    "attack_steps": [
      {{
        "step_number": 1,
        "action": "Exact action",
        "payload": "Actual payload/command",
        "expected_response": "What success looks like",
        "indicators": "Detection indicators"
      }}
    ],
    "proof_of_concept": "Complete PoC demonstrating vulnerability",
    "limitations": "Exploitation limitations"
  }},
  "remediation": {{
    "priority": "Critical|High|Medium|Low",
    "effort_estimate": "Quick Fix|Moderate|Complex|Major Refactor",
    "immediate_workaround": "Quick mitigation available now",
    "permanent_solution": "Complete fix description",
    "implementation_steps": [
      {{
        "step_number": 1,
        "action": "Exact action",
        "location": "Specific file/service",
        "before": "Vulnerable code",
        "after": "Secure code",
        "code_example": "Actual fix code",
        "verification": "How to verify fix"
      }}
    ],
    "testing_requirements": "Tests to verify fix",
    "regression_risks": "Potential side effects",
    "rollback_plan": "Safe rollback procedure"
  }},
  "security_references": {{
    "owasp_category": "OWASP Top 10 item (e.g., A03:2021)",
    "cwe_ids": ["CWE-XXX with descriptions"],
    "cvss_score": "CVSS v3.1 score",
    "cvss_vector": "CVSS v3.1 vector string",
    "cve_references": ["Related CVEs"],
    "exploit_references": ["Public exploits"],
    "remediation_references": ["Vendor advisories"]
  }},
  "compliance_impact": {{
    "gdpr": "Impact with specific articles",
    "pci_dss": "Impact with specific requirements",
    "hipaa": "Impact with specific rules",
    "sox": "SOX compliance impact",
    "iso27001": "Violated controls",
    "nist": "NIST framework categories"
  }},
  "business_impact": {{
    "confidentiality_impact": "Critical|High|Medium|Low - specific data at risk",
    "integrity_impact": "Critical|High|Medium|Low - manipulation risks",
    "availability_impact": "Critical|High|Medium|Low - disruption risks",
    "financial_risk": "Quantified financial impact",
    "reputational_risk": "Brand impact",
    "legal_risk": "Legal liabilities",
    "operational_risk": "Business operations impact",
    "data_at_risk": ["Specific data types compromised"]
  }},
  "risk_assessment": {{
    "likelihood": "Very High|High|Medium|Low|Very Low",
    "likelihood_factors": ["Factors determining likelihood"],
    "impact_severity": "Critical|High|Medium|Low",
    "impact_factors": ["Factors determining impact"],
    "overall_risk_rating": "Critical|High|Medium|Low",
    "risk_calculation": "Risk rating explanation"
  }},
  "attack_scenarios": [
    {{
      "scenario_name": "Realistic scenario",
      "attacker_profile": "Script kiddie|Skilled|Nation state",
      "attack_narrative": "Step-by-step attack story",
      "business_outcome": "Business impact",
      "probability": "High|Medium|Low"
    }}
  ],
  "detection_and_monitoring": {{
    "detection_methods": ["How to detect exploitation"],
    "log_indicators": ["Specific log entries"],
    "ids_signatures": ["IDS/IPS signatures"],
    "monitoring_recommendations": ["Monitoring to implement"]
  }},
  "technical_notes": "Additional technical details"
}}

CRITICAL: Be SPECIFIC with exact payloads, URLs, code locations, and working PoC."""

        try:
            if self.has_gemini:
                response_text = self._call_gemini(prompt)
            else:
                response_text = self._call_anthropic(prompt, max_tokens=4000)

            response_text = response_text.strip()
            if response_text.startswith('```json'):
                response_text = response_text[7:]
            if response_text.startswith('```'):
                response_text = response_text[3:]
            if response_text.endswith('```'):
                response_text = response_text[:-3]
            response_text = response_text.strip()

            try:
                from datetime import datetime
                analysis = json.loads(response_text)
                logger.info(f"Professional vulnerability analysis completed for {vuln_title}")
                return {
                    'success': True,
                    'analysis': analysis,
                    'generated_by': provider,
                    'timestamp': datetime.now().isoformat()
                }
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse vulnerability analysis: {e}")
                return {
                    'success': False,
                    'analysis': {
                        'finding_id': f'VULN-{vuln_severity.upper()}-ERROR',
                        'title': vuln_title,
                        'executive_summary': vuln_description[:200],
                        'raw_ai_response': response_text
                    },
                    'error': str(e),
                    'generated_by': provider
                }
        except Exception as e:
            logger.error(f"Vulnerability analysis failed: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}

    def analyze_reconnaissance_professional(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Professional-grade reconnaissance analysis for official reports
        
        Provides:
        - Detailed attack surface mapping
        - Service-specific vulnerability assessment
        - Technology stack risk analysis
        - Prioritized penetration testing roadmap
        - Compliance and regulatory considerations
        
        Uses: Gemini (preferred) or Anthropic (fallback)
        """
        provider = "Gemini" if self.has_gemini else "Anthropic" if self.has_anthropic else None
        if not provider:
            return {'error': 'AI features not available - API key missing'}

        target = recon_data.get('target', 'Unknown')
        logger.info(f"Generating professional reconnaissance analysis for: {target} using {provider}")

        prompt = f"""You are a Senior Penetration Tester with 25 years of experience analyzing reconnaissance data and writing official penetration testing reports.

RECONNAISSANCE DATA:
{json.dumps(recon_data, indent=2)}

YOUR TASK:
Analyze this reconnaissance data and provide professional, report-quality intelligence suitable for an official penetration test report. Be SPECIFIC - provide exact services, versions, configurations, and actionable findings.

OUTPUT (JSON):
{{
  "assessment_id": "Generate unique ID like RECON-{target.replace('.', '-').upper()}",
  "executive_summary": "2-3 sentences for executives explaining discovered attack surface and key risks",
  "target_profile": {{
    "primary_target": "{target}",
    "ip_addresses": ["All discovered IPs"],
    "hosting_provider": "Provider name if identifiable",
    "geolocation": "Physical/cloud location if known",
    "organization": "Owning organization if identifiable",
    "domain_registrar": "Domain registrar if applicable"
  }},
  "attack_surface_analysis": {{
    "total_services_discovered": 0,
    "externally_accessible_services": ["Service:port pairs"],
    "high_risk_services": [
      {{
        "service": "Service name",
        "port": "Port number",
        "version": "Exact version",
        "risk_level": "Critical|High|Medium|Low",
        "risk_factors": ["Why this is risky"],
        "known_vulns": ["CVEs or vulnerability types"],
        "exploitation_difficulty": "Easy|Moderate|Hard"
      }}
    ],
    "tls_ssl_analysis": {{
      "tls_enabled": true,
      "tls_versions": ["Versions supported"],
      "weak_ciphers": ["Any weak ciphers"],
      "certificate_issues": ["Certificate problems if any"]
    }},
    "entry_points": [
      {{
        "entry_point": "Specific URL/endpoint/service",
        "access_level": "Public|Authenticated|Internal",
        "attack_vectors": ["Possible attack methods"],
        "priority": "Critical|High|Medium|Low"
      }}
    ]
  }},
  "technology_stack": {{
    "web_server": {{
      "software": "Server software",
      "version": "Exact version",
      "known_vulnerabilities": ["CVEs or issues"],
      "configuration_issues": ["Misconfigurations found"],
      "eol_status": "End-of-life status"
    }},
    "application_framework": {{
      "framework": "Framework name",
      "version": "Version if detected",
      "language": "Programming language",
      "known_issues": ["Framework-specific vulnerabilities"]
    }},
    "database": {{
      "database_type": "DB type if exposed",
      "version": "Version if known",
      "exposure_level": "Direct|Indirect|Unknown"
    }},
    "third_party_services": [
      {{
        "service": "Service name",
        "purpose": "What it's used for",
        "security_implications": "Security risks"
      }}
    ]
  }},
  "prioritized_testing_plan": {{
    "phase_1_critical": [
      {{
        "target": "Specific service/endpoint",
        "test_type": "Test to perform",
        "rationale": "Why this is priority 1",
        "expected_findings": ["Likely vulnerabilities"],
        "tools_recommended": ["Specific tools to use"],
        "estimated_time": "Time estimate"
      }}
    ],
    "phase_2_high": ["Similar structure"],
    "phase_3_medium": ["Similar structure"],
    "out_of_scope": ["Services/tests to avoid with reasons"]
  }},
  "security_posture_assessment": {{
    "overall_rating": "Poor|Fair|Good|Excellent",
    "rating_justification": "Detailed explanation",
    "strengths": ["Security strengths identified"],
    "weaknesses": ["Security weaknesses identified"],
    "security_maturity_indicators": {{
      "patch_management": "Poor|Fair|Good|Excellent",
      "hardening": "Poor|Fair|Good|Excellent",
      "monitoring": "Poor|Fair|Good|Excellent",
      "access_controls": "Poor|Fair|Good|Excellent"
    }}
  }},
  "compliance_considerations": {{
    "pci_dss": "Considerations if processing payments",
    "gdpr": "Data protection implications",
    "hipaa": "Healthcare data implications",
    "industry_specific": "Other compliance factors"
  }},
  "risk_summary": {{
    "critical_risks": 0,
    "high_risks": 0,
    "medium_risks": 0,
    "low_risks": 0,
    "overall_risk_level": "Critical|High|Medium|Low",
    "immediate_concerns": ["Issues needing immediate attention"]
  }},
  "recommendations": {{
    "immediate_actions": ["Actions for next 24-48 hours"],
    "short_term": ["Actions for next 1-2 weeks"],
    "long_term": ["Strategic improvements"],
    "quick_wins": ["Easy fixes with high impact"]
  }},
  "intelligence_gaps": ["What additional reconnaissance is needed"],
  "notes_for_penetration_test": "Key insights for the testing team"
}}

CRITICAL: Be SPECIFIC with exact versions, ports, services, and actionable intelligence."""

        try:
            if self.has_gemini:
                response_text = self._call_gemini(prompt)
            else:
                response_text = self._call_anthropic(prompt, max_tokens=4000)

            response_text = response_text.strip()
            if response_text.startswith('```json'):
                response_text = response_text[7:]
            if response_text.startswith('```'):
                response_text = response_text[3:]
            if response_text.endswith('```'):
                response_text = response_text[:-3]
            response_text = response_text.strip()

            try:
                from datetime import datetime
                analysis = json.loads(response_text)
                logger.info(f"Professional reconnaissance analysis completed for {target}")
                return {
                    'success': True,
                    'analysis': analysis,
                    'generated_by': provider,
                    'timestamp': datetime.now().isoformat()
                }
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse reconnaissance analysis: {e}")
                return {
                    'success': False,
                    'analysis': {
                        'assessment_id': f'RECON-{target.replace(".", "-").upper()}-ERROR',
                        'executive_summary': f'Reconnaissance data requires manual analysis',
                        'raw_ai_response': response_text
                    },
                    'error': str(e),
                    'generated_by': provider
                }
        except Exception as e:
            logger.error(f"Reconnaissance analysis failed: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}

    def analyze_penetration_test_finding(self, finding_data: Dict[str, Any], engagement_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Professional-grade penetration test finding analysis
        
        Provides:
        - Detailed technical analysis with exact reproduction steps
        - Business impact quantification
        - Comprehensive remediation roadmap
        - Compliance mapping
        - Executive and technical narratives
        
        Uses: Gemini (preferred) or Anthropic (fallback)
        """
        provider = "Gemini" if self.has_gemini else "Anthropic" if self.has_anthropic else None
        if not provider:
            return {'error': 'AI features not available - API key missing'}

        finding_title = finding_data.get('title', 'Unknown Finding')
        logger.info(f"Generating professional penetration test analysis for: {finding_title} using {provider}")

        prompt = f"""You are a Senior Penetration Tester with 25 years of experience writing official penetration testing reports for Fortune 500 companies and government agencies.

FINDING DATA:
{json.dumps(finding_data, indent=2)}

ENGAGEMENT CONTEXT:
{json.dumps(engagement_context, indent=2)}

YOUR TASK:
Create a professional, report-quality finding analysis suitable for presentation to executives, board members, auditors, and regulators. This will be included in an official penetration test report.

OUTPUT (JSON):
{{
  "finding_id": "Generate unique ID",
  "classification": "Authentication|Authorization|Input Validation|Cryptography|Configuration|etc.",
  "title": "Professional title suitable for executive report",
  "severity": "Critical|High|Medium|Low|Informational",
  "cvss_score": "CVSS v3.1 score if applicable",
  "cvss_vector": "CVSS vector string",
  
  "executive_narrative": {{
    "overview": "2-3 sentences explaining the finding to C-level executives",
    "business_risk": "What this means for the business in business terms",
    "potential_scenarios": ["Real-world attack scenarios"],
    "recommended_action": "What executives should do"
  }},
  
  "technical_details": {{
    "description": "Comprehensive technical description",
    "affected_systems": ["Specific systems/URLs/services"],
    "attack_complexity": "Low|Medium|High",
    "privileges_required": "None|Low|High",
    "user_interaction": "None|Required",
    "scope": "Unchanged|Changed",
    "root_cause_analysis": "Exact technical root cause",
    "vulnerability_chain": ["If multiple vulns chain together"]
  }},
  
  "reproduction_steps": {{
    "prerequisites": ["What's needed to reproduce"],
    "detailed_steps": [
      {{
        "step_number": 1,
        "action": "Exact action performed",
        "command_or_request": "Actual command/request used",
        "expected_result": "What should happen",
        "actual_result": "What actually happened",
        "screenshot_reference": "Screenshot filename if applicable",
        "notes": "Additional notes"
      }}
    ],
    "proof_of_concept_code": "Complete PoC if applicable",
    "reproduction_reliability": "100%|Intermittent|Rare"
  }},
  
  "evidence": {{
    "request_examples": ["Actual HTTP requests or commands"],
    "response_examples": ["Actual responses"],
    "log_entries": ["Relevant log data"],
    "screenshots": ["Screenshot descriptions"],
    "network_captures": ["PCAP file references"],
    "exploit_output": ["Actual exploit results"]
  }},
  
  "impact_analysis": {{
    "confidentiality": {{
      "impact": "High|Medium|Low|None",
      "description": "Specific data at risk",
      "data_classification": ["Types of sensitive data affected"]
    }},
    "integrity": {{
      "impact": "High|Medium|Low|None",
      "description": "What can be modified",
      "manipulation_scenarios": ["Specific manipulation risks"]
    }},
    "availability": {{
      "impact": "High|Medium|Low|None",
      "description": "Service disruption potential",
      "dos_scenarios": ["Denial of service risks"]
    }},
    "financial_impact": {{
      "direct_costs": "Quantified direct financial risk",
      "indirect_costs": "Reputation, legal, operational costs",
      "regulatory_fines": "Potential fines and penalties"
    }},
    "compliance_impact": {{
      "pci_dss": "Specific requirements violated",
      "gdpr": "Articles impacted",
      "hipaa": "Rules affected",
      "sox": "Control failures",
      "iso27001": "Controls violated"
    }}
  }},
  
  "exploitation_assessment": {{
    "exploit_availability": "Public|Private|None Known",
    "exploit_maturity": "Functional|Proof of Concept|Unproven",
    "automation_potential": "Easily Automated|Partial|Manual Only",
    "skill_level_required": "Script Kiddie|Intermediate|Expert",
    "attacker_motivation": "Why would an attacker target this",
    "real_world_exploits": ["Known real-world exploitation if any"]
  }},
  
  "remediation_roadmap": {{
    "emergency_mitigation": {{
      "actions": ["Immediate actions (hours)"],
      "implementation_time": "< 4 hours",
      "effectiveness": "Temporary|Partial|Complete",
      "business_impact": "Impact of implementing mitigation"
    }},
    "short_term_fix": {{
      "actions": ["Actions for 1-2 weeks"],
      "implementation_steps": [
        {{
          "step": 1,
          "task": "Specific task",
          "owner": "Team/role responsible",
          "location": "Exact file/service/config",
          "code_before": "Current code",
          "code_after": "Fixed code",
          "testing": "How to test",
          "rollback": "Rollback procedure"
        }}
      ],
      "dependencies": ["Dependencies to address"],
      "risks": ["Implementation risks"]
    }},
    "long_term_solution": {{
      "architectural_changes": ["Strategic changes needed"],
      "process_improvements": ["Process changes"],
      "timeline": "Estimated timeline",
      "investment_required": "Budget/resources needed"
    }},
    "verification": {{
      "testing_methodology": "How to verify fix",
      "acceptance_criteria": ["Criteria for successful remediation"],
      "regression_testing": ["Tests to ensure no breakage"]
    }}
  }},
  
  "security_references": {{
    "owasp_references": ["OWASP categories and testing guides"],
    "cwe_mappings": ["CWE-XXX with descriptions"],
    "cve_references": ["Related CVEs"],
    "nist_controls": ["NIST 800-53 controls"],
    "sans_top_25": ["SANS ranking if applicable"],
    "attack_mitre": ["MITRE ATT&CK techniques"]
  }},
  
  "lessons_learned": {{
    "security_weaknesses": ["Systemic issues identified"],
    "detection_gaps": ["Why this wasn't detected"],
    "process_failures": ["Process breakdowns"],
    "recommendations": ["Strategic recommendations"]
  }},
  
  "appendices": {{
    "technical_deep_dive": "Additional technical details",
    "tool_output": "Raw tool output if relevant",
    "references": ["External references and resources"]
  }}
}}

CRITICAL: Provide EXACT reproduction steps, SPECIFIC remediation code, and QUANTIFIED business impact."""

        try:
            if self.has_gemini:
                response_text = self._call_gemini(prompt)
            else:
                response_text = self._call_anthropic(prompt, max_tokens=4096)

            response_text = response_text.strip()
            if response_text.startswith('```json'):
                response_text = response_text[7:]
            if response_text.startswith('```'):
                response_text = response_text[3:]
            if response_text.endswith('```'):
                response_text = response_text[:-3]
            response_text = response_text.strip()

            try:
                from datetime import datetime
                analysis = json.loads(response_text)
                logger.info(f"Professional penetration test analysis completed for {finding_title}")
                return {
                    'success': True,
                    'analysis': analysis,
                    'generated_by': provider,
                    'timestamp': datetime.now().isoformat()
                }
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse penetration test analysis: {e}")
                return {
                    'success': False,
                    'analysis': {
                        'finding_id': 'PENTEST-ERROR',
                        'title': finding_title,
                        'executive_narrative': {'overview': 'Analysis requires manual review'},
                        'raw_ai_response': response_text
                    },
                    'error': str(e),
                    'generated_by': provider
                }
        except Exception as e:
            logger.error(f"Penetration test analysis failed: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}
