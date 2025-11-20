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
            # Use the correct model name for Gemini
            self.gemini_client = genai.GenerativeModel('gemini-1.5-flash-latest')
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
