"""
Tests for AISecurityAgent Module
Run with: pytest -k ai_agent -v
"""

import pytest
from unittest.mock import patch, MagicMock
from app.modules.ai_agent import AISecurityAgent

@pytest.fixture
def ai_agent_mocked():
    with patch('app.modules.ai_agent.anthropic.Anthropic') as mock_anthropic:
        mock_client = MagicMock()
        mock_anthropic.return_value = mock_client
        yield AISecurityAgent(api_key='test-key'), mock_client

class TestAISecurityAgent:
    def test_analyze_reconnaissance(self, ai_agent_mocked):
        ai_agent, mock_client = ai_agent_mocked
        mock_client.messages.create.return_value.content = [MagicMock(text='{"attack_surface": "test"}')]

        recon_data = {'target': 'example.com'}
        result = ai_agent.analyze_reconnaissance(recon_data)

        assert 'attack_surface' in result
        assert result['attack_surface'] == 'test'

    def test_analyze_vulnerabilities(self, ai_agent_mocked):
        ai_agent, mock_client = ai_agent_mocked
        mock_client.messages.create.return_value.content = [MagicMock(text='{"executive_summary": "test"}')]

        findings = [{'title': 'test finding'}]
        result = ai_agent.analyze_vulnerabilities(findings)

        assert 'executive_summary' in result
        assert result['executive_summary'] == 'test'

    def test_generate_attack_strategy(self, ai_agent_mocked):
        ai_agent, mock_client = ai_agent_mocked
        mock_client.messages.create.return_value.content = [MagicMock(text='{"initial_access": "test"}')]

        target_info = {'target': 'example.com'}
        result = ai_agent.generate_attack_strategy(target_info)

        assert 'initial_access' in result
        assert result['initial_access'] == 'test'

    def test_explain_vulnerability(self, ai_agent_mocked):
        ai_agent, mock_client = ai_agent_mocked
        mock_client.messages.create.return_value.content = [MagicMock(text='test explanation')]

        vulnerability = {'title': 'test finding'}
        result = ai_agent.explain_vulnerability(vulnerability)

        assert result == 'test explanation'

    def test_analyze_with_self_critique(self, ai_agent_mocked):
        ai_agent, mock_client = ai_agent_mocked

        with patch.object(ai_agent, 'analyze_vulnerabilities', side_effect=[
            {'executive_summary': 'initial analysis'},
            {'executive_summary': 'refined analysis'}
        ]) as mock_analyze, \
             patch.object(ai_agent, '_critique_analysis', side_effect=[
                {'quality_score': 0.5, 'improvements_needed': ['test improvement']},
                {'quality_score': 0.9, 'improvements_needed': []}
             ]) as mock_critique:

            findings = [{'title': 'test'}]
            result = ai_agent.analyze_with_self_critique(findings)

            assert result['executive_summary'] == 'refined analysis'
            assert mock_analyze.call_count == 2

    def test_critique_analysis_error_handling(self, ai_agent_mocked):
        ai_agent, mock_client = ai_agent_mocked
        mock_client.messages.create.side_effect = Exception("API Error")

        analysis = {'executive_summary': 'test'}
        findings = [{'title': 'test'}]
        result = ai_agent._critique_analysis(analysis, findings)

        assert result['quality_score'] == 0
        assert "Critique failed" in result['improvements_needed'][0]

    def test_parse_critique_response_invalid_json(self, ai_agent_mocked):
        ai_agent, mock_client = ai_agent_mocked
        response_text = "invalid json"
        result = ai_agent._parse_critique_response(response_text)

        assert result['quality_score'] == 0
        assert "Failed to parse AI critique" in result['improvements_needed'][0]

    def test_refine_analysis_with_improvements(self, ai_agent_mocked):
        ai_agent, mock_client = ai_agent_mocked
        current_analysis = {'executive_summary': 'initial'}
        improvements = ["Accuracy: Are severity ratings appropriate?"]
        findings = [{'title': 'test'}]

        with patch.object(ai_agent, 'analyze_vulnerabilities', return_value={'executive_summary': 'refined'}) as mock_analyze:
            result = ai_agent._refine_analysis(current_analysis, improvements, findings)

            assert result['executive_summary'] == 'refined'
            mock_analyze.assert_called_once_with(findings)

    def test_generate_executive_summary_error_handling(self, ai_agent_mocked):
        ai_agent, mock_client = ai_agent_mocked
        mock_client.messages.create.side_effect = Exception("API Error")

        engagement_data = {'name': 'test'}
        result = ai_agent.generate_executive_summary(engagement_data)

        assert "Error generating summary" in result

    def test_suggest_exploitation_method_error_handling(self, ai_agent_mocked):
        ai_agent, mock_client = ai_agent_mocked
        mock_client.messages.create.side_effect = Exception("API Error")

        vulnerability = {'title': 'test'}
        result = ai_agent.suggest_exploitation_method(vulnerability)

        assert 'error' in result
        assert "API Error" in result['error']

    def test_generate_executive_summary_success(self, ai_agent_mocked):
        ai_agent, mock_client = ai_agent_mocked
        mock_client.messages.create.return_value.content = [MagicMock(text='test summary')]

        engagement_data = {'name': 'test engagement'}
        result = ai_agent.generate_executive_summary(engagement_data)

        assert result == 'test summary'

    def test_suggest_exploitation_method_success(self, ai_agent_mocked):
        ai_agent, mock_client = ai_agent_mocked
        mock_client.messages.create.return_value.content = [MagicMock(text='{"method": "test method"}')]

        vulnerability = {'title': 'test vuln'}
        result = ai_agent.suggest_exploitation_method(vulnerability)

        assert 'method' in result
        assert result['method'] == 'test method'

    def test_ai_features_disabled(self):
        ai_agent = AISecurityAgent(api_key=None)

        recon_data = {'target': 'example.com'}
        result = ai_agent.analyze_reconnaissance(recon_data)
        assert result == {'error': 'AI features not available - API key missing'}

        findings = [{'title': 'test finding'}]
        result = ai_agent.analyze_vulnerabilities(findings)
        assert result == {'error': 'AI features not available - API key missing'}

        target_info = {'target': 'example.com'}
        result = ai_agent.generate_attack_strategy(target_info)
        assert result == {'error': 'AI features not available - API key missing'}

        vulnerability = {'title': 'test finding'}
        result = ai_agent.explain_vulnerability(vulnerability)
        assert result == 'AI explanation not available - API key missing'

        engagement_data = {'name': 'test engagement'}
        result = ai_agent.generate_executive_summary(engagement_data)
        assert result == 'AI summary not available - API key missing'

        result = ai_agent.suggest_exploitation_method(vulnerability)
        assert result == {'error': 'AI features not available - API key missing'}
