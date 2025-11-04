"""
Tests for Adaptive Reconnaissance
Run with: pytest -k adaptive_recon -v
"""

import pytest
from unittest.mock import patch, MagicMock
from app.modules.recon import ReconEngine
import nmap
import dns.resolver
import socket
import requests

@pytest.fixture
def recon_engine():
    with patch('app.modules.recon.nmap.PortScanner'), \
         patch('app.modules.recon.dns.resolver.Resolver'), \
         patch('app.modules.recon.LearningEngine'):
        return ReconEngine()

class TestReconEngine:
    def test_run_adaptive_recon_with_recommendations(self, recon_engine):
        with patch.object(recon_engine.learning_engine, 'get_recommended_techniques', return_value=['some-recommendation']) as mock_get_recommendations, \
             patch.object(recon_engine, 'port_scan', return_value={'some': 'scan'}) as mock_port_scan, \
             patch.object(recon_engine, '_resolve_to_ip', return_value='127.0.0.1'):
            results = recon_engine.run_adaptive_recon('example.com', {'technologies': ['nginx']})

            mock_get_recommendations.assert_called_once_with({'technologies': ['nginx']})
            mock_port_scan.assert_called_once_with('127.0.0.1', ports='80,443,8080')
            assert results['adaptive_scan'] is True
            assert results['port_scan'] == {'some': 'scan'}

    def test_run_adaptive_recon_without_recommendations(self, recon_engine):
        with patch.object(recon_engine.learning_engine, 'get_recommended_techniques', return_value=[]) as mock_get_recommendations, \
             patch.object(recon_engine, 'run_full_recon', return_value={'full': 'recon'}) as mock_full_recon:
            results = recon_engine.run_adaptive_recon('example.com', {'technologies': ['nginx']})

            mock_get_recommendations.assert_called_once_with({'technologies': ['nginx']})
            mock_full_recon.assert_called_once_with('example.com')
            assert results == {'full': 'recon'}

    def test_identify_target_type(self, recon_engine):
        assert recon_engine._identify_target_type('http://example.com') == 'url'
        assert recon_engine._identify_target_type('https://example.com') == 'url'
        assert recon_engine._identify_target_type('192.168.1.1') == 'ip'
        assert recon_engine._identify_target_type('sub.example.com') == 'subdomain'
        assert recon_engine._identify_target_type('example.com') == 'domain'
        assert recon_engine._identify_target_type('unknown_target') == 'unknown'

    @patch('app.modules.recon.socket.gethostbyname', return_value='127.0.0.1')
    def test_resolve_to_ip_success(self, mock_gethostbyname, recon_engine):
        ip = recon_engine._resolve_to_ip('example.com')
        assert ip == '127.0.0.1'
        mock_gethostbyname.assert_called_once_with('example.com')

    @patch('app.modules.recon.socket.gethostbyname', side_effect=socket.gaierror)
    def test_resolve_to_ip_failure(self, mock_gethostbyname, recon_engine):
        ip = recon_engine._resolve_to_ip('nonexistent.com')
        assert ip is None
        mock_gethostbyname.assert_called_once_with('nonexistent.com')

    @patch('app.modules.recon.dns.resolver.Resolver.resolve')
    def test_dns_enumeration(self, mock_resolve, recon_engine):
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = '1.1.1.1'
        mock_resolve.return_value = [mock_answer]
        dns_info = recon_engine.dns_enumeration('example.com')
        assert 'A' in dns_info
        assert '1.1.1.1' in dns_info['A']

    @patch('app.modules.recon.socket.gethostbyname', side_effect=['1.1.1.1', socket.gaierror])
    def test_find_subdomains(self, mock_gethostbyname, recon_engine):
        subdomains = recon_engine.find_subdomains('example.com')
        assert len(subdomains) > 0
        assert 'www.example.com' in subdomains[0]['subdomain']

    @patch('app.modules.recon.nmap.PortScanner')
    def test_port_scan(self, mock_nmap, recon_engine):
        mock_scanner = MagicMock()
        mock_nmap.return_value = mock_scanner
        mock_scanner.all_hosts.return_value = ['127.0.0.1']
        mock_scanner.__getitem__.return_value = {
            'tcp': {
                80: {'state': 'open', 'name': 'http'}
            }
        }

        results = recon_engine.port_scan('127.0.0.1')
        assert 'open_ports' in results
        assert 80 in results['open_ports']

    @patch('app.modules.recon.requests.get')
    @patch('app.modules.recon.BeautifulSoup')
    def test_http_analysis(self, mock_bs, mock_get, recon_engine):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Server': 'nginx', 'Content-Type': 'text/html'}
        mock_response.text = '<html><head><title>Test</title></head></html>'
        mock_response.cookies = []
        mock_get.return_value = mock_response
        mock_bs.return_value.title.string = 'Test'

        results = recon_engine.http_analysis('http://example.com')
        assert results['status_code'] == 200
        assert results['server'] == 'nginx'
        assert results['title'] == 'Test'

    @patch('app.modules.recon.requests.get')
    def test_detect_technologies(self, mock_get, recon_engine):
        mock_response = MagicMock()
        mock_response.headers = {'X-Powered-By': 'PHP/7.4'}
        mock_response.text = '<html><body><script>jQuery</script></body></html>'
        mock_get.return_value = mock_response

        technologies = recon_engine.detect_technologies('http://example.com')
        assert len(technologies) > 0
        assert any(tech['name'] == 'PHP/7.4' for tech in technologies)
        assert any(tech['name'] == 'Jquery' for tech in technologies)

    @patch.object(ReconEngine, '_identify_target_type', return_value='domain')
    @patch.object(ReconEngine, 'dns_enumeration', return_value={'A': ['1.1.1.1']})
    @patch.object(ReconEngine, 'find_subdomains', return_value=[{'subdomain': 'www.example.com'}])
    @patch.object(ReconEngine, '_resolve_to_ip', return_value='1.1.1.1')
    @patch.object(ReconEngine, 'port_scan', return_value={'open_ports': [80]})
    @patch.object(ReconEngine, 'http_analysis', return_value={'status_code': 200})
    @patch.object(ReconEngine, 'detect_technologies', return_value=[{'name': 'nginx'}])
    def test_run_full_recon(self, mock_detect_technologies, mock_http_analysis, mock_port_scan, mock_resolve_to_ip, mock_find_subdomains, mock_dns_enumeration, mock_identify_target_type, recon_engine):
        results = recon_engine.run_full_recon('example.com')
        assert results['target'] == 'example.com'
        assert 'dns_info' in results
        assert 'port_scan' in results
        assert 'http_info' in results
        assert 'subdomains' in results
        assert 'technologies' in results