"""
Tests for ReportGenerator Module
Run with: pytest -k reporter -v
"""

import pytest
import os
import json
from app.modules.reporter import ReportGenerator

@pytest.fixture
def reports_dir(tmpdir):
    return str(tmpdir.mkdir("reports"))

@pytest.fixture
def report_generator(reports_dir):
    return ReportGenerator(reports_dir)

@pytest.fixture
def engagement_data():
    return {
        'id': 1,
        'name': 'Test Engagement',
        'client': 'Test Client',
        'findings': [
            {'title': 'Critical Finding', 'severity': 'critical', 'description': '...'},
            {'title': 'High Finding', 'severity': 'high', 'description': '...'},
        ]
    }

class TestReportGenerator:
    def test_generate_executive_report(self, report_generator, engagement_data, reports_dir):
        filepath = report_generator._generate_executive_report(engagement_data)
        assert os.path.exists(filepath)
        with open(filepath, 'r') as f:
            content = f.read()
        assert "Executive Summary" in content
        assert "Test Engagement" in content

    def test_generate_technical_report(self, report_generator, engagement_data, reports_dir):
        filepath = report_generator._generate_technical_report(engagement_data)
        assert os.path.exists(filepath)
        with open(filepath, 'r') as f:
            content = f.read()
        assert "Technical Security Assessment Report" in content
        assert "Critical Finding" in content

    def test_generate_remediation_report(self, report_generator, engagement_data, reports_dir):
        filepath = report_generator._generate_remediation_report(engagement_data)
        assert os.path.exists(filepath)
        with open(filepath, 'r') as f:
            content = f.read()
        assert "Security Remediation Guide" in content
        assert "Critical Priority" in content

    def test_generate_json_report(self, report_generator, engagement_data, reports_dir):
        filepath = report_generator.generate_json_report(engagement_data)
        assert os.path.exists(filepath)
        with open(filepath, 'r') as f:
            data = json.load(f)
        assert data['name'] == 'Test Engagement'
