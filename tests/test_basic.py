"""
Basic Tests for Red Team Agent
Run with: pytest test_basic.py -v
"""

import pytest
import json
from flask_jwt_extended import create_access_token
from app import create_app
from app.models import db, Engagement, Target, Finding, User

@pytest.fixture
def app():
    """Create and configure a test app"""
    app = create_app('testing')

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def test_user(app):
    """Create a test user for authentication"""
    with app.app_context():
        user = User(
            username='testadmin',
            email='testadmin@example.com',
            role='admin',
            is_active=True,
        )
        user.set_password('testpassword123')
        db.session.add(user)
        db.session.commit()
        return user.id

@pytest.fixture
def auth_headers(app, test_user):
    """Generate JWT auth headers for testing"""
    with app.app_context():
        token = create_access_token(
            identity=str(test_user),
            additional_claims={'role': 'admin'}
        )
        return {'Authorization': f'Bearer {token}'}

@pytest.fixture
def client(app):
    """Test client"""
    return app.test_client()

@pytest.fixture
def engagement(app, auth_headers):
    """Create a test engagement"""
    with app.app_context():
        eng = Engagement(
            name="Test Engagement",
            client="Test Client",
            engagement_type="internal",
            scope=json.dumps(["test.example.com"])
        )
        db.session.add(eng)
        db.session.commit()
        return eng.id

# ============================================================================
# BASIC TESTS
# ============================================================================

def test_health_check(client):
    """Test health endpoint"""
    response = client.get('/health')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] in ['healthy', 'degraded']
    assert 'checks' in data
    assert 'timestamp' in data

def test_index(client):
    """Test index endpoint"""
    response = client.get('/')
    assert response.status_code == 200

# ============================================================================
# ENGAGEMENT TESTS
# ============================================================================

def test_create_engagement(client, auth_headers):
    """Test creating an engagement"""
    response = client.post('/api/v1/engagements',
        json={
            'name': 'Test Engagement',
            'client': 'Test Client',
            'type': 'internal'
        },
        headers=auth_headers
    )
    assert response.status_code == 201
    data = response.get_json()
    assert data['success'] is True
    assert 'engagement' in data
    assert data['engagement']['name'] == 'Test Engagement'

def test_list_engagements(client, engagement, auth_headers):
    """Test listing engagements"""
    response = client.get('/api/v1/engagements', headers=auth_headers)
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True
    assert data['count'] >= 1

def test_get_engagement(client, engagement, auth_headers):
    """Test getting a specific engagement"""
    response = client.get(f'/api/v1/engagements/{engagement}', headers=auth_headers)
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True
    assert data['engagement']['id'] == engagement

def test_update_engagement(client, engagement, auth_headers):
    """Test updating an engagement"""
    response = client.put(f'/api/v1/engagements/{engagement}',
        json={'status': 'active'},
        headers=auth_headers
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True
    assert data['engagement']['status'] == 'active'

# ============================================================================
# TARGET TESTS
# ============================================================================

def test_add_target(client, engagement, auth_headers):
    """Test adding a target to engagement"""
    response = client.post(f'/api/v1/engagements/{engagement}/targets',
        json={'target': 'example.com', 'priority': 1},
        headers=auth_headers
    )
    assert response.status_code == 201
    data = response.get_json()
    assert data['success'] is True
    assert data['target']['value'] == 'example.com'

# ============================================================================
# VALIDATION TESTS
# ============================================================================

def test_validate_domain(client):
    """Test target validation - domain"""
    response = client.post('/api/v1/validate-target',
        json={'target': 'example.com'}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data['type'] == 'domain'
    assert data['valid'] is True

def test_validate_url(client):
    """Test target validation - URL"""
    response = client.post('/api/v1/validate-target',
        json={'target': 'https://example.com'}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data['type'] == 'url'
    assert data['valid'] is True

def test_validate_ip(client):
    """Test target validation - IP"""
    response = client.post('/api/v1/validate-target',
        json={'target': '192.168.1.1'}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data['type'] == 'ip'
    assert data['valid'] is True

def test_validate_invalid(client):
    """Test target validation - invalid"""
    response = client.post('/api/v1/validate-target',
        json={'target': 'not-a-valid-target!!!'}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data['valid'] is False

# ============================================================================
# STATISTICS TESTS
# ============================================================================

def test_get_stats(client):
    """Test getting system statistics"""
    response = client.get('/api/v1/stats')
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True
    assert 'stats' in data
    assert 'engagements' in data['stats']
    assert 'findings' in data['stats']

def test_findings_stats(client, engagement, auth_headers):
    """Test getting findings statistics"""
    response = client.get(f'/api/v1/findings/stats?engagement_id={engagement}', headers=auth_headers)
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True
    assert 'stats' in data

# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

def test_engagement_not_found(client, auth_headers):
    """Test getting non-existent engagement"""
    response = client.get('/api/v1/engagements/99999', headers=auth_headers)
    assert response.status_code == 404

def test_missing_required_field(client, auth_headers):
    """Test creating engagement without required field"""
    response = client.post('/api/v1/engagements', json={}, headers=auth_headers)
    assert response.status_code == 400
    data = response.get_json()
    assert data['success'] is False

def test_invalid_target_add(client, engagement, auth_headers):
    """Test adding target without value"""
    response = client.post(f'/api/v1/engagements/{engagement}/targets',
        json={'priority': 1},
        headers=auth_headers
    )
    assert response.status_code == 400

# ============================================================================
# DATABASE MODEL TESTS
# ============================================================================

def test_engagement_model(app):
    """Test Engagement model"""
    with app.app_context():
        eng = Engagement(
            name="Test",
            client="Client",
            engagement_type="internal"
        )
        db.session.add(eng)
        db.session.commit()
        
        retrieved = Engagement.query.filter_by(name="Test").first()
        assert retrieved is not None
        assert retrieved.name == "Test"
        assert retrieved.client == "Client"

def test_target_model(app):
    """Test Target model"""
    with app.app_context():
        eng = Engagement(name="Test", client="Client")
        db.session.add(eng)
        db.session.commit()
        
        target = Target(
            engagement_id=eng.id,
            target_type="domain",
            value="example.com"
        )
        db.session.add(target)
        db.session.commit()
        
        retrieved = Target.query.filter_by(value="example.com").first()
        assert retrieved is not None
        assert retrieved.engagement_id == eng.id

def test_finding_model(app):
    """Test Finding model"""
    with app.app_context():
        eng = Engagement(name="Test", client="Client")
        db.session.add(eng)
        db.session.commit()
        
        finding = Finding(
            engagement_id=eng.id,
            title="Test Finding",
            description="Test description",
            severity="high"
        )
        db.session.add(finding)
        db.session.commit()
        
        retrieved = Finding.query.filter_by(title="Test Finding").first()
        assert retrieved is not None
        assert retrieved.severity == "high"

# ============================================================================
# INTEGRATION TESTS (Optional - require actual scanning)
# ============================================================================

@pytest.mark.slow
def test_recon_scan(client, engagement, auth_headers):
    """Test reconnaissance scan (slow test)"""
    response = client.post('/api/v1/scan/recon',
        json={
            'target': 'example.com',
            'engagement_id': engagement,
            'ai_analysis': False  # Skip AI for testing
        },
        headers=auth_headers
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True
    assert 'results' in data

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def create_test_finding(app, engagement_id, severity='high'):
    """Helper to create a test finding"""
    with app.app_context():
        finding = Finding(
            engagement_id=engagement_id,
            title=f"Test {severity} Finding",
            description="Test description",
            severity=severity,
            status='new'
        )
        db.session.add(finding)
        db.session.commit()
        return finding.id

if __name__ == '__main__':
    pytest.main([__file__, '-v'])