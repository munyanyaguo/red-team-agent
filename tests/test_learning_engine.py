"""
Tests for LearningEngine behaviors
Run with: pytest -k learning_engine -v
"""

import json
import pytest
from datetime import datetime, timedelta

from app import create_app
from app.models import db, AttackKnowledge, ScanFeedback
from app.modules.learning_engine import LearningEngine


@pytest.fixture
def app():
    app = create_app('testing')
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def engine():
    return LearningEngine()


def _mk_feedback(app, **overrides):
    with app.app_context():
        fb = ScanFeedback(
            finding_id=overrides.get('finding_id', 1),
            outcome=overrides.get('outcome', 'successful'),
            detection_method=overrides.get('detection_method', 'nmap'),
            time_to_detect=overrides.get('time_to_detect', 5.0),
            environmental_factors=overrides.get('environmental_factors', {'attack_type': 'web', 'target_tech': 'nginx'})
        )
        db.session.add(fb)
        db.session.commit()
        return fb


# ----------------------------------------------------------------------------
# Behaviors being tested
# ----------------------------------------------------------------------------
# 1. record_scan_outcome should persist feedback and update the knowledge base
# 2. _update_knowledge_base should create new knowledge entry if not exists and update counters
# 3. _update_knowledge_base should update success metrics and effectiveness score correctly
# 4. get_recommended_techniques should return sorted recommendations limited by `limit`
# 5. get_recommended_techniques should include relevance boost when target tech matches
# 6. analyze_performance_trends should return insufficient_data when no recent feedback
# 7. analyze_performance_trends should compute rates and averages correctly over period
# 8. record_scan_outcome should handle non-success outcomes affecting rates


def test_record_scan_outcome_persists_and_updates(app, engine):
    with app.app_context():
        engine.record_scan_outcome(
            finding_id=42,
            outcome='successful',
            detection_method='sqlmap',
            time_taken=3.2,
            environment={'attack_type': 'web', 'target_tech': 'mysql'}
        )
        # feedback persisted
        fb = ScanFeedback.query.filter_by(finding_id=42).first()
        assert fb is not None
        assert fb.detection_method == 'sqlmap'
        # knowledge created/updated
        kn = AttackKnowledge.query.filter_by(technique='sqlmap', target_pattern='mysql').first()
        assert kn is not None
        assert kn.times_used >= 1
        assert kn.times_successful >= 1
        assert kn.success_rate == pytest.approx(kn.times_successful / kn.times_used)


def test_update_knowledge_base_creates_and_increments(app, engine):
    with app.app_context():
        # Initially absent
        assert AttackKnowledge.query.filter_by(technique='nmap', target_pattern='nginx').first() is None
        engine._update_knowledge_base('nmap', 'true_positive', {'attack_type': 'net', 'target_tech': 'nginx'})
        kn = AttackKnowledge.query.filter_by(technique='nmap', target_pattern='nginx').first()
        assert kn is not None
        assert kn.attack_type == 'net'
        assert kn.times_used == 1
        assert kn.times_successful == 1
        prev_score = kn.effectiveness_score
        # Call again with non-success to change ratios
        engine._update_knowledge_base('nmap', 'false_positive', {'attack_type': 'net', 'target_tech': 'nginx'})
        db.session.refresh(kn)
        assert kn.times_used == 2
        assert kn.times_successful == 1
        assert kn.effectiveness_score != prev_score


def test_recommendations_sorted_and_limited(app, engine):
    with app.app_context():
        # Seed knowledge with varying effectiveness and usage > 4
        for i in range(6):
            kn = AttackKnowledge(
                attack_type='web',
                target_pattern='nginx' if i % 2 == 0 else 'apache',
                technique=f'tech-{i}',
                context={'seed': i}
            )
            kn.times_used = 5 + i
            kn.times_successful = 3 + (i % 3)
            kn.success_rate = kn.times_successful / kn.times_used
            kn.last_used = datetime.utcnow() - timedelta(days=i)
            # effectiveness similar to production formula
            kn.effectiveness_score = 0.6 * kn.success_rate + 0.4 * max(0, 1 - (i / 365))
            db.session.add(kn)
        db.session.commit()

        recs = engine.get_recommended_techniques({'technologies': ['nginx']}, limit=3)
        assert len(recs) == 3
        # Ensure sorted by effectiveness + relevance
        scores = [r['effectiveness_score'] + r['relevance'] for r in recs]
        assert scores == sorted(scores, reverse=True)
        # All fields present
        for r in recs:
            assert set(r.keys()) == {"technique", "success_rate", "effectiveness_score", "times_used", "relevance"}


def test_recommendations_relevance_boost(app, engine):
    with app.app_context():
        # Two techniques with identical effectiveness, one matching tech
        for tech, pattern in [('a', 'nginx'), ('b', 'iis')]:
            kn = AttackKnowledge(
                attack_type='web',
                target_pattern=pattern,
                technique=tech,
                context={}
            )
            kn.times_used = 10
            kn.times_successful = 5
            kn.success_rate = 0.5
            kn.last_used = datetime.utcnow()
            kn.effectiveness_score = 0.5
            db.session.add(kn)
        db.session.commit()

        recs = engine.get_recommended_techniques({'technologies': ['nginx']}, limit=1)
        assert len(recs) == 1
        assert recs[0]['technique'] == 'a'  # nginx relevant
        assert recs[0]['relevance'] == 0.5


def test_analyze_trends_insufficient_data(app, engine):
    with app.app_context():
        result = engine.analyze_performance_trends(days=7)
        assert result == {'status': 'insufficient_data'}


def test_analyze_trends_computation(app, engine):
    with app.app_context():
        # 3 feedbacks within window: 2 success, 1 false_positive
        for outcome in ['successful', 'true_positive', 'false_positive']:
            _mk_feedback(app, outcome=outcome, time_to_detect=10.0)
        result = engine.analyze_performance_trends(days=30)
        assert result['period_days'] == 30
        assert result['total_scans'] == 3
        assert result['success_rate'] == pytest.approx(2/3)
        assert result['false_positive_rate'] == pytest.approx(1/3)
        assert result['average_detection_time'] == pytest.approx(10.0)


def test_record_scan_outcome_non_success_affects_rates(app, engine):
    with app.app_context():
        # First a success
        engine.record_scan_outcome(1, 'successful', 'wfuzz', 4.0, {'attack_type': 'web', 'target_tech': 'nginx'})
        # Then false positive
        engine.record_scan_outcome(2, 'false_positive', 'wfuzz', 6.0, {'attack_type': 'web', 'target_tech': 'nginx'})
        kn = AttackKnowledge.query.filter_by(technique='wfuzz', target_pattern='nginx').first()
        assert kn is not None
        assert kn.times_used == 2
        assert kn.times_successful == 1
        assert kn.success_rate == pytest.approx(0.5)
