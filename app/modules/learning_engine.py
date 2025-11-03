import logging
from datetime import datetime, timedelta
from app.models import AttackKnowledge, ScanFeedback
from app import db

logger = logging.getLogger(__name__)

class LearningEngine:
    def record_scan_outcome(self, finding_id, outcome, detection_method, time_taken, environment):
        feedback = ScanFeedback(
            finding_id=finding_id,
            outcome=outcome,
            detection_method=detection_method,
            time_to_detect=time_taken,
            environmental_factors=environment
        )
        db.session.add(feedback)
        db.session.commit()
        self._update_knowledge_base(detection_method, outcome, environment)

    def _update_knowledge_base(self, technique, outcome, context):
        knowledge = AttackKnowledge.query.filter_by(
            technique=technique,
            target_pattern=context.get('target_tech')
        ).first()
        if not knowledge:
            knowledge = AttackKnowledge(
                attack_type=context.get('attack_type', 'unknown'),
                target_pattern=context.get('target_tech'),
                technique=technique,
                context=context
            )
            db.session.add(knowledge)
        knowledge.times_used += 1
        knowledge.last_used = datetime.utcnow()
        if outcome in ['true_positive', 'successful']:
            knowledge.times_successful += 1
        knowledge.success_rate = knowledge.times_successful / knowledge.times_used if knowledge.times_used else 0
        knowledge.effectiveness_score = (
            0.6 * knowledge.success_rate +
            0.4 * max(0, 1 - ((datetime.utcnow() - knowledge.last_used).days / 365))
        )
        db.session.commit()
        logger.info(f"Knowledge updated for {technique}: Success rate {knowledge.success_rate:.2%}")

    def get_recommended_techniques(self, target_context, limit=5):
        relevant_knowledge = AttackKnowledge.query.filter(
            AttackKnowledge.times_used > 4
        ).order_by(
            AttackKnowledge.effectiveness_score.desc()
        ).limit(limit * 2).all()

        recommendations = []
        for knowledge in relevant_knowledge:
            technologies = target_context.get('technologies', [])
            relevance = 0.5 if any(t in (knowledge.target_pattern or '') for t in technologies) else 0
            recommendations.append({
                'technique': knowledge.technique,
                'success_rate': knowledge.success_rate,
                'effectiveness_score': knowledge.effectiveness_score,
                'times_used': knowledge.times_used,
                'relevance': relevance
            })
        return sorted(recommendations, key=lambda x: x['effectiveness_score'] + x['relevance'], reverse=True)[:limit]

    def analyze_performance_trends(self, days=30):
        cutoff = datetime.utcnow() - timedelta(days=days)
        feedback = ScanFeedback.query.filter(ScanFeedback.created_at >= cutoff).all()
        if not feedback:
            return {'status': 'insufficient_data'}
        scans = len(feedback)
        successful = sum(1 for f in feedback if f.outcome in ['true_positive', 'successful'])
        false_positives = sum(1 for f in feedback if f.outcome == 'false_positive')
        avg_time = sum(f.time_to_detect for f in feedback if f.time_to_detect) / scans
        return {
            'period_days': days,
            'total_scans': scans,
            'success_rate': successful / scans,
            'false_positive_rate': false_positives / scans,
            'average_detection_time': avg_time
        }