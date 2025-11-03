import schedule
import time
import logging
from threading import Thread
from app import db
from app.models import ScheduledScan

logger = logging.getLogger(__name__)

def run_scheduler():
    """Run the scheduler in a separate thread."""
    logger.info("Starting scheduler...")
    while True:
        schedule.run_pending()
        time.sleep(1)

def load_scheduled_scans(app):
    """Load existing scheduled scans from the database and add them to the scheduler."""
    with app.app_context():
        scheduled_scans = ScheduledScan.query.all()
        for scan in scheduled_scans:
            add_scheduled_scan(scan.to_dict(), app)
        logger.info(f"Loaded {len(scheduled_scans)} scheduled scans from database.")

def start_scheduler(app):
    """Start the scheduler thread and load existing schedules."""
    load_scheduled_scans(app)
    scheduler_thread = Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()

def add_scheduled_scan(scan_details, app):
    """Add a new scheduled scan."""
    logger.info(f"Scheduling scan: {scan_details}")
    schedule_str = scan_details.get('schedule')
    if not schedule_str:
        logger.error("Schedule string is missing.")
        return

    try:
        # This is a simplified parser. A more robust solution would use a proper parsing library.
        if 'every' in schedule_str and 'day' in schedule_str and 'at' in schedule_str:
            time_str = schedule_str.split('at("')[1].split('")')[0]
            schedule.every().day.at(time_str).do(trigger_scan, scan_details, app)
        else:
            logger.error(f"Unsupported schedule string: {schedule_str}")
    except Exception as e:
        logger.error(f"Error parsing schedule string: {e}")

def trigger_scan(scan_details, app):
    """Trigger a scan by making an API call."""
    logger.info(f"Triggering scan for target: {scan_details['target']}")
    with app.app_context():
        try:
            import requests
            response = requests.post(
                'http://localhost:5000/api/scan/full',
                json=scan_details
            )
            if response.status_code == 200:
                logger.info(f"Scan triggered successfully for target: {scan_details['target']}")
            else:
                logger.error(f"Error triggering scan for target: {scan_details['target']}. Status code: {response.status_code}. Response: {response.text}")
        except Exception as e:
            logger.error(f"Error triggering scan: {e}")
