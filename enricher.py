"""
TA-Enricher Service
Standalone service for ingesting and enriching threat actor data from MITRE ATT&CK and Feedly.
Designed to run as a separate container sharing a database volume with the webapp.
Can also run locally for development.
"""

import os
import time
import schedule
from dotenv import load_dotenv
from database import init_db, db
from services.mitre_service import fetch_and_parse_mitre_data
from flask import Flask

# Load environment variables
load_dotenv()

# Create minimal Flask app for database context
app = Flask(__name__)

# Determine database path
# Docker: /data/taprofiler.db (if /data directory exists)
# Local: ./taprofiler.db (current directory)
if os.path.exists('/data') and os.path.isdir('/data'):
    default_db_uri = 'sqlite:////data/taprofiler.db'
    print("[ENRICHER] Running in Docker mode")
else:
    default_db_uri = 'sqlite:///taprofiler.db'
    print("[ENRICHER] Running in local mode")

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', default_db_uri)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
init_db(app)

def run_enrichment():
    """Execute the data enrichment process"""
    with app.app_context():
        print("=" * 70)
        print("TA-ENRICHER: Starting data enrichment cycle")
        print("=" * 70)
        try:
            fetch_and_parse_mitre_data()
            print("=" * 70)
            print("TA-ENRICHER: Enrichment cycle completed successfully")
            print("=" * 70)
        except Exception as e:
            print("=" * 70)
            print(f"TA-ENRICHER: ERROR during enrichment: {e}")
            print("=" * 70)

def main():
    """Main entry point for the enricher service"""
    print("=" * 70)
    print("TA-ENRICHER SERVICE STARTED")
    print("=" * 70)
    print(f"Database: {app.config['SQLALCHEMY_DATABASE_URI']}")
    print(f"Max Actors to Enrich: {os.getenv('MAX_ACTORS_TO_ENRICH', '0 (unlimited)')}")

    run_mode = os.getenv('ENRICHER_MODE', 'once')
    print(f"Run Mode: {run_mode}")

    if run_mode == 'once':
        print("Running enrichment once and exiting...")
        run_enrichment()
        print("TA-ENRICHER: Exiting after single run")
    else:
        schedule_interval = int(os.getenv('ENRICHER_INTERVAL_HOURS', '24'))
        print(f"Schedule: Every {schedule_interval} hours")
        print("=" * 70)

        print("TA-ENRICHER: Running initial enrichment...")
        run_enrichment()

        schedule.every(schedule_interval).hours.do(run_enrichment)
        print(f"TA-ENRICHER: Scheduled to run every {schedule_interval} hours")
        print("TA-ENRICHER: Service running. Press Ctrl+C to stop.")

        while True:
            schedule.run_pending()
            time.sleep(60)

if __name__ == '__main__':
    main()
