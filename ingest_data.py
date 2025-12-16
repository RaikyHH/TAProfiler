from dotenv import load_dotenv

# Load environment variables FIRST before importing anything else
load_dotenv()

from app import app
from services.mitre_service import fetch_and_parse_mitre_data
from database import init_db

# Initialize DB context
with app.app_context():
    print("Running manual ingestion...")
    fetch_and_parse_mitre_data()
    print("Done.")
