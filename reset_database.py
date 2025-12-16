"""
Database reset script - removes old database and recreates with new schema
"""
import os
from app import app
from database import db

def reset_database():
    """Delete old database and create new one with updated schema"""

    # Path to database file
    db_path = 'instance/taprofiler.db'

    # Delete old database if it exists
    if os.path.exists(db_path):
        print(f"Deleting old database at {db_path}...")
        os.remove(db_path)
        print("Old database deleted.")
    else:
        print("No existing database found.")

    # Create new database with updated schema
    print("Creating new database with updated schema...")
    with app.app_context():
        db.create_all()
    print("New database created successfully!")
    print("\nNext steps:")
    print("1. Run 'python ingest_data.py' to populate the database with MITRE data")
    print("2. Or run 'python app.py' to start the application (data will load in background)")

if __name__ == '__main__':
    reset_database()
