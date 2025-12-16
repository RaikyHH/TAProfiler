"""
Database migration script - adds new columns to existing database
This is safer than deleting the database as it preserves existing data.
"""
import sqlite3
import os
from app import app
from database import db

def migrate_database():
    """Add new Feedly enrichment columns to existing database"""

    db_path = 'instance/taprofiler.db'

    if not os.path.exists(db_path):
        print("No database found. Run 'python app.py' to create a new one.")
        return

    print(f"Migrating database at {db_path}...")

    # Connect to database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # List of new columns to add
    new_columns = [
        ("motivations", "TEXT"),
        ("associated_malware", "TEXT"),
        ("target_entities", "TEXT"),
        ("popularity", "INTEGER"),
        ("knowledge_base_url", "TEXT"),
        ("badges", "TEXT"),
        ("first_seen_at", "TEXT"),
        ("feedly_id", "TEXT")
    ]

    # Check which columns already exist
    cursor.execute("PRAGMA table_info(threat_actor)")
    existing_columns = {row[1] for row in cursor.fetchall()}

    # Add missing columns
    added_count = 0
    for column_name, column_type in new_columns:
        if column_name not in existing_columns:
            try:
                cursor.execute(f"ALTER TABLE threat_actor ADD COLUMN {column_name} {column_type}")
                print(f"[+] Added column: {column_name}")
                added_count += 1
            except sqlite3.Error as e:
                print(f"[!] Error adding column {column_name}: {e}")
        else:
            print(f"[=] Column already exists: {column_name}")

    # Create settings table if it doesn't exist
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY,
                trusted_domains TEXT
            )
        """)
        print("[+] Settings table created or already exists")
    except sqlite3.Error as e:
        print(f"[!] Error creating settings table: {e}")

    # Commit changes
    conn.commit()
    conn.close()

    if added_count > 0:
        print(f"\n[SUCCESS] Migration complete! Added {added_count} new column(s).")
        print("\nNext steps:")
        print("1. Run 'python ingest_data.py' to re-ingest data with Feedly enrichment")
        print("2. Or run 'python app.py' to start the application")
    else:
        print("\n[SUCCESS] Database is already up to date!")

if __name__ == '__main__':
    migrate_database()
