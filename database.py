import sqlite3
import os
from werkzeug.security import generate_password_hash

DATABASE = "database.db"

def init_db():
    # Remove existing database for a clean start
    if os.path.exists(DATABASE):
        try:
            os.remove(DATABASE)
            print(f"Removed existing {DATABASE}")
        except PermissionError:
            print(f"Error: Could not remove {DATABASE}. Please ensure the app is not running.")
            return

    conn = sqlite3.connect(DATABASE)
    conn.execute("PRAGMA foreign_keys = ON")
    cursor = conn.cursor()

    # 1. USERS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        id_proof_path TEXT,
        verification_status TEXT DEFAULT 'Pending',
        verified_by INTEGER,
        verified_at TIMESTAMP,
        FOREIGN KEY (verified_by) REFERENCES users(id)
    )
    """)

    # 2. EVACUEES
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS evacuees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        contact TEXT NOT NULL,
        town TEXT NOT NULL,
        city TEXT NOT NULL,
        district TEXT NOT NULL,
        state TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # 3. VOLUNTEERS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS volunteers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        contact TEXT NOT NULL,
        town TEXT NOT NULL,
        city TEXT NOT NULL,
        district TEXT NOT NULL,
        state TEXT NOT NULL,
        shelter_id INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (shelter_id) REFERENCES shelters(id)
    )
    """)

    # 4. SHELTERS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS shelters (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        town TEXT NOT NULL,
        city TEXT NOT NULL,
        district TEXT NOT NULL,
        state TEXT NOT NULL,
        capacity INTEGER NOT NULL,
        occupancy INTEGER DEFAULT 0,
        status TEXT DEFAULT 'ACTIVE'
    )
    """)

    # 5. SHELTER REQUESTS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS shelter_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evacuee_id INTEGER NOT NULL,
        reason TEXT NOT NULL,
        category TEXT,
        group_size INTEGER DEFAULT 1,
        priority_score INTEGER DEFAULT 0,
        check_in_status TEXT DEFAULT 'Pending',
        review_status TEXT DEFAULT 'Pending',
        reviewed_by INTEGER,
        assignment_status TEXT DEFAULT 'Not Assigned',
        shelter_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (evacuee_id) REFERENCES evacuees(id) ON DELETE CASCADE,
        FOREIGN KEY (reviewed_by) REFERENCES volunteers(id),
        FOREIGN KEY (shelter_id) REFERENCES shelters(id)
    )
    """)

    # 6. SHELTER SUPPLIES
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS shelter_supplies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        shelter_id INTEGER NOT NULL,
        item_name TEXT NOT NULL,
        quantity INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (shelter_id) REFERENCES shelters(id) ON DELETE CASCADE
    )
    """)

    # 7. MEDICAL REQUESTS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS medical_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evacuee_id INTEGER NOT NULL,
        shelter_id INTEGER NOT NULL,
        request_details TEXT NOT NULL,
        status TEXT DEFAULT 'Pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (evacuee_id) REFERENCES evacuees(id) ON DELETE CASCADE,
        FOREIGN KEY (shelter_id) REFERENCES shelters(id) ON DELETE CASCADE
    )
    """)

    # 8. DISASTER STATUS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS disaster_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        disaster_type TEXT NOT NULL,
        status TEXT DEFAULT 'ACTIVE',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 9. ALERTS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 10. VOLUNTEER TASKS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS volunteer_tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        volunteer_id INTEGER NOT NULL,
        task_description TEXT NOT NULL,
        status TEXT DEFAULT 'Pending',
        FOREIGN KEY (volunteer_id) REFERENCES volunteers(id) ON DELETE CASCADE
    )
    """)

    # 11. MISSING PERSON REPORTS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS missing_person_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        age INTEGER NOT NULL,
        last_seen_location TEXT NOT NULL,
        description TEXT NOT NULL,
        reported_by INTEGER NOT NULL,
        report_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (reported_by) REFERENCES evacuees(id) ON DELETE CASCADE
    )
    """)

    # DEFAULT ADMIN
    # Ensure verification_status is 'Verified' for admin to prevent locking
    cursor.execute("""
    INSERT INTO users (username, password, role, verification_status)
    VALUES (?, ?, 'admin', 'Verified')
    """, ("admin", generate_password_hash("admin")))

    # Initial Disaster Status
    cursor.execute("INSERT INTO disaster_status (disaster_type) VALUES ('System Normal - No active disaster')")

    conn.commit()
    conn.close()
    print("Database initialized successfully with clean state.")

if __name__ == "__main__":
    init_db()
