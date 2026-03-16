import os
import time
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from flask_wtf.csrf import CSRFProtect
from markupsafe import escape
import re
import uuid

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_secret")
csrf = CSRFProtect(app)

# Custom decorator for multiple roles
def roles_accepted(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if session.get("role") not in roles:
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return decorated
    return wrapper

UPLOAD_FOLDER = 'static/uploads/id_proofs'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB max

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

DATABASE = "database.db"


# ---------------- DATABASE ----------------

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# ---------------- GLOBAL CONTEXT ----------------
@app.context_processor
def inject_global_data():
    conn = get_db()
    
    active_disaster = conn.execute("SELECT disaster_type FROM disaster_status ORDER BY id DESC LIMIT 1").fetchone()
    latest_alert = conn.execute("SELECT message FROM alerts ORDER BY created_at DESC LIMIT 1").fetchone()
    
    
    
    return {
        'global_disaster_type': active_disaster['disaster_type'] if active_disaster else "System Normal",
        'global_alert': latest_alert['message'] if latest_alert else ""
    }


# ---------------- ROLE DECORATOR ----------------

def role_required(role):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if session.get("role") != role:
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return decorated
    return wrapper


# ---------------- HOME ----------------

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/home")
def role_home():
    role = session.get("role")

    if role == "admin":
        return redirect(url_for("admin_dashboard"))
    elif role == "volunteer":
        return redirect(url_for("volunteer_dashboard"))
    elif role == "evacuee":
        return redirect(url_for("evacuee_dashboard"))

    return redirect(url_for("home"))


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        ).fetchone()
        

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            return redirect(url_for("role_home"))

        flash("Invalid credentials")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        username = request.form["username"]
        old_password = request.form["old_password"]
        new_password = request.form["new_password"]
        
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        
        if not user or not check_password_hash(user["password"], old_password):
            flash("Incorrect original username or password.")
            return redirect(url_for("reset_password"))
            
        if len(new_password) < 8 or not re.search(r"\d", new_password) or not re.search(r"[A-Z]", new_password) or not re.search(r"[@$!%*?&]", new_password):
            flash("Password must be at least 8 characters, and contain a number, an uppercase letter, and a special character.")
            return redirect(url_for("reset_password"))
            
        conn.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(new_password), user["id"]))
        conn.commit()
        
        flash("Password successfully reset! Please login.")
        return redirect(url_for("login"))
        
    return render_template("reset_password.html")



# =====================================================
# ---------------- EVACUEE ----------------
# =====================================================

@app.route("/register/evacuee", methods=["GET", "POST"])
def evacuee_register():
    if request.method == "POST":
        conn = get_db()
        cursor = conn.cursor()

        username = request.form["username"]
        password = request.form["password"]
        contact = request.form["contact"]

        if 'id_proof' not in request.files:
            flash("No ID proof uploaded")
            return redirect(url_for("evacuee_register"))
            
        file = request.files['id_proof']
        if file.filename == '':
            flash("No selected file")
            return redirect(url_for("evacuee_register"))
            
        if not (file and allowed_file(file.filename)):
            flash("Invalid file type. Only jpg, jpeg, png, pdf allowed.")
            return redirect(url_for("evacuee_register"))

        if len(password) < 8 or not re.search(r"\d", password) or not re.search(r"[A-Z]", password) or not re.search(r"[@$!%*?&]", password):
            flash("Password must be at least 8 characters, and contain a number, an uppercase letter, and a special character.")
            return redirect(url_for("evacuee_register"))

        if not contact.isdigit() or len(contact) < 10:
            flash("Enter a valid contact number.")
            return redirect(url_for("evacuee_register"))

        if conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
            flash("Username already exists")
            return redirect(url_for("evacuee_register"))

        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, 'evacuee')",
            (username, generate_password_hash(password))
        )
        user_id = cursor.lastrowid
        
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"user_{user_id}_{int(time.time())}_{uuid.uuid4().hex}.{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        cursor.execute("UPDATE users SET id_proof_path=?, verification_status='Pending' WHERE id=?", (filepath, user_id))

        cursor.execute("""
            INSERT INTO evacuees 
            (user_id, name, contact, town, city, district, state)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            escape(request.form["name"]),
            contact,
            escape(request.form["town"]),
            escape(request.form["city"]),
            escape(request.form["district"]),
            escape(request.form["state"])
        ))

        conn.commit()
        

        flash("Registration successful")
        return redirect(url_for("login"))

    return render_template("evacuee_register.html")


@app.route("/evacuee")
@role_required("evacuee")
def evacuee_dashboard():
    conn = get_db()

    evacuee = conn.execute(
        "SELECT e.id, u.verification_status FROM evacuees e JOIN users u ON e.user_id = u.id WHERE e.user_id=?",
        (session["user_id"],)
    ).fetchone()

    if not evacuee:
        
        flash("Profile not found.")
        return redirect(url_for("logout"))

    request_info = conn.execute("""
        SELECT sr.review_status,
               sr.assignment_status,
               sr.check_in_status,
               s.name AS shelter_name,
               s.town, s.city, s.district, s.state,
               v.name AS volunteer_name,
               v.contact AS volunteer_contact
        FROM shelter_requests sr
        LEFT JOIN shelters s ON sr.shelter_id = s.id
        LEFT JOIN volunteers v ON sr.reviewed_by = v.id
        WHERE sr.evacuee_id=?
        ORDER BY sr.created_at DESC
        LIMIT 1
    """, (evacuee["id"],)).fetchone()

    missing_persons = conn.execute("""
        SELECT * FROM missing_person_reports
        WHERE reported_by=?
        ORDER BY report_time DESC
    """, (evacuee["id"],)).fetchall()

    

    return render_template("evacuee_dashboard.html",
                           request_info=request_info,
                           missing_persons=missing_persons,
                           verification_status=evacuee["verification_status"])


@app.route("/evacuee/request", methods=["GET", "POST"])
@role_required("evacuee")
def submit_request():
    conn = get_db()

    evacuee = conn.execute(
        "SELECT e.*, u.verification_status FROM evacuees e JOIN users u ON e.user_id = u.id WHERE e.user_id=?",
        (session["user_id"],)
    ).fetchone()

    if not evacuee:
        flash("Profile not found.")
        return redirect(url_for("logout"))
        
    if evacuee["verification_status"] != 'Verified':
        flash("Your account must be verified before requesting shelter.")
        return redirect(url_for("evacuee_dashboard"))
        
    nearest_shelters = conn.execute("""
        SELECT * FROM shelters 
        WHERE district=? AND status='ACTIVE' AND occupancy < capacity 
        ORDER BY (capacity - occupancy) DESC LIMIT 5
    """, (evacuee["district"],)).fetchall()

    if request.method == "POST":

        existing = conn.execute("""
            SELECT id FROM shelter_requests
            WHERE evacuee_id=? 
            AND review_status IN ('Pending','Approved')
        """, (evacuee["id"],)).fetchone()

        if existing:
            flash("You already have an active request.")
            return redirect(url_for("submit_request"))

        category = escape(request.form.get("category", ""))
        try:
            group_size = int(request.form.get("group_size", 1))
        except ValueError:
            flash("Group size must be a valid number.")
            return redirect(url_for("submit_request"))
            
        reason = escape(request.form["reason"])
        
        # Priority Scoring System
        priority_score = 0
        cat_lower = category.lower()
        if "child" in cat_lower: priority_score += 2
        if "elderly" in cat_lower: priority_score += 3
        if "disabled" in cat_lower: priority_score += 4
        
        reason_lower = reason.lower()
        if any(word in reason_lower for word in ["medical", "medicine", "wheelchair", "insulin", "asthma", "pregnant"]):
            priority_score += 5

        conn.execute("""
            INSERT INTO shelter_requests (evacuee_id, reason, category, group_size, priority_score)
            VALUES (?, ?, ?, ?, ?)
        """, (evacuee["id"], reason, category, group_size, priority_score))

        conn.commit()
        flash("Shelter request submitted successfully.")
        return redirect(url_for("evacuee_dashboard"))

    
    return render_template("evacuee_request.html", nearest_shelters=nearest_shelters)

@app.route("/verify_evacuees")
@roles_accepted("admin", "volunteer")
def verify_evacuees():
    if session.get("role") not in ["admin", "volunteer"]:
        return redirect(url_for("login"))
        
    conn = get_db()
    pending_users = conn.execute("""
        SELECT u.id as user_id, u.username, u.id_proof_path, e.name, e.contact, e.town, e.city
        FROM users u 
        JOIN evacuees e ON u.id = e.user_id
        WHERE u.verification_status = 'Pending'
    """).fetchall()
    pending_users = pending_users if pending_users else []
    
    return render_template("verify_evacuees.html", pending_users=pending_users)

@app.route("/verify_evacuees/<int:user_id>/<action>", methods=["POST"])
@roles_accepted("admin", "volunteer")
def verify_evacuee_action(user_id, action):
    if session.get("role") not in ["admin", "volunteer"]:
        return redirect(url_for("login"))
        
    conn = get_db()
    if action == "verify":
        conn.execute("UPDATE users SET verification_status='Verified', verified_by=?, verified_at=CURRENT_TIMESTAMP WHERE id=?", (session["user_id"], user_id))
        flash("Evacuee verified successfully.")
    elif action == "reject":
        conn.execute("UPDATE users SET verification_status='Rejected' WHERE id=?", (user_id,))
        flash("Evacuee rejected.")
        
    conn.commit()
    return redirect(url_for("verify_evacuees"))
    

@app.route("/evacuee/medical", methods=["GET", "POST"])
@role_required("evacuee")
def evacuee_medical():
    conn = get_db()
    
    evacuee = conn.execute(
        "SELECT id FROM evacuees WHERE user_id=?",
        (session["user_id"],)
    ).fetchone()
    
    if not evacuee:
        
        flash("Profile not found.")
        return redirect(url_for("logout"))
    
    # Check if they have an assigned shelter
    active_assignment = conn.execute("""
        SELECT shelter_id FROM shelter_requests
        WHERE evacuee_id=? AND assignment_status='Assigned'
    """, (evacuee["id"],)).fetchone()
    
    if not active_assignment:
        flash("You must be assigned to a shelter to request medical assistance.")
        return redirect(url_for("evacuee_dashboard"))
        
    if request.method == "POST":
        details = escape(request.form["request_details"])
        conn.execute("""
            INSERT INTO medical_requests (evacuee_id, shelter_id, request_details)
            VALUES (?, ?, ?)
        """, (evacuee["id"], active_assignment["shelter_id"], details))
        conn.commit()
        flash("Medical request submitted successfully.")
        return redirect(url_for("evacuee_medical"))
        
    requests = conn.execute("""
        SELECT * FROM medical_requests WHERE evacuee_id=? ORDER BY created_at DESC
    """, (evacuee["id"],)).fetchall()
    
    
    return render_template("evacuee_medical.html", requests=requests)

@app.route("/evacuee/checkin", methods=["POST"])
@role_required("evacuee")
def evacuee_checkin():
    conn = get_db()
    evacuee = conn.execute("SELECT id FROM evacuees WHERE user_id=?", (session["user_id"],)).fetchone()
    if evacuee:
        conn.execute("UPDATE shelter_requests SET check_in_status='Checked-In' WHERE evacuee_id=? AND assignment_status='Assigned'", (evacuee["id"],))
        conn.commit()
        flash("Check-in successful! Please see a volunteer for orientation.")
        return redirect(url_for("evacuee_dashboard"))

@app.route("/evacuee/checkout", methods=["POST"])
@role_required("evacuee")
def evacuee_checkout():
    conn = get_db()
    cursor = conn.cursor()
    evacuee = cursor.execute("SELECT id FROM evacuees WHERE user_id=?", (session["user_id"],)).fetchone()
    if evacuee:
        req = cursor.execute("SELECT id, shelter_id, group_size FROM shelter_requests WHERE evacuee_id=? AND assignment_status='Assigned'", (evacuee["id"],)).fetchone()
        if req:
            group_size = req["group_size"] if req["group_size"] else 1
            cursor.execute("UPDATE shelters SET occupancy = MAX(0, occupancy - ?) WHERE id=?", (group_size, req["shelter_id"]))
            cursor.execute("UPDATE shelter_requests SET assignment_status='Completed', check_in_status='Checked-Out' WHERE id=?", (req["id"],))
            conn.commit()
            flash("Successfully checked out of the shelter. Capacity has been freed.")
    return redirect(url_for("evacuee_dashboard"))

@app.route("/evacuee/missing-person", methods=["POST"])
@role_required("evacuee")
def report_missing_person():
    conn = get_db()
    evacuee = conn.execute("SELECT id FROM evacuees WHERE user_id=?", (session["user_id"],)).fetchone()
    if evacuee:
        name = escape(request.form["name"])
        try:
            age = int(request.form["age"])
        except ValueError:
            flash("Age must be a valid number.")
            return redirect(url_for("evacuee_dashboard"))
        location = escape(request.form["last_seen_location"])
        desc = escape(request.form["description"])
        
        conn.execute("""
            INSERT INTO missing_person_reports (name, age, last_seen_location, description, reported_by) 
            VALUES (?, ?, ?, ?, ?)
        """, (name, age, location, desc, evacuee["id"]))
        conn.commit()
        flash("Missing person report submitted. Volunteers and admins have been notified.")
    
    return redirect(url_for("evacuee_dashboard"))


# =====================================================
# ---------------- VOLUNTEER ----------------
# =====================================================

@app.route("/register/volunteer", methods=["GET", "POST"])
def volunteer_register():
    if request.method == "POST":
        conn = get_db()
        cursor = conn.cursor()

        username = request.form["username"]
        password = request.form["password"]
        contact = request.form["contact"]

        if len(password) < 8 or not re.search(r"\d", password) or not re.search(r"[A-Z]", password) or not re.search(r"[@$!%*?&]", password):
            flash("Password must be at least 8 characters, and contain a number, an uppercase letter, and a special character.")
            return redirect(url_for("volunteer_register"))

        if not contact.isdigit() or len(contact) < 10:
            flash("Enter a valid contact number.")
            return redirect(url_for("volunteer_register"))

        if conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
            flash("Username already exists")
            return redirect(url_for("volunteer_register"))

        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, 'volunteer')",
            (username, generate_password_hash(password))
        )
        user_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO volunteers 
            (user_id, name, contact, town, city, district, state)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            escape(request.form["name"]),
            contact,
            escape(request.form["town"]),
            escape(request.form["city"]),
            escape(request.form["district"]),
            escape(request.form["state"])
        ))

        conn.commit()
        

        flash("Registration successful")
        return redirect(url_for("login"))

    return render_template("volunteer_register.html")


@app.route("/volunteer")
@role_required("volunteer")
def volunteer_dashboard():
    conn = get_db()
    
    volunteer = conn.execute(
        "SELECT * FROM volunteers WHERE user_id=?",
        (session["user_id"],)
    ).fetchone()
    
    if not volunteer:
        conn.close()
        flash("Profile not found.")
        return redirect(url_for("logout"))
    
    shelter = None
    evacuees_list = []
    
    if volunteer["shelter_id"]:
        shelter = conn.execute(
            "SELECT * FROM shelters WHERE id=?",
            (volunteer["shelter_id"],)
        ).fetchone()
        
        evacuees_list = conn.execute("""
            SELECT e.name, e.contact, e.town, e.city, sr.category, sr.group_size, sr.priority_score, sr.check_in_status
            FROM shelter_requests sr
            JOIN evacuees e ON sr.evacuee_id = e.id
            WHERE sr.shelter_id=? AND sr.assignment_status='Assigned'
            ORDER BY sr.priority_score DESC
        """, (shelter["id"],)).fetchall()
        
    tasks = conn.execute("SELECT * FROM volunteer_tasks WHERE volunteer_id=?", (volunteer["id"],)).fetchall()
    missing_persons = conn.execute("SELECT * FROM missing_person_reports ORDER BY report_time DESC").fetchall()
        
    
    return render_template("volunteer_dashboard.html", 
                           shelter=shelter, 
                           evacuees_list=evacuees_list,
                           tasks=tasks,
                           missing_persons=missing_persons)


@app.route("/volunteer/review")
@role_required("volunteer")
def volunteer_review():
    conn = get_db()

    volunteer = conn.execute(
        "SELECT * FROM volunteers WHERE user_id=?",
        (session["user_id"],)
    ).fetchone()

    if not volunteer:
        conn.close()
        flash("Profile not found.")
        return redirect(url_for("logout"))

    if not volunteer["shelter_id"]:
        flash("You are not assigned to any shelter")
        return redirect(url_for("volunteer_dashboard"))

    shelter = conn.execute(
        "SELECT * FROM shelters WHERE id=?",
        (volunteer["shelter_id"],)
    ).fetchone()

    requests = conn.execute("""
        SELECT sr.*, e.name, e.town, e.city, e.district, e.state
        FROM shelter_requests sr
        JOIN evacuees e ON sr.evacuee_id = e.id
        WHERE sr.review_status='Pending'
        AND e.district=?
        AND e.state=?
        ORDER BY sr.priority_score DESC
        LIMIT 100
    """, (shelter["district"], shelter["state"])).fetchall()

    

    return render_template("volunteer_review.html",
                           requests=requests)


@app.route("/volunteer/approve/<int:request_id>", methods=["POST"])
@role_required("volunteer")
def approve_request(request_id):
    conn = get_db()
    cursor = conn.cursor()

    volunteer = cursor.execute(
        "SELECT * FROM volunteers WHERE user_id=?",
        (session["user_id"],)
    ).fetchone()
    
    if not volunteer:
        flash("Profile not found.")
        return redirect(url_for("logout"))

    shelter = cursor.execute(
        "SELECT * FROM shelters WHERE id=?",
        (volunteer["shelter_id"],)
    ).fetchone()
    
    shelter_request = cursor.execute(
        "SELECT * FROM shelter_requests WHERE id=?",
        (request_id,)
    ).fetchone()
    
    if not shelter_request:
        flash("Request not found.")
        return redirect(url_for("volunteer_review"))

    available_space = shelter["capacity"] - shelter["occupancy"]
    group_size = shelter_request["group_size"] if shelter_request["group_size"] else 1

    # Atomic update to prevent race conditions
    cursor.execute("""
        UPDATE shelters
        SET occupancy = occupancy + ?
        WHERE id=? AND (capacity - occupancy) >= ?
    """, (group_size, shelter["id"], group_size))
    
    if cursor.rowcount == 0:
        flash(f"Approval failed. The shelter does not have enough capacity for a group of {group_size}.")
        return redirect(url_for("volunteer_review"))
        
    cursor.execute("""
        UPDATE shelter_requests
        SET review_status='Approved',
            assignment_status='Assigned',
            shelter_id=?,
            reviewed_by=?
        WHERE id=?
    """, (shelter["id"], volunteer["id"], request_id))
    
    # Feature 9: Supply Consumption Tracking
    # Assumes standardized consumption mapping per person
    supplies_to_decrement = {
        "Food Packs": 2 * group_size,
        "Water Bottles": 3 * group_size,
        "Blankets": 1 * group_size,
        "First Aid Kits": 0 if group_size < 3 else 1
    }
    
    for item, amount in supplies_to_decrement.items():
        if amount > 0:
            cursor.execute("""
                UPDATE shelter_supplies 
                SET quantity = MAX(0, quantity - ?) 
                WHERE shelter_id = ? AND item_name = ?
            """, (amount, shelter["id"], item))

    conn.commit()
    

    flash("Request approved and shelter assigned")
    return redirect(url_for("volunteer_review"))


@app.route("/volunteer/reject/<int:request_id>", methods=["POST"])
@role_required("volunteer")
def reject_request(request_id):
    conn = get_db()

    conn.execute("""
        UPDATE shelter_requests
        SET review_status='Rejected'
        WHERE id=?
    """, (request_id,))

    conn.commit()
    

    flash("Request rejected")
    return redirect(url_for("volunteer_review"))


@app.route("/volunteer/medical")
@role_required("volunteer")
def volunteer_medical():
    conn = get_db()
    
    volunteer = conn.execute("SELECT shelter_id FROM volunteers WHERE user_id=?", (session["user_id"],)).fetchone()
    
    if not volunteer:
        flash("Profile not found.")
        return redirect(url_for("logout"))
        
    if not volunteer["shelter_id"]:
        flash("You are not assigned to any shelter")
        return redirect(url_for("volunteer_dashboard"))
        
    requests = conn.execute("""
        SELECT mr.*, e.name, e.contact, e.town, e.city 
        FROM medical_requests mr
        JOIN evacuees e ON mr.evacuee_id = e.id
        WHERE mr.shelter_id=? AND mr.status='Pending'
        ORDER BY mr.created_at DESC
    """, (volunteer["shelter_id"],)).fetchall()
    
    supplies = conn.execute("SELECT * FROM shelter_supplies WHERE shelter_id=?", (volunteer["shelter_id"],)).fetchall()
    
    
    return render_template("volunteer_medical.html", requests=requests, supplies=supplies)


@app.route("/volunteer/medical/<int:request_id>/complete", methods=["POST"])
@role_required("volunteer")
def complete_medical(request_id):
    conn = get_db()
    volunteer = conn.execute("SELECT shelter_id FROM volunteers WHERE user_id=?", (session["user_id"],)).fetchone()
    
    if not volunteer or not volunteer["shelter_id"]:
        flash("You are not assigned to a shelter.")
        return redirect(url_for("volunteer_dashboard"))
        
    cursor = conn.cursor()
    cursor.execute("UPDATE medical_requests SET status='Completed' WHERE id=? AND shelter_id=?", (request_id, volunteer["shelter_id"]))
    conn.commit()
    
    if cursor.rowcount == 0:
        flash("Failed to mark request as completed. It may not belong to your shelter.")
    else:
        flash("Medical request marked as completed.")
        
    return redirect(url_for("volunteer_medical"))


# =====================================================
# ---------------- ADMIN ----------------
# =====================================================

@app.route("/admin")
@role_required("admin")
def admin_dashboard():
    conn = get_db()
    
    # Existing stats
    shelters = conn.execute("SELECT * FROM shelters").fetchall()
    volunteers = conn.execute("SELECT * FROM volunteers").fetchall()
    
    # Optimized Analytics (Feature 7) using COUNT(*)
    stats = {
        "total_shelters": conn.execute("SELECT COUNT(*) FROM shelters").fetchone()[0],
        "active_shelters": conn.execute("SELECT COUNT(*) FROM shelters WHERE status='ACTIVE'").fetchone()[0],
        "total_evacuees": conn.execute("SELECT COUNT(*) FROM shelter_requests WHERE assignment_status='Assigned'").fetchone()[0],
        "shelters_full": conn.execute("SELECT COUNT(*) FROM shelters WHERE occupancy >= capacity").fetchone()[0],
        "pending_requests": conn.execute("SELECT COUNT(*) FROM shelter_requests WHERE review_status='Pending'").fetchone()[0],
        "medical_requests": conn.execute("SELECT COUNT(*) FROM medical_requests WHERE status='Pending'").fetchone()[0]
    }
    
    # Fetch Active Disaster Type to display in form
    current_disaster = conn.execute("SELECT disaster_type FROM disaster_status ORDER BY id DESC LIMIT 1").fetchone()
    current_disaster_val = current_disaster["disaster_type"] if current_disaster else "System Normal - No active disaster"

    
    return render_template("admin_dashboard.html", 
                           shelters=shelters, 
                           volunteers=volunteers,
                           stats=stats,
                           current_disaster=current_disaster_val)


@app.route("/admin/shelters", methods=["GET", "POST"])
@role_required("admin")
def manage_shelters():
    conn = get_db()

    if request.method == "POST":
        try:
            capacity = int(request.form["capacity"])
            if capacity <= 0:
                raise ValueError
        except ValueError:
            flash("Capacity must be a valid number greater than 0.")
            return redirect(url_for("manage_shelters"))

        conn.execute("""
            INSERT INTO shelters 
            (name, town, city, district, state, capacity)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            escape(request.form["name"]),
            escape(request.form["town"]),
            escape(request.form["city"]),
            escape(request.form["district"]),
            escape(request.form["state"]),
            capacity
        ))
        conn.commit()

    shelters = conn.execute("SELECT * FROM shelters").fetchall()
    

    return render_template("manage_shelters.html",
                           shelters=shelters)

@app.route("/admin/shelter/<int:shelter_id>/supplies", methods=["GET", "POST"])
@role_required("admin")
def manage_supplies(shelter_id):
    conn = get_db()
    
    shelter = conn.execute("SELECT * FROM shelters WHERE id=?", (shelter_id,)).fetchone()
    if not shelter:
        return redirect(url_for("manage_shelters"))
        
    if request.method == "POST":
        item_name = escape(request.form["item_name"])
        try:
            quantity = int(request.form["quantity"])
            if quantity <= 0:
                raise ValueError
        except ValueError:
            flash("Quantity must be a valid number greater than 0.")
            return redirect(url_for("manage_supplies", shelter_id=shelter_id))
        
        existing = conn.execute("SELECT id FROM shelter_supplies WHERE shelter_id=? AND item_name=?", (shelter_id, item_name)).fetchone()
        
        if existing:
            conn.execute("UPDATE shelter_supplies SET quantity = quantity + ?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (quantity, existing["id"]))
        else:
            conn.execute("INSERT INTO shelter_supplies (shelter_id, item_name, quantity) VALUES (?, ?, ?)", (shelter_id, item_name, quantity))
            
        conn.commit()
        flash(f"Added {quantity} {item_name} to {shelter['name']}.")
        
    supplies = conn.execute("SELECT * FROM shelter_supplies WHERE shelter_id=?", (shelter_id,)).fetchall()
    
    
    return render_template("admin_supplies.html", shelter=shelter, supplies=supplies)

@app.route("/admin/disaster-status", methods=["POST"])
@role_required("admin")
def update_disaster_status():
    conn = get_db()
    new_type = escape(request.form["disaster_type"])
    conn.execute("INSERT INTO disaster_status (disaster_type) VALUES (?)", (new_type,))
    conn.commit()
    
    flash("Disaster status updated successfully.")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/broadcast-alert", methods=["POST"])
@role_required("admin")
def broadcast_alert():
    conn = get_db()
    message = escape(request.form["message"])
    conn.execute("INSERT INTO alerts (message) VALUES (?)", (message,))
    conn.commit()
    
    flash("Alert broadcast successfully.")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/shelter/<int:shelter_id>/toggle", methods=["POST"])
@role_required("admin")
def toggle_shelter_status(shelter_id):
    conn = get_db()
    cursor = conn.cursor()
    
    shelter = cursor.execute("SELECT status FROM shelters WHERE id=?", (shelter_id,)).fetchone()
    
    if shelter:
        new_status = 'INACTIVE' if shelter['status'] == 'ACTIVE' else 'ACTIVE'
        cursor.execute("UPDATE shelters SET status=? WHERE id=?", (new_status, shelter_id))
        conn.commit()
        flash(f"Shelter status updated to {new_status}")
        
    
    return redirect(url_for('manage_shelters'))


@app.route("/admin/assign-volunteer", methods=["GET", "POST"])
@role_required("admin")
def assign_volunteer():
    conn = get_db()

    if request.method == "POST":
        conn.execute("""
            UPDATE volunteers
            SET shelter_id=?
            WHERE id=?
        """, (
            request.form["shelter_id"],
            request.form["volunteer_id"]
        ))
        conn.commit()

    volunteers = conn.execute("SELECT * FROM volunteers").fetchall()
    shelters = conn.execute("SELECT * FROM shelters WHERE status='ACTIVE'").fetchall()
    

    return render_template("admin_assign_volunteer.html",
                           volunteers=volunteers,
                           shelters=shelters)


@app.route("/admin/assigned-requests")
@role_required("admin")
def assigned_requests():
    conn = get_db()

    requests = conn.execute("""
        SELECT e.name,
               e.town, e.city, e.district, e.state,
               s.name AS shelter_name,
               s.town AS shelter_town,
               s.city AS shelter_city,
               s.district AS shelter_district,
               s.state AS shelter_state
        FROM shelter_requests sr
        JOIN evacuees e ON sr.evacuee_id = e.id
        JOIN shelters s ON sr.shelter_id = s.id
        WHERE sr.assignment_status='Assigned'
        ORDER BY sr.created_at DESC
        LIMIT 100
    """).fetchall()

    

    return render_template("admin_assigned_requests.html",
                           requests=requests)


@app.route("/admin/assign-task", methods=["POST"])
@role_required("admin")
def assign_volunteer_task():
    conn = get_db()
    volunteer_id = request.form["volunteer_id"]
    task_desc = escape(request.form["task_description"])
    
    conn.execute("INSERT INTO volunteer_tasks (volunteer_id, task_description) VALUES (?, ?)", 
                 (volunteer_id, task_desc))
    conn.commit()
    
    
    flash("Task assigned to volunteer successfully.")
    return redirect(url_for("admin_dashboard"))

@app.route("/volunteer/tasks/<int:task_id>/complete", methods=["POST"])
@role_required("volunteer")
def complete_volunteer_task(task_id):
    conn = get_db()
    
    volunteer = conn.execute(
        "SELECT id FROM volunteers WHERE user_id=?", 
        (session["user_id"],)
    ).fetchone()
    
    if volunteer:
        conn.execute("UPDATE volunteer_tasks SET status='Completed' WHERE id=? AND volunteer_id=?", 
                     (task_id, volunteer["id"]))
        conn.commit()
        flash("Task marked as completed.")
        
    
    return redirect(url_for("volunteer_dashboard"))

if __name__ == "__main__":
    app.run(debug=True)
