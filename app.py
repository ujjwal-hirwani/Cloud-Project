from flask import Flask, render_template, request, redirect, url_for, send_file, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from dotenv import load_dotenv
from datetime import datetime, timedelta
import pytz
import gridfs
from io import BytesIO
from werkzeug.utils import secure_filename
import bcrypt
import random, string
import os
from functools import wraps

# Load environment variables
load_dotenv()

# -----------------------------
# Initialize app
# -----------------------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
IST = pytz.timezone('Asia/Kolkata')

# -----------------------------
# MongoDB Atlas (Flask-PyMongo)
# -----------------------------
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
mongo = PyMongo(app)

users_collection       = mongo.db.users
teams_collection       = mongo.db.teams
hackathons_collection  = mongo.db.hackathons
fs = gridfs.GridFS(mongo.db)

ALLOWED_EXTENSIONS = {'pdf', 'docx', 'ppt', 'pptx'}
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB

# -----------------------------
# Flask-Login setup
# -----------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# -----------------------------
# User model wrapper
# -----------------------------
class User(UserMixin):
    def __init__(self, user_data):
        self.id         = str(user_data['_id'])
        self.regn_no    = user_data['regn_no']
        self.first_name = user_data['first_name']
        self.last_name  = user_data['last_name']
        self.email      = user_data['email']
        self.role       = user_data.get('role', 'participant')

@login_manager.user_loader
def load_user(user_id):
    data = users_collection.find_one({"_id": ObjectId(user_id)})
    return User(data) if data else None

# -----------------------------
# Utilities
# -----------------------------
def hash_password(password: str) -> str:
    salt   = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def check_password(entered_password: str, stored_hashed_password: str) -> bool:
    return bcrypt.checkpw(entered_password.encode('utf-8'), stored_hashed_password.encode('utf-8'))

def generate_otp() -> str:
    return str(random.randint(100000, 999999))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_unique_code(length=6):
    while True:
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
        if not teams_collection.find_one({"code": code}):
            return code

def generate_hackathon_code(length=8):
    while True:
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
        if not hackathons_collection.find_one({"join_code": code}):
            return code

from email_sender import send_email  # after utilities to avoid circulars

# -----------------------------
# Decorators
# -----------------------------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def organizer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'organizer':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def participant_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'participant':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Helper: check if current organizer owns hackathon
def get_hackathon_or_403(hackathon_id, check_owner=False):
    hackathon = hackathons_collection.find_one({"_id": ObjectId(hackathon_id)})
    if not hackathon:
        return None, ("Hackathon not found", 404)
    if check_owner and hackathon.get("organizer_regn") != current_user.regn_no:
        return None, ("Unauthorized", 403)
    return hackathon, None

# ============================================================
#  PUBLIC / AUTH ROUTES
# ============================================================

@app.route('/')
def home():
    hackathons = list(hackathons_collection.find({"status": "open"}))
    for h in hackathons:
        h["_id"] = str(h["_id"])
    return render_template('index.html', hackathons=hackathons)

# ----- Signup -----
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    message = ""
    if request.method == 'POST':
        regn_no    = request.form['regn_no'].strip()
        password   = request.form['password']
        first_name = request.form['first_name'].strip()
        last_name  = request.form['last_name'].strip()
        email      = request.form['email'].strip().lower()
        role       = request.form['role']

        if users_collection.find_one({'regn_no': regn_no}):
            message = "User already registered with this registration number."
            return render_template('signup.html', message=message)
        if users_collection.find_one({'email': email}):
            message = "Email already registered!"
            return render_template('signup.html', message=message)

        hashed_pw   = hash_password(password)
        otp         = generate_otp()
        expiry_time = datetime.utcnow() + timedelta(minutes=5)

        users_collection.insert_one({
            'regn_no':    regn_no,
            'password':   hashed_pw,
            'first_name': first_name,
            'last_name':  last_name,
            'email':      email,
            'role':       role,
            'verified':   False,
            'otp':        otp,
            'otp_expiry': expiry_time
        })

        send_email(
            recipient_email=email,
            subject="TeamUp – Verify your account",
            body=f"Hi {first_name},\n\nYour verification code is: {otp}\nIt will expire in 5 minutes.\n\n— TeamUp."
        )

        return redirect(url_for('verify_email', email=email))

    return render_template('signup.html', message=message)

# ----- Resend OTP -----
@app.route('/resend-otp/<email>', methods=['POST'])
def resend_otp(email):
    email = email.strip().lower()
    user  = users_collection.find_one({'email': email})
    if not user:
        return redirect(url_for('signup'))
    if user.get('verified'):
        return redirect(url_for('login'))

    new_otp    = generate_otp()
    new_expiry = datetime.utcnow() + timedelta(minutes=5)
    users_collection.update_one({'_id': user['_id']}, {'$set': {'otp': new_otp, 'otp_expiry': new_expiry}})

    send_email(
        recipient_email=email,
        subject="Your new verification code",
        body=f"Hi {user.get('first_name', '')},\n\nYour new verification code is: {new_otp}\nIt will expire in 5 minutes.\n\n— TeamUp"
    )
    return redirect(url_for('verify_email', email=email))

# ----- Verify -----
@app.route('/verify/<email>', methods=['GET', 'POST'])
def verify_email(email):
    email   = email.strip().lower()
    message = ""
    if request.method == 'POST':
        entered_otp = request.form['otp'].strip()
        user        = users_collection.find_one({'email': email})

        if not user:
            message = "User not found."
        elif user.get('verified'):
            return redirect(url_for('login'))
        elif not user.get('otp') or not user.get('otp_expiry'):
            message = "No active OTP. Please resend a code."
        elif datetime.utcnow() > user['otp_expiry']:
            message = "OTP expired. Please request a new one."
        elif entered_otp == user['otp']:
            users_collection.update_one(
                {'_id': user['_id']},
                {'$set': {'verified': True}, '$unset': {'otp': "", 'otp_expiry': ""}}
            )
            return redirect(url_for('login'))
        else:
            message = "Invalid OTP. Please try again."

    return render_template('verify.html', email=email, message=message)

# ----- Login -----
@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ""
    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not email or not password:
            message = "Please fill out both email and password."
            return render_template('login.html', message=message)

        user_data = users_collection.find_one({'email': email})

        if user_data and check_password(password, user_data['password']):
            if not user_data.get('verified', False):
                return redirect(url_for('verify_email', email=email))

            user = User(user_data)
            login_user(user)

            role = user_data.get('role', 'participant')
            if role == 'participant':
                return redirect(url_for('participant_dashboard'))
            elif role == 'organizer':
                return redirect(url_for('organizer_dashboard'))
            else:
                message = "Invalid user role."
                logout_user()
        else:
            message = "Invalid credentials."

    return render_template('login.html', message=message)

# ----- Logout -----
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ============================================================
#  PARTICIPANT ROUTES
# ============================================================

@app.route('/participant_dashboard')
@login_required
@participant_required
def participant_dashboard():
    # Hackathons the participant has joined
    joined_hackathon_ids = [
        ObjectId(hid) for hid in
        users_collection.find_one({"regn_no": current_user.regn_no}).get("joined_hackathons", [])
    ]
    my_hackathons = list(hackathons_collection.find({"_id": {"$in": joined_hackathon_ids}}))
    for h in my_hackathons:
        h["_id"] = str(h["_id"])

    # All open hackathons (not yet joined)
    open_hackathons = list(hackathons_collection.find({"status": "open", "_id": {"$nin": joined_hackathon_ids}}))
    for h in open_hackathons:
        h["_id"] = str(h["_id"])

    # Teams the participant is in
    teams = list(teams_collection.find({"users": current_user.regn_no}))
    for team in teams:
        creator = users_collection.find_one({"regn_no": team["created_by"]})
        team["creator_name"] = f"{creator['first_name']} {creator['last_name']}" if creator else "Unknown"
        team["_id"] = str(team["_id"])
        hackathon = hackathons_collection.find_one({"_id": ObjectId(team.get("hackathon_id", ""))}) if team.get("hackathon_id") else None
        team["hackathon_name"] = hackathon["name"] if hackathon else "—"

    return render_template(
        "participant_dashboard.html",
        user=current_user,
        my_hackathons=my_hackathons,
        open_hackathons=open_hackathons,
        teams=teams
    )

# ----- Join Hackathon -----
@app.route('/hackathon/join', methods=['GET', 'POST'])
@login_required
@participant_required
def join_hackathon():
    message = request.args.get('message', '')
    if request.method == 'POST':
        join_code = request.form.get('join_code', '').strip().upper()
        hackathon = hackathons_collection.find_one({"join_code": join_code})

        if not hackathon:
            return redirect(url_for('join_hackathon', message="Invalid hackathon code."))
        if hackathon.get("status") != "open":
            return redirect(url_for('join_hackathon', message="This hackathon is not accepting participants right now."))

        hackathon_id = str(hackathon["_id"])
        user_doc = users_collection.find_one({"regn_no": current_user.regn_no})
        if hackathon_id in user_doc.get("joined_hackathons", []):
            return redirect(url_for('join_hackathon', message="You have already joined this hackathon."))

        users_collection.update_one(
            {"regn_no": current_user.regn_no},
            {"$addToSet": {"joined_hackathons": hackathon_id}}
        )
        hackathons_collection.update_one(
            {"_id": hackathon["_id"]},
            {"$addToSet": {"participants": current_user.regn_no}}
        )
        return redirect(url_for('hackathon_lobby', hackathon_id=hackathon_id))

    return render_template('join_hackathon.html', user=current_user, message=message)

# ----- Hackathon Lobby (participant view) -----
@app.route('/hackathon/<hackathon_id>')
@login_required
@participant_required
def hackathon_lobby(hackathon_id):
    hackathon = hackathons_collection.find_one({"_id": ObjectId(hackathon_id)})
    if not hackathon:
        return redirect(url_for('participant_dashboard'))

    user_doc = users_collection.find_one({"regn_no": current_user.regn_no})
    if hackathon_id not in user_doc.get("joined_hackathons", []):
        return redirect(url_for('participant_dashboard'))

    # Teams in this hackathon
    teams = list(teams_collection.find({"hackathon_id": hackathon_id}))
    for team in teams:
        team["_id"] = str(team["_id"])
        team["points"] = team.get("points", 0)

    leaderboard = sorted(teams, key=lambda x: x["points"], reverse=True)

    # Team the participant belongs to (in this hackathon)
    my_team = teams_collection.find_one({"hackathon_id": hackathon_id, "users": current_user.regn_no})
    if my_team:
        my_team["_id"] = str(my_team["_id"])

    hackathon["_id"] = str(hackathon["_id"])
    return render_template(
        'hackathon_lobby.html',
        user=current_user,
        hackathon=hackathon,
        leaderboard=leaderboard,
        my_team=my_team
    )

# ----- Create Team (within a hackathon) -----
@app.route('/hackathon/<hackathon_id>/create_team', methods=['GET', 'POST'])
@login_required
@participant_required
def create_team(hackathon_id):
    hackathon = hackathons_collection.find_one({"_id": ObjectId(hackathon_id)})
    if not hackathon:
        return redirect(url_for('participant_dashboard'))
    if hackathon.get("teams_locked"):
        flash("Team registration is currently locked by the organizer.", "error")
        return redirect(url_for('hackathon_lobby', hackathon_id=hackathon_id))

    # Participant must have joined this hackathon
    user_doc = users_collection.find_one({"regn_no": current_user.regn_no})
    if hackathon_id not in user_doc.get("joined_hackathons", []):
        return redirect(url_for('participant_dashboard'))

    # Check if user already has a team in this hackathon
    existing = teams_collection.find_one({"hackathon_id": hackathon_id, "users": current_user.regn_no})
    if existing:
        flash("You are already in a team for this hackathon.", "error")
        return redirect(url_for('hackathon_lobby', hackathon_id=hackathon_id))

    message = ""
    if request.method == 'POST':
        team_name   = request.form['team_name'].strip()
        description = request.form['description'].strip()
        github_repo = request.form.get('github_repo', '').strip()

        if teams_collection.find_one({"hackathon_id": hackathon_id, "team_name": team_name}):
            message = "Team name already exists in this hackathon. Choose a different one."
            return render_template('create_team.html', user=current_user, hackathon=hackathon, message=message)

        code     = generate_unique_code()
        now_ist  = datetime.now(IST)

        team_doc = {
            "hackathon_id":  hackathon_id,
            "team_name":     team_name,
            "description":   description,
            "code":          code,
            "created_by":    current_user.regn_no,
            "date":          now_ist.date().isoformat(),
            "time":          now_ist.time().isoformat(timespec="seconds"),
            "users":         [current_user.regn_no],
            "github_repo":   github_repo,
            "points":        0
        }
        teams_collection.insert_one(team_doc)
        return redirect(url_for('hackathon_lobby', hackathon_id=hackathon_id))

    hackathon["_id"] = str(hackathon["_id"])
    return render_template('create_team.html', user=current_user, hackathon=hackathon, message=message)

# ----- Join Team (within a hackathon) -----
@app.route('/hackathon/<hackathon_id>/join_team', methods=['GET', 'POST'])
@login_required
@participant_required
def join_team(hackathon_id):
    hackathon = hackathons_collection.find_one({"_id": ObjectId(hackathon_id)})
    if not hackathon:
        return redirect(url_for('participant_dashboard'))
    if hackathon.get("teams_locked"):
        flash("Team registration is currently locked by the organizer.", "error")
        return redirect(url_for('hackathon_lobby', hackathon_id=hackathon_id))

    user_doc = users_collection.find_one({"regn_no": current_user.regn_no})
    if hackathon_id not in user_doc.get("joined_hackathons", []):
        return redirect(url_for('participant_dashboard'))

    existing = teams_collection.find_one({"hackathon_id": hackathon_id, "users": current_user.regn_no})
    if existing:
        flash("You are already in a team for this hackathon.", "error")
        return redirect(url_for('hackathon_lobby', hackathon_id=hackathon_id))

    message = request.args.get('message', '')
    if request.method == 'POST':
        code = request.form.get('code', '').strip().upper()
        team = teams_collection.find_one({"hackathon_id": hackathon_id, "code": code})

        if not team:
            return redirect(url_for('join_team', hackathon_id=hackathon_id, message="Invalid team code."))
        if current_user.regn_no in team['users']:
            return redirect(url_for('join_team', hackathon_id=hackathon_id, message="You are already in this team."))

        max_size = hackathon.get("max_team_size", 0)
        if max_size and len(team['users']) >= max_size:
            return redirect(url_for('join_team', hackathon_id=hackathon_id, message=f"Team is full (max {max_size} members)."))

        teams_collection.update_one({"_id": team['_id']}, {"$addToSet": {"users": current_user.regn_no}})
        return redirect(url_for('hackathon_lobby', hackathon_id=hackathon_id))

    hackathon["_id"] = str(hackathon["_id"])
    return render_template('join_team.html', user=current_user, hackathon=hackathon, message=message)

# ----- Team Detail (participant view) -----
@app.route('/team/<team_id>', methods=['GET', 'POST'])
@login_required
def team(team_id):
    team = teams_collection.find_one({"_id": ObjectId(team_id)})
    if not team:
        return redirect(url_for('participant_dashboard'))

    hackathon    = hackathons_collection.find_one({"_id": ObjectId(team["hackathon_id"])}) if team.get("hackathon_id") else None
    hackathon_id = team.get("hackathon_id", "")
    message      = request.args.get("message", "")

    # Only members (or organizer of the hackathon) can view
    is_organizer = (
        current_user.role == 'organizer' and
        hackathon and hackathon.get("organizer_regn") == current_user.regn_no
    )
    is_member = current_user.regn_no in team.get('users', [])
    if not is_member and not is_organizer:
        return "Unauthorized", 403

    if request.method == 'POST':
        file = request.files.get('file')
        if not file:
            message = "No file provided."
        elif not allowed_file(file.filename):
            message = "Invalid file type."
        else:
            content = file.read()
            if len(content) > MAX_FILE_SIZE:
                message = "File too large. Max 2 MB."
            else:
                file.seek(0)
                filename = secure_filename(file.filename)
                fs.put(file, filename=filename, team_id=team_id,
                       team_name=team["team_name"], uploaded_by=current_user.regn_no)
                message = "File uploaded successfully."
        return redirect(url_for('team', team_id=team_id, message=message))

    # Fetch files
    files = []
    for f in fs.find({"team_id": team_id}):
        uploader      = users_collection.find_one({"regn_no": f.uploaded_by})
        uploader_name = f"{uploader.get('first_name','')} {uploader.get('last_name','')}" if uploader else f.uploaded_by
        files.append({"id": str(f._id), "filename": f.filename, "uploaded_by": uploader_name})

    creator = users_collection.find_one({"regn_no": team['created_by']})
    created_by_name = f"{creator.get('first_name', '')} {creator.get('last_name', '')}" if creator else team['created_by']

    members = []
    for regn_no in team.get('users', []):
        u = users_collection.find_one({"regn_no": regn_no})
        members.append({
            "regn_no": regn_no,
            "name": f"{u.get('first_name','')} {u.get('last_name','')}" if u else regn_no
        })

    if hackathon:
        hackathon["_id"] = str(hackathon["_id"])

    return render_template(
        'team.html',
        team=team,
        hackathon=hackathon,
        created_by_name=created_by_name,
        members=members,
        files=files,
        message=message,
        user=current_user,
        is_organizer=is_organizer
    )

# ----- Leave Team -----
@app.route('/team/<team_id>/leave', methods=['POST'])
@login_required
@participant_required
def leave_team(team_id):
    team = teams_collection.find_one({"_id": ObjectId(team_id)})
    if not team:
        return redirect(url_for('participant_dashboard'))
    hackathon_id = team.get("hackathon_id", "")
    if current_user.regn_no in team.get('users', []):
        teams_collection.update_one({"_id": ObjectId(team_id)}, {"$pull": {"users": current_user.regn_no}})
    return redirect(url_for('hackathon_lobby', hackathon_id=hackathon_id))

# ----- Remove Member (creator only) -----
@app.route('/team/<team_id>/remove/<regn_no>', methods=['POST'])
@login_required
def remove_member(team_id, regn_no):
    team = teams_collection.find_one({"_id": ObjectId(team_id)})
    if not team:
        return redirect(url_for('participant_dashboard'))
    if current_user.regn_no == team['created_by'] or current_user.role == 'organizer':
        teams_collection.update_one({"_id": ObjectId(team_id)}, {"$pull": {"users": regn_no}})
    return redirect(url_for('team', team_id=team_id))

# ----- Delete Team (creator only) -----
@app.route('/team/<team_id>/delete', methods=['POST'])
@login_required
def delete_team(team_id):
    team = teams_collection.find_one({"_id": ObjectId(team_id)})
    if not team:
        return redirect(url_for('participant_dashboard'))

    hackathon_id = team.get("hackathon_id", "")
    hackathon    = hackathons_collection.find_one({"_id": ObjectId(hackathon_id)}) if hackathon_id else None
    is_organizer = (
        current_user.role == 'organizer' and
        hackathon and hackathon.get("organizer_regn") == current_user.regn_no
    )

    if current_user.regn_no != team['created_by'] and not is_organizer:
        return "Unauthorized", 403

    for f in fs.find({"team_id": team_id}):
        fs.delete(f._id)
    teams_collection.delete_one({"_id": ObjectId(team_id)})

    if is_organizer and hackathon_id:
        return redirect(url_for('organizer_hackathon_detail', hackathon_id=hackathon_id))
    return redirect(url_for('hackathon_lobby', hackathon_id=hackathon_id))

# ----- Download File -----
@app.route('/team/<team_id>/file/<file_id>')
@login_required
def download_file(team_id, file_id):
    f = fs.get(ObjectId(file_id))
    return send_file(BytesIO(f.read()), download_name=f.filename, as_attachment=True)

# ----- Delete File -----
@app.route('/team/<team_id>/file/<file_id>/delete', methods=['POST'])
@login_required
def delete_file(team_id, file_id):
    team = teams_collection.find_one({"_id": ObjectId(team_id)})
    if not team:
        return "Team not found", 404

    hackathon_id = team.get("hackathon_id", "")
    hackathon    = hackathons_collection.find_one({"_id": ObjectId(hackathon_id)}) if hackathon_id else None
    is_organizer = (
        current_user.role == 'organizer' and
        hackathon and hackathon.get("organizer_regn") == current_user.regn_no
    )

    if current_user.regn_no not in team.get('users', []) and not is_organizer:
        return "Unauthorized", 403

    f = fs.get(ObjectId(file_id))
    fs.delete(f._id)
    return redirect(url_for('team', team_id=team_id))

# ----- Leave Hackathon -----
@app.route('/hackathon/<hackathon_id>/leave', methods=['POST'])
@login_required
@participant_required
def leave_hackathon(hackathon_id):
    # Remove from any team in this hackathon
    my_team = teams_collection.find_one({"hackathon_id": hackathon_id, "users": current_user.regn_no})
    if my_team:
        teams_collection.update_one({"_id": my_team["_id"]}, {"$pull": {"users": current_user.regn_no}})

    users_collection.update_one(
        {"regn_no": current_user.regn_no},
        {"$pull": {"joined_hackathons": hackathon_id}}
    )
    hackathons_collection.update_one(
        {"_id": ObjectId(hackathon_id)},
        {"$pull": {"participants": current_user.regn_no}}
    )
    return redirect(url_for('participant_dashboard'))

# ============================================================
#  ORGANIZER ROUTES
# ============================================================

@app.route('/organizer_dashboard')
@login_required
@organizer_required
def organizer_dashboard():
    hackathons = list(hackathons_collection.find({"organizer_regn": current_user.regn_no}))
    for h in hackathons:
        h["_id"]           = str(h["_id"])
        h["team_count"]    = teams_collection.count_documents({"hackathon_id": str(h["_id"])})
        h["participant_count"] = len(h.get("participants", []))
    return render_template('organizer_dashboard.html', user=current_user, hackathons=hackathons)

# ----- Create Hackathon -----
@app.route('/organizer/hackathon/create', methods=['GET', 'POST'])
@login_required
@organizer_required
def create_hackathon():
    message = ""
    if request.method == 'POST':
        name          = request.form['name'].strip()
        description   = request.form['description'].strip()
        start_date    = request.form.get('start_date', '').strip()
        end_date      = request.form.get('end_date', '').strip()
        max_team_size = int(request.form.get('max_team_size', 0))
        status        = request.form.get('status', 'draft')  # draft | open | closed

        if hackathons_collection.find_one({"name": name, "organizer_regn": current_user.regn_no}):
            message = "You already have a hackathon with this name."
            return render_template('create_hackathon.html', user=current_user, message=message)

        join_code = generate_hackathon_code()
        now_ist   = datetime.now(IST)

        hackathon_doc = {
            "name":           name,
            "description":    description,
            "organizer_regn": current_user.regn_no,
            "organizer_name": f"{current_user.first_name} {current_user.last_name}",
            "join_code":      join_code,
            "start_date":     start_date,
            "end_date":       end_date,
            "max_team_size":  max_team_size,
            "status":         status,
            "teams_locked":   False,
            "participants":   [],
            "created_at":     now_ist.isoformat()
        }
        hackathons_collection.insert_one(hackathon_doc)
        return redirect(url_for('organizer_dashboard'))

    return render_template('create_hackathon.html', user=current_user, message=message)

# ----- Hackathon Detail (organizer view) -----
@app.route('/organizer/hackathon/<hackathon_id>', methods=['GET'])
@login_required
@organizer_required
def organizer_hackathon_detail(hackathon_id):
    hackathon, err = get_hackathon_or_403(hackathon_id, check_owner=True)
    if err:
        return err

    teams = list(teams_collection.find({"hackathon_id": hackathon_id}))
    for team in teams:
        team["_id"]    = str(team["_id"])
        team["points"] = team.get("points", 0)

        # Enrich members
        member_names = []
        for regn_no in team.get("users", []):
            u = users_collection.find_one({"regn_no": regn_no})
            member_names.append(f"{u.get('first_name','')} {u.get('last_name','')}" if u else regn_no)
        team["member_names"] = member_names

        # Files
        team_files = []
        for f in fs.find({"team_id": str(team["_id"])}):
            team_files.append({"_id": str(f._id), "filename": f.filename})
        team["files"] = team_files

    participants = []
    for regn_no in hackathon.get("participants", []):
        u = users_collection.find_one({"regn_no": regn_no})
        if u:
            team_of_user = teams_collection.find_one({"hackathon_id": hackathon_id, "users": regn_no})
            participants.append({
                "regn_no":   regn_no,
                "name":      f"{u.get('first_name','')} {u.get('last_name','')}",
                "email":     u.get('email',''),
                "team_name": team_of_user["team_name"] if team_of_user else "No Team"
            })

    leaderboard = sorted(teams, key=lambda x: x["points"], reverse=True)

    hackathon["_id"] = str(hackathon["_id"])
    message = request.args.get('message', '')
    return render_template(
        'organizer_hackathon_detail.html',
        user=current_user,
        hackathon=hackathon,
        teams=teams,
        participants=participants,
        leaderboard=leaderboard,
        message=message
    )

# ----- Edit Hackathon -----
@app.route('/organizer/hackathon/<hackathon_id>/edit', methods=['GET', 'POST'])
@login_required
@organizer_required
def edit_hackathon(hackathon_id):
    hackathon, err = get_hackathon_or_403(hackathon_id, check_owner=True)
    if err:
        return err

    message = ""
    if request.method == 'POST':
        update = {
            "name":          request.form['name'].strip(),
            "description":   request.form['description'].strip(),
            "start_date":    request.form.get('start_date', '').strip(),
            "end_date":      request.form.get('end_date', '').strip(),
            "max_team_size": int(request.form.get('max_team_size', 0)),
            "status":        request.form.get('status', hackathon.get('status', 'draft')),
        }
        hackathons_collection.update_one({"_id": ObjectId(hackathon_id)}, {"$set": update})
        return redirect(url_for('organizer_hackathon_detail', hackathon_id=hackathon_id))

    hackathon["_id"] = str(hackathon["_id"])
    return render_template('edit_hackathon.html', user=current_user, hackathon=hackathon, message=message)

# ----- Update Hackathon Status -----
@app.route('/organizer/hackathon/<hackathon_id>/status', methods=['POST'])
@login_required
@organizer_required
def update_hackathon_status(hackathon_id):
    hackathon, err = get_hackathon_or_403(hackathon_id, check_owner=True)
    if err:
        return err
    new_status = request.form.get('status', 'draft')
    hackathons_collection.update_one({"_id": ObjectId(hackathon_id)}, {"$set": {"status": new_status}})
    return redirect(url_for('organizer_hackathon_detail', hackathon_id=hackathon_id,
                            message=f"Status updated to '{new_status}'."))

# ----- Toggle Team Lock -----
@app.route('/organizer/hackathon/<hackathon_id>/toggle_lock', methods=['POST'])
@login_required
@organizer_required
def toggle_team_lock(hackathon_id):
    hackathon, err = get_hackathon_or_403(hackathon_id, check_owner=True)
    if err:
        return err
    current_lock = hackathon.get("teams_locked", False)
    hackathons_collection.update_one(
        {"_id": ObjectId(hackathon_id)},
        {"$set": {"teams_locked": not current_lock}}
    )
    state = "locked" if not current_lock else "unlocked"
    return redirect(url_for('organizer_hackathon_detail', hackathon_id=hackathon_id,
                            message=f"Team registration {state}."))

# ----- Delete Hackathon -----
@app.route('/organizer/hackathon/<hackathon_id>/delete', methods=['POST'])
@login_required
@organizer_required
def delete_hackathon(hackathon_id):
    hackathon, err = get_hackathon_or_403(hackathon_id, check_owner=True)
    if err:
        return err

    # Delete all files of all teams in this hackathon
    for team in teams_collection.find({"hackathon_id": hackathon_id}):
        for f in fs.find({"team_id": str(team["_id"])}):
            fs.delete(f._id)
    teams_collection.delete_many({"hackathon_id": hackathon_id})

    # Remove this hackathon from participants' joined list
    for regn_no in hackathon.get("participants", []):
        users_collection.update_one(
            {"regn_no": regn_no},
            {"$pull": {"joined_hackathons": hackathon_id}}
        )

    hackathons_collection.delete_one({"_id": ObjectId(hackathon_id)})
    return redirect(url_for('organizer_dashboard'))

# ----- Remove Participant -----
@app.route('/organizer/hackathon/<hackathon_id>/remove_participant/<regn_no>', methods=['POST'])
@login_required
@organizer_required
def remove_participant(hackathon_id, regn_no):
    hackathon, err = get_hackathon_or_403(hackathon_id, check_owner=True)
    if err:
        return err

    hackathons_collection.update_one({"_id": ObjectId(hackathon_id)}, {"$pull": {"participants": regn_no}})
    users_collection.update_one({"regn_no": regn_no}, {"$pull": {"joined_hackathons": hackathon_id}})
    # Remove from team
    teams_collection.update_many({"hackathon_id": hackathon_id}, {"$pull": {"users": regn_no}})
    return redirect(url_for('organizer_hackathon_detail', hackathon_id=hackathon_id,
                            message="Participant removed."))

# ----- Update Team Points (organizer) -----
@app.route('/organizer/hackathon/<hackathon_id>/team/<team_id>/update_points', methods=['POST'])
@login_required
@organizer_required
def organizer_update_points(hackathon_id, team_id):
    hackathon, err = get_hackathon_or_403(hackathon_id, check_owner=True)
    if err:
        return err
    try:
        new_points = int(request.form.get('points', 0))
        teams_collection.update_one({"_id": ObjectId(team_id)}, {"$set": {"points": new_points}})
        message = "Points updated."
    except Exception:
        message = "Error updating points."
    return redirect(url_for('organizer_hackathon_detail', hackathon_id=hackathon_id, message=message))

# ----- Organizer Upload File to Team -----
@app.route('/organizer/hackathon/<hackathon_id>/team/<team_id>/upload', methods=['POST'])
@login_required
@organizer_required
def organizer_upload_file(hackathon_id, team_id):
    hackathon, err = get_hackathon_or_403(hackathon_id, check_owner=True)
    if err:
        return err
    team = teams_collection.find_one({"_id": ObjectId(team_id)})
    if not team:
        return redirect(url_for('organizer_hackathon_detail', hackathon_id=hackathon_id, message="Team not found."))

    file = request.files.get('file')
    if not file:
        return redirect(url_for('organizer_hackathon_detail', hackathon_id=hackathon_id, message="No file."))
    if not allowed_file(file.filename):
        return redirect(url_for('organizer_hackathon_detail', hackathon_id=hackathon_id, message="Invalid file type."))

    content = file.read()
    if len(content) > MAX_FILE_SIZE:
        return redirect(url_for('organizer_hackathon_detail', hackathon_id=hackathon_id, message="File too large (max 2MB)."))

    file.seek(0)
    filename = secure_filename(file.filename)
    fs.put(file, filename=filename, team_id=team_id, team_name=team["team_name"], uploaded_by=f"ORGANIZER:{current_user.regn_no}")
    return redirect(url_for('organizer_hackathon_detail', hackathon_id=hackathon_id, message=f"'{filename}' uploaded."))

# ----- Organizer Delete File from Team -----
@app.route('/organizer/hackathon/<hackathon_id>/team/<team_id>/file/<file_id>/delete', methods=['POST'])
@login_required
@organizer_required
def organizer_delete_file(hackathon_id, team_id, file_id):
    hackathon, err = get_hackathon_or_403(hackathon_id, check_owner=True)
    if err:
        return err
    try:
        f = fs.get(ObjectId(file_id))
        fs.delete(f._id)
        message = "File deleted."
    except Exception:
        message = "Error deleting file."
    return redirect(url_for('organizer_hackathon_detail', hackathon_id=hackathon_id, message=message))

# ----- Organizer Download File -----
@app.route('/organizer/hackathon/<hackathon_id>/team/<team_id>/file/<file_id>')
@login_required
@organizer_required
def organizer_download_file(hackathon_id, team_id, file_id):
    hackathon, err = get_hackathon_or_403(hackathon_id, check_owner=True)
    if err:
        return err
    f = fs.get(ObjectId(file_id))
    return send_file(BytesIO(f.read()), download_name=f.filename, as_attachment=True)

# ----- Organizer Remove Team -----
@app.route('/organizer/hackathon/<hackathon_id>/team/<team_id>/delete', methods=['POST'])
@login_required
@organizer_required
def organizer_delete_team(hackathon_id, team_id):
    hackathon, err = get_hackathon_or_403(hackathon_id, check_owner=True)
    if err:
        return err
    for f in fs.find({"team_id": team_id}):
        fs.delete(f._id)
    teams_collection.delete_one({"_id": ObjectId(team_id)})
    return redirect(url_for('organizer_hackathon_detail', hackathon_id=hackathon_id, message="Team deleted."))

# ============================================================
#  LEGACY ADMIN ROUTES (kept for backward compatibility)
# ============================================================

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    message = ""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if username != os.getenv("ADMIN_USERNAME") or not check_password(password, os.getenv("ADMIN_PASSWORD_HASH")):
            message = "You are not the Admin!"
            return render_template('admin_login.html', message=message)
        session['admin_logged_in'] = True
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_login.html', message=message)

@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    teams = list(teams_collection.find())
    for team in teams:
        team["_id"]        = str(team["_id"])
        team["points"]     = team.get("points", 0)
        team["github_repo"] = team.get("github_repo", "")
        team_files = []
        for f in fs.find({"team_id": team["_id"]}):
            team_files.append({"_id": str(f._id), "filename": f.filename})
        team["files"] = team_files

    hackathons = list(hackathons_collection.find())
    for h in hackathons:
        h["_id"] = str(h["_id"])

    message = request.args.get('message', '')
    return render_template('admin_dashboard.html', teams=teams, hackathons=hackathons, message=message)

@app.route('/admin/team/<team_id>/update_points', methods=['POST'])
@admin_required
def admin_update_points(team_id):
    try:
        new_points = int(request.form.get('points', 0))
        teams_collection.update_one({"_id": ObjectId(team_id)}, {"$set": {"points": new_points}})
        message = "Points updated for team."
    except Exception:
        message = "Error updating points."
    return redirect(url_for('admin_dashboard', message=message))

@app.route('/admin/team/<team_id>/upload', methods=['POST'])
@admin_required
def admin_upload_file(team_id):
    team = teams_collection.find_one({"_id": ObjectId(team_id)})
    if not team:
        return redirect(url_for('admin_dashboard', message="Team not found."))
    file = request.files.get('file')
    if not file:
        return redirect(url_for('admin_dashboard', message="No file provided."))
    if not allowed_file(file.filename):
        return redirect(url_for('admin_dashboard', message="Invalid file type."))
    content = file.read()
    if len(content) > MAX_FILE_SIZE:
        return redirect(url_for('admin_dashboard', message="File too large. Max 2 MB."))
    file.seek(0)
    filename = secure_filename(file.filename)
    fs.put(file, filename=filename, team_id=team_id, team_name=team["team_name"], uploaded_by="ADMIN")
    return redirect(url_for('admin_dashboard', message=f"File '{filename}' uploaded successfully."))

@app.route('/admin/team/<team_id>/file/<file_id>/delete', methods=['POST'])
@admin_required
def admin_delete_file(team_id, file_id):
    try:
        f = fs.get(ObjectId(file_id))
        fs.delete(f._id)
        message = f"File '{f.filename}' deleted successfully."
    except Exception:
        message = "Error deleting file."
    return redirect(url_for('admin_dashboard', message=message))

@app.route('/admin/team/<team_id>/file/<file_id>')
@admin_required
def admin_download_file(team_id, file_id):
    f = fs.get(ObjectId(file_id))
    return send_file(BytesIO(f.read()), download_name=f.filename, as_attachment=True)

@app.route('/admin_logout')
@admin_required
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

# ============================================================
#  LEGACY dashboard alias (redirects based on role)
# ============================================================
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'organizer':
        return redirect(url_for('organizer_dashboard'))
    return redirect(url_for('participant_dashboard'))

# ============================================================
#  Run
# ============================================================
if __name__ == "__main__":
    app.run(debug=True)
