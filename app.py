# app.py
from flask import Flask, render_template, request, redirect, url_for, send_file, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
import pytz
import gridfs
from io import BytesIO
from werkzeug.utils import secure_filename
import bcrypt
import random, string
import os

# Load environment variables
load_dotenv()

# -----------------------------
# Initialize app
# -----------------------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
IST = pytz.timezone('Asia/Kolkata')

now_ist = datetime.utcnow().replace(tzinfo=pytz.utc).astimezone(IST)
# -----------------------------
# MongoDB Atlas (Flask-PyMongo)
# -----------------------------
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
mongo = PyMongo(app)
users_collection = mongo.db.users
teams_collection = mongo.db.teams
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
        self.id = str(user_data['_id'])
        self.regn_no = user_data['regn_no']
        self.first_name = user_data['first_name']
        self.last_name = user_data['last_name']
        self.email = user_data['email']

@login_manager.user_loader
def load_user(user_id):
    data = users_collection.find_one({"_id": ObjectId(user_id)})
    return User(data) if data else None

# -----------------------------
# Utilities
# -----------------------------
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
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
        # Check if code already exists
        if not teams_collection.find_one({"code": code}):
            return code


from email_sender import send_email  # after utilities to avoid circulars

# -----------------------------
# Admin Decorator
# -----------------------------
from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function


# -----------------------------
# Routes
# -----------------------------
@app.route('/')
def home():
    return render_template('index.html')

# ----- Signup -----
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    message = ""
    if request.method == 'POST':
        regn_no = request.form['regn_no'].strip()
        password = request.form['password']
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()
        email = request.form['email'].strip().lower()

        # Existence checks
        if users_collection.find_one({'regn_no': regn_no}):
            message = "User already registered with this registration number."
            return render_template('signup.html', message=message)
        if users_collection.find_one({'email': email}):
            message = "Email already registered!"
            return render_template('signup.html', message=message)

        # Hash & create user (unverified initially)
        hashed_pw = hash_password(password)
        otp = generate_otp()
        expiry_time = datetime.utcnow() + timedelta(minutes=5)

        users_collection.insert_one({
            'regn_no': regn_no,
            'password': hashed_pw,
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'verified': False,
            'otp': otp,
            'otp_expiry': expiry_time
        })

        # Send OTP
        send_email(
            recipient_email=email,
            subject="TeamUp - Verify your account",
            body=f"Hi {first_name},\n\nYour verification code is: {otp}\nIt will expire in 5 minutes.\n\n— TeamUp."
        )

        message = "Signup successful! Check your email for the verification code."
        return redirect(url_for('verify_email', email=email))

    return render_template('signup.html', message=message)

# ----- Resend OTP -----
@app.route('/resend-otp/<email>', methods=['POST'])
def resend_otp(email):
    email = email.strip().lower()
    user = users_collection.find_one({'email': email})
    if not user:
        message = "User not found."
        return redirect(url_for('signup'))

    if user.get('verified'):
        message = "Your email is already verified. Please login."
        return redirect(url_for('login'))

    new_otp = generate_otp()
    new_expiry = datetime.utcnow() + timedelta(minutes=5)
    users_collection.update_one({'_id': user['_id']}, {'$set': {'otp': new_otp, 'otp_expiry': new_expiry}})

    send_email(
        recipient_email=email,
        subject="Your new verification code",
        body=f"Hi {user.get('first_name', '')},\n\nYour new verification code is: {new_otp}\nIt will expire in 5 minutes.\n\n— TeamUp"
    )

    message = "A new verification code has been sent to your email."
    return redirect(url_for('verify_email', email=email))

# ----- Verify -----
@app.route('/verify/<email>', methods=['GET', 'POST'])
def verify_email(email):
    email = email.strip().lower()
    message = ""
    if request.method == 'POST':
        entered_otp = request.form['otp'].strip()
        user = users_collection.find_one({'email': email})

        if not user:
            message = "User not found."
        elif user.get('verified'):
            message = "Your email is already verified. Please login."
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
            message = "Email verified! You can now login."
            return redirect(url_for('login'))
        else:
            message = "Invalid OTP. Please try again."

    return render_template('verify.html', email=email, message=message)

# ----- Login -----
@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
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
            return redirect(url_for('dashboard'))
        else:
            message = "Invalid credentials."

    return render_template('login.html', message=message)

# ----- Dashboard -----
@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch all teams where current user is a member
    teams = list(teams_collection.find({"users": current_user.regn_no}))

    # Enrich teams with creator name (lookup from users collection)
    for team in teams:
        creator = users_collection.find_one({"regn_no": team["created_by"]})
        team["creator_name"] = f"{creator['first_name']} {creator['last_name']}" if creator else "Unknown"

        # Convert ObjectId to string for urls
        team["_id"] = str(team["_id"])

    # Fetch all teams for leaderboard
    leaderboard_teams = list(teams_collection.find())

    for team in leaderboard_teams:
        # Ensure points field exists
        team["points"] = team.get("points", 0)

    # Sort leaderboard by points (descending)
    leaderboard_teams = sorted(leaderboard_teams, key=lambda x: x["points"], reverse=True)

    return render_template(
        "dashboard.html",
        user=current_user,
        teams=teams,
        leaderboard=leaderboard_teams
    )



# ----- Create Team -----
@app.route('/create_team', methods=['GET', 'POST'])
@login_required
def create_team():
    if request.method == 'POST':
        team_name = request.form['team_name'].strip()
        description = request.form['description'].strip()
        github_repo = request.form['github_repo'].strip()

        # Ensure unique team name
        if teams_collection.find_one({"team_name": team_name}):
            message = "Team name already exists. Choose a different one."
            return redirect(url_for('create_team'))

        # Generate guaranteed unique 6-char code
        code = generate_unique_code()
        
        now_ist = datetime.now(IST)
        team_doc = {
            "team_name": team_name,
            "description": description,
            "code": code,
            "created_by": current_user.regn_no,
            "date": now_ist.date().isoformat(),
            "time": now_ist.time().isoformat(timespec="seconds"),
            "users": [current_user.regn_no],
            "github_repo": github_repo,
            "points": 0   # ✅ Initialize with 0 points
        }

        teams_collection.insert_one(team_doc)

        return redirect(url_for('dashboard'))

    return render_template('create_team.html', user=current_user)

# ----- Join Team -----
@app.route('/join_team', methods=['GET', 'POST'])
@login_required
def join_team():
    if request.method == 'POST':
        code = request.form.get('code', '').strip().upper()

        if not code:
            message = "Please enter a team code."
            return redirect(url_for('join_team', message=message))

        team = teams_collection.find_one({"code": code})

        if not team:
            message = "Invalid team code."
            return redirect(url_for('join_team', message=message))

        if current_user.regn_no in team['users']:
            message = "You are already in this team."
            return redirect(url_for('join_team', message=message))

        teams_collection.update_one(
            {"_id": team['_id']},
            {"$addToSet": {"users": current_user.regn_no}}
        )

        # success message → go dashboard directly
        return redirect(url_for('dashboard'))

    # Handle GET request → read message from query params
    message = request.args.get("message", "")
    return render_template('join_team.html', user=current_user, message=message)

@app.route('/team/<team_id>', methods=['GET', 'POST'])
@login_required
def team(team_id):
    team = teams_collection.find_one({"_id": ObjectId(team_id)})
    if not team:
        return redirect(url_for('dashboard'))

    message = request.args.get("message", "")  # Read message from query params

    if request.method == 'POST':
        file = request.files.get('file')
        if not file:
            message = "No file provided."
        elif not allowed_file(file.filename):
            message = "Invalid file type."
        elif len(file.read()) > MAX_FILE_SIZE:
            message = "File too large. Max 2 MB."
        else:
            file.seek(0)
            filename = secure_filename(file.filename)
            fs.put(
                file,
                filename=filename,
                team_id=team_id,
                team_name=team["team_name"],
                uploaded_by=current_user.regn_no
            )
            message = "File uploaded successfully."

        # Redirect to GET to prevent reupload on refresh
        return redirect(url_for('team', team_id=team_id, message=message, user = current_user))

    # Fetch files for this team (same as before)
    files = []
    for f in fs.find({"team_id": team_id}):
        uploader = users_collection.find_one({"regn_no": f.uploaded_by})
        uploader_name = f"{uploader.get('first_name','')} {uploader.get('last_name','')}" if uploader else f.uploaded_by
        files.append({
            "id": str(f._id),
            "filename": f.filename,
            "uploaded_by": uploader_name
        })

    creator = users_collection.find_one({"regn_no": team['created_by']})
    created_by_name = f"{creator.get('first_name', '')} {creator.get('last_name', '')}" if creator else team['created_by']

    members = []
    for regn_no in team.get('users', []):
        user = users_collection.find_one({"regn_no": regn_no})
        if user:
            members.append(f"{user.get('first_name','')} {user.get('last_name','')}")
        else:
            members.append(regn_no)

    return render_template(
        'team.html',
        team=team,
        created_by_name=created_by_name,
        members=members,
        files=files,
        message=message, 
        user = current_user
    )


# Member leaving the team
@app.route('/team/<team_id>/leave', methods=['POST'])
@login_required
def leave_team(team_id):
    team = teams_collection.find_one({"_id": ObjectId(team_id)})
    if not team:
        return redirect(url_for('dashboard'))

    if current_user.regn_no in team.get('users', []):
        teams_collection.update_one(
            {"_id": ObjectId(team_id)},
            {"$pull": {"users": current_user.regn_no}}
        )
    return redirect(url_for('dashboard'))

# Creator removing a member
@app.route('/team/<team_id>/remove/<regn_no>', methods=['POST'])
@login_required
def remove_member(team_id, regn_no):
    team = teams_collection.find_one({"_id": ObjectId(team_id)})
    if not team:
        return redirect(url_for('dashboard'))

    # Only creator can remove
    if current_user.regn_no == team['created_by']:
        teams_collection.update_one(
            {"_id": ObjectId(team_id)},
            {"$pull": {"users": regn_no}}
        )
    return redirect(url_for('team', team_id=team_id))

# Delete team route
@app.route('/team/<team_id>/delete', methods=['POST'])
@login_required
def delete_team(team_id):
    team = teams_collection.find_one({"_id": ObjectId(team_id)})
    if not team:
        return redirect(url_for('dashboard'))

    # Only creator can delete the team
    if current_user.regn_no != team['created_by']:
        return "Unauthorized", 403

    # Delete all files uploaded by the team (optional)
    for f in fs.find({"team_id": team_id}):
        fs.delete(f._id)

    # Delete the team
    teams_collection.delete_one({"_id": ObjectId(team_id)})

    return redirect(url_for('dashboard'))


# Route to download file
@app.route('/team/<team_id>/file/<file_id>')
@login_required
def download_file(team_id, file_id):
    f = fs.get(ObjectId(file_id))
    return send_file(BytesIO(f.read()), download_name=f.filename, as_attachment=True)

# Route to delete file
@app.route('/team/<team_id>/file/<file_id>/delete', methods=['POST'])
@login_required
def delete_file(team_id, file_id):
    team = teams_collection.find_one({"_id": ObjectId(team_id)})
    if not team:
        return "Team not found", 404

    # Check if current user is a member of the team
    if current_user.regn_no not in team.get('users', []):
        return "Unauthorized", 403

    # If check passes, delete the file
    f = fs.get(ObjectId(file_id))
    fs.delete(f._id)

    return redirect(url_for('team', team_id=team_id))


# ----- Admin Login -----
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    message = ""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Check username and password
        if username != os.getenv("ADMIN_USERNAME") or not check_password(password, os.getenv("ADMIN_PASSWORD_HASH")):
            message = "You are not the Admin!"
            return render_template('admin_login.html', message=message)

        # Mark admin as logged in
        session['admin_logged_in'] = True

        return redirect(url_for('admin_dashboard'))

    return render_template('admin_login.html', message=message)


# ----- Admin Dashboard -----
@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    teams = list(teams_collection.find())
    for team in teams:
        team["_id"] = str(team["_id"])
        team["points"] = team.get("points", 0)
        team["github_repo"] = team.get("github_repo", "")

        # Fetch files for this team and attach to the team dict
        team_files = []
        for f in fs.find({"team_id": team["_id"]}):
            team_files.append({
                "_id": str(f._id),
                "filename": f.filename
            })
        team["files"] = team_files

    # Message passed via query parameter after redirect (PRG)
    message = request.args.get('message', '')
    return render_template('admin_dashboard.html', teams=teams, message=message)




# ----- Admin Update Points -----
@app.route('/admin/team/<team_id>/update_points', methods=['POST'])
@admin_required
def admin_update_points(team_id):
    try:
        new_points = int(request.form.get('points', 0))
        teams_collection.update_one({"_id": ObjectId(team_id)}, {"$set": {"points": new_points}})
        message = f"Points updated for team."
    except:
        message = "Error updating points."
    return redirect(url_for('admin_dashboard', message=message))


# ----- Admin Upload File -----
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
        return redirect(url_for('admin_dashboard', message="Invalid file type. Allowed: pdf, docx, ppt, pptx."))

    if len(file.read()) > MAX_FILE_SIZE:
        return redirect(url_for('admin_dashboard', message="File too large. Max 2 MB."))

    file.seek(0)  # Reset pointer
    filename = secure_filename(file.filename)

    fs.put(file, filename=filename, team_id=team_id, team_name=team["team_name"], uploaded_by="ADMIN")

    return redirect(url_for('admin_dashboard', message=f"File '{filename}' uploaded successfully."))


# ----- Admin Delete File -----
@app.route('/admin/team/<team_id>/file/<file_id>/delete', methods=['POST'])
@admin_required
def admin_delete_file(team_id, file_id):
    try:
        f = fs.get(ObjectId(file_id))
        fs.delete(f._id)
        message = f"File '{f.filename}' deleted successfully."
    except:
        message = "Error deleting file."
    return redirect(url_for('admin_dashboard', message=message))


# ----- Admin Download File -----
@app.route('/admin/team/<team_id>/file/<file_id>')
@admin_required
def admin_download_file(team_id, file_id):
    f = fs.get(ObjectId(file_id))
    return send_file(BytesIO(f.read()), download_name=f.filename, as_attachment=True)



# ----- Logout -----
@app.route('/logout')
@login_required
def logout():
    logout_user()
    message = "You have been logged out."
    return redirect(url_for('login'))

# ----- Admin Logout -----
@app.route('/admin_logout')
@admin_required
def admin_logout():
    session.pop('admin_logged_in', None)  # Clear the admin login flag
    return redirect(url_for('admin_login'))


# -----------------------------
# Run app
# -----------------------------
if __name__ == "__main__":
    # Avoid reloader sending duplicate emails; use debug=True during dev if you want
    app.run(debug=False)
