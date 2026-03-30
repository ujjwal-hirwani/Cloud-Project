from flask import Flask, render_template, request, redirect, url_for, send_file, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from dotenv import load_dotenv
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.utils import secure_filename
import boto3
from botocore.exceptions import ClientError
import bcrypt
import random
import string
import pytz
import os
import uuid

load_dotenv()

# ─────────────────────────────────────────
# App
# ─────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
IST = pytz.timezone("Asia/Kolkata")

# ─────────────────────────────────────────
# MongoDB
# ─────────────────────────────────────────
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
mongo = PyMongo(app)
users_col      = mongo.db.users
teams_col      = mongo.db.teams
hackathons_col = mongo.db.hackathons

# ─────────────────────────────────────────
# AWS S3
# ─────────────────────────────────────────
s3 = boto3.client(
    "s3",
    aws_access_key_id     = os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name           = os.getenv("AWS_REGION", "ap-south-1"),
)
S3_BUCKET = os.getenv("AWS_BUCKET_NAME")
S3_REGION = os.getenv("AWS_REGION", "ap-south-1")

ALLOWED_EXT   = {"pdf", "docx", "ppt", "pptx"}
MAX_FILE_SIZE = 2 * 1024 * 1024

MIME_MAP = {
    "pdf":  "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "ppt":  "application/vnd.ms-powerpoint",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

def s3_upload(file_obj, key, filename):
    ext  = filename.rsplit(".", 1)[1].lower()
    mime = MIME_MAP.get(ext, "application/octet-stream")
    s3.upload_fileobj(file_obj, S3_BUCKET, key,
                      ExtraArgs={"ContentType": mime, "ACL": "private"})

def s3_delete(key):
    try:
        s3.delete_object(Bucket=S3_BUCKET, Key=key)
    except ClientError:
        pass

def s3_presign(key, expires=300):
    return s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": S3_BUCKET, "Key": key},
        ExpiresIn=expires,
    )

def make_s3_key(team_id, filename):
    uid = uuid.uuid4().hex[:8]
    return f"teams/{team_id}/{uid}_{filename}"

# ─────────────────────────────────────────
# Flask-Login
# ─────────────────────────────────────────
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, d):
        self.id         = str(d["_id"])
        self.regn_no    = d["regn_no"]
        self.first_name = d["first_name"]
        self.last_name  = d["last_name"]
        self.email      = d["email"]
        self.role       = d.get("role", "participant")

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

@login_manager.user_loader
def load_user(uid):
    d = users_col.find_one({"_id": ObjectId(uid)})
    return User(d) if d else None

# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────
def hash_pw(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_pw(plain, hashed):
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def gen_otp():
    return str(random.randint(100000, 999999))

def gen_code(length, col, field):
    while True:
        code = "".join(random.choices(string.ascii_uppercase + string.digits, k=length))
        if not col.find_one({field: code}):
            return code

def now_ist():
    return datetime.now(IST)

def name_of(regn_no):
    u = users_col.find_one({"regn_no": regn_no})
    return f"{u.get('first_name','')} {u.get('last_name','')}".strip() if u else regn_no

def enrich_team(t):
    t["_id"]          = str(t["_id"])
    t["points"]       = t.get("points", 0)
    t["member_count"] = len(t.get("users", []))
    t["files"]        = t.get("files", [])
    t["member_names"] = [name_of(r) for r in t.get("users", [])]
    return t

from email_sender import send_email

# ─────────────────────────────────────────
# Decorators
# ─────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    def inner(*a, **kw):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return f(*a, **kw)
    return inner

def organizer_only(f):
    @wraps(f)
    def inner(*a, **kw):
        if not current_user.is_authenticated or current_user.role != "organizer":
            return redirect(url_for("login"))
        return f(*a, **kw)
    return inner

def participant_only(f):
    @wraps(f)
    def inner(*a, **kw):
        if not current_user.is_authenticated or current_user.role != "participant":
            return redirect(url_for("login"))
        return f(*a, **kw)
    return inner

def fetch_hackathon(hackathon_id, check_owner=False):
    h = hackathons_col.find_one({"_id": ObjectId(hackathon_id)})
    if not h:
        return None, ("Hackathon not found", 404)
    if check_owner and h.get("organizer_regn") != current_user.regn_no:
        return None, ("Unauthorized", 403)
    return h, None

# ─────────────────────────────────────────
# PUBLIC
# ─────────────────────────────────────────
@app.route("/")
def home():
    hackathons = list(hackathons_col.find({"status": "open"}))
    for h in hackathons:
        h["_id"] = str(h["_id"])
        h["participant_count"] = len(h.get("participants", []))
    return render_template("index.html", hackathons=hackathons)

# ─────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        regn_no = request.form["regn_no"].strip()
        fn      = request.form["first_name"].strip()
        ln      = request.form["last_name"].strip()
        email   = request.form["email"].strip().lower()
        pw      = request.form["password"]
        role    = request.form.get("role", "participant")

        if users_col.find_one({"regn_no": regn_no}):
            return render_template("signup.html", error="Registration number already used.")
        if users_col.find_one({"email": email}):
            return render_template("signup.html", error="Email already registered.")

        otp    = gen_otp()
        expiry = datetime.utcnow() + timedelta(minutes=5)
        users_col.insert_one({
            "regn_no": regn_no, "first_name": fn, "last_name": ln,
            "email": email, "password": hash_pw(pw), "role": role,
            "verified": False, "otp": otp, "otp_expiry": expiry,
            "joined_hackathons": [],
        })
        send_email(email, "Verify your TeamUp account",
                   f"Hi {fn},\n\nYour verification code: {otp}\nExpires in 5 minutes.\n\n— TeamUp")
        return redirect(url_for("verify_email", email=email))
    return render_template("signup.html")

@app.route("/resend-otp/<email>", methods=["POST"])
def resend_otp(email):
    email = email.strip().lower()
    u = users_col.find_one({"email": email})
    if not u or u.get("verified"):
        return redirect(url_for("login"))
    otp    = gen_otp()
    expiry = datetime.utcnow() + timedelta(minutes=5)
    users_col.update_one({"_id": u["_id"]}, {"$set": {"otp": otp, "otp_expiry": expiry}})
    send_email(email, "New verification code",
               f"Hi {u.get('first_name','')},\n\nYour new code: {otp}\nExpires in 5 minutes.\n\n— TeamUp")
    return redirect(url_for("verify_email", email=email))

@app.route("/verify/<email>", methods=["GET", "POST"])
def verify_email(email):
    email = email.strip().lower()
    if request.method == "POST":
        entered = request.form["otp"].strip()
        u = users_col.find_one({"email": email})
        if not u:
            return render_template("verify.html", email=email, error="User not found.")
        if u.get("verified"):
            return redirect(url_for("login"))
        if not u.get("otp"):
            return render_template("verify.html", email=email, error="No active code. Please resend.")
        if datetime.utcnow() > u["otp_expiry"]:
            return render_template("verify.html", email=email, error="Code expired. Please resend.")
        if entered != u["otp"]:
            return render_template("verify.html", email=email, error="Incorrect code.")
        users_col.update_one({"_id": u["_id"]},
                             {"$set": {"verified": True}, "$unset": {"otp": "", "otp_expiry": ""}})
        return redirect(url_for("login"))
    return render_template("verify.html", email=email)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw    = request.form.get("password", "")
        u     = users_col.find_one({"email": email})
        if not u or not check_pw(pw, u["password"]):
            return render_template("login.html", error="Invalid email or password.")
        if not u.get("verified"):
            return redirect(url_for("verify_email", email=email))
        login_user(User(u))
        return redirect(url_for("organizer_dashboard") if u.get("role") == "organizer"
                        else url_for("participant_dashboard"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ─────────────────────────────────────────
# PARTICIPANT
# ─────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "organizer":
        return redirect(url_for("organizer_dashboard"))
    return redirect(url_for("participant_dashboard"))

@app.route("/participant/dashboard")
@login_required
@participant_only
def participant_dashboard():
    ud = users_col.find_one({"regn_no": current_user.regn_no})
    joined_ids = [ObjectId(hid) for hid in ud.get("joined_hackathons", [])]

    my_hackathons = list(hackathons_col.find({"_id": {"$in": joined_ids}}))
    for h in my_hackathons:
        h["_id"] = str(h["_id"])
        h["team_count"] = teams_col.count_documents({"hackathon_id": str(h["_id"])})
        mt = teams_col.find_one({"hackathon_id": str(h["_id"]), "users": current_user.regn_no})
        h["my_team_name"] = mt["team_name"] if mt else None

    open_hackathons = list(hackathons_col.find({"status": "open", "_id": {"$nin": joined_ids}}))
    for h in open_hackathons:
        h["_id"] = str(h["_id"])
        h["participant_count"] = len(h.get("participants", []))

    return render_template("participant_dashboard.html",
                           my_hackathons=my_hackathons,
                           open_hackathons=open_hackathons)

@app.route("/hackathon/join", methods=["GET", "POST"])
@login_required
@participant_only
def join_hackathon():
    if request.method == "POST":
        code = request.form.get("join_code", "").strip().upper()
        h    = hackathons_col.find_one({"join_code": code})
        if not h:
            return render_template("join_hackathon.html", error="Invalid join code.")
        if h.get("status") != "open":
            return render_template("join_hackathon.html", error="This hackathon is not open.")
        hid  = str(h["_id"])
        ud   = users_col.find_one({"regn_no": current_user.regn_no})
        if hid in ud.get("joined_hackathons", []):
            return redirect(url_for("hackathon_lobby", hackathon_id=hid))
        users_col.update_one({"regn_no": current_user.regn_no}, {"$addToSet": {"joined_hackathons": hid}})
        hackathons_col.update_one({"_id": h["_id"]}, {"$addToSet": {"participants": current_user.regn_no}})
        return redirect(url_for("hackathon_lobby", hackathon_id=hid))
    return render_template("join_hackathon.html")

@app.route("/hackathon/<hackathon_id>")
@login_required
@participant_only
def hackathon_lobby(hackathon_id):
    h, err = fetch_hackathon(hackathon_id)
    if err: return err
    ud = users_col.find_one({"regn_no": current_user.regn_no})
    if hackathon_id not in ud.get("joined_hackathons", []):
        return redirect(url_for("participant_dashboard"))
    teams       = [enrich_team(t) for t in teams_col.find({"hackathon_id": hackathon_id})]
    leaderboard = sorted(teams, key=lambda x: x["points"], reverse=True)
    my_team     = next((t for t in teams if current_user.regn_no in t.get("users", [])), None)
    h["_id"]    = str(h["_id"])
    return render_template("hackathon_lobby.html", hackathon=h, leaderboard=leaderboard, my_team=my_team)

@app.route("/hackathon/<hackathon_id>/leave", methods=["POST"])
@login_required
@participant_only
def leave_hackathon(hackathon_id):
    mt = teams_col.find_one({"hackathon_id": hackathon_id, "users": current_user.regn_no})
    if mt:
        teams_col.update_one({"_id": mt["_id"]}, {"$pull": {"users": current_user.regn_no}})
    users_col.update_one({"regn_no": current_user.regn_no}, {"$pull": {"joined_hackathons": hackathon_id}})
    hackathons_col.update_one({"_id": ObjectId(hackathon_id)}, {"$pull": {"participants": current_user.regn_no}})
    return redirect(url_for("participant_dashboard"))

@app.route("/hackathon/<hackathon_id>/create-team", methods=["GET", "POST"])
@login_required
@participant_only
def create_team(hackathon_id):
    h, err = fetch_hackathon(hackathon_id)
    if err: return err
    if h.get("teams_locked"):
        return redirect(url_for("hackathon_lobby", hackathon_id=hackathon_id))
    ud = users_col.find_one({"regn_no": current_user.regn_no})
    if hackathon_id not in ud.get("joined_hackathons", []):
        return redirect(url_for("participant_dashboard"))
    if teams_col.find_one({"hackathon_id": hackathon_id, "users": current_user.regn_no}):
        return redirect(url_for("hackathon_lobby", hackathon_id=hackathon_id))

    if request.method == "POST":
        name = request.form["team_name"].strip()
        desc = request.form.get("description", "").strip()
        gh   = request.form.get("github_repo", "").strip()
        if teams_col.find_one({"hackathon_id": hackathon_id, "team_name": name}):
            h["_id"] = str(h["_id"])
            return render_template("create_team.html", hackathon=h, error="Team name already taken.")
        code = gen_code(6, teams_col, "code")
        n    = now_ist()
        teams_col.insert_one({
            "hackathon_id": hackathon_id, "team_name": name, "description": desc,
            "code": code, "created_by": current_user.regn_no,
            "date": n.date().isoformat(), "time": n.time().isoformat(timespec="seconds"),
            "users": [current_user.regn_no], "github_repo": gh, "points": 0, "files": [],
        })
        return redirect(url_for("hackathon_lobby", hackathon_id=hackathon_id))

    h["_id"] = str(h["_id"])
    return render_template("create_team.html", hackathon=h)

@app.route("/hackathon/<hackathon_id>/join-team", methods=["GET", "POST"])
@login_required
@participant_only
def join_team(hackathon_id):
    h, err = fetch_hackathon(hackathon_id)
    if err: return err
    if h.get("teams_locked"):
        return redirect(url_for("hackathon_lobby", hackathon_id=hackathon_id))
    ud = users_col.find_one({"regn_no": current_user.regn_no})
    if hackathon_id not in ud.get("joined_hackathons", []):
        return redirect(url_for("participant_dashboard"))
    if teams_col.find_one({"hackathon_id": hackathon_id, "users": current_user.regn_no}):
        return redirect(url_for("hackathon_lobby", hackathon_id=hackathon_id))

    if request.method == "POST":
        code = request.form.get("code", "").strip().upper()
        team = teams_col.find_one({"hackathon_id": hackathon_id, "code": code})
        if not team:
            h["_id"] = str(h["_id"])
            return render_template("join_team.html", hackathon=h, error="Invalid team code.")
        max_sz = h.get("max_team_size", 0)
        if max_sz and len(team["users"]) >= max_sz:
            h["_id"] = str(h["_id"])
            return render_template("join_team.html", hackathon=h, error=f"Team full (max {max_sz} members).")
        teams_col.update_one({"_id": team["_id"]}, {"$addToSet": {"users": current_user.regn_no}})
        return redirect(url_for("hackathon_lobby", hackathon_id=hackathon_id))

    h["_id"] = str(h["_id"])
    return render_template("join_team.html", hackathon=h)

# ─────────────────────────────────────────
# TEAM (shared)
# ─────────────────────────────────────────
@app.route("/team/<team_id>", methods=["GET", "POST"])
@login_required
def team_detail(team_id):
    team = teams_col.find_one({"_id": ObjectId(team_id)})
    if not team: return redirect(url_for("dashboard"))

    hid = team.get("hackathon_id", "")
    hackathon = hackathons_col.find_one({"_id": ObjectId(hid)}) if hid else None
    is_organizer = hackathon and hackathon.get("organizer_regn") == current_user.regn_no and current_user.role == "organizer"
    is_member    = current_user.regn_no in team.get("users", [])
    if not is_member and not is_organizer:
        return "Unauthorized", 403

    error = request.args.get("error", "")
    success = request.args.get("success", "")

    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            return redirect(url_for("team_detail", team_id=team_id, error="No file selected."))
        if not allowed_file(file.filename):
            return redirect(url_for("team_detail", team_id=team_id, error="Invalid file type. Allowed: PDF, DOCX, PPT, PPTX."))
        content = file.read()
        if len(content) > MAX_FILE_SIZE:
            return redirect(url_for("team_detail", team_id=team_id, error="File exceeds 2 MB limit."))
        file.seek(0)
        filename = secure_filename(file.filename)
        key      = make_s3_key(team_id, filename)
        s3_upload(file, key, filename)
        file_doc = {
            "file_id":     str(uuid.uuid4()),
            "filename":    filename,
            "s3_key":      key,
            "uploaded_by": current_user.regn_no,
            "uploaded_at": now_ist().isoformat(),
        }
        teams_col.update_one({"_id": ObjectId(team_id)}, {"$push": {"files": file_doc}})
        return redirect(url_for("team_detail", team_id=team_id, success=f"'{filename}' uploaded."))

    team = teams_col.find_one({"_id": ObjectId(team_id)})
    members = []
    for rno in team.get("users", []):
        u = users_col.find_one({"regn_no": rno})
        members.append({
            "regn_no":    rno,
            "name":       f"{u.get('first_name','')} {u.get('last_name','')}" if u else rno,
            "is_creator": rno == team["created_by"],
        })
    creator_doc = users_col.find_one({"regn_no": team["created_by"]})
    created_by_name = f"{creator_doc.get('first_name','')} {creator_doc.get('last_name','')}" if creator_doc else team["created_by"]
    if hackathon: hackathon["_id"] = str(hackathon["_id"])

    return render_template("team.html",
                           team=team, hackathon=hackathon,
                           members=members, created_by_name=created_by_name,
                           is_organizer=is_organizer,
                           error=error, success=success)

@app.route("/team/<team_id>/file/<file_id>/download")
@login_required
def download_file(team_id, file_id):
    team = teams_col.find_one({"_id": ObjectId(team_id)})
    if not team: return "Not found", 404
    hid = team.get("hackathon_id", "")
    hackathon = hackathons_col.find_one({"_id": ObjectId(hid)}) if hid else None
    is_organizer = hackathon and hackathon.get("organizer_regn") == current_user.regn_no
    if current_user.regn_no not in team.get("users", []) and not is_organizer:
        return "Unauthorized", 403
    fd = next((f for f in team.get("files", []) if f["file_id"] == file_id), None)
    if not fd: return "File not found", 404
    return redirect(s3_presign(fd["s3_key"]))

@app.route("/team/<team_id>/file/<file_id>/delete", methods=["POST"])
@login_required
def delete_file(team_id, file_id):
    team = teams_col.find_one({"_id": ObjectId(team_id)})
    if not team: return "Not found", 404
    hid = team.get("hackathon_id", "")
    hackathon = hackathons_col.find_one({"_id": ObjectId(hid)}) if hid else None
    is_organizer = hackathon and hackathon.get("organizer_regn") == current_user.regn_no
    if current_user.regn_no not in team.get("users", []) and not is_organizer:
        return "Unauthorized", 403
    fd = next((f for f in team.get("files", []) if f["file_id"] == file_id), None)
    if fd:
        s3_delete(fd["s3_key"])
        teams_col.update_one({"_id": ObjectId(team_id)}, {"$pull": {"files": {"file_id": file_id}}})
    return redirect(url_for("team_detail", team_id=team_id, success="File deleted."))

@app.route("/team/<team_id>/leave", methods=["POST"])
@login_required
@participant_only
def leave_team(team_id):
    team = teams_col.find_one({"_id": ObjectId(team_id)})
    if not team: return redirect(url_for("participant_dashboard"))
    hid = team.get("hackathon_id", "")
    teams_col.update_one({"_id": ObjectId(team_id)}, {"$pull": {"users": current_user.regn_no}})
    return redirect(url_for("hackathon_lobby", hackathon_id=hid))

@app.route("/team/<team_id>/remove/<regn_no>", methods=["POST"])
@login_required
def remove_member(team_id, regn_no):
    team = teams_col.find_one({"_id": ObjectId(team_id)})
    if not team: return redirect(url_for("dashboard"))
    hid = team.get("hackathon_id", "")
    hackathon = hackathons_col.find_one({"_id": ObjectId(hid)}) if hid else None
    is_organizer = hackathon and hackathon.get("organizer_regn") == current_user.regn_no
    if current_user.regn_no == team["created_by"] or is_organizer:
        teams_col.update_one({"_id": ObjectId(team_id)}, {"$pull": {"users": regn_no}})
    return redirect(url_for("team_detail", team_id=team_id))

@app.route("/team/<team_id>/delete", methods=["POST"])
@login_required
def delete_team(team_id):
    team = teams_col.find_one({"_id": ObjectId(team_id)})
    if not team: return redirect(url_for("dashboard"))
    hid = team.get("hackathon_id", "")
    hackathon = hackathons_col.find_one({"_id": ObjectId(hid)}) if hid else None
    is_organizer = hackathon and hackathon.get("organizer_regn") == current_user.regn_no
    if current_user.regn_no != team["created_by"] and not is_organizer:
        return "Unauthorized", 403
    for f in team.get("files", []):
        s3_delete(f["s3_key"])
    teams_col.delete_one({"_id": ObjectId(team_id)})
    if is_organizer:
        return redirect(url_for("organizer_hackathon_detail", hackathon_id=hid))
    return redirect(url_for("hackathon_lobby", hackathon_id=hid))

# ─────────────────────────────────────────
# ORGANIZER
# ─────────────────────────────────────────
@app.route("/organizer/dashboard")
@login_required
@organizer_only
def organizer_dashboard():
    hackathons = list(hackathons_col.find({"organizer_regn": current_user.regn_no}))
    for h in hackathons:
        h["_id"]               = str(h["_id"])
        h["participant_count"] = len(h.get("participants", []))
        h["team_count"]        = teams_col.count_documents({"hackathon_id": str(h["_id"])})
    return render_template("organizer_dashboard.html", hackathons=hackathons)

@app.route("/organizer/hackathon/create", methods=["GET", "POST"])
@login_required
@organizer_only
def create_hackathon():
    if request.method == "POST":
        name   = request.form["name"].strip()
        desc   = request.form.get("description", "").strip()
        start  = request.form.get("start_date", "")
        end    = request.form.get("end_date", "")
        max_sz = int(request.form.get("max_team_size", 0))
        status = request.form.get("status", "draft")
        if hackathons_col.find_one({"name": name, "organizer_regn": current_user.regn_no}):
            return render_template("create_hackathon.html", error="You already have a hackathon with this name.")
        jc = gen_code(8, hackathons_col, "join_code")
        hackathons_col.insert_one({
            "name": name, "description": desc,
            "organizer_regn": current_user.regn_no,
            "organizer_name": current_user.full_name,
            "join_code": jc, "start_date": start, "end_date": end,
            "max_team_size": max_sz, "status": status,
            "teams_locked": False, "participants": [],
            "created_at": now_ist().isoformat(),
        })
        return redirect(url_for("organizer_dashboard"))
    return render_template("create_hackathon.html")

@app.route("/organizer/hackathon/<hackathon_id>")
@login_required
@organizer_only
def organizer_hackathon_detail(hackathon_id):
    h, err = fetch_hackathon(hackathon_id, check_owner=True)
    if err: return err
    teams       = [enrich_team(t) for t in teams_col.find({"hackathon_id": hackathon_id})]
    leaderboard = sorted(teams, key=lambda x: x["points"], reverse=True)
    participants = []
    for rno in h.get("participants", []):
        u = users_col.find_one({"regn_no": rno})
        if u:
            t = teams_col.find_one({"hackathon_id": hackathon_id, "users": rno})
            participants.append({
                "regn_no":   rno,
                "name":      f"{u.get('first_name','')} {u.get('last_name','')}",
                "email":     u.get("email", ""),
                "team_name": t["team_name"] if t else None,
            })
    h["_id"] = str(h["_id"])
    message  = request.args.get("message", "")
    return render_template("organizer_hackathon_detail.html",
                           hackathon=h, teams=teams, participants=participants,
                           leaderboard=leaderboard, message=message)

@app.route("/organizer/hackathon/<hackathon_id>/edit", methods=["GET", "POST"])
@login_required
@organizer_only
def edit_hackathon(hackathon_id):
    h, err = fetch_hackathon(hackathon_id, check_owner=True)
    if err: return err
    if request.method == "POST":
        hackathons_col.update_one({"_id": ObjectId(hackathon_id)}, {"$set": {
            "name":          request.form["name"].strip(),
            "description":   request.form.get("description", "").strip(),
            "start_date":    request.form.get("start_date", ""),
            "end_date":      request.form.get("end_date", ""),
            "max_team_size": int(request.form.get("max_team_size", 0)),
            "status":        request.form.get("status", h["status"]),
        }})
        return redirect(url_for("organizer_hackathon_detail", hackathon_id=hackathon_id))
    h["_id"] = str(h["_id"])
    return render_template("edit_hackathon.html", hackathon=h)

@app.route("/organizer/hackathon/<hackathon_id>/status", methods=["POST"])
@login_required
@organizer_only
def update_hackathon_status(hackathon_id):
    h, err = fetch_hackathon(hackathon_id, check_owner=True)
    if err: return err
    hackathons_col.update_one({"_id": ObjectId(hackathon_id)},
                               {"$set": {"status": request.form.get("status", "draft")}})
    return redirect(url_for("organizer_hackathon_detail", hackathon_id=hackathon_id))

@app.route("/organizer/hackathon/<hackathon_id>/toggle-lock", methods=["POST"])
@login_required
@organizer_only
def toggle_team_lock(hackathon_id):
    h, err = fetch_hackathon(hackathon_id, check_owner=True)
    if err: return err
    hackathons_col.update_one({"_id": ObjectId(hackathon_id)},
                               {"$set": {"teams_locked": not h.get("teams_locked", False)}})
    return redirect(url_for("organizer_hackathon_detail", hackathon_id=hackathon_id))

@app.route("/organizer/hackathon/<hackathon_id>/delete", methods=["POST"])
@login_required
@organizer_only
def delete_hackathon(hackathon_id):
    h, err = fetch_hackathon(hackathon_id, check_owner=True)
    if err: return err
    for team in teams_col.find({"hackathon_id": hackathon_id}):
        for f in team.get("files", []):
            s3_delete(f["s3_key"])
    teams_col.delete_many({"hackathon_id": hackathon_id})
    for rno in h.get("participants", []):
        users_col.update_one({"regn_no": rno}, {"$pull": {"joined_hackathons": hackathon_id}})
    hackathons_col.delete_one({"_id": ObjectId(hackathon_id)})
    return redirect(url_for("organizer_dashboard"))

@app.route("/organizer/hackathon/<hackathon_id>/remove-participant/<regn_no>", methods=["POST"])
@login_required
@organizer_only
def remove_participant(hackathon_id, regn_no):
    h, err = fetch_hackathon(hackathon_id, check_owner=True)
    if err: return err
    hackathons_col.update_one({"_id": ObjectId(hackathon_id)}, {"$pull": {"participants": regn_no}})
    users_col.update_one({"regn_no": regn_no}, {"$pull": {"joined_hackathons": hackathon_id}})
    teams_col.update_many({"hackathon_id": hackathon_id}, {"$pull": {"users": regn_no}})
    return redirect(url_for("organizer_hackathon_detail", hackathon_id=hackathon_id, message="Participant removed."))

@app.route("/organizer/hackathon/<hackathon_id>/team/<team_id>/points", methods=["POST"])
@login_required
@organizer_only
def update_points(hackathon_id, team_id):
    h, err = fetch_hackathon(hackathon_id, check_owner=True)
    if err: return err
    try:
        teams_col.update_one({"_id": ObjectId(team_id)},
                              {"$set": {"points": int(request.form.get("points", 0))}})
        msg = "Points updated."
    except Exception:
        msg = "Failed to update points."
    return redirect(url_for("organizer_hackathon_detail", hackathon_id=hackathon_id, message=msg))

@app.route("/organizer/hackathon/<hackathon_id>/team/<team_id>/upload", methods=["POST"])
@login_required
@organizer_only
def organizer_upload_file(hackathon_id, team_id):
    h, err = fetch_hackathon(hackathon_id, check_owner=True)
    if err: return err
    team = teams_col.find_one({"_id": ObjectId(team_id)})
    if not team:
        return redirect(url_for("organizer_hackathon_detail", hackathon_id=hackathon_id, message="Team not found."))
    file = request.files.get("file")
    if not file or not allowed_file(file.filename):
        return redirect(url_for("organizer_hackathon_detail", hackathon_id=hackathon_id, message="Invalid or missing file."))
    content = file.read()
    if len(content) > MAX_FILE_SIZE:
        return redirect(url_for("organizer_hackathon_detail", hackathon_id=hackathon_id, message="File exceeds 2 MB."))
    file.seek(0)
    filename = secure_filename(file.filename)
    key      = make_s3_key(team_id, filename)
    s3_upload(file, key, filename)
    teams_col.update_one({"_id": ObjectId(team_id)}, {"$push": {"files": {
        "file_id": str(uuid.uuid4()), "filename": filename,
        "s3_key": key, "uploaded_by": f"organizer:{current_user.regn_no}",
        "uploaded_at": now_ist().isoformat(),
    }}})
    return redirect(url_for("organizer_hackathon_detail", hackathon_id=hackathon_id, message=f"'{filename}' uploaded."))

@app.route("/organizer/hackathon/<hackathon_id>/team/<team_id>/file/<file_id>/delete", methods=["POST"])
@login_required
@organizer_only
def organizer_delete_file(hackathon_id, team_id, file_id):
    h, err = fetch_hackathon(hackathon_id, check_owner=True)
    if err: return err
    team = teams_col.find_one({"_id": ObjectId(team_id)})
    if team:
        fd = next((f for f in team.get("files", []) if f["file_id"] == file_id), None)
        if fd:
            s3_delete(fd["s3_key"])
            teams_col.update_one({"_id": ObjectId(team_id)}, {"$pull": {"files": {"file_id": file_id}}})
    return redirect(url_for("organizer_hackathon_detail", hackathon_id=hackathon_id, message="File deleted."))

@app.route("/organizer/hackathon/<hackathon_id>/team/<team_id>/file/<file_id>/download")
@login_required
@organizer_only
def organizer_download_file(hackathon_id, team_id, file_id):
    h, err = fetch_hackathon(hackathon_id, check_owner=True)
    if err: return err
    team = teams_col.find_one({"_id": ObjectId(team_id)})
    if not team: return "Not found", 404
    fd = next((f for f in team.get("files", []) if f["file_id"] == file_id), None)
    if not fd: return "File not found", 404
    return redirect(s3_presign(fd["s3_key"]))

@app.route("/organizer/hackathon/<hackathon_id>/team/<team_id>/delete", methods=["POST"])
@login_required
@organizer_only
def organizer_delete_team(hackathon_id, team_id):
    h, err = fetch_hackathon(hackathon_id, check_owner=True)
    if err: return err
    team = teams_col.find_one({"_id": ObjectId(team_id)})
    if team:
        for f in team.get("files", []): s3_delete(f["s3_key"])
        teams_col.delete_one({"_id": ObjectId(team_id)})
    return redirect(url_for("organizer_hackathon_detail", hackathon_id=hackathon_id, message="Team deleted."))

# ─────────────────────────────────────────
# ADMIN (legacy super-admin)
# ─────────────────────────────────────────
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if request.form.get("username") != os.getenv("ADMIN_USERNAME") or \
           not check_pw(request.form.get("password",""), os.getenv("ADMIN_PASSWORD_HASH","")):
            return render_template("admin_login.html", error="Invalid credentials.")
        session["admin_logged_in"] = True
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_login.html")

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    hackathons = list(hackathons_col.find())
    for h in hackathons:
        h["_id"] = str(h["_id"])
        h["participant_count"] = len(h.get("participants", []))
        h["team_count"] = teams_col.count_documents({"hackathon_id": str(h["_id"])})
    teams = [enrich_team(t) for t in teams_col.find()]
    return render_template("admin_dashboard.html",
                           hackathons=hackathons, teams=teams,
                           message=request.args.get("message", ""))

@app.route("/admin/team/<team_id>/points", methods=["POST"])
@admin_required
def admin_update_points(team_id):
    try:
        teams_col.update_one({"_id": ObjectId(team_id)},
                              {"$set": {"points": int(request.form.get("points", 0))}})
        msg = "Points updated."
    except Exception:
        msg = "Error updating points."
    return redirect(url_for("admin_dashboard", message=msg))

@app.route("/admin/team/<team_id>/upload", methods=["POST"])
@admin_required
def admin_upload_file(team_id):
    team = teams_col.find_one({"_id": ObjectId(team_id)})
    if not team: return redirect(url_for("admin_dashboard", message="Team not found."))
    file = request.files.get("file")
    if not file or not allowed_file(file.filename):
        return redirect(url_for("admin_dashboard", message="Invalid file."))
    content = file.read()
    if len(content) > MAX_FILE_SIZE:
        return redirect(url_for("admin_dashboard", message="File too large."))
    file.seek(0)
    filename = secure_filename(file.filename)
    key      = make_s3_key(team_id, filename)
    s3_upload(file, key, filename)
    teams_col.update_one({"_id": ObjectId(team_id)}, {"$push": {"files": {
        "file_id": str(uuid.uuid4()), "filename": filename,
        "s3_key": key, "uploaded_by": "admin", "uploaded_at": now_ist().isoformat(),
    }}})
    return redirect(url_for("admin_dashboard", message=f"'{filename}' uploaded."))

@app.route("/admin/team/<team_id>/file/<file_id>/delete", methods=["POST"])
@admin_required
def admin_delete_file(team_id, file_id):
    team = teams_col.find_one({"_id": ObjectId(team_id)})
    if not team: return redirect(url_for("admin_dashboard"))
    fd = next((f for f in team.get("files", []) if f["file_id"] == file_id), None)
    if fd:
        s3_delete(fd["s3_key"])
        teams_col.update_one({"_id": ObjectId(team_id)}, {"$pull": {"files": {"file_id": file_id}}})
    return redirect(url_for("admin_dashboard", message="File deleted."))

@app.route("/admin/team/<team_id>/file/<file_id>/download")
@admin_required
def admin_download_file(team_id, file_id):
    team = teams_col.find_one({"_id": ObjectId(team_id)})
    if not team: return "Not found", 404
    fd = next((f for f in team.get("files", []) if f["file_id"] == file_id), None)
    if not fd: return "File not found", 404
    return redirect(s3_presign(fd["s3_key"]))

@app.route("/admin/logout")
@admin_required
def admin_logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("admin_login"))

# backward-compat aliases
@app.route("/admin_login")
def admin_login_alias(): return redirect(url_for("admin_login"))
@app.route("/admin_dashboard")
def admin_dashboard_alias(): return redirect(url_for("admin_dashboard"))
@app.route("/participant_dashboard")
@login_required
def participant_dashboard_alias(): return redirect(url_for("participant_dashboard"))
@app.route("/organizer_dashboard")
@login_required
def organizer_dashboard_alias(): return redirect(url_for("organizer_dashboard"))

if __name__ == "__main__":
    app.run(debug=True)
