"""BIJHO BRAND ASHISH - Phase 1 server (Student + Admin login).
Run: SECRET_KEY=... python app.py   (dev)   |   gunicorn app:app   (production, HTTPS ke peeche)
"""
import os, re, time, sqlite3, hmac, hashlib, struct, base64, secrets
from functools import wraps
import uuid, json, urllib.request, urllib.error
from urllib.parse import urlparse, parse_qs
import random, math
from flask import Flask, request, jsonify, g, send_file, abort, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

app = Flask(__name__)
if os.environ.get("TRUSTED_PROXY") == "1":      # Render/Railway ke peeche chalate samay (asli IP ke liye)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
SECRET = os.environ.get("SECRET_KEY")
if not SECRET:
    raise SystemExit("SECRET_KEY environment variable set karo (lamba random text).")
DB_PATH = os.environ.get("DB_PATH", "bijho.db")
TOKEN_AGE = 60 * 60 * 24 * 90          # student: 90 din (baar-baar password nahi)
ADMIN_TOKEN_AGE = 60 * 60 * 24 * 14    # admin: 14 din (2-step code ke saath)
signer = URLSafeTimedSerializer(SECRET, salt="bijho-auth")
media_signer = URLSafeTimedSerializer(SECRET, salt="bijho-media")   # video/PDF ke chhote samay wale link
STREAMS = {"Science", "Arts", "Commerce"}
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
PDF_MAX = 25 * 1024 * 1024        # PDF 25 MB tak
VIDEO_MAX = 200 * 1024 * 1024     # video 200 MB tak (480p mein compress karke daalo)
app.config["MAX_CONTENT_LENGTH"] = VIDEO_MAX + 2 * 1024 * 1024
CATALOG = {
    "8-10": ["Hindi", "English", "Math", "Science", "Social Science", "Sanskrit"],
    "Science": ["Physics", "Chemistry", "Maths", "Biology", "Hindi", "English"],
    "Arts": ["Hindi", "English", "History", "Political Science", "Geography", "Economics", "Sociology", "Psychology", "Philosophy", "Sanskrit"],
    "Commerce": ["Accountancy", "Business Studies", "Economics", "Business Maths", "Hindi", "English"],
}
def subjects_for(cls, stream):
    return CATALOG["8-10"] if cls <= 10 else CATALOG.get(stream, [])

# ---------- database ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

def init_db():
    c = sqlite3.connect(DB_PATH)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY, name TEXT NOT NULL,
      mobile TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL, class_no INTEGER NOT NULL,
      stream TEXT, created_at INTEGER NOT NULL, tv INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS resets(student_id INTEGER PRIMARY KEY REFERENCES students(id) ON DELETE CASCADE,
      requested_at INTEGER NOT NULL, name_given TEXT NOT NULL DEFAULT '', code_hash TEXT NOT NULL DEFAULT '',
      code_expires INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS feedback(id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
      message TEXT NOT NULL, created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS chapters(id INTEGER PRIMARY KEY, class_no INTEGER NOT NULL, stream TEXT,
      subject TEXT NOT NULL, title TEXT NOT NULL, position INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, chapter_id INTEGER NOT NULL REFERENCES chapters(id) ON DELETE CASCADE,
      title TEXT NOT NULL, file_name TEXT NOT NULL, size INTEGER NOT NULL, created_at INTEGER NOT NULL, ext_url TEXT NOT NULL DEFAULT '');
    CREATE TABLE IF NOT EXISTS tests(id INTEGER PRIMARY KEY, class_no INTEGER NOT NULL, stream TEXT, subject TEXT NOT NULL,
      title TEXT NOT NULL, duration_min INTEGER NOT NULL, created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS questions(id INTEGER PRIMARY KEY, test_id INTEGER NOT NULL REFERENCES tests(id) ON DELETE CASCADE,
      text TEXT NOT NULL, options TEXT NOT NULL, correct INTEGER NOT NULL, explanation TEXT NOT NULL DEFAULT '');
    CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
      test_id INTEGER NOT NULL REFERENCES tests(id) ON DELETE CASCADE, started_at INTEGER NOT NULL, ends_at INTEGER NOT NULL,
      finished_at INTEGER, score INTEGER, total INTEGER, late INTEGER NOT NULL DEFAULT 0, answers TEXT NOT NULL DEFAULT '{}', qids TEXT NOT NULL DEFAULT '');
    CREATE TABLE IF NOT EXISTS ai_usage(student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
      day TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(student_id, day));
    CREATE TABLE IF NOT EXISTS videos(id INTEGER PRIMARY KEY, chapter_id INTEGER NOT NULL REFERENCES chapters(id) ON DELETE CASCADE,
      title TEXT NOT NULL, file_name TEXT NOT NULL, size INTEGER NOT NULL, created_at INTEGER NOT NULL, ext_url TEXT NOT NULL DEFAULT '');
    CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, login_id TEXT UNIQUE NOT NULL,
      pw_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'owner', totp_secret TEXT NOT NULL DEFAULT '', tv INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
    """)
    c.commit(); c.close()

# ---------- simple rate limit (login brute-force rokne ke liye) ----------
_hits = {}
def limited(key, limit=5, window=300):
    now = time.time()
    arr = [t for t in _hits.get(key, []) if now - t < window]
    _hits[key] = arr
    return len(arr) >= limit
def hit(key): _hits.setdefault(key, []).append(time.time())

# ---------- 2-step code (Google Authenticator jaisa, RFC 6238) ----------
def totp(secret, at=None):
    h = hmac.new(base64.b32decode(secret), struct.pack(">Q", int((at or time.time()) // 30)), hashlib.sha1).digest()
    o = h[-1] & 15
    return f"{(struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 10**6:06d}"
def verify_totp(secret, code):
    return any(hmac.compare_digest(totp(secret, time.time() + d * 30), code) for d in (-1, 0, 1))

# ---------- auth helpers ----------
def make_token(role, uid, v=0): return signer.dumps({"r": role, "u": uid, "v": v})
def auth(required_role):
    def deco(f):
        @wraps(f)
        def w(*a, **kw):
            h = request.headers.get("Authorization", "")
            if not h.startswith("Bearer "): return jsonify(error="Login zaroori hai"), 401
            age = ADMIN_TOKEN_AGE if required_role == "admin" else TOKEN_AGE
            try: d = signer.loads(h[7:], max_age=age)
            except SignatureExpired: return jsonify(error="Session khatam, dobara login karo"), 401
            except BadSignature: return jsonify(error="Galat token"), 401
            if d["r"] != required_role: return jsonify(error="Aapko ye access nahi hai"), 403
            g.uid = d["u"]
            tbl = "admins" if required_role == "admin" else "students"     # password/ID badalne par purane token band
            row = db().execute(f"SELECT tv FROM {tbl} WHERE id=?", (d["u"],)).fetchone()
            if not row or row["tv"] != d.get("v", 0): return jsonify(error="Session khatam, dobara login karo"), 401
            g.tv = row["tv"]
            return f(*a, **kw)
        return w
    return deco

def student_json(r):
    return {"name": r["name"], "mobile": r["mobile"], "class": r["class_no"], "stream": r["stream"]}

@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Cache-Control"] = "no-store"
    if r.mimetype == "text/html":
        r.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data: blob:; media-src 'self' blob: https:; frame-src https://www.youtube-nocookie.com https://www.youtube.com; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'")
        r.headers["X-Frame-Options"] = "DENY"
    return r

# ---------- student ----------
@app.post("/api/register")
def register():
    d = request.get_json(silent=True) or {}
    name = str(d.get("name", "")).strip()
    mobile = str(d.get("mobile", "")).strip()
    pw = str(d.get("password", ""))
    cls = d.get("class")
    stream = d.get("stream")
    if len(name) < 2 or len(name) > 60: return jsonify(error="Naam 2-60 akshar ka likho"), 400
    if not re.fullmatch(r"[6-9]\d{9}", mobile): return jsonify(error="Sahi 10 ank ka mobile number likho"), 400
    if len(pw) < 6 or len(pw) > 100: return jsonify(error="Password kam se kam 6 akshar ka rakho"), 400
    if cls not in (8, 9, 10, 11, 12): return jsonify(error="Class 8 se 12 chuno"), 400
    if cls > 10 and stream not in STREAMS: return jsonify(error="Stream chuno"), 400
    if cls <= 10: stream = None
    if d.get("accept_privacy") is not True: return jsonify(error="Privacy Policy manna zaroori hai"), 400
    if limited("reg:" + request.remote_addr, 10, 3600): return jsonify(error="Bahut koshish, baad mein try karo"), 429
    hit("reg:" + request.remote_addr)
    try:
        cur = db().execute("INSERT INTO students(name,mobile,pw_hash,class_no,stream,created_at) VALUES(?,?,?,?,?,?)",
            (name, mobile, generate_password_hash(pw), cls, stream, int(time.time())))
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Ye number pehle se register hai"), 409
    row = db().execute("SELECT * FROM students WHERE id=?", (cur.lastrowid,)).fetchone()
    return jsonify(token=make_token("student", row["id"]), student=student_json(row)), 201

@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or {}
    mobile, pw = str(d.get("mobile", "")), str(d.get("password", ""))
    key = f"login:{request.remote_addr}:{mobile}"
    if limited(key): return jsonify(error="Bahut galat koshish. 5 minute baad try karo"), 429
    row = db().execute("SELECT * FROM students WHERE mobile=?", (mobile,)).fetchone()
    if not row or not check_password_hash(row["pw_hash"], pw):
        hit(key); return jsonify(error="Mobile ya password galat hai"), 401
    return jsonify(token=make_token("student", row["id"], row["tv"]), student=student_json(row))

@app.get("/api/me")
@auth("student")
def me():
    row = db().execute("SELECT * FROM students WHERE id=?", (g.uid,)).fetchone()
    if not row: return jsonify(error="Account nahi mila"), 404
    return jsonify(student=student_json(row), token=make_token("student", row["id"], row["tv"]))  # naya token: active user ka session badhta rahe

@app.delete("/api/me")
@auth("student")
def delete_me():
    db().execute("DELETE FROM students WHERE id=?", (g.uid,)); db().commit()
    return jsonify(ok=True)

# ---------- admin (alag login, alag token) ----------
@app.post("/api/admin/login")
def admin_login():
    d = request.get_json(silent=True) or {}
    lid, pw = str(d.get("login_id", "")).strip(), str(d.get("password", ""))
    code = re.sub(r"\D", "", str(d.get("code", "")))
    key = f"admin:{request.remote_addr}:{lid}"
    if limited(key, 3, 900): return jsonify(error="Bahut galat koshish. 15 minute baad try karo"), 429
    row = db().execute("SELECT * FROM admins WHERE login_id=?", (lid,)).fetchone()
    ok = row and check_password_hash(row["pw_hash"], pw) and row["totp_secret"] and verify_totp(row["totp_secret"], code)
    if not ok:
        hit(key); return jsonify(error="Admin ID, password ya 6 ank ka code galat hai"), 401
    return jsonify(token=make_token("admin", row["id"], row["tv"]), role=row["role"])

@app.get("/api/admin/stats")
@auth("admin")
def admin_stats():
    n = db().execute("SELECT COUNT(*) c FROM students").fetchone()["c"]
    by = db().execute("SELECT class_no, COUNT(*) c FROM students GROUP BY class_no").fetchall()
    return jsonify(students=n, by_class={str(r["class_no"]): r["c"] for r in by}, token=make_token("admin", g.uid, g.tv))

# ---------- padhai ka content (Study Zone) ----------
def me_student():
    return db().execute("SELECT * FROM students WHERE id=?", (g.uid,)).fetchone()

def chapter_visible(ch, st):
    return ch["class_no"] == st["class_no"] and (ch["stream"] is None or ch["stream"] == st["stream"])

@app.get("/api/subjects")
@auth("student")
def my_subjects():
    st = me_student()
    if not st: return jsonify(error="Account nahi mila"), 404
    return jsonify(subjects=subjects_for(st["class_no"], st["stream"]))

@app.get("/api/chapters")
@auth("student")
def my_chapters():
    st = me_student(); subj = request.args.get("subject", "")
    if not st: return jsonify(error="Account nahi mila"), 404
    if subj not in subjects_for(st["class_no"], st["stream"]): return jsonify(error="Ye subject aapki class mein nahi hai"), 400
    rows = db().execute("""SELECT c.id,c.title,(SELECT COUNT(*) FROM notes n WHERE n.chapter_id=c.id) AS notes
        FROM chapters c WHERE c.class_no=? AND (c.stream IS NULL OR c.stream=?) AND c.subject=? ORDER BY c.position,c.id""",
        (st["class_no"], st["stream"], subj)).fetchall()
    return jsonify(chapters=[dict(r) for r in rows])

def clean_url(u, maxlen=500):
    u = (u or "").strip(); p = urlparse(u)
    if not u or len(u) > maxlen or p.scheme != "https" or not p.hostname or re.search(r"\s", u): return None
    return u

def youtube_id(u):
    p = urlparse(u or ""); h = (p.hostname or "").lower(); vid = None
    if p.scheme != "https": return None
    if h == "youtu.be": vid = p.path.strip("/").split("/")[0]
    elif h in ("youtube.com", "www.youtube.com", "m.youtube.com", "youtube-nocookie.com", "www.youtube-nocookie.com"):
        if p.path == "/watch": vid = (parse_qs(p.query).get("v") or [""])[0]
        else:
            m = re.match(r"^/(shorts|embed|live)/([^/?]+)", p.path); vid = m.group(2) if m else None
    return vid if vid and re.fullmatch(r"[A-Za-z0-9_-]{11}", vid) else None

def video_json(r):
    if r["file_name"]: return {"id": r["id"], "title": r["title"], "size": r["size"], "kind": "file"}
    y = youtube_id(r["ext_url"])
    return {"id": r["id"], "title": r["title"], "size": 0, "kind": "youtube" if y else "mp4link", "yt": y}

@app.get("/api/chapters/<int:cid>/notes")
@auth("student")
def chapter_notes(cid):
    st = me_student(); ch = db().execute("SELECT * FROM chapters WHERE id=?", (cid,)).fetchone()
    if not st or not ch or not chapter_visible(ch, st): return jsonify(error="Chapter nahi mila"), 404
    rows = db().execute("SELECT id,title,size,ext_url FROM notes WHERE chapter_id=? ORDER BY id", (cid,)).fetchall()
    return jsonify(notes=[{"id": r["id"], "title": r["title"], "size": r["size"], "link": bool(r["ext_url"])} for r in rows])

@app.get("/api/notes/<int:nid>/file")
@auth("student")
def note_file(nid):
    st = me_student()
    r = db().execute("SELECT n.*,c.class_no,c.stream FROM notes n JOIN chapters c ON c.id=n.chapter_id WHERE n.id=?", (nid,)).fetchone()
    if not st or not r or not chapter_visible(r, st) or not r["file_name"]: abort(404)
    return send_file(os.path.join(UPLOAD_DIR, r["file_name"]), mimetype="application/pdf", download_name=r["title"] + ".pdf")

@app.post("/api/admin/chapters")
@auth("admin")
def add_chapter():
    d = request.get_json(silent=True) or {}
    cls, stream, subj, title = d.get("class"), d.get("stream"), str(d.get("subject", "")), str(d.get("title", "")).strip()
    if cls not in (8, 9, 10, 11, 12): return jsonify(error="Class 8 se 12 chuno"), 400
    if cls > 10 and stream not in STREAMS: return jsonify(error="Stream chuno"), 400
    if cls <= 10: stream = None
    if subj not in subjects_for(cls, stream): return jsonify(error="Is class mein ye subject nahi hai"), 400
    if not 2 <= len(title) <= 120: return jsonify(error="Chapter ka naam 2-120 akshar ka likho"), 400
    cur = db().execute("INSERT INTO chapters(class_no,stream,subject,title,position,created_at) VALUES(?,?,?,?,?,?)",
        (cls, stream, subj, title, int(d.get("position", 0) or 0), int(time.time())))
    db().commit(); return jsonify(id=cur.lastrowid), 201

@app.post("/api/admin/notes")
@auth("admin")
def add_note():
    ch = db().execute("SELECT id FROM chapters WHERE id=?", (request.form.get("chapter_id", type=int),)).fetchone()
    title = request.form.get("title", "").strip(); f = request.files.get("pdf"); url = request.form.get("url", "").strip()
    if not ch: return jsonify(error="Chapter nahi mila"), 404
    if not 2 <= len(title) <= 120: return jsonify(error="Notes ka naam 2-120 akshar ka likho"), 400
    if url:       # file ki jagah link (Google Drive / koi bhi https link)
        link = clean_url(url)
        if not link: return jsonify(error="Link https:// se shuru hona chahiye"), 400
        cur = db().execute("INSERT INTO notes(chapter_id,title,file_name,size,created_at,ext_url) VALUES(?,?,?,?,?,?)", (ch["id"], title, "", 0, int(time.time()), link))
        db().commit(); return jsonify(id=cur.lastrowid), 201
    if not f: return jsonify(error="PDF file chuno ya link daalo"), 400
    data = f.read()
    if len(data) > PDF_MAX: return jsonify(error="PDF 25 MB se chhoti rakho"), 413
    if not data.startswith(b"%PDF-"): return jsonify(error="Sirf PDF file chalegi"), 400
    name = uuid.uuid4().hex + ".pdf"
    with open(os.path.join(UPLOAD_DIR, name), "wb") as out: out.write(data)
    cur = db().execute("INSERT INTO notes(chapter_id,title,file_name,size,created_at) VALUES(?,?,?,?,?)", (ch["id"], title, name, len(data), int(time.time())))
    db().commit(); return jsonify(id=cur.lastrowid), 201

@app.delete("/api/admin/notes/<int:nid>")
@auth("admin")
def del_note(nid):
    r = db().execute("SELECT file_name FROM notes WHERE id=?", (nid,)).fetchone()
    if not r: return jsonify(error="Notes nahi mile"), 404
    db().execute("DELETE FROM notes WHERE id=?", (nid,)); db().commit()
    try: r["file_name"] and os.remove(os.path.join(UPLOAD_DIR, r["file_name"]))
    except OSError: pass
    return jsonify(ok=True)

@app.errorhandler(413)
def too_big(_): return jsonify(error="File bahut badi hai (PDF 25 MB, video 200 MB tak)"), 413

# ---------- Video classes (streaming + offline) ----------
@app.post("/api/admin/videos")
@auth("admin")
def add_video():
    ch = db().execute("SELECT id FROM chapters WHERE id=?", (request.form.get("chapter_id", type=int),)).fetchone()
    title = request.form.get("title", "").strip(); f = request.files.get("video"); url = request.form.get("url", "").strip()
    if not ch: return jsonify(error="Chapter nahi mila"), 404
    if not 2 <= len(title) <= 120: return jsonify(error="Video ka naam 2-120 akshar ka likho"), 400
    if url:       # YouTube ka link (sabse sasta/aasan) ya .mp4 ka seedha https link
        y = youtube_id(url); link = None
        if y: link = f"https://www.youtube.com/watch?v={y}"
        else:
            c = clean_url(url)
            if c and urlparse(c).path.lower().endswith(".mp4"): link = c
        if not link: return jsonify(error="Sirf YouTube ka link ya .mp4 ka seedha https link chalega"), 400
        cur = db().execute("INSERT INTO videos(chapter_id,title,file_name,size,created_at,ext_url) VALUES(?,?,?,?,?,?)", (ch["id"], title, "", 0, int(time.time()), link))
        db().commit(); return jsonify(id=cur.lastrowid, kind="youtube" if y else "mp4link"), 201
    if not f: return jsonify(error="Video file chuno ya link daalo"), 400
    head = f.stream.read(12); f.stream.seek(0)
    if len(head) < 12 or head[4:8] != b"ftyp": return jsonify(error="Sirf MP4 video chalega"), 400
    name = uuid.uuid4().hex + ".mp4"; path = os.path.join(UPLOAD_DIR, name)
    f.save(path); size = os.path.getsize(path)
    if size > VIDEO_MAX:
        os.remove(path); return jsonify(error="Video 200 MB se chhota rakho"), 413
    cur = db().execute("INSERT INTO videos(chapter_id,title,file_name,size,created_at) VALUES(?,?,?,?,?)", (ch["id"], title, name, size, int(time.time())))
    db().commit(); return jsonify(id=cur.lastrowid, size=size, kind="file"), 201

@app.delete("/api/admin/videos/<int:vid>")
@auth("admin")
def del_video(vid):
    r = db().execute("SELECT file_name FROM videos WHERE id=?", (vid,)).fetchone()
    if not r: return jsonify(error="Video nahi mila"), 404
    db().execute("DELETE FROM videos WHERE id=?", (vid,)); db().commit()
    try: r["file_name"] and os.remove(os.path.join(UPLOAD_DIR, r["file_name"]))
    except OSError: pass
    return jsonify(ok=True)

@app.get("/api/chapters/<int:cid>/videos")
@auth("student")
def chapter_videos(cid):
    st = me_student(); ch = db().execute("SELECT * FROM chapters WHERE id=?", (cid,)).fetchone()
    if not st or not ch or not chapter_visible(ch, st): return jsonify(error="Chapter nahi mila"), 404
    rows = db().execute("SELECT id,title,size,file_name,ext_url FROM videos WHERE chapter_id=? ORDER BY id", (cid,)).fetchall()
    return jsonify(videos=[video_json(r) for r in rows])

def media_row(kind, mid):
    q = ("SELECT n.title,n.file_name,n.ext_url,c.class_no,c.stream FROM notes n JOIN chapters c ON c.id=n.chapter_id WHERE n.id=?" if kind == "n" else
         "SELECT v.title,v.file_name,v.ext_url,c.class_no,c.stream FROM videos v JOIN chapters c ON c.id=v.chapter_id WHERE v.id=?")
    return db().execute(q, (mid,)).fetchone()

def make_link(kind, mid):
    st = me_student(); r = media_row(kind, mid)
    if not st or not r or not chapter_visible(r, st): abort(404)
    if not r["file_name"]:      # bahari link: seedha wahi link do
        y = youtube_id(r["ext_url"]) if kind == "v" else None
        return jsonify(url=("https://www.youtube-nocookie.com/embed/" + y) if y else r["ext_url"], external=True, kind="youtube" if y else ("mp4link" if kind == "v" else "link"))
    return jsonify(url="/m/" + media_signer.dumps({"k": kind, "i": mid, "u": st["id"]}))

@app.get("/api/notes/<int:nid>/link")
@auth("student")
def note_link(nid): return make_link("n", nid)

@app.get("/api/videos/<int:vid>/link")
@auth("student")
def video_link(vid): return make_link("v", vid)

@app.get("/m/<token>")
def media(token):
    try: d = media_signer.loads(token, max_age=6 * 3600)
    except (BadSignature, SignatureExpired): abort(403)
    g.uid = d["u"]; st = me_student(); r = media_row(d["k"], d["i"])
    if not st or not r or not chapter_visible(r, st) or not r["file_name"]: abort(404)
    mime, ext = ("application/pdf", ".pdf") if d["k"] == "n" else ("video/mp4", ".mp4")
    return send_file(os.path.join(UPLOAD_DIR, r["file_name"]), mimetype=mime, conditional=True,   # Range = video aage-peeche chale
                     as_attachment=request.args.get("dl") == "1", download_name=r["title"] + ext)

# ---------- Online Tests (MCQ + timer + result) ----------
GRACE = 60   # second: internet dheema ho to submit ke liye extra samay

def test_visible(t, st):
    return t["class_no"] == st["class_no"] and (t["stream"] is None or t["stream"] == st["stream"])

@app.post("/api/admin/tests")
@auth("admin")
def add_test():
    d = request.get_json(silent=True) or {}
    cls, stream, subj, title = d.get("class"), d.get("stream"), str(d.get("subject", "")), str(d.get("title", "")).strip()
    dur, qs = d.get("duration_min"), d.get("questions")
    if cls not in (8, 9, 10, 11, 12): return jsonify(error="Class 8 se 12 chuno"), 400
    if cls > 10 and stream not in STREAMS: return jsonify(error="Stream chuno"), 400
    if cls <= 10: stream = None
    if subj not in subjects_for(cls, stream): return jsonify(error="Is class mein ye subject nahi hai"), 400
    if not 2 <= len(title) <= 120: return jsonify(error="Test ka naam 2-120 akshar ka likho"), 400
    if not isinstance(dur, int) or not 1 <= dur <= 180: return jsonify(error="Samay 1 se 180 minute chuno"), 400
    if not isinstance(qs, list) or not 1 <= len(qs) <= 100: return jsonify(error="1 se 100 sawal chahiye"), 400
    clean = []
    for i, q in enumerate(qs, 1):
        text = str(q.get("text", "")).strip(); op = q.get("options"); c = q.get("correct")
        if not 2 <= len(text) <= 500: return jsonify(error=f"Sawal {i}: sawal 2-500 akshar ka likho"), 400
        if not (isinstance(op, list) and len(op) == 4 and all(isinstance(o, str) and 1 <= len(o.strip()) <= 200 for o in op)):
            return jsonify(error=f"Sawal {i}: 4 vikalp chahiye"), 400
        if c not in (0, 1, 2, 3) or isinstance(c, bool): return jsonify(error=f"Sawal {i}: sahi uttar 0 se 3 ke beech"), 400
        clean.append((text, json.dumps([o.strip() for o in op], ensure_ascii=False), c, str(q.get("explanation", ""))[:500]))
    cur = db().execute("INSERT INTO tests(class_no,stream,subject,title,duration_min,created_at) VALUES(?,?,?,?,?,?)",
        (cls, stream, subj, title, dur, int(time.time())))
    for text, op, c, ex in clean:
        db().execute("INSERT INTO questions(test_id,text,options,correct,explanation) VALUES(?,?,?,?,?)", (cur.lastrowid, text, op, c, ex))
    db().commit(); return jsonify(id=cur.lastrowid, questions=len(clean)), 201

@app.delete("/api/admin/tests/<int:tid>")
@auth("admin")
def del_test(tid):
    if not db().execute("SELECT 1 FROM tests WHERE id=?", (tid,)).fetchone(): return jsonify(error="Test nahi mila"), 404
    db().execute("DELETE FROM tests WHERE id=?", (tid,)); db().commit(); return jsonify(ok=True)

@app.get("/api/tests")
@auth("student")
def list_tests():
    st = me_student(); subj = request.args.get("subject", "")
    if not st: return jsonify(error="Account nahi mila"), 404
    if subj not in subjects_for(st["class_no"], st["stream"]): return jsonify(error="Ye subject aapki class mein nahi hai"), 400
    rows = db().execute("""SELECT t.id,t.title,t.duration_min,(SELECT COUNT(*) FROM questions q WHERE q.test_id=t.id) AS questions,
        (SELECT a.score FROM attempts a WHERE a.test_id=t.id AND a.student_id=? AND a.finished_at IS NOT NULL AND a.total>0 ORDER BY a.score*1.0/a.total DESC, a.total DESC LIMIT 1) AS best_score,
        (SELECT a.total FROM attempts a WHERE a.test_id=t.id AND a.student_id=? AND a.finished_at IS NOT NULL AND a.total>0 ORDER BY a.score*1.0/a.total DESC, a.total DESC LIMIT 1) AS best_total
        FROM tests t WHERE t.class_no=? AND (t.stream IS NULL OR t.stream=?) AND t.subject=? ORDER BY t.id DESC""",
        (st["id"], st["id"], st["class_no"], st["stream"], subj)).fetchall()
    return jsonify(tests=[dict(r) for r in rows])

def attempt_qids(a):
    try: return json.loads(a["qids"]) if a["qids"] else None
    except ValueError: return None

def questions_public(tid, qids=None):
    rows = db().execute("SELECT * FROM questions WHERE test_id=? ORDER BY id", (tid,)).fetchall()
    if qids is not None: rows = [q for q in rows if q["id"] in set(qids)]
    return [{"id": q["id"], "text": q["text"], "options": json.loads(q["options"])} for q in rows]

@app.post("/api/tests/<int:tid>/start")
@auth("student")
def start_test(tid):
    st = me_student(); t = db().execute("SELECT * FROM tests WHERE id=?", (tid,)).fetchone()
    if not st or not t or not test_visible(t, st): return jsonify(error="Test nahi mila"), 404
    now = int(time.time())
    a = db().execute("SELECT * FROM attempts WHERE student_id=? AND test_id=? AND finished_at IS NULL AND ends_at>? ORDER BY id DESC",
        (st["id"], tid, now)).fetchone()
    if not a:
        ids = [q["id"] for q in db().execute("SELECT id FROM questions WHERE test_id=? ORDER BY id", (tid,))]
        cnt = (request.get_json(silent=True) or {}).get("count")
        if cnt is None: n = len(ids)
        elif isinstance(cnt, bool) or not isinstance(cnt, int) or not 1 <= cnt <= len(ids) or not (cnt % 10 == 0 or cnt == len(ids)):
            return jsonify(error="Sawalon ki sankhya 10, 20, 30... ya 'sabhi' chuno"), 400
        else: n = cnt
        chosen = ids if n == len(ids) else sorted(random.sample(ids, n))      # chhota Quiz = random sawal
        secs = max(60, math.ceil(t["duration_min"] * 60 * n / len(ids)))      # samay sawalon ke hisaab se
        cur = db().execute("INSERT INTO attempts(student_id,test_id,started_at,ends_at,qids) VALUES(?,?,?,?,?)",
            (st["id"], tid, now, now + secs, json.dumps(chosen)))
        db().commit(); a = db().execute("SELECT * FROM attempts WHERE id=?", (cur.lastrowid,)).fetchone()
    return jsonify(attempt_id=a["id"], title=t["title"], ends_at=a["ends_at"], seconds_left=max(0, a["ends_at"] - now),
                   questions=questions_public(tid, attempt_qids(a)))   # sahi uttar yahan nahi bheje jaate

def review(a):
    ans = json.loads(a["answers"]); out = []
    ids = attempt_qids(a)
    for q in db().execute("SELECT * FROM questions WHERE test_id=? ORDER BY id", (a["test_id"],)):
        if ids is not None and q["id"] not in ids: continue
        out.append({"id": q["id"], "text": q["text"], "options": json.loads(q["options"]), "your": ans.get(str(q["id"])),
                    "correct": q["correct"], "explanation": q["explanation"]})
    return out

@app.post("/api/attempts/<int:aid>/submit")
@auth("student")
def submit_attempt(aid):
    a = db().execute("SELECT * FROM attempts WHERE id=? AND student_id=?", (aid, g.uid)).fetchone()
    if not a: return jsonify(error="Attempt nahi mila"), 404
    if a["finished_at"]: return jsonify(error="Ye test pehle hi jama ho chuka hai"), 409
    d = request.get_json(silent=True) or {}; given = d.get("answers") if isinstance(d.get("answers"), dict) else {}
    now = int(time.time()); late = now > a["ends_at"] + GRACE
    qs = db().execute("SELECT id,correct FROM questions WHERE test_id=?", (a["test_id"],)).fetchall()
    ids = attempt_qids(a)
    if ids is not None: qs = [q for q in qs if q["id"] in ids]
    clean = {} if late else {str(q["id"]): given[str(q["id"])] for q in qs if given.get(str(q["id"])) in (0, 1, 2, 3)}
    score = sum(1 for q in qs if clean.get(str(q["id"])) == q["correct"])
    db().execute("UPDATE attempts SET finished_at=?,score=?,total=?,late=?,answers=? WHERE id=?",
        (now, score, len(qs), int(late), json.dumps(clean), aid)); db().commit()
    a = db().execute("SELECT * FROM attempts WHERE id=?", (aid,)).fetchone()
    return jsonify(score=score, total=len(qs), late=late, review=review(a))

@app.get("/api/attempts")
@auth("student")
def my_attempts():
    rows = db().execute("""SELECT a.id,t.title,t.subject,a.score,a.total,a.late,a.finished_at FROM attempts a
        JOIN tests t ON t.id=a.test_id WHERE a.student_id=? AND a.finished_at IS NOT NULL ORDER BY a.id DESC LIMIT 100""", (g.uid,)).fetchall()
    return jsonify(attempts=[dict(r) for r in rows])

@app.get("/api/attempts/<int:aid>")
@auth("student")
def attempt_detail(aid):
    a = db().execute("SELECT * FROM attempts WHERE id=? AND student_id=?", (aid, g.uid)).fetchone()
    if not a or not a["finished_at"]: return jsonify(error="Result nahi mila"), 404
    return jsonify(score=a["score"], total=a["total"], late=bool(a["late"]), review=review(a))

# ---------- BIJHO Doubt AI (sirf padhai ke sawal, roz ki seema) ----------
AI_KEY = os.environ.get("ANTHROPIC_API_KEY", "")          # kabhi code mein mat likho
AI_MODEL = os.environ.get("AI_MODEL", "claude-haiku-5-5")
DAILY_LIMIT = int(os.environ.get("AI_DAILY_LIMIT", "15"))

def today_ist(): return time.strftime("%Y-%m-%d", time.gmtime(time.time() + 19800))

def call_ai(system, question):
    body = json.dumps({"model": AI_MODEL, "max_tokens": 700, "system": system,
                       "messages": [{"role": "user", "content": question}]}).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, method="POST",
        headers={"content-type": "application/json", "x-api-key": AI_KEY, "anthropic-version": "2023-06-01"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read())
    return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text").strip()

def ai_system(st, subject):
    cls = f"Class {st['class_no']}" + (f" ({st['stream']})" if st["stream"] else "")
    return (f"Tum BIJHO ke padhai-sahayak ho. Vidyarthi Bihar Board ki {cls} mein padhta hai"
            + (f", vishay: {subject}" if subject else "") + ". "
            "Sirf padhai (school ke vishay, NCERT/Bihar Board, exam taiyari) ke sawalon ka jawab do. "
            "Padhai se bahar ke sawal par vinamrata se mana karo aur padhai ka sawal poochne ko kaho. "
            "Jawab aasan Hindi mein do (agar vidyarthi English mein pooche to English mein), step-by-step, "
            "chhote vakyon mein, aur 250 shabdon se kam. Sawal-jawab ka sahi uttar na pata ho to saaf kaho. "
            "Koi nuksandeh, hinsak ya vayask samagri na do. Vidyarthi ki niji jaankari kabhi mat maango.")

def ai_left(sid):
    r = db().execute("SELECT count FROM ai_usage WHERE student_id=? AND day=?", (sid, today_ist())).fetchone()
    return max(0, DAILY_LIMIT - (r["count"] if r else 0))

@app.get("/api/ai/usage")
@auth("student")
def ai_usage():
    return jsonify(remaining=ai_left(g.uid), daily_limit=DAILY_LIMIT)

@app.post("/api/ai/ask")
@auth("student")
def ai_ask():
    st = me_student()
    if not st: return jsonify(error="Account nahi mila"), 404
    d = request.get_json(silent=True) or {}
    q, subj = str(d.get("question", "")).strip(), d.get("subject")
    if not 2 <= len(q) <= 1000: return jsonify(error="Sawal 2 se 1000 akshar ka likho"), 400
    if subj is not None and subj not in subjects_for(st["class_no"], st["stream"]):
        return jsonify(error="Ye subject aapki class mein nahi hai"), 400
    if not AI_KEY and call_ai is _real_call_ai: return jsonify(error="AI abhi chalu nahi hai"), 503
    if limited(f"ai:{g.uid}", 5, 60): return jsonify(error="Thoda ruko, ek minute baad poochho"), 429
    hit(f"ai:{g.uid}")
    if ai_left(g.uid) <= 0: return jsonify(error=f"Aaj ke {DAILY_LIMIT} sawal pure ho gaye. Kal fir poochho!"), 429
    db().execute("INSERT INTO ai_usage(student_id,day,count) VALUES(?,?,1) ON CONFLICT(student_id,day) DO UPDATE SET count=count+1",
        (g.uid, today_ist())); db().commit()
    try:
        answer = call_ai(ai_system(st, subj), q)
        if not answer: raise ValueError("khali jawab")
    except Exception:
        db().execute("UPDATE ai_usage SET count=MAX(0,count-1) WHERE student_id=? AND day=?", (g.uid, today_ist())); db().commit()
        return jsonify(error="AI abhi jawab nahi de pa raha, thodi der baad try karo"), 502   # galti ka vivaran vidyarthi ko nahi
    return jsonify(answer=answer, remaining=ai_left(g.uid))
_real_call_ai = call_ai

# ---------- admin ke liye suchiyan + ऐप ke pages ----------
@app.get("/api/admin/chapters")
@auth("admin")
def admin_chapters():
    rows = db().execute("""SELECT c.id,c.class_no,c.stream,c.subject,c.title,
        (SELECT COUNT(*) FROM notes n WHERE n.chapter_id=c.id) AS notes,
        (SELECT COUNT(*) FROM videos v WHERE v.chapter_id=c.id) AS videos FROM chapters c ORDER BY c.class_no,c.subject,c.position,c.id""").fetchall()
    return jsonify(chapters=[dict(r) for r in rows])

@app.get("/api/admin/tests")
@auth("admin")
def admin_tests():
    rows = db().execute("""SELECT t.id,t.class_no,t.stream,t.subject,t.title,t.duration_min,
        (SELECT COUNT(*) FROM questions q WHERE q.test_id=t.id) AS questions FROM tests t ORDER BY t.id DESC""").fetchall()
    return jsonify(tests=[dict(r) for r in rows])

WEB_FILES = {"index.html", "manifest.webmanifest", "sw.js"}
@app.get("/")
def home_page(): return send_from_directory(WEB_DIR, "index.html")

@app.get("/<path:f>")
def web_files(f):
    if f in WEB_FILES or (f.startswith("icons/") and f.endswith(".png")):
        return send_from_directory(WEB_DIR, f)
    abort(404)

# ---------- Admin: ID / password badalna ----------
@app.post("/api/admin/change-credentials")
@auth("admin")
def change_credentials():
    d = request.get_json(silent=True) or {}
    cur, newid, newpw = str(d.get("current_password", "")), str(d.get("new_login_id", "")).strip(), str(d.get("new_password", ""))
    code = re.sub(r"\D", "", str(d.get("code", "")))
    key = f"chg:{g.uid}"
    if limited(key, 5, 900): return jsonify(error="Bahut galat koshish. 15 minute baad try karo"), 429
    row = db().execute("SELECT * FROM admins WHERE id=?", (g.uid,)).fetchone()
    if not (check_password_hash(row["pw_hash"], cur) and row["totp_secret"] and verify_totp(row["totp_secret"], code)):
        hit(key); return jsonify(error="Purana password ya 6 ank ka code galat hai"), 401
    if not newid and not newpw: return jsonify(error="Naya Admin ID ya naya password likho"), 400
    if newid:
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,40}", newid): return jsonify(error="Admin ID 3-40 akshar ka ho (A-Z, 0-9, _ . @ -)"), 400
        if db().execute("SELECT 1 FROM admins WHERE login_id=? AND id<>?", (newid, g.uid)).fetchone(): return jsonify(error="Ye Admin ID pehle se hai"), 409
    else: newid = row["login_id"]
    pw_hash = row["pw_hash"]
    if newpw:
        if not 10 <= len(newpw) <= 100: return jsonify(error="Naya password kam se kam 10 akshar ka rakho"), 400
        if newpw == cur or newpw == newid: return jsonify(error="Naya password alag aur mushkil rakho"), 400
        pw_hash = generate_password_hash(newpw)
    tv = row["tv"] + 1
    db().execute("UPDATE admins SET login_id=?, pw_hash=?, tv=? WHERE id=?", (newid, pw_hash, tv, g.uid)); db().commit()
    return jsonify(ok=True, login_id=newid, token=make_token("admin", g.uid, tv))   # naya token; purane sab band

# ---------- Social links (Instagram / Facebook / YouTube) ----------
SOCIAL = {"instagram": ("instagram.com",), "facebook": ("facebook.com", "fb.com", "fb.me"), "youtube": ("youtube.com", "youtu.be"),
          "whatsapp": ("wa.me", "whatsapp.com")}     # whatsapp.com mein chat./api./channel links bhi aate hain
DEFAULT_LINKS = {   # pehli baar ke liye; Admin baad mein badal sakta hai
    "instagram": "https://www.instagram.com/bijho_brand_ashish",
    "facebook": "https://www.facebook.com/share/18TqS2pNAs/",
    "youtube": "https://youtube.com/@bijho_brand_ashish",
    "whatsapp": "https://whatsapp.com/channel/0029Vb8y9CuDzgTHqBnGoB0X"}
def valid_link(kind, u):
    if not u: return True
    if len(u) > 300: return False
    p = urlparse(u); host = (p.hostname or "").lower()
    return p.scheme == "https" and any(host == dom or host.endswith("." + dom) for dom in SOCIAL[kind])

def get_links():
    rows = {r["key"]: r["value"] for r in db().execute("SELECT key,value FROM settings WHERE key LIKE 'link_%'")}
    return {k: rows.get("link_" + k, DEFAULT_LINKS.get(k, "")) for k in SOCIAL}   # Admin ne khali save kiya to khali hi rahega

@app.get("/api/links")
def public_links(): return jsonify(get_links())

@app.post("/api/admin/links")
@auth("admin")
def set_links():
    d = request.get_json(silent=True) or {}; new = {}
    for k in SOCIAL:
        u = str(d.get(k, "")).strip()
        if not valid_link(k, u): return jsonify(error=f"{k.capitalize()} ka link sahi nahi hai (https://... aur sahi website ka)"), 400
        new[k] = u
    for k, u in new.items():
        db().execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", ("link_" + k, u))
    db().commit(); return jsonify(new)

# ---------- Student Settings: naam/class, password, sab jagah se logout, feedback ----------
@app.patch("/api/me")
@auth("student")
def update_me():
    st = me_student(); d = request.get_json(silent=True) or {}
    name = str(d.get("name", st["name"])).strip(); cls = d.get("class", st["class_no"]); stream = d.get("stream", st["stream"])
    if len(name) < 2 or len(name) > 60: return jsonify(error="Naam 2-60 akshar ka likho"), 400
    if cls not in (8, 9, 10, 11, 12) or isinstance(cls, bool): return jsonify(error="Class 8 se 12 chuno"), 400
    if cls > 10 and stream not in STREAMS: return jsonify(error="Stream chuno"), 400
    if cls <= 10: stream = None
    db().execute("UPDATE students SET name=?, class_no=?, stream=? WHERE id=?", (name, cls, stream, g.uid)); db().commit()
    return jsonify(student=student_json(me_student()))

@app.post("/api/me/password")
@auth("student")
def change_my_password():
    d = request.get_json(silent=True) or {}; cur, new = str(d.get("current_password", "")), str(d.get("new_password", ""))
    key = f"pw:{g.uid}"
    if limited(key, 5, 900): return jsonify(error="Bahut galat koshish. 15 minute baad try karo"), 429
    row = me_student()
    if not check_password_hash(row["pw_hash"], cur): hit(key); return jsonify(error="Purana password galat hai"), 401
    if not 6 <= len(new) <= 100: return jsonify(error="Naya password kam se kam 6 akshar ka rakho"), 400
    if new == cur: return jsonify(error="Naya password purane se alag rakho"), 400
    tv = row["tv"] + 1
    db().execute("UPDATE students SET pw_hash=?, tv=? WHERE id=?", (generate_password_hash(new), tv, g.uid)); db().commit()
    return jsonify(ok=True, token=make_token("student", g.uid, tv))      # is phone par login bana rahe; baaki sab band

@app.post("/api/me/logout-all")
@auth("student")
def logout_all():
    tv = me_student()["tv"] + 1
    db().execute("UPDATE students SET tv=? WHERE id=?", (tv, g.uid)); db().commit()
    return jsonify(ok=True, token=make_token("student", g.uid, tv))

@app.post("/api/feedback")
@auth("student")
def send_feedback():
    msg = str((request.get_json(silent=True) or {}).get("message", "")).strip()
    if not 5 <= len(msg) <= 1000: return jsonify(error="Sandesh 5 se 1000 akshar ka likho"), 400
    if limited(f"fb:{g.uid}", 5, 3600): return jsonify(error="Thodi der baad dobara bhejo"), 429
    hit(f"fb:{g.uid}")
    db().execute("INSERT INTO feedback(student_id,message,created_at) VALUES(?,?,?)", (g.uid, msg, int(time.time()))); db().commit()
    return jsonify(ok=True), 201

@app.get("/api/admin/feedback")
@auth("admin")
def admin_feedback():
    rows = db().execute("""SELECT f.id,f.message,f.created_at,s.name,s.mobile,s.class_no,s.stream FROM feedback f
        JOIN students s ON s.id=f.student_id ORDER BY f.id DESC LIMIT 100""").fetchall()
    return jsonify(feedback=[dict(r) for r in rows])

# ---------- Password bhool gaye (Admin ki jaanch + ek baar ka code) ----------
RESET_HOURS = 24
def code_hash(code): return hmac.new(SECRET.encode(), code.encode(), hashlib.sha256).hexdigest()

@app.post("/api/forgot")
def forgot():
    d = request.get_json(silent=True) or {}
    mobile, name = str(d.get("mobile", "")).strip(), str(d.get("name", "")).strip()[:60]
    if limited("forgot:" + request.remote_addr, 5, 3600): return jsonify(error="Bahut koshish ho gayi, baad mein try karo"), 429
    hit("forgot:" + request.remote_addr)
    st = db().execute("SELECT id FROM students WHERE mobile=?", (mobile,)).fetchone()
    if st:      # number registered ho ya na ho, jawab ek jaisa (koi number pata na kar sake)
        db().execute("""INSERT INTO resets(student_id,requested_at,name_given) VALUES(?,?,?)
            ON CONFLICT(student_id) DO UPDATE SET requested_at=excluded.requested_at, name_given=excluded.name_given, code_hash='', code_expires=0, attempts=0""",
            (st["id"], int(time.time()), name)); db().commit()
    return jsonify(ok=True)

@app.get("/api/admin/resets")
@auth("admin")
def admin_resets():
    now = int(time.time())
    rows = db().execute("""SELECT r.student_id,r.requested_at,r.name_given,r.code_hash,r.code_expires,s.name,s.mobile,s.class_no,s.stream
        FROM resets r JOIN students s ON s.id=r.student_id ORDER BY r.requested_at DESC LIMIT 100""").fetchall()
    return jsonify(requests=[{"student_id": r["student_id"], "name": r["name"], "name_given": r["name_given"], "mobile": r["mobile"],
        "class_no": r["class_no"], "stream": r["stream"], "requested_at": r["requested_at"],
        "code_sent": bool(r["code_hash"]) and r["code_expires"] > now} for r in rows])

@app.post("/api/admin/resets/<int:sid>/code")
@auth("admin")
def issue_reset_code(sid):
    r = db().execute("SELECT s.name,s.mobile FROM resets x JOIN students s ON s.id=x.student_id WHERE x.student_id=?", (sid,)).fetchone()
    if not r: return jsonify(error="Anurodh nahi mila"), 404
    code = f"{secrets.randbelow(10**6):06d}"
    db().execute("UPDATE resets SET code_hash=?, code_expires=?, attempts=0 WHERE student_id=?", (code_hash(code), int(time.time()) + RESET_HOURS * 3600, sid)); db().commit()
    return jsonify(code=code, name=r["name"], mobile=r["mobile"], hours=RESET_HOURS)

@app.delete("/api/admin/resets/<int:sid>")
@auth("admin")
def dismiss_reset(sid):
    db().execute("DELETE FROM resets WHERE student_id=?", (sid,)); db().commit(); return jsonify(ok=True)

@app.post("/api/reset-password")
def reset_password():
    d = request.get_json(silent=True) or {}
    mobile, code, new = str(d.get("mobile", "")).strip(), re.sub(r"\D", "", str(d.get("code", ""))), str(d.get("new_password", ""))
    key = f"rst:{request.remote_addr}:{mobile}"
    if limited(key, 5, 900): return jsonify(error="Bahut galat koshish. 15 minute baad try karo"), 429
    bad = jsonify(error="Mobile ya code galat hai, ya code purana ho gaya hai"), 400
    st = db().execute("SELECT id,tv FROM students WHERE mobile=?", (mobile,)).fetchone()
    r = st and db().execute("SELECT * FROM resets WHERE student_id=?", (st["id"],)).fetchone()
    if not r or not r["code_hash"] or r["code_expires"] < time.time() or r["attempts"] >= 5: hit(key); return bad
    if not hmac.compare_digest(r["code_hash"], code_hash(code)):
        db().execute("UPDATE resets SET attempts=attempts+1 WHERE student_id=?", (st["id"],)); db().commit(); hit(key); return bad
    if not 6 <= len(new) <= 100: return jsonify(error="Naya password kam se kam 6 akshar ka rakho"), 400
    tv = st["tv"] + 1
    db().execute("UPDATE students SET pw_hash=?, tv=? WHERE id=?", (generate_password_hash(new), tv, st["id"]))
    db().execute("DELETE FROM resets WHERE student_id=?", (st["id"],)); db().commit()      # code sirf ek baar
    row = db().execute("SELECT * FROM students WHERE id=?", (st["id"],)).fetchone()
    return jsonify(token=make_token("student", st["id"], tv), student=student_json(row))

# ---------- Admin password / 2-step code bhool gaye (Recovery Key se) ----------
# Hosting ki settings mein ADMIN_RECOVERY_KEY (20+ akshar ka lamba random text) rakho. Ye key sirf aapke paas rahe.
RECOVERY_KEY = os.environ.get("ADMIN_RECOVERY_KEY", "")

@app.post("/api/admin/recover")
def admin_recover():
    if len(RECOVERY_KEY) < 20: return jsonify(error="Recovery chalu nahi hai (hosting mein ADMIN_RECOVERY_KEY rakho)"), 404
    d = request.get_json(silent=True) or {}
    key, lid, newpw = str(d.get("recovery_key", "")), str(d.get("login_id", "")).strip(), str(d.get("new_password", ""))
    if limited("rec:" + request.remote_addr, 5, 3600): return jsonify(error="Bahut koshish ho gayi, 1 ghante baad try karo"), 429
    hit("rec:" + request.remote_addr)
    if not hmac.compare_digest(key.encode(), RECOVERY_KEY.encode()): return jsonify(error="Recovery key galat hai"), 401
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,40}", lid): return jsonify(error="Admin ID 3-40 akshar ka ho (A-Z, 0-9, _ . @ -)"), 400
    if not 10 <= len(newpw) <= 100 or newpw == lid: return jsonify(error="Naya password kam se kam 10 akshar ka aur ID se alag rakho"), 400
    secret = base64.b32encode(os.urandom(20)).decode()      # naya 2-step code key
    row = db().execute("SELECT id FROM admins WHERE login_id=?", (lid,)).fetchone()
    if row:   # purana password + purane sabhi session band, naya 2-step key
        db().execute("UPDATE admins SET pw_hash=?, totp_secret=?, tv=tv+1 WHERE id=?", (generate_password_hash(newpw), secret, row["id"]))
    else:     # pehli baar: Admin bana do (phone se setup ke liye)
        db().execute("INSERT INTO admins(login_id,pw_hash,role,totp_secret) VALUES(?,?,?,?)", (lid, generate_password_hash(newpw), "owner", secret))
    db().commit()
    return jsonify(ok=True, login_id=lid, totp_secret=secret, created=not row)

@app.cli.command("reset-admin")
def reset_admin():
    """flask --app app reset-admin  -> Admin ka password aur 2-step key naya karo"""
    import getpass
    lid = input("Admin ID: ").strip(); pw = getpass.getpass("Naya password (10+ akshar): ")
    if len(pw) < 10: raise SystemExit("Password kam se kam 10 akshar ka rakho")
    init_db(); c = sqlite3.connect(DB_PATH)
    if not c.execute("SELECT 1 FROM admins WHERE login_id=?", (lid,)).fetchone(): raise SystemExit("Ye Admin ID nahi mila")
    secret = base64.b32encode(os.urandom(20)).decode()
    c.execute("UPDATE admins SET pw_hash=?, totp_secret=?, tv=tv+1 WHERE login_id=?", (generate_password_hash(pw), secret, lid)); c.commit(); c.close()
    print("\nPassword badal diya. Naya 2-step key (Google Authenticator mein daalo):\n   ", secret)

@app.cli.command("create-admin")
def create_admin():
    """flask --app app create-admin  -> naya admin/teacher banao"""
    import getpass
    lid = input("Admin ID: ").strip(); pw = getpass.getpass("Password (10+ akshar): ")
    role = input("Role (owner/teacher) [owner]: ").strip() or "owner"
    if len(pw) < 10: raise SystemExit("Password kam se kam 10 akshar ka rakho")
    secret = base64.b32encode(os.urandom(20)).decode()
    init_db(); c = sqlite3.connect(DB_PATH)
    c.execute("INSERT INTO admins(login_id,pw_hash,role,totp_secret) VALUES(?,?,?,?)", (lid, generate_password_hash(pw), role, secret))
    c.commit(); c.close()
    print("\nAdmin bana diya gaya.")
    print("Google Authenticator app kholo -> '+' -> 'Enter a setup key' -> ye key daalo (Time based):")
    print("   ", secret)
    print("Is key ko kisi ko mat dikhao, aur ise safe jagah likh kar rakho.")

init_db()
if __name__ == "__main__":
    app.run(debug=False, port=5000)
