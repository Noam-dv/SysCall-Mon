import time
import uuid
import json
import sqlite3
import os
from flask import Flask, request, jsonify, send_from_directory, g
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

"""
sysmon server
handles auth, sessions, and event storage
agents push events here
web ui connects via websockets to watch sessions live
"""

app = Flask(__name__, static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY", "noamisthebest")
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")
tokenttl = 60 * 60 * 24  # 24 hours
DB_PATH = os.environ.get("DB_PATH", "sysmon.db")
ph = PasswordHasher()

# db

def get_db():
    """get db connection for this request"""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            pw_hash  TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tokens (
            token      TEXT PRIMARY KEY,
            username   TEXT NOT NULL,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            owner       TEXT NOT NULL,
            started     REAL NOT NULL,
            event_count INTEGER NOT NULL DEFAULT 0,
            alive       INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            payload    TEXT NOT NULL,
            received   REAL NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );
        CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
    """)
    db.commit()
    db.close()

# auth helpers

def _check_token(req):
    h = req.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        return None
    t = h[7:]
    row = get_db().execute("SELECT username, created_at FROM tokens WHERE token=?",(t,)).fetchone()
    if not row:
        return None
    #check expiration
    if time.time() - row["created_at"] > tokenttl:
        get_db().execute("DELETE FROM tokens WHERE token=?", (t,))
        get_db().commit()
        return None
    return row["username"]

def _check_token_raw(req):
    """return raw token string"""
    h = req.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        return None
    return h[7:]

# auth endpoints

@app.route("/api/signup", methods=["POST"])
def signup():
    d = request.json or {}
    u = d.get("username", "").strip()
    p = d.get("password", "")

    if not u or not p:
        return jsonify({"error": "missing fields"}), 400

    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
        return jsonify({"error": "user exists"}), 409

    db.execute("INSERT INTO users VALUES (?,?)", (u, ph.hash(p)))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/login", methods=["POST"])
def login():
    d = request.json or {}
    u = d.get("username", "").strip()
    p = d.get("password", "")

    row=get_db().execute("SELECT pw_hash FROM users WHERE username=?", (u,)).fetchone()

    if row is None:
        ph.verify(ph.hash("timing_dummy"), "timing_dummy") #timing attack prevention
        return jsonify({"error": "bad credentials"}), 401

    try:
        ph.verify(row["pw_hash"], p)
    except VerifyMismatchError:
        return jsonify({"error": "bad credentials"}), 401
    except Exception:
        return jsonify({"error": "bad credentials"}), 401

    t = str(uuid.uuid4())
    db = get_db()
    db.execute("INSERT INTO tokens VALUES (?,?,?)", (t, u, time.time()))
    db.commit()
    return jsonify({"token":t, "username":u})

@app.route("/api/logout", methods=["POST"])
def logout():
    u = _check_token(request)   
    if not u:
        return jsonify({"error": "unauth"}), 401
    t = _check_token_raw(request)
    db = get_db()
    db.execute("DELETE FROM tokens WHERE token=?", (t,))
    db.commit()
    return jsonify({"ok": True})

# session endpoints

@app.route("/api/sessions", methods=["GET"])
def list_sessions():
    """list all sessions for dashboard"""
    u = _check_token(request)
    if not u:
        return jsonify({"error": "unauth"}), 401

    rows=get_db().execute("SELECT * FROM sessions WHERE owner=? ORDER BY started DESC", 
    (u,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/sessions/<sid>", methods=["GET"])
def get_session(sid):
    """get single session info, used by agent remote panel"""
    u = _check_token(request)
    if not u:
        return jsonify({"error": "unauth"}), 401

    row=get_db().execute("SELECT * FROM sessions WHERE id=?", 
    (sid,)).fetchone()
    if not row:
        return jsonify({"error": "no session"}), 404
    return jsonify(dict(row))

@app.route("/api/sessions", methods=["POST"])
def create_session():
    """agent creates a session when it starts"""
    u = _check_token(request)
    if not u:
        return jsonify({"error": "unauth"}), 401

    d = request.json or {}
    name = d.get("name", "unnamed session")
    sid = str(uuid.uuid4())[:8]

    db = get_db()
    db.execute("INSERT INTO sessions (id,name,owner,started) VALUES (?,?,?,?)",
               (sid, name, u, time.time()))
    db.commit()
    return jsonify({"id": sid, "name": name})

@app.route("/api/sessions/<sid>", methods=["DELETE"])
def close_session(sid):
    """close a session"""
    u = _check_token(request)
    if not u:
        return jsonify({"error": "unauth"}), 401

    db = get_db()
    row=db.execute("SELECT owner FROM sessions WHERE id=?", (sid,)).fetchone()
    if not row:
        return jsonify({"error": "no session"}), 404
    if row["owner"] != u:
        return jsonify({"error": "not your session"}), 403

    db.execute("UPDATE sessions SET alive=0 WHERE id=?", (sid,))
    db.commit()
    socketio.emit("session_closed", {"id": sid}, room=f"session_{sid}")
    return jsonify({"ok": True})

# event ingestion from agents

@app.route("/api/sessions/<sid>/push", methods=["POST"])
def push_events(sid):
    """agent posts batches of events here"""
    u = _check_token(request)
    if not u:
        return jsonify({"error": "unauth"}), 401

    db = get_db()
    row=db.execute("SELECT owner FROM sessions WHERE id=?", (sid,)).fetchone()
    if not row:
        return jsonify({"error": "no session"}), 404
    if row["owner"] != u:
        return jsonify({"error": "not your session"}), 403

    d = request.json or {}
    events = d.get("events", [])
    now = time.time()

    db.executemany("INSERT INTO events (session_id,payload,received) VALUES (?,?,?)",
                   [(sid, json.dumps(e), now) for e in events])
    db.execute("UPDATE sessions SET event_count=event_count+? WHERE id=?", (len(events), sid))
    db.commit()

    #fan out to web clients
    socketio.emit("events", {"sid": sid, "events": events}, room=f"session_{sid}")
    return jsonify({"ok":True, "ingested":len(events)})

@app.route("/api/sessions/<sid>/push_anomaly", methods=["POST"])
def push_anomaly(sid):
    """agent posts anomalies here"""
    u=_check_token(request)
    if not u:
        return jsonify({"error": "unauth"}), 401

    db = get_db()
    row=db.execute("SELECT owner FROM sessions WHERE id=?", (sid,)).fetchone()
    if not row:
        return jsonify({"error": "no session"}), 404
    if row["owner"]!=u:
        return jsonify({"error": "not your session"}), 403

    d=request.json or {}
    socketio.emit("anomaly", {"sid": sid, "anomaly": d}, room=f"session_{sid}")
    return jsonify({"ok": True})

# websockets for web dashboard

@socketio.on("subscribe")
def on_subscribe(data):
    """web client wants to watch a session"""
    token=data.get("token", "")
    # ws runs outside flask context so open fresh connection
    con=sqlite3.connect(DB_PATH)
    con.row_factory=sqlite3.Row

    row=con.execute(
        "SELECT username, created_at FROM tokens WHERE token=?", 
        (token,)).fetchone()
    if not row or time.time() - row["created_at"] > tokenttl:
        con.close()
        emit("error", {"msg":"unauthorized"})
        return

    sid = data.get("sid")
    srow=con.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    if not srow:
        con.close()
        emit("error", {"msg":"session not found"})
        return

    join_room(f"session_{sid}")

    #send recent events so they dont stare at blank screen
    recent=con.execute(
        "SELECT payload FROM events WHERE session_id=? ORDER BY id DESC LIMIT 200", 
        (sid,)
    ).fetchall()
    con.close()

    if recent:
        events=[json.loads(r["payload"]) for r in reversed(recent)]
        emit("events", {"sid": sid, "events": events})

    emit("subscribed", {"sid": sid, "name": srow["name"]})

# serve dashboard

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

if __name__ == "__main__":
    init_db()
    print(f"starting sysmon server on :5000  (db: {DB_PATH})")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)