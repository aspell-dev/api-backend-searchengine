import io
import os
import re
import sqlite3
import hashlib
import secrets
import time
import requests
import socket
import json
from flask import Flask, request, send_file, abort, session, redirect, url_for, render_template_string, g

# --- CONFIGURATION ---
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DB_PATH = "users.db"
AGENT_HOST = "127.0.0.1"
AGENT_PORT = 9009

ADMIN_EMAILS = {"VOTRE/VOS MAILS ADMIN"}
MAX_ATTEMPTS = 5
BLOCK_TIME = 600  # 10 minutes

DISCORD_ID_REGEX = re.compile(r"^\d{17,20}$")
IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
FIVEM_LICENSE_REGEX = re.compile(r"^license:[0-9a-fA-F]{40}$")

# --- AGENT CLIENT ---
def agent_search(query):
    try:
        with socket.create_connection((AGENT_HOST, AGENT_PORT), timeout=10) as s:
            s.sendall((query + "\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            resp = json.loads(data.decode())
            return resp
    except Exception as e:
        print("Erreur agent:", e)
        return None

def is_vpn(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=proxy,hosting,mobile")
        data = r.json()
        return data.get("proxy") or data.get("hosting") or data.get("mobile")
    except Exception:
        return False

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            ip TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            ip TEXT PRIMARY KEY,
            count INTEGER,
            last_attempt REAL
        )
    """)
    db.commit()

def hash_password(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${hashed}"

def verify_password(password, hashed):
    try:
        salt, hash_val = hashed.split('$')
        return hashlib.sha256((salt + password).encode()).hexdigest() == hash_val
    except Exception:
        return False

def is_valid_query(query):
    return (
        DISCORD_ID_REGEX.match(query)
        or IP_REGEX.match(query)
        or FIVEM_LICENSE_REGEX.match(query)
    )

def is_blocked(ip):
    db = get_db()
    row = db.execute("SELECT count, last_attempt FROM login_attempts WHERE ip=?", (ip,)).fetchone()
    now = time.time()
    if row:
        count, last = row
        if count >= MAX_ATTEMPTS and now - last < BLOCK_TIME:
            return True
        elif now - last >= BLOCK_TIME:
            db.execute("DELETE FROM login_attempts WHERE ip=?", (ip,))
            db.commit()
    return False

def register_attempt(ip, success):
    db = get_db()
    now = time.time()
    row = db.execute("SELECT count, last_attempt FROM login_attempts WHERE ip=?", (ip,)).fetchone()
    if success:
        db.execute("DELETE FROM login_attempts WHERE ip=?", (ip,))
    else:
        if row:
            count, last = row
            if now - last < BLOCK_TIME:
                db.execute("UPDATE login_attempts SET count=?, last_attempt=? WHERE ip=?", (count+1, now, ip))
            else:
                db.execute("UPDATE login_attempts SET count=1, last_attempt=? WHERE ip=?", (now, ip))
        else:
            db.execute("INSERT INTO login_attempts (ip, count, last_attempt) VALUES (?, ?, ?)", (ip, 1, now))
    db.commit()

DISCORD_CSS = """body {background: #313338; color: #fff; font-family: 'gg sans', 'Noto Sans', 'Helvetica Neue', Helvetica, Arial, sans-serif; margin: 0;}a { color: #00A8FC; text-decoration: none; }a:hover { text-decoration: underline; }.container {background: #23272a; margin: 100px auto 30px auto; padding: 40px 30px 30px 30px; border-radius: 12px; box-shadow: 0 2px 20px #0008; width: 370px; max-width: 95vw; position: relative;}input, button {padding: 12px; border-radius: 5px; border: none; margin-bottom: 18px; font-size: 1rem;}input {width: 90%; background: #1e1f22; color: #fff; border: 1px solid #5865f2;}button {background: #5865f2; color: #fff; font-weight: bold; width: 100%; transition: background 0.2s;}button:hover {background: #4752c4;}h2 {font-weight: 800; margin-bottom: 30px; letter-spacing: 1px;}.error { color: #ff5555; margin-bottom: 10px; }.success { color: #00ffae; margin-bottom: 10px; }.footer {margin-top: 40px; color: #aaa; font-size: 0.95em; text-align: center; letter-spacing: 1px;}.topbar {position: fixed; top: 20px; left: 0; width: 100vw; z-index: 1000; display: flex; align-items: center; justify-content: flex-start; gap: 18px;}.topbar a, .topbar .admin, .topbar .logout {position: static !important; margin-left: 0 !important; margin-right: 0 !important; background: #5865f2; color: #fff; padding: 10px 22px; border-radius: 8px; font-weight: bold; text-decoration: none; box-shadow: 0 2px 8px #0004; letter-spacing: 1px; display: flex; align-items: center; border: none; transition: background 0.2s;}.topbar a:hover, .topbar .admin:hover, .topbar .logout:hover {background: #4752c4;}.topbar .avatar-link {padding: 0; background: none; box-shadow: none;}.topbar .avatar-link span {margin-left: 10px; color: #fff; font-weight: bold;}.topbar img {width: 38px; height: 38px; border-radius: 50%; background: #23272a; border: 2px solid #5865f2;}@media (max-width: 700px) {.container { width: 98vw; padding: 10vw 2vw; }.topbar { flex-direction: column; align-items: flex-start; gap: 8px; }}table {width: 100%; border-collapse: collapse; margin-top: 20px; background: #23272a; color: #fff;}th, td {border: 1px solid #444; padding: 8px;}th { background: #5865f2; }tr:nth-child(even) { background: #22252c; }tr:nth-child(odd) { background: #23272f; }"""
TOPBAR = """<div class="topbar"><a href="https://discord.gg/searchengine" target="_blank">Discord</a><a href="/profile" class="avatar-link"><img src="https://api.dicebear.com/7.x/identicon/svg?seed={{ user }}" alt="avatar"><span>Mon compte</span></a><a href="/logout" class="logout">Déconnexion</a>{% if is_admin %}<a href="/admin" class="admin">Liste des comptes</a>{% endif %}</div>"""
LOGIN_HTML = """<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Connexion</title><style>{DISCORD_CSS}</style></head><body>{TOPBAR}<div class="container" style="margin-top:110px;"><h2>Connexion</h2>{% if error %}<div class="error">{{ error }}</div>{% endif %}<form method="post"><input type="text" name="username" placeholder="Nom d'utilisateur" required><br><input type="password" name="password" placeholder="Mot de passe" required><br><input type="email" name="email" placeholder="Email" required><br><button type="submit">Se connecter</button></form><br><a href="/register">Créer un compte</a><div class="footer">Developped by Heaven.ss</div></div></body></html>""".replace("{DISCORD_CSS}", DISCORD_CSS).replace("{TOPBAR}", TOPBAR)
REGISTER_HTML = """<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Créer un compte</title><style>{DISCORD_CSS}</style></head><body>{TOPBAR}<div class="container" style="margin-top:110px;"><h2>Créer un compte</h2>{% if error %}<div class="error">{{ error }}</div>{% endif %}{% if success %}<div class="success">{{ success }}</div>{% endif %}<form method="post"><input type="text" name="username" placeholder="Nom d'utilisateur" required><br><input type="password" name="password" placeholder="Mot de passe" required><br><input type="email" name="email" placeholder="Email" required><br><button type="submit">S'inscrire</button></form><br><a href="/login">Déjà un compte ? Se connecter</a><div class="footer">Developped by Heaven.ss</div></div></body></html>""".replace("{DISCORD_CSS}", DISCORD_CSS).replace("{TOPBAR}", TOPBAR)
SEARCH_HTML = """<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Recherche Discord ID</title><style>{DISCORD_CSS}</style></head><body>{TOPBAR}<div class="container" style="margin-top:110px;"><h2>Recherche dans la base par ID Discord / IP / License FiveM</h2><form id="searchForm"><input type="text" id="discordId" placeholder="Entrez un ID Discord, IP ou license:..." required><br><button type="submit">Rechercher</button></form><div id="result"></div><div class="footer">Developped by Heaven.ss</div></div><script>document.getElementById('searchForm').onsubmit = async function(e) {e.preventDefault();const id = document.getElementById('discordId').value.trim();const resultDiv = document.getElementById('result');resultDiv.innerHTML = "Recherche en cours...";try {const res = await fetch(`/search?id=${encodeURIComponent(id)}`);if (res.status === 200) {const blob = await res.blob();const url = window.URL.createObjectURL(blob);resultDiv.innerHTML = `<a class="download" href="${url}" download="resultats_${id}.txt">Télécharger le résultat TXT</a>`;} else if (res.status === 404) {resultDiv.innerHTML = "Aucun résultat trouvé pour cette recherche.";} else if (res.status === 400) {resultDiv.innerHTML = "Recherche non autorisée. Seuls les ID Discord, IP ou license FiveM sont acceptés.";} else {resultDiv.innerHTML = "Erreur lors de la recherche.";}} catch {resultDiv.innerHTML = "Erreur de connexion au serveur.";}};</script></body></html>""".replace("{DISCORD_CSS}", DISCORD_CSS).replace("{TOPBAR}", TOPBAR)
ADMIN_HTML = """<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Comptes enregistrés</title><style>{DISCORD_CSS}</style></head><body>{TOPBAR}<div class="container" style="width:98vw;max-width:1200px;margin-top:110px;"><h2>Liste des comptes créés</h2><table><tr><th>ID</th><th>Nom d'utilisateur</th><th>Email</th><th>Mot de passe (hashé)</th><th>IP</th><th>Date de création</th></tr>{% for user in users %}<tr><td>{{ user['id'] }}</td><td>{{ user['username'] }}</td><td>{{ user['email'] }}</td><td style="font-size:0.85em;word-break:break-all;">{{ user['password'] }}</td><td>{{ user['ip'] }}</td><td>{{ user['created_at'] }}</td></tr>{% endfor %}</table><br><a href="/">Retour à la recherche</a><div class="footer">Developped by Heaven.ss</div></div></body></html>""".replace("{DISCORD_CSS}", DISCORD_CSS).replace("{TOPBAR}", TOPBAR)
ACCOUNT_HTML = """<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Modifier mon compte</title><style>{DISCORD_CSS}</style></head><body>{TOPBAR}<div class="container" style="margin-top:110px;"><img src="https://api.dicebear.com/7.x/identicon/svg?seed={{ user }}" alt="avatar" style="width:80px;height:80px;border-radius:50%;background:#23272a;border:3px solid #5865f2;margin-bottom:20px;"><h2>Modifier mon compte</h2>{% if error %}<div class="error">{{ error }}</div>{% endif %}{% if success %}<div class="success">{{ success }}</div>{% endif %}<form method="post"><input type="text" name="username" value="{{ user }}" placeholder="Nom d'utilisateur" required><br><input type="email" name="email" value="{{ email }}" placeholder="Email" required><br><input type="password" name="old_password" placeholder="Ancien mot de passe" required><br><input type="password" name="new_password" placeholder="Nouveau mot de passe (laisser vide pour ne pas changer)"><br><button type="submit">Mettre à jour</button></form><div class="footer">Developped by Heaven.ss</div></div></body></html>""".replace("{DISCORD_CSS}", DISCORD_CSS).replace("{TOPBAR}", TOPBAR)
PROFILE_HTML = """<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Profil</title><style>{DISCORD_CSS}</style></head><body>{TOPBAR}<div class="container" style="margin-top:110px;"><img src="https://api.dicebear.com/7.x/identicon/svg?seed={{ user }}" alt="avatar" style="width:100px;height:100px;border-radius:50%;background:#23272a;border:3px solid #5865f2;margin-bottom:20px;"><h2>Profil de {{ user }}</h2><p><strong>Email :</strong> {{ email }}</p><p><strong>Adresse IP :</strong> {{ ip }}</p><p><strong>Date de création :</strong> {{ created_at }}</p><br><a href="/account" style="background:#5865f2;color:#fff;padding:10px 22px;border-radius:8px;font-weight:bold;text-decoration:none;">Modifier mes informations</a><div class="footer">Developped by Heaven.ss</div></div></body></html>""".replace("{DISCORD_CSS}", DISCORD_CSS).replace("{TOPBAR}", TOPBAR)

with app.app_context():
    init_db()

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    ip = request.remote_addr
    if is_vpn(ip):
        error = "Connexion via VPN/proxy/dédié ou mobile interdite."
        return render_template_string(LOGIN_HTML, error=error, user="", is_admin=False)
    if is_blocked(ip):
        error = "Trop de tentatives. Réessayez plus tard."
        return render_template_string(LOGIN_HTML, error=error, user="", is_admin=False)
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        email = request.form.get("email", "").strip()
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username=? AND email=?",
            (username, email)
        ).fetchone()
        if user and verify_password(password, user["password"]):
            session["user"] = username
            session["email"] = email
            register_attempt(ip, True)
            return redirect(url_for("index"))
        else:
            register_attempt(ip, False)
            error = "Identifiants incorrects."
    return render_template_string(LOGIN_HTML, error=error, user="", is_admin=False)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    success = None
    ip = request.remote_addr
    if is_vpn(ip):
        error = "Inscription via VPN/proxy/dédié ou mobile interdite."
        return render_template_string(REGISTER_HTML, error=error, success=success, user="", is_admin=False)
    if is_blocked(ip):
        error = "Trop de tentatives. Réessayez plus tard."
        return render_template_string(REGISTER_HTML, error=error, success=success, user="", is_admin=False)
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        email = request.form.get("email", "").strip()
        db = get_db()
        if db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            error = "Nom d'utilisateur déjà utilisé."
        elif db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            error = "Email déjà utilisé."
        elif len(password) < 8 or not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
            error = "Le mot de passe doit faire au moins 8 caractères et contenir lettres et chiffres."
        else:
            hashed = hash_password(password)
            db.execute(
                "INSERT INTO users (username, password, email, ip) VALUES (?, ?, ?, ?)",
                (username, hashed, email, ip)
            )
            db.commit()
            register_attempt(ip, True)
            success = "Compte créé avec succès ! Vous pouvez maintenant vous connecter."
    return render_template_string(REGISTER_HTML, error=error, success=success, user="", is_admin=False)

@app.route('/logout')
def logout():
    session.pop("user", None)
    session.pop("email", None)
    return redirect(url_for("login"))

@app.route('/')
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    is_admin = session.get("email") in ADMIN_EMAILS
    return render_template_string(SEARCH_HTML, is_admin=is_admin, user=session.get("user"))

@app.route('/search')
def search():
    if "user" not in session:
        abort(401)
    query = request.args.get('id', '').strip()
    if not query or not is_valid_query(query):
        abort(400, "Recherche non autorisée. Seuls les ID Discord, IP ou license:xxx sont acceptés.")

    resp = agent_search(query)
    if not resp or not resp.get("results"):
        abort(404)
    txt = ""
    for row in resp["results"]:
        txt += (
            f"Fichier: {row['file']} - Ligne: {row['line_num']}\n"
            f"  Steam:   {row['steam'] or 'Non trouvé'}\n"
            f"  Discord: {row['discord'] or 'Non trouvé'}\n"
            f"  FiveM:   {row['fivem'] or 'Non trouvé'}\n"
            f"  IP:      {row['ip'] or 'Non trouvé'}\n"
            f"  Pseudo:  {row['pseudo'] or 'Non trouvé'}\n"
            f"  Ligne brute: {row['raw_line']}\n"
            "----------------------------------------\n"
        )
    return send_file(
        io.BytesIO(txt.encode('utf-8')),
        mimetype='text/plain',
        as_attachment=True,
        download_name=f"resultats_{query}.txt"
    )

@app.route('/admin')
def admin():
    if "user" not in session or session.get("email") not in ADMIN_EMAILS:
        return redirect(url_for("login"))
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    return render_template_string(ADMIN_HTML, users=users, user=session.get("user"), is_admin=True)

@app.route('/account', methods=['GET', 'POST'])
def account():
    if "user" not in session:
        return redirect(url_for("login"))
    db = get_db()
    user_row = db.execute("SELECT * FROM users WHERE username=?", (session["user"],)).fetchone()
    error = None
    success = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        if not verify_password(old_password, user_row["password"]):
            error = "Ancien mot de passe incorrect."
        elif db.execute("SELECT 1 FROM users WHERE username=? AND username!=?", (username, session["user"])).fetchone():
            error = "Nom d'utilisateur déjà utilisé."
        elif db.execute("SELECT 1 FROM users WHERE email=? AND username!=?", (email, session["user"])).fetchone():
            error = "Email déjà utilisé."
        else:
            if new_password:
                if len(new_password) < 8 or not re.search(r"[A-Za-z]", new_password) or not re.search(r"\d", new_password):
                    error = "Le nouveau mot de passe doit faire au moins 8 caractères et contenir lettres et chiffres."
                else:
                    hashed = hash_password(new_password)
                    db.execute("UPDATE users SET username=?, email=?, password=? WHERE username=?",
                               (username, email, hashed, session["user"]))
                    db.commit()
                    session["user"] = username
                    session["email"] = email
                    success = "Compte et mot de passe mis à jour."
            else:
                db.execute("UPDATE users SET username=?, email=? WHERE username=?",
                           (username, email, session["user"]))
                db.commit()
                session["user"] = username
                session["email"] = email
                success = "Compte mis à jour."
            user_row = db.execute("SELECT * FROM users WHERE username=?", (session["user"],)).fetchone()
    return render_template_string(ACCOUNT_HTML, user=session["user"], email=session["email"], error=error, success=success, is_admin=(session.get("email") in ADMIN_EMAILS))

@app.route('/profile')
def profile():
    if "user" not in session:
        return redirect(url_for("login"))
    db = get_db()
    user_row = db.execute("SELECT * FROM users WHERE username=?", (session["user"],)).fetchone()
    return render_template_string(
        PROFILE_HTML,
        user=session["user"],
        email=session["email"],
        ip=user_row["ip"],
        created_at=user_row["created_at"],
        is_admin=(session.get("email") in ADMIN_EMAILS)
    )

@app.route('/<path:path>')
def block_files(path):
    abort(404)

if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(port=VOTRE PORT DE SITE)