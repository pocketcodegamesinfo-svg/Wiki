import sqlite3
import os
import html
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, request, session, redirect, url_for,
                   render_template_string, g, abort, send_from_directory,
                   flash, jsonify)

# ===== НАСТРОЙКИ =====
SECRET_KEY = os.environ.get("SECRET_KEY") or "temp-key-for-local-dev"
DB_PATH = "wiki.db"
UPLOAD_DIR = "uploads"
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_AVATAR_BYTES = 2 * 1024 * 1024
ONLINE_TIMEOUT_SEC = 300  # 5 минут — считаем «онлайн»

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = SECRET_KEY


# ===== ПРАВА =====
PERMS = {
    "create_page":  "Создавать статьи",
    "edit_own":     "Редактировать свои статьи",
    "edit_any":     "Редактировать чужие статьи",
    "delete_page":  "Удалять статьи",
    "chat_write":   "Писать в чат",
    "chat_delete":  "Удалять сообщения в чате",
    "manage_users": "Управлять пользователями",
    "manage_roles": "Управлять ролями",
    "view_admin":   "Видеть админ-панель",
}


# ===== БАЗА =====
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            avatar TEXT DEFAULT '',
            bio TEXT DEFAULT '',
            status TEXT DEFAULT '',
            is_owner INTEGER DEFAULT 0,
            role_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            tags TEXT DEFAULT '',
            author TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS private_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            body TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS invites (
            token TEXT PRIMARY KEY,
            created_by TEXT NOT NULL,
            used_by TEXT,
            role_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            color TEXT DEFAULT '#3b82f6',
            perms TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.commit()
    db.close()

def migrate_db():
    db = sqlite3.connect(DB_PATH)
    def table_exists(t):
        return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                          (t,)).fetchone() is not None
    def cols(t):
        return [r[1] for r in db.execute(f"PRAGMA table_info({t})").fetchall()]

    if table_exists("users"):
        uc = cols("users")
        for name, ddl in [
            ("avatar",     "ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT ''"),
            ("bio",        "ALTER TABLE users ADD COLUMN bio TEXT DEFAULT ''"),
            ("status",     "ALTER TABLE users ADD COLUMN status TEXT DEFAULT ''"),
            ("is_owner",   "ALTER TABLE users ADD COLUMN is_owner INTEGER DEFAULT 0"),
            ("role_id",    "ALTER TABLE users ADD COLUMN role_id INTEGER"),
            ("created_at", "ALTER TABLE users ADD COLUMN created_at TIMESTAMP"),
            ("last_seen",  "ALTER TABLE users ADD COLUMN last_seen TIMESTAMP"),
        ]:
            if name not in uc:
                db.execute(ddl)
        db.execute("UPDATE users SET is_owner=1 WHERE id=(SELECT MIN(id) FROM users)")
        db.execute("UPDATE users SET last_seen=CURRENT_TIMESTAMP WHERE last_seen IS NULL")
    if table_exists("pages") and "tags" not in cols("pages"):
        db.execute("ALTER TABLE pages ADD COLUMN tags TEXT DEFAULT ''")
    if table_exists("invites") and "role_id" not in cols("invites"):
        db.execute("ALTER TABLE invites ADD COLUMN role_id INTEGER")
    db.commit()
    db.close()


# ===== ПАРОЛИ =====
def hash_password(pw: str) -> str:
    salt = os.urandom(16).hex()
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 100_000)
    return f"{salt}${h.hex()}"

def verify_password(pw: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(),
                                   bytes.fromhex(salt), 100_000).hex()
        return calc == h
    except Exception:
        return False


# ===== РОЛИ И ПРАВА =====
def get_role(db, role_id):
    if not role_id:
        return None
    return db.execute("SELECT * FROM roles WHERE id=?", (role_id,)).fetchone()

def role_perms(role):
    if not role:
        return set()
    return set(p for p in (role["perms"] or "").split(",") if p)

def current_perms():
    if session.get("is_owner"):
        return set(PERMS.keys())
    if "user" not in session:
        return set()
    db = get_db()
    u = db.execute("SELECT role_id FROM users WHERE username=?",
                   (session["user"],)).fetchone()
    if not u:
        return set()
    return role_perms(get_role(db, u["role_id"]))

def has_perm(perm: str) -> bool:
    return perm in current_perms()


# ===== ОНЛАЙН-СТАТУС =====
def is_online(last_seen_str):
    if not last_seen_str:
        return False
    try:
        last = datetime.strptime(last_seen_str, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return False
    return (datetime.utcnow() - last) < timedelta(seconds=ONLINE_TIMEOUT_SEC)

def human_last_seen(last_seen_str):
    if not last_seen_str:
        return "неизвестно"
    try:
        last = datetime.strptime(last_seen_str, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return "неизвестно"
    delta = datetime.utcnow() - last
    secs = int(delta.total_seconds())
    if secs < ONLINE_TIMEOUT_SEC:
        return "в сети"
    if secs < 3600:
        return f"был {secs // 60} мин назад"
    if secs < 86400:
        return f"был {secs // 3600} ч назад"
    return f"был {secs // 86400} дн назад"


# ===== ДЕКОРАТОРЫ =====
def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if "user" not in session:
            return redirect(url_for("login", next=request.path))
        return f(*a, **kw)
    return w

def owner_required(f):
    @wraps(f)
    def w(*a, **kw):
        if "user" not in session:
            return redirect(url_for("login"))
        if not session.get("is_owner"):
            abort(403)
        return f(*a, **kw)
    return w

def perm_required(perm: str):
    def deco(f):
        @wraps(f)
        def w(*a, **kw):
            if "user" not in session:
                return redirect(url_for("login", next=request.path))
            if not has_perm(perm):
                abort(403)
            return f(*a, **kw)
        return w
    return deco


# ===== ОБНОВЛЕНИЕ last_seen =====
@app.before_request
def update_last_seen():
    if "user" in session:
        try:
            db = get_db()
            db.execute("UPDATE users SET last_seen=CURRENT_TIMESTAMP WHERE username=?",
                       (session["user"],))
            db.commit()
        except Exception:
            pass


# ===== БАЗОВЫЙ ШАБЛОН =====
BASE = """
<!doctype html>
<html lang="ru" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{% block title %}Библиотека{% endblock %}</title>
<script>
  (function() {
    var t = localStorage.getItem('theme');
    if (!t) t = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', t);
  })();
</script>
<style>
  :root {
    --bg: #ffffff; --bg-soft: #f6f8fa; --bg-card: #ffffff;
    --border: #e5e7eb; --text: #1f2328; --text-muted: #656d76;
    --accent: #3b82f6; --accent-hover: #2563eb; --accent-soft: #eff6ff;
    --danger: #dc2626; --online: #22c55e;
    --shadow: 0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04);
    --radius: 10px;
  }
  [data-theme="dark"] {
    --bg: #0d1117; --bg-soft: #161b22; --bg-card: #161b22;
    --border: #30363d; --text: #e6edf3; --text-muted: #8b949e;
    --accent: #58a6ff; --accent-hover: #79b8ff; --accent-soft: #1f2937;
    --danger: #f85149; --online: #22c55e;
    --shadow: 0 1px 3px rgba(0,0,0,0.4);
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.65;
    transition: background .2s, color .2s;
  }
  .container { max-width: 960px; margin: 0 auto; padding: 0 1.2rem; }
  header {
    background: var(--bg-soft); border-bottom: 1px solid var(--border);
    padding: .9rem 0; margin-bottom: 2rem;
    transition: background .2s, border-color .2s;
  }
  header .container {
    display: flex; justify-content: space-between; align-items: center;
    gap: 1rem; flex-wrap: wrap;
  }
  .brand {
    font-size: 1.15rem; font-weight: 700; color: var(--text);
    display: flex; align-items: center; gap: .5rem;
  }
  .brand:hover { text-decoration: none; }
  nav { display: flex; align-items: center; gap: .4rem; flex-wrap: wrap; }
  nav a, nav button {
    color: var(--text); text-decoration: none;
    padding: .4rem .7rem; border-radius: 6px; font-size: .92rem;
    transition: background .15s; background: transparent;
    border: 0; cursor: pointer; font-family: inherit;
  }
  nav a:hover { background: var(--accent-soft); text-decoration: none; }
  nav a.primary { background: var(--accent); color: #fff; }
  nav a.primary:hover { background: var(--accent-hover); }
  .theme-toggle {
    background: transparent; border: 1px solid var(--border);
    width: 36px; height: 36px; border-radius: 8px; cursor: pointer;
    display: flex; align-items: center; justify-content: center;
    font-size: 1rem; padding: 0; color: var(--text);
  }
  .theme-toggle:hover { background: var(--accent-soft); }
  .user-chip {
    display: inline-flex; align-items: center; gap: .45rem;
    padding: .25rem .6rem .25rem .25rem; border-radius: 999px;
    background: var(--bg-card); border: 1px solid var(--border);
    color: var(--text); font-size: .9rem;
  }
  .user-chip:hover { text-decoration: none; border-color: var(--accent); }
  h1 { font-size: 1.9rem; margin: 0 0 1.2rem; line-height: 1.2; }
  h2 { font-size: 1.35rem; margin: 1.8rem 0 1rem; }
  h3 { font-size: 1.1rem; margin: 1.4rem 0 .8rem; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  hr { border: 0; border-top: 1px solid var(--border); margin: 1.5rem 0; }
  input, textarea, select {
    font: inherit; padding: .65rem .8rem; width: 100%;
    background: var(--bg-card); color: var(--text);
    border: 1px solid var(--border); border-radius: 8px;
    margin: .3rem 0; transition: border-color .15s, box-shadow .15s;
  }
  input:focus, textarea:focus, select:focus {
    outline: none; border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(59,130,246,.2);
  }
  textarea { min-height: 240px; font-family: ui-monospace, SFMono-Regular, monospace; }
  label { display: block; margin-top: .8rem; font-size: .9rem; color: var(--text-muted); }
  button, .btn {
    font: inherit; padding: .6rem 1.1rem; border-radius: 8px;
    background: var(--accent); color: #fff; border: 0; cursor: pointer;
    display: inline-block; text-decoration: none;
    transition: background .15s;
  }
  button:hover, .btn:hover { background: var(--accent-hover); text-decoration: none; }
  .btn-ghost { background: transparent; color: var(--text); border: 1px solid var(--border); }
  .btn-ghost:hover { background: var(--accent-soft); }
  .btn-danger { background: var(--danger); }
  .btn-danger:hover { filter: brightness(.85); }
  .card {
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 1.1rem 1.2rem;
    margin-bottom: .8rem; box-shadow: var(--shadow);
    transition: border-color .15s;
  }
  .card:hover { border-color: var(--accent); }
  .card a.title { color: var(--text); font-weight: 600; font-size: 1.05rem; }
  .card a.title:hover { color: var(--accent); text-decoration: none; }
  .muted { color: var(--text-muted); font-size: .88rem; }
  .flash {
    background: var(--accent-soft); padding: .7rem 1rem;
    border-radius: 8px; margin: 0 0 1rem; border-left: 3px solid var(--accent);
  }
  .tag {
    display: inline-block; background: var(--accent-soft); color: var(--accent);
    padding: .15rem .55rem; border-radius: 999px; font-size: .78rem;
    margin-right: .3rem; font-weight: 500;
  }
  .tag:hover { text-decoration: none; }
  .avatar {
    width: 28px; height: 28px; border-radius: 50%; object-fit: cover;
    background: var(--border); display: inline-block; vertical-align: middle;
  }
  .avatar-lg { width: 56px; height: 56px; }
  .avatar-wrap { position: relative; display: inline-block; }
  .online-dot {
    position: absolute; bottom: 0; right: 0;
    width: 12px; height: 12px; border-radius: 50%;
    background: var(--online); border: 2px solid var(--bg-card);
  }
  .online-dot.offline { background: #9ca3af; }
  .chat-box {
    background: var(--bg-soft); border: 1px solid var(--border);
    border-radius: var(--radius); height: 440px; overflow-y: auto;
    padding: 1rem;
  }
  .msg { display: flex; gap: .7rem; margin-bottom: .9rem; }
  .msg .who { font-weight: 600; color: var(--text); }
  .msg .when { color: var(--text-muted); font-size: .78rem; margin-left: .4rem; }
  .msg .body { color: var(--text); margin-top: .1rem; }
  .auth-wrap { max-width: 400px; margin: 3rem auto; }
  .auth-wrap h1 { text-align: center; margin-bottom: 1.5rem; }
  .auth-wrap .card { padding: 1.5rem; }
  .center-actions { text-align: center; margin-top: 1rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: .6rem .5rem; text-align: left; border-bottom: 1px solid var(--border); }
  th { color: var(--text-muted); font-size: .85rem; font-weight: 600; }
  @media (max-width: 600px) {
    header .container { gap: .5rem; }
    nav { font-size: .85rem; }
    h1 { font-size: 1.5rem; }
  }
</style>
</head>
<body>
<header>
  <div class="container">
    <a class="brand" href="{{ url_for('index') }}">📚 Библиотека</a>
    <nav>
      {% if session.user %}
        <a href="{{ url_for('chat') }}">💬 Чат</a>
        <a href="{{ url_for('messages_inbox') }}">✉️ Личные
          {% if unread_count %}<span class="tag" style="background:#ef4444;color:#fff;margin-left:.2rem">{{ unread_count }}</span>{% endif %}
        </a>
        {% if 'create_page' in perms %}
          <a href="{{ url_for('new_page') }}">+ Статья</a>
        {% endif %}
        {% if is_owner or 'view_admin' in perms or 'manage_users' in perms or 'manage_roles' in perms %}
          <a href="{{ url_for('admin_users') }}" class="primary">👥 Админка</a>
        {% endif %}
        <a href="{{ url_for('user_profile', username=session.user) }}" class="user-chip">
          <span class="avatar-wrap">
            {% if me and me['avatar'] %}
              <img class="avatar" src="{{ url_for('uploaded_file', filename=me['avatar']) }}">
            {% else %}
              <span class="avatar" style="display:inline-flex;align-items:center;justify-content:center;font-size:.75rem;color:var(--text-muted)">
                {{ session.user[0]|upper }}
              </span>
            {% endif %}
            <span class="online-dot"></span>
          </span>
          <span>{{ session.user }}{% if is_owner %} ★{% endif %}</span>
          {% if role %}
            <span class="tag" style="background:{{ role['color'] }}22;color:{{ role['color'] }};margin-left:.2rem">{{ role['name'] }}</span>
          {% endif %}
        </a>
        <a href="{{ url_for('logout') }}">Выйти</a>
      {% endif %}
      <button class="theme-toggle" onclick="toggleTheme()" title="Сменить тему"
              aria-label="Сменить тему" id="theme-btn">☀️</button>
    </nav>
  </div>
</header>

<main class="container">
{% with msgs = get_flashed_messages() %}
  {% for m in msgs %}<div class="flash">{{ m }}</div>{% endfor %}
{% endwith %}
{% block body %}{% endblock %}
</main>

<script>
  function toggleTheme() {
    var cur = document.documentElement.getAttribute('data-theme');
    var next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    updateThemeButton();
  }
  function updateThemeButton() {
    var t = document.documentElement.getAttribute('data-theme');
    var b = document.getElementById('theme-btn');
    if (b) b.textContent = t === 'dark' ? '🌙' : '☀️';
  }
  updateThemeButton();
</script>
</body>
</html>
"""

def tpl(body: str) -> str:
    return BASE.replace("{% block body %}{% endblock %}",
                        "{% block body %}" + body + "{% endblock %}")


# ===== ШАБЛОНЫ =====
INDEX_TPL = tpl("""
<h1>Все статьи</h1>
<form method="get" action="{{ url_for('index') }}">
  <input name="q" placeholder="🔍 Поиск по заголовку или тексту..." value="{{ q or '' }}">
</form>
{% if all_tags %}
  <p style="margin-top:1rem">
    <a href="{{ url_for('index') }}" class="tag">все</a>
    {% for t in all_tags %}
      <a href="{{ url_for('index', tag=t) }}" class="tag">{{ t }}</a>
    {% endfor %}
  </p>
{% endif %}
<div style="margin-top:1.2rem">
{% if pages %}
  {% for p in pages %}
    <div class="card">
      <a class="title" href="{{ url_for('view_page', slug=p['slug']) }}">{{ p['title'] }}</a>
      <div style="margin:.4rem 0">
        {% for t in (p['tags'] or '').split(',') if t.strip() %}
          <a href="{{ url_for('index', tag=t.strip()) }}" class="tag">{{ t.strip() }}</a>
        {% endfor %}
      </div>
      <div class="muted">автор:
        <a href="{{ url_for('user_profile', username=p['author']) }}">{{ p['author'] }}</a>
        · обновлено {{ p['updated_at'] }}
      </div>
    </div>
  {% endfor %}
{% else %}
  <div class="card">
    <p class="muted">Пока пусто.
      {% if 'create_page' in perms %}<a href="{{ url_for('new_page') }}">Создайте первую статью</a>.{% endif %}
    </p>
  </div>
{% endif %}
</div>
""")

VIEW_TPL = tpl("""
<h1>{{ page['title'] }}</h1>
<div class="muted" style="margin-bottom:.6rem">
  автор: <a href="{{ url_for('user_profile', username=page['author']) }}">{{ page['author'] }}</a>
  · slug: <code>{{ page['slug'] }}</code> · обновлено {{ page['updated_at'] }}
</div>
<p>
  {% for t in (page['tags'] or '').split(',') if t.strip() %}
    <a href="{{ url_for('index', tag=t.strip()) }}" class="tag">{{ t.strip() }}</a>
  {% endfor %}
</p>
<hr>
<div>{{ content_html|safe }}</div>
<hr>
{% if 'edit_any' in perms or ('edit_own' in perms and page['author'] == session.user) %}
  <a class="btn" href="{{ url_for('edit_page', slug=page['slug']) }}">✏️ Редактировать</a>
{% endif %}
{% if 'delete_page' in perms %}
  <form method="post" action="{{ url_for('delete_page', slug=page['slug']) }}"
        style="display:inline" onsubmit="return confirm('Удалить статью?')">
    <button class="btn btn-danger" type="submit">🗑 Удалить</button>
  </form>
{% endif %}
""")

EDIT_TPL = tpl("""
<h1>{{ 'Редактировать статью' if page else 'Новая статья' }}</h1>
<form method="post">
  <label>Заголовок</label>
  <input name="title" required value="{{ page['title'] if page else '' }}" autofocus>
  <label>Slug (латиница, цифры, дефис)</label>
  <input name="slug" required value="{{ page['slug'] if page else '' }}"
         pattern="[a-z0-9\\-]+" title="латиница, цифры и дефис">
  <label>Теги (через запятую)</label>
  <input name="tags" value="{{ page['tags'] if page else '' }}">
  <label>Содержимое (можно использовать # ## ### для заголовков)</label>
  <textarea name="content" required>{{ page['content'] if page else '' }}</textarea>
  <div style="margin-top:1rem">
    <button type="submit">💾 Сохранить</button>
    <a class="btn btn-ghost" href="{{ url_for('index') }}">Отмена</a>
  </div>
</form>
""")

LOGIN_TPL = tpl("""
<div class="auth-wrap">
  <h1>Вход в библиотеку</h1>
  <div class="card">
    <form method="post">
      <input name="username" placeholder="Логин" required autofocus autocomplete="username">
      <input name="password" type="password" placeholder="Пароль" required autocomplete="current-password">
      <button type="submit" style="width:100%;margin-top:.8rem">Войти</button>
    </form>
  </div>
  <div class="center-actions">
    <p class="muted">Нет аккаунта?</p>
    <a class="btn btn-ghost" href="{{ url_for('register_info') }}">Создать аккаунт</a>
  </div>
  {% if need_setup %}
    <div class="center-actions" style="margin-top:2rem">
      <p class="muted">Пользователей ещё нет.</p>
      <a class="btn" href="{{ url_for('setup') }}">Создать аккаунт создателя</a>
    </div>
  {% endif %}
</div>
""")

SETUP_TPL = tpl("""
<div class="auth-wrap">
  <h1>Создание аккаунта создателя</h1>
  <div class="card">
    <p class="muted">Эта страница доступна только один раз — пока в системе нет пользователей.</p>
    <form method="post">
      <input name="username" placeholder="Логин создателя" required autofocus>
      <input name="password" type="password" placeholder="Пароль" required>
      <button type="submit" style="width:100%;margin-top:.8rem">Создать</button>
    </form>
  </div>
</div>
""")

REGISTER_INFO_TPL = tpl("""
<div class="auth-wrap">
  <h1>Регистрация закрыта</h1>
  <div class="card">
    <p>Доступ к библиотеке — только по приглашению от владельца.</p>
    <p class="muted">
      Если у вас есть пригласительная ссылка — откройте её в браузере,
      и вы сможете создать аккаунт.
    </p>
    <p class="muted">Если ссылки нет — свяжитесь с администратором библиотеки.</p>
    <div class="center-actions">
      <a class="btn btn-ghost" href="{{ url_for('login') }}">← Назад ко входу</a>
    </div>
  </div>
</div>
""")

CHAT_TPL = tpl("""
<h1>💬 Общий чат</h1>
<div class="chat-box" id="chat-box" data-last-id="{{ last_id }}">
  {% for m in messages %}
    <div class="msg" data-id="{{ m['id'] }}">
      <a href="{{ url_for('user_profile', username=m['author']) }}">
        <span class="avatar-wrap">
          {% if m['avatar'] %}
            <img class="avatar" src="{{ url_for('uploaded_file', filename=m['avatar']) }}">
          {% else %}
            <span class="avatar" style="display:inline-flex;align-items:center;justify-content:center;font-size:.75rem;color:var(--text-muted)">
              {{ m['author'][0]|upper }}
            </span>
          {% endif %}
          <span class="online-dot {% if not m['online'] %}offline{% endif %}"></span>
        </span>
      </a>
      <div style="flex:1">
        <a href="{{ url_for('user_profile', username=m['author']) }}" class="who">{{ m['author'] }}</a>
        <span class="when">{{ m['created_at'] }}</span>
        {% if 'chat_delete' in perms %}
          <button class="btn btn-danger" style="padding:.1rem .5rem;font-size:.75rem;float:right"
                  onclick="deleteMessage({{ m['id'] }})">×</button>
        {% endif %}
        <div class="body">{{ m['body'] }}</div>
      </div>
    </div>
  {% endfor %}
</div>
{% if 'chat_write' in perms %}
<form id="chat-form" style="margin-top:1rem" onsubmit="return sendMessage(event)">
  <input name="body" id="chat-input" placeholder="Ваше сообщение..." required autocomplete="off">
  <button type="submit" style="margin-top:.4rem">Отправить</button>
</form>
{% else %}
<p class="muted">У вас нет права писать в чат.</p>
{% endif %}

<script>
const box = document.getElementById('chat-box');
const canDelete = {{ ('chat_delete' in perms)|tojson }};

function scrollDown() { if (box) box.scrollTop = box.scrollHeight; }
scrollDown();

function renderMsg(m) {
  const wrap = document.createElement('div');
  wrap.className = 'msg';
  wrap.dataset.id = m.id;
  const avatarHtml = m.avatar
    ? `<img class="avatar" src="/uploads/${m.avatar}">`
    : `<span class="avatar" style="display:inline-flex;align-items:center;justify-content:center;font-size:.75rem;color:var(--text-muted)">${m.author[0].toUpperCase()}</span>`;
  const delBtn = canDelete
    ? `<button class="btn btn-danger" style="padding:.1rem .5rem;font-size:.75rem;float:right" onclick="deleteMessage(${m.id})">×</button>`
    : '';
  wrap.innerHTML = `
    <a href="/user/${encodeURIComponent(m.author)}">
      <span class="avatar-wrap">
        ${avatarHtml}
        <span class="online-dot ${m.online ? '' : 'offline'}"></span>
      </span>
    </a>
    <div style="flex:1">
      <a href="/user/${encodeURIComponent(m.author)}" class="who">${m.author}</a>
      <span class="when">${m.created_at}</span>
      ${delBtn}
      <div class="body">${m.body}</div>
    </div>`;
  return wrap;
}

async function pollMessages() {
  if (!box) return;
  try {
    const lastId = box.dataset.lastId || '0';
    const r = await fetch(`/chat/messages?after=${lastId}`);
    if (!r.ok) return;
    const arr = await r.json();
    let added = 0;
    for (const m of arr) {
      if (box.querySelector(`[data-id="${m.id}"]`)) continue;
      box.appendChild(renderMsg(m));
      box.dataset.lastId = m.id;
      added++;
    }
    if (added) scrollDown();
  } catch (e) {}
}
setInterval(pollMessages, 2000);

async function sendMessage(ev) {
  ev.preventDefault();
  const input = document.getElementById('chat-input');
  const body = input.value.trim();
  if (!body) return false;
  input.value = '';
  try {
    await fetch('/chat/send_ajax', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({body})
    });
    pollMessages();
  } catch (e) {}
  return false;
}

function deleteMessage(id) {
  if (!confirm('Удалить сообщение?')) return;
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = `/chat/delete/${id}`;
  document.body.appendChild(form);
  form.submit();
}
</script>
""")

PROFILE_TPL = tpl("""
<h1>Мой профиль</h1>
<div class="card" style="display:flex;gap:1.5rem;align-items:flex-start">
  <span class="avatar-wrap">
    {% if me and me['avatar'] %}
      <img class="avatar avatar-lg" style="width:96px;height:96px" src="{{ url_for('uploaded_file', filename=me['avatar']) }}">
    {% else %}
      <span class="avatar avatar-lg" style="width:96px;height:96px;font-size:2.4rem;display:inline-flex;align-items:center;justify-content:center;color:var(--text-muted)">
        {{ me['username'][0]|upper }}
      </span>
    {% endif %}
    <span class="online-dot"></span>
  </span>
  <div style="flex:1">
    <h2 style="margin:0 0 .3rem">{{ me['username'] }}
      {% if is_owner %}<span class="tag">владелец ★</span>{% endif %}
      {% if role %}<span class="tag" style="background:{{ role['color'] }}22;color:{{ role['color'] }}">{{ role['name'] }}</span>{% endif %}
    </h2>
    <div class="muted">в системе с {{ me['created_at'] }}</div>
    <a class="btn btn-ghost" style="margin-top:.6rem" href="{{ url_for('user_profile', username=me['username']) }}">
      Открыть публичный профиль →
    </a>
  </div>
</div>

<div class="card">
  <h2 style="margin-top:0">О себе</h2>
  <form method="post" action="{{ url_for('update_profile') }}">
    <label>Статус (короткая строка)</label>
    <input name="status" maxlength="100" value="{{ me['status'] or '' }}"
           placeholder="Например: Читаю вики">
    <label>О себе (до 500 символов)</label>
    <textarea name="bio" maxlength="500" style="min-height:120px"
              placeholder="Пара слов о вас...">{{ me['bio'] or '' }}</textarea>
    <button type="submit" style="margin-top:.6rem">Сохранить</button>
  </form>
</div>

<div class="card">
  <h2 style="margin-top:0">Сменить аватар</h2>
  <form method="post" action="{{ url_for('profile') }}" enctype="multipart/form-data">
    <input type="file" name="avatar" accept="image/*" required>
    <div style="margin-top:.6rem">
      <button type="submit">Загрузить</button>
      {% if me['avatar'] %}
        <button class="btn btn-ghost" type="submit"
                formaction="{{ url_for('remove_avatar') }}">Удалить</button>
      {% endif %}
    </div>
  </form>
  <p class="muted">Форматы: png, jpg, gif, webp. Максимум {{ max_mb }} МБ.</p>
</div>

<div class="card">
  <h2 style="margin-top:0">Сменить пароль</h2>
  <form method="post" action="{{ url_for('change_password') }}">
    <input name="old" type="password" placeholder="Текущий пароль" required>
    <input name="new1" type="password" placeholder="Новый пароль" required>
    <input name="new2" type="password" placeholder="Повторите новый" required>
    <button type="submit" style="margin-top:.6rem">Сменить пароль</button>
  </form>
</div>
""")

USER_PROFILE_TPL = tpl("""
<div class="card" style="display:flex;gap:1.5rem;align-items:flex-start">
  <span class="avatar-wrap">
    {% if user['avatar'] %}
      <img class="avatar avatar-lg" style="width:96px;height:96px" src="{{ url_for('uploaded_file', filename=user['avatar']) }}">
    {% else %}
      <span class="avatar avatar-lg" style="width:96px;height:96px;font-size:2.4rem;display:inline-flex;align-items:center;justify-content:center;color:var(--text-muted)">
        {{ user['username'][0]|upper }}
      </span>
    {% endif %}
    <span class="online-dot {% if not online %}offline{% endif %}"></span>
  </span>
  <div style="flex:1">
    <h1 style="margin:0 0 .3rem">{{ user['username'] }}
      {% if user['is_owner'] %}<span class="tag">владелец ★</span>{% endif %}
      {% if role %}<span class="tag" style="background:{{ role['color'] }}22;color:{{ role['color'] }}">{{ role['name'] }}</span>{% endif %}
    </h1>
    {% if user['status'] %}
      <div class="muted" style="margin-bottom:.4rem">💬 {{ user['status'] }}</div>
    {% endif %}
    <div class="muted">
      <span class="online-dot {% if not online %}offline{% endif %}"
            style="position:static;display:inline-block;margin-right:.4rem;vertical-align:middle"></span>
      {{ last_seen_text }}
    </div>
    <div class="muted" style="margin-top:.3rem">в системе с {{ user['created_at'] }}</div>
    <div class="muted" style="margin-top:.3rem">
      📝 статей: {{ pages_count }} · 💬 сообщений в чате: {{ chat_count }}
    </div>
    {% if session.user and session.user != user['username'] %}
      <a class="btn" style="margin-top:.8rem"
         href="{{ url_for('messages_with', username=user['username']) }}">
        ✉️ Написать сообщение
      </a>
    {% endif %}
    {% if session.user == user['username'] %}
      <a class="btn btn-ghost" style="margin-top:.8rem" href="{{ url_for('profile') }}">
        ✏️ Редактировать профиль
      </a>
    {% endif %}
  </div>
</div>

{% if user['bio'] %}
  <div class="card">
    <h2 style="margin-top:0">О себе</h2>
    <div style="white-space:pre-wrap">{{ user['bio'] }}</div>
  </div>
{% endif %}
""")

MESSAGES_TPL = tpl("""
<h1>✉️ Личные сообщения</h1>
{% if dialogs %}
  {% for d in dialogs %}
    <div class="card" style="display:flex;gap:1rem;align-items:center">
      <a href="{{ url_for('user_profile', username=d['other']) }}">
        <span class="avatar-wrap">
          {% if d['avatar'] %}
            <img class="avatar" style="width:44px;height:44px" src="{{ url_for('uploaded_file', filename=d['avatar']) }}">
          {% else %}
            <span class="avatar" style="width:44px;height:44px;font-size:1.2rem;display:inline-flex;align-items:center;justify-content:center;color:var(--text-muted)">
              {{ d['other'][0]|upper }}
            </span>
          {% endif %}
          <span class="online-dot {% if not d['online'] %}offline{% endif %}"></span>
        </span>
      </a>
      <div style="flex:1">
        <a href="{{ url_for('messages_with', username=d['other']) }}"><b>{{ d['other'] }}</b></a>
        <span class="muted" style="font-size:.8rem;margin-left:.4rem">{{ d['last_seen_text'] }}</span>
        <div class="muted">{{ d['last_body'][:80] }}{% if d['last_body']|length > 80 %}...{% endif %}</div>
        <div class="muted" style="font-size:.8rem">{{ d['last_at'] }}</div>
      </div>
      {% if d['unread'] %}
        <span class="tag" style="background:#ef4444;color:#fff">{{ d['unread'] }}</span>
      {% endif %}
    </div>
  {% endfor %}
{% else %}
  <div class="card"><p class="muted">Пока нет диалогов. Откройте чей-нибудь профиль и напишите первым.</p></div>
{% endif %}
""")

MESSAGES_WITH_TPL = tpl("""
<h1 style="display:flex;align-items:center;gap:.6rem">
  ✉️ Чат с
  <a href="{{ url_for('user_profile', username=other['username']) }}"
     style="display:inline-flex;align-items:center;gap:.5rem">
    <span class="avatar-wrap">
      {% if other['avatar'] %}
        <img class="avatar" src="{{ url_for('uploaded_file', filename=other['avatar']) }}">
      {% else %}
        <span class="avatar" style="display:inline-flex;align-items:center;justify-content:center;font-size:.75rem;color:var(--text-muted)">
          {{ other['username'][0]|upper }}
        </span>
      {% endif %}
      <span class="online-dot {% if not online %}offline{% endif %}"></span>
    </span>
    {{ other['username'] }}
  </a>
  <span class="muted" style="font-size:.9rem;font-weight:400">{{ last_seen_text }}</span>
</h1>
<div class="chat-box" id="chat-box" data-last-id="{{ last_id }}" data-other="{{ other['username'] }}" style="height:400px">
  {% for m in messages %}
    <div class="msg" data-id="{{ m['id'] }}">
      {% if m['sender'] == session.user %}
        <div style="flex:1;text-align:right">
          <span class="who">Вы</span>
          <span class="when">{{ m['created_at'] }}</span>
          <div class="body" style="display:inline-block;background:var(--accent-soft);padding:.4rem .7rem;border-radius:10px;margin-top:.2rem;text-align:left">{{ m['body'] }}</div>
        </div>
      {% else %}
        <div style="flex:1">
          <span class="who">{{ m['sender'] }}</span>
          <span class="when">{{ m['created_at'] }}</span>
          <div class="body" style="display:inline-block;background:var(--bg-soft);padding:.4rem .7rem;border-radius:10px;margin-top:.2rem">{{ m['body'] }}</div>
        </div>
      {% endif %}
    </div>
  {% endfor %}
</div>
<form id="pm-form" style="margin-top:1rem" onsubmit="return sendPM(event)">
  <input name="body" id="pm-input" placeholder="Ваше сообщение..." required autocomplete="off">
  <button type="submit" style="margin-top:.4rem">Отправить</button>
</form>
<script>
const box = document.getElementById('chat-box');
const other = box.dataset.other;

function scrollDown() { box.scrollTop = box.scrollHeight; }
scrollDown();

function renderPM(m) {
  const wrap = document.createElement('div');
  wrap.className = 'msg';
  wrap.dataset.id = m.id;
  if (m.is_me) {
    wrap.innerHTML = `<div style="flex:1;text-align:right">
      <span class="who">Вы</span>
      <span class="when">${m.created_at}</span>
      <div class="body" style="display:inline-block;background:var(--accent-soft);padding:.4rem .7rem;border-radius:10px;margin-top:.2rem;text-align:left">${m.body}</div>
    </div>`;
  } else {
    wrap.innerHTML = `<div style="flex:1">
      <span class="who">${m.sender}</span>
      <span class="when">${m.created_at}</span>
      <div class="body" style="display:inline-block;background:var(--bg-soft);padding:.4rem .7rem;border-radius:10px;margin-top:.2rem">${m.body}</div>
    </div>`;
  }
  return wrap;
}

async function pollPM() {
  try {
    const lastId = box.dataset.lastId || '0';
    const r = await fetch(`/messages/${encodeURIComponent(other)}/api?after=${lastId}`);
    if (!r.ok) return;
    const arr = await r.json();
    let added = 0;
    for (const m of arr) {
      if (box.querySelector(`[data-id="${m.id}"]`)) continue;
      box.appendChild(renderPM(m));
      box.dataset.lastId = m.id;
      added++;
    }
    if (added) scrollDown();
  } catch (e) {}
}
setInterval(pollPM, 2000);

async function sendPM(ev) {
  ev.preventDefault();
  const input = document.getElementById('pm-input');
  const body = input.value.trim();
  if (!body) return false;
  input.value = '';
  try {
    await fetch(`/messages/${encodeURIComponent(other)}/send_ajax`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({body})
    });
    pollPM();
  } catch (e) {}
  return false;
}
</script>
""")

ADMIN_TPL = tpl("""
<h1>👥 Админ-панель</h1>

{% if 'manage_roles' in perms %}
<div class="card">
  <h2 style="margin-top:0">🎭 Роли</h2>
  <p class="muted">Создавайте роли с нужным набором прав и назначайте их пользователям.</p>

  <form method="post" action="{{ url_for('admin_create_role') }}"
        style="display:grid;grid-template-columns:1fr 120px auto;gap:.5rem;align-items:start">
    <input name="name" placeholder="Название роли (например: Редактор)" required>
    <input name="color" type="color" value="#3b82f6" style="padding:.2rem;height:42px">
    <button type="submit">+ Создать роль</button>
  </form>

  {% if roles %}
  <table style="margin-top:1rem">
    <tr><th>Роль</th><th>Права</th><th>Пользователей</th><th></th></tr>
    {% for r in roles %}
      <tr>
        <td>
          <span class="tag" style="background:{{ r['color'] }}22;color:{{ r['color'] }}">{{ r['name'] }}</span>
        </td>
        <td>
          {% for p in (r['perms'] or '').split(',') if p %}
            <span class="tag">{{ PERMS.get(p, p) }}</span>
          {% endfor %}
        </td>
        <td class="muted">{{ role_user_counts.get(r['id'], 0) }}</td>
        <td style="text-align:right;white-space:nowrap">
          <a class="btn btn-ghost" href="{{ url_for('admin_edit_role', rid=r['id']) }}"
             style="padding:.3rem .7rem;font-size:.85rem">Права</a>
          <form method="post" action="{{ url_for('admin_delete_role', rid=r['id']) }}"
                style="display:inline" onsubmit="return confirm('Удалить роль «{{ r['name'] }}»?')">
            <button class="btn btn-danger" type="submit"
                    style="padding:.3rem .7rem;font-size:.85rem">×</button>
          </form>
        </td>
      </tr>
    {% endfor %}
  </table>
  {% endif %}
</div>
{% endif %}

{% if 'manage_users' in perms %}
<div class="card">
  <h2 style="margin-top:0">➕ Создать пользователя</h2>
  <form method="post" action="{{ url_for('admin_create_user') }}">
    <input name="username" placeholder="Логин" required>
    <input name="password" type="password" placeholder="Пароль" required>
    <label>Роль</label>
    <select name="role_id">
      <option value="">— без роли —</option>
      {% for r in roles %}
        <option value="{{ r['id'] }}">{{ r['name'] }}</option>
      {% endfor %}
    </select>
    <button type="submit" style="margin-top:.6rem">Создать</button>
  </form>
</div>

<div class="card">
  <h2 style="margin-top:0">🔗 Пригласительная ссылка</h2>
  <p class="muted">Ссылка одноразовая. Можно сразу указать роль для приглашённого.</p>
  <form method="post" action="{{ url_for('admin_create_invite') }}">
    <select name="role_id">
      <option value="">— без роли —</option>
      {% for r in roles %}
        <option value="{{ r['id'] }}">{{ r['name'] }}</option>
      {% endfor %}
    </select>
    <button type="submit" style="margin-top:.6rem">🔗 Сгенерировать</button>
  </form>
  {% if last_invite %}
    <p style="margin-top:1rem">Ссылка:</p>
    <input value="{{ last_invite }}" readonly onclick="this.select()">
  {% endif %}
  {% if invites %}
    <h3>Активные приглашения</h3>
    <ul>
      {% for inv in invites %}
        <li><code>{{ request.host_url.rstrip('/') }}/invite/{{ inv['token'] }}</code>
            <span class="muted">— {{ inv['role_name'] or 'без роли' }} · {{ inv['created_at'] }}</span></li>
      {% endfor %}
    </ul>
  {% endif %}
</div>

<div class="card">
  <h2 style="margin-top:0">Все пользователи ({{ users|length }})</h2>
  <table>
    <tr><th></th><th>Логин</th><th>Онлайн</th><th>Роль</th><th>Создан</th><th></th></tr>
    {% for u in users %}
      <tr>
        <td style="width:40px">
          <span class="avatar-wrap">
            {% if u['avatar'] %}
              <img class="avatar" src="{{ url_for('uploaded_file', filename=u['avatar']) }}">
            {% endif %}
            <span class="online-dot {% if not u['online'] %}offline{% endif %}"></span>
          </span>
        </td>
        <td>
          <a href="{{ url_for('user_profile', username=u['username']) }}"><b>{{ u['username'] }}</b></a>
          {% if u['is_owner'] %} <span class="tag">владелец ★</span>{% endif %}
        </td>
        <td class="muted" style="font-size:.85rem">{{ u['last_seen_text'] }}</td>
        <td>
          {% if not u['is_owner'] %}
            <form method="post" action="{{ url_for('admin_set_role', uid=u['id']) }}"
                  style="display:flex;gap:.4rem">
              <select name="role_id" onchange="this.form.submit()" style="margin:0;padding:.3rem">
                <option value="">— без роли —</option>
                {% for r in roles %}
                  <option value="{{ r['id'] }}" {% if u['role_id'] == r['id'] %}selected{% endif %}>
                    {{ r['name'] }}
                  </option>
                {% endfor %}
              </select>
            </form>
          {% else %}
            <span class="muted">все права</span>
          {% endif %}
        </td>
        <td class="muted">{{ u['created_at'] }}</td>
        <td style="text-align:right">
          {% if not u['is_owner'] %}
            <form method="post" action="{{ url_for('admin_delete_user', uid=u['id']) }}"
                  onsubmit="return confirm('Удалить {{ u['username'] }}?')">
              <button class="btn btn-danger" type="submit"
                      style="padding:.3rem .7rem;font-size:.85rem">Удалить</button>
            </form>
          {% else %}
            <span class="muted" title="Владельца удалить нельзя">🔒</span>
          {% endif %}
        </td>
      </tr>
    {% endfor %}
  </table>
</div>
{% endif %}
""")

EDIT_ROLE_TPL = tpl("""
<h1>🎭 Роль «{{ role['name'] }}»</h1>
<form method="post">
  <label>Название</label>
  <input name="name" value="{{ role['name'] }}" required>
  <label>Цвет</label>
  <input name="color" type="color" value="{{ role['color'] }}" style="padding:.2rem;height:42px">
  <label>Права</label>
  <div>
    {% for k, label in PERMS.items() %}
      <label style="display:flex;gap:.5rem;align-items:center;margin:.4rem 0;font-size:1rem;color:var(--text)">
        <input type="checkbox" name="perm" value="{{ k }}"
               style="width:auto;margin:0"
               {% if k in current %}checked{% endif %}>
        {{ label }} <span class="muted">({{ k }})</span>
      </label>
    {% endfor %}
  </div>
  <div style="margin-top:1rem">
    <button type="submit">💾 Сохранить</button>
    <a class="btn btn-ghost" href="{{ url_for('admin_users') }}">Отмена</a>
  </div>
</form>
""")

INVITE_TPL = tpl("""
<div class="auth-wrap">
  <h1>Регистрация по приглашению</h1>
  <div class="card">
    <p class="muted">Выберите логин и пароль. Приглашение одноразовое.</p>
    <form method="post">
      <input name="username" placeholder="Логин" required autofocus>
      <input name="password" type="password" placeholder="Пароль" required>
      <button type="submit" style="width:100%;margin-top:.8rem">Создать аккаунт</button>
    </form>
  </div>
</div>
""")


# ===== КОНТЕКСТ ШАБЛОНОВ =====
@app.context_processor
def inject_user():
    me = None
    role = None
    unread_count = 0
    if "user" in session:
        db = get_db()
        me = db.execute("SELECT * FROM users WHERE username=?",
                        (session["user"],)).fetchone()
        if me:
            role = get_role(db, me["role_id"])
            try:
                unread_count = db.execute(
                    "SELECT COUNT(*) c FROM private_messages WHERE recipient=? AND is_read=0",
                    (session["user"],)).fetchone()["c"]
            except sqlite3.OperationalError:
                unread_count = 0
    return {
        "me": me,
        "role": role,
        "is_owner": bool(session.get("is_owner")),
        "perms": current_perms(),
        "PERMS": PERMS,
        "max_mb": MAX_AVATAR_BYTES // (1024 * 1024),
        "unread_count": unread_count,
    }


# ===== РЕНДЕР CONTENT =====
def render_content(text: str) -> str:
    out = []
    for line in text.split("\n"):
        if line.startswith("### "):
            out.append(f"<h3>{html.escape(line[4:])}</h3>")
        elif line.startswith("## "):
            out.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("# "):
            out.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.strip() == "":
            out.append("<br>")
        else:
            out.append(f"<p>{html.escape(line)}</p>")
    return "\n".join(out)


# ===== АВАТАРЫ =====
@app.route("/uploads/<filename>")
def uploaded_file(filename):
    if "/" in filename or "\\" in filename or filename.startswith("."):
        abort(404)
    return send_from_directory(UPLOAD_DIR, filename)

def save_avatar(file_storage, username: str):
    if not file_storage or not file_storage.filename:
        return None
    ext = file_storage.filename.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_EXT:
        return None
    data = file_storage.read()
    if len(data) > MAX_AVATAR_BYTES:
        return None
    name = f"{username}_{secrets.token_hex(6)}.{ext}"
    with open(os.path.join(UPLOAD_DIR, name), "wb") as f:
        f.write(data)
    return name


# ===== СТАТЬИ =====
@app.route("/")
@login_required
def index():
    q = request.args.get("q", "").strip()
    tag = request.args.get("tag", "").strip()
    db = get_db()
    sql = "SELECT * FROM pages"
    params = []
    where = []
    if q:
        where.append("(title LIKE ? OR content LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]
    if tag:
        where.append("(',' || tags || ',') LIKE ?")
        params.append(f"%,{tag},%")
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY title"
    pages = db.execute(sql, params).fetchall()

    tags_set = set()
    for r in db.execute("SELECT tags FROM pages").fetchall():
        for t in (r["tags"] or "").split(","):
            t = t.strip()
            if t:
                tags_set.add(t)
    return render_template_string(INDEX_TPL, pages=pages, q=q,
                                  all_tags=sorted(tags_set))


@app.route("/page/<slug>")
@login_required
def view_page(slug):
    db = get_db()
    page = db.execute("SELECT * FROM pages WHERE slug=?", (slug,)).fetchone()
    if not page:
        abort(404)
    return render_template_string(VIEW_TPL, page=page,
                                  content_html=render_content(page["content"]))


@app.route("/new", methods=["GET", "POST"])
@perm_required("create_page")
def new_page():
    if request.method == "POST":
        title = request.form["title"].strip()
        slug = request.form["slug"].strip().lower()
        tags = request.form.get("tags", "").strip()
        content = request.form["content"]
        db = get_db()
        try:
            db.execute(
                "INSERT INTO pages (slug, title, content, tags, author) VALUES (?,?,?,?,?)",
                (slug, title, content, tags, session["user"]))
            db.commit()
        except sqlite3.IntegrityError:
            flash("Такой slug уже существует")
            return render_template_string(EDIT_TPL, page=None), 400
        return redirect(url_for("view_page", slug=slug))
    return render_template_string(EDIT_TPL, page=None)


@app.route("/edit/<slug>", methods=["GET", "POST"])
@login_required
def edit_page(slug):
    db = get_db()
    page = db.execute("SELECT * FROM pages WHERE slug=?", (slug,)).fetchone()
    if not page:
        abort(404)
    if not (has_perm("edit_any") or
            (has_perm("edit_own") and page["author"] == session["user"])):
        abort(403)
    if request.method == "POST":
        title = request.form["title"].strip()
        new_slug = request.form["slug"].strip().lower()
        tags = request.form.get("tags", "").strip()
        content = request.form["content"]
        db.execute(
            "UPDATE pages SET title=?, slug=?, content=?, tags=?, "
            "updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (title, new_slug, content, tags, page["id"]))
        db.commit()
        return redirect(url_for("view_page", slug=new_slug))
    return render_template_string(EDIT_TPL, page=page)


@app.route("/delete/<slug>", methods=["POST"])
@perm_required("delete_page")
def delete_page(slug):
    db = get_db()
    db.execute("DELETE FROM pages WHERE slug=?", (slug,))
    db.commit()
    return redirect(url_for("index"))


# ===== АУТЕНТИФИКАЦИЯ =====
@app.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()
    users_count = db.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    if users_count == 0:
        return redirect(url_for("setup"))

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and verify_password(password, user["password"]):
            session["user"] = username
            session["is_owner"] = bool(user["is_owner"])
            db.execute("UPDATE users SET last_seen=CURRENT_TIMESTAMP WHERE username=?", (username,))
            db.commit()
            nxt = request.args.get("next") or url_for("index")
            return redirect(nxt)
        flash("Неверный логин или пароль")
        return render_template_string(LOGIN_TPL, need_setup=False), 401
    return render_template_string(LOGIN_TPL, need_setup=False)


@app.route("/setup", methods=["GET", "POST"])
def setup():
    db = get_db()
    users_count = db.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    if users_count > 0:
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if len(username) < 3 or len(password) < 4:
            flash("Логин ≥3 символов, пароль ≥4")
            return render_template_string(SETUP_TPL), 400
        db.execute("INSERT INTO users (username, password, is_owner) VALUES (?, ?, 1)",
                   (username, hash_password(password)))
        db.commit()
        session["user"] = username
        session["is_owner"] = True
        return redirect(url_for("index"))
    return render_template_string(SETUP_TPL)


@app.route("/register")
def register_info():
    return render_template_string(REGISTER_INFO_TPL)


@app.route("/invite/<token>", methods=["GET", "POST"])
def invite(token):
    db = get_db()
    inv = db.execute("SELECT * FROM invites WHERE token=? AND used_by IS NULL",
                     (token,)).fetchone()
    if not inv:
        return "Приглашение недействительно или уже использовано", 410

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if len(username) < 3 or len(password) < 4:
            flash("Логин ≥3 символов, пароль ≥4")
            return render_template_string(INVITE_TPL), 400
        try:
            db.execute("INSERT INTO users (username, password, is_owner, role_id) VALUES (?, ?, 0, ?)",
                       (username, hash_password(password), inv["role_id"]))
            db.execute("UPDATE invites SET used_by=? WHERE token=?", (username, token))
            db.commit()
        except sqlite3.IntegrityError:
            flash("Такой логин уже занят")
            return render_template_string(INVITE_TPL), 400
        session["user"] = username
        session["is_owner"] = False
        return redirect(url_for("index"))
    return render_template_string(INVITE_TPL)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ===== ПУБЛИЧНЫЙ ПРОФИЛЬ =====
@app.route("/user/<username>")
@login_required
def user_profile(username):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        abort(404)
    role = get_role(db, user["role_id"])
    pages_count = db.execute("SELECT COUNT(*) c FROM pages WHERE author=?", (username,)).fetchone()["c"]
    chat_count = db.execute("SELECT COUNT(*) c FROM messages WHERE author=?", (username,)).fetchone()["c"]
    online = is_online(user["last_seen"])
    last_seen_text = human_last_seen(user["last_seen"])
    return render_template_string(USER_PROFILE_TPL, user=user, role=role,
                                  pages_count=pages_count, chat_count=chat_count,
                                  online=online, last_seen_text=last_seen_text)


@app.route("/profile/edit", methods=["POST"])
@login_required
def update_profile():
    db = get_db()
    status = request.form.get("status", "").strip()[:100]
    bio = request.form.get("bio", "").strip()[:500]
    db.execute("UPDATE users SET status=?, bio=? WHERE username=?",
               (status, bio, session["user"]))
    db.commit()
    flash("Профиль обновлён")
    return redirect(url_for("profile"))


# ===== ЛИЧНЫЕ СООБЩЕНИЯ =====
@app.route("/messages")
@login_required
def messages_inbox():
    db = get_db()
    me = session["user"]
    rows = db.execute("""
        SELECT * FROM private_messages
        WHERE sender=? OR recipient=?
        ORDER BY id DESC
    """, (me, me)).fetchall()
    dialogs = {}
    for r in rows:
        other = r["recipient"] if r["sender"] == me else r["sender"]
        if other not in dialogs:
            dialogs[other] = {
                "other": other,
                "last_body": r["body"],
                "last_at": r["created_at"],
                "unread": 0,
            }
        if r["recipient"] == me and not r["is_read"]:
            dialogs[other]["unread"] += 1
    dialog_list = []
    for d in dialogs.values():
        u = db.execute("SELECT avatar, last_seen FROM users WHERE username=?", (d["other"],)).fetchone()
        d["avatar"] = u["avatar"] if u else ""
        d["online"] = is_online(u["last_seen"]) if u else False
        d["last_seen_text"] = human_last_seen(u["last_seen"]) if u else "неизвестно"
        dialog_list.append(d)
    return render_template_string(MESSAGES_TPL, dialogs=dialog_list)


@app.route("/messages/<username>", methods=["GET", "POST"])
@login_required
def messages_with(username):
    db = get_db()
    if username == session["user"]:
        return redirect(url_for("messages_inbox"))
    other = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not other:
        abort(404)

    if request.method == "POST":
        body = request.form.get("body", "").strip()
        if body:
            db.execute("INSERT INTO private_messages (sender, recipient, body) VALUES (?,?,?)",
                       (session["user"], username, body[:2000]))
            db.commit()
        return redirect(url_for("messages_with", username=username))

    db.execute("UPDATE private_messages SET is_read=1 WHERE recipient=? AND sender=?",
               (session["user"], username))
    db.commit()

    messages = db.execute("""
        SELECT * FROM private_messages
        WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?)
        ORDER BY id ASC LIMIT 500
    """, (session["user"], username, username, session["user"])).fetchall()
    online = is_online(other["last_seen"])
    last_seen_text = human_last_seen(other["last_seen"])
    last_id = messages[-1]["id"] if messages else 0
    return render_template_string(MESSAGES_WITH_TPL, other=other, messages=messages,
                                  online=online, last_seen_text=last_seen_text,
                                  last_id=last_id)


# ===== API: общий чат =====
@app.route("/chat/messages")
@login_required
def chat_messages_api():
    try:
        after = int(request.args.get("after", 0))
    except ValueError:
        after = 0
    db = get_db()
    rows = db.execute("""
        SELECT m.id, m.author, m.body, m.created_at, u.avatar, u.last_seen
        FROM messages m
        LEFT JOIN users u ON u.username = m.author
        WHERE m.id > ?
        ORDER BY m.id ASC
        LIMIT 200
    """, (after,)).fetchall()
    out = []
    for m in rows:
        out.append({
            "id": m["id"],
            "author": m["author"],
            "body": m["body"],
            "created_at": m["created_at"],
            "avatar": m["avatar"] or "",
            "online": is_online(m["last_seen"]),
            "is_me": m["author"] == session["user"],
        })
    return jsonify(out)


@app.route("/chat/send_ajax", methods=["POST"])
@perm_required("chat_write")
def chat_send_ajax():
    data = request.get_json(silent=True) or {}
    body = (data.get("body") or "").strip()
    if not body:
        return jsonify({"ok": False, "error": "Пустое сообщение"}), 400
    db = get_db()
    cur = db.execute("INSERT INTO messages (author, body) VALUES (?, ?)",
                     (session["user"], body[:2000]))
    db.commit()
    return jsonify({"ok": True, "id": cur.lastrowid})


# ===== API: личные сообщения =====
@app.route("/messages/<username>/api")
@login_required
def pm_messages_api(username):
    try:
        after = int(request.args.get("after", 0))
    except ValueError:
        after = 0
    db = get_db()
    rows = db.execute("""
        SELECT * FROM private_messages
        WHERE ((sender=? AND recipient=?) OR (sender=? AND recipient=?))
          AND id > ?
        ORDER BY id ASC LIMIT 500
    """, (session["user"], username, username, session["user"], after)).fetchall()
    db.execute("UPDATE private_messages SET is_read=1 WHERE recipient=? AND sender=?",
               (session["user"], username))
    db.commit()
    out = []
    for m in rows:
        out.append({
            "id": m["id"],
            "sender": m["sender"],
            "body": m["body"],
            "created_at": m["created_at"],
            "is_me": m["sender"] == session["user"],
        })
    return jsonify(out)


@app.route("/messages/<username>/send_ajax", methods=["POST"])
@login_required
def pm_send_ajax(username):
    data = request.get_json(silent=True) or {}
    body = (data.get("body") or "").strip()
    if not body:
        return jsonify({"ok": False, "error": "Пустое сообщение"}), 400
    db = get_db()
    other = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not other:
        return jsonify({"ok": False, "error": "Пользователь не найден"}), 404
    cur = db.execute("INSERT INTO private_messages (sender, recipient, body) VALUES (?,?,?)",
                     (session["user"], username, body[:2000]))
    db.commit()
    return jsonify({"ok": True, "id": cur.lastrowid})


# ===== АДМИНКА =====
@app.route("/admin/users")
@login_required
def admin_users():
    if not (session.get("is_owner") or has_perm("view_admin") or
            has_perm("manage_users") or has_perm("manage_roles")):
        abort(403)
    db = get_db()
    users_rows = db.execute("SELECT * FROM users ORDER BY id").fetchall()
    users = []
    for u in users_rows:
        d = dict(u)
        d["online"] = is_online(u["last_seen"])
        d["last_seen_text"] = human_last_seen(u["last_seen"])
        users.append(d)
    roles = db.execute("SELECT * FROM roles ORDER BY name").fetchall()
    invites = db.execute("""
        SELECT i.token, i.created_at, r.name AS role_name
        FROM invites i LEFT JOIN roles r ON r.id = i.role_id
        WHERE i.used_by IS NULL ORDER BY i.created_at DESC
    """).fetchall()
    role_user_counts = {}
    for row in db.execute("SELECT role_id, COUNT(*) c FROM users WHERE role_id IS NOT NULL GROUP BY role_id"):
        role_user_counts[row["role_id"]] = row["c"]
    return render_template_string(ADMIN_TPL, users=users, roles=roles,
                                  invites=invites, role_user_counts=role_user_counts,
                                  last_invite=session.pop("last_invite", None))


@app.route("/admin/roles/create", methods=["POST"])
@perm_required("manage_roles")
def admin_create_role():
    name = request.form["name"].strip()
    color = request.form.get("color", "#3b82f6")
    if not name:
        flash("Название обязательно")
        return redirect(url_for("admin_users"))
    db = get_db()
    try:
        cur = db.execute("INSERT INTO roles (name, color, perms) VALUES (?, ?, '')",
                         (name, color))
        db.commit()
        return redirect(url_for("admin_edit_role", rid=cur.lastrowid))
    except sqlite3.IntegrityError:
        flash("Роль с таким названием уже есть")
        return redirect(url_for("admin_users"))


@app.route("/admin/roles/<int:rid>", methods=["GET", "POST"])
@perm_required("manage_roles")
def admin_edit_role(rid):
    db = get_db()
    role = db.execute("SELECT * FROM roles WHERE id=?", (rid,)).fetchone()
    if not role:
        abort(404)
    if request.method == "POST":
        name = request.form["name"].strip()
        color = request.form.get("color", "#3b82f6")
        picked = request.form.getlist("perm")
        valid = [p for p in picked if p in PERMS]
        try:
            db.execute("UPDATE roles SET name=?, color=?, perms=? WHERE id=?",
                       (name, color, ",".join(valid), rid))
            db.commit()
            flash("Роль сохранена")
        except sqlite3.IntegrityError:
            flash("Роль с таким названием уже есть")
        return redirect(url_for("admin_users"))
    current = set(p for p in (role["perms"] or "").split(",") if p)
    return render_template_string(EDIT_ROLE_TPL, role=role, current=current)


@app.route("/admin/roles/<int:rid>/delete", methods=["POST"])
@perm_required("manage_roles")
def admin_delete_role(rid):
    db = get_db()
    db.execute("UPDATE users SET role_id=NULL WHERE role_id=? AND is_owner=0", (rid,))
    db.execute("DELETE FROM roles WHERE id=?", (rid,))
    db.commit()
    flash("Роль удалена")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:uid>/role", methods=["POST"])
@perm_required("manage_users")
def admin_set_role(uid):
    rid = request.form.get("role_id") or None
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        abort(404)
    if u["is_owner"]:
        flash("Нельзя менять роль владельца")
        return redirect(url_for("admin_users"))
    if rid:
        r = db.execute("SELECT id FROM roles WHERE id=?", (rid,)).fetchone()
        if not r:
            flash("Роль не найдена")
            return redirect(url_for("admin_users"))
    db.execute("UPDATE users SET role_id=? WHERE id=?", (rid, uid))
    db.commit()
    flash(f"Роль пользователя «{u['username']}» обновлена")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/create", methods=["POST"])
@perm_required("manage_users")
def admin_create_user():
    username = request.form["username"].strip()
    password = request.form["password"]
    role_id = request.form.get("role_id") or None
    if len(username) < 3 or len(password) < 4:
        flash("Логин ≥3 и пароль ≥4 символов")
        return redirect(url_for("admin_users"))
    db = get_db()
    try:
        db.execute("INSERT INTO users (username, password, is_owner, role_id) VALUES (?, ?, 0, ?)",
                   (username, hash_password(password), role_id))
        db.commit()
        flash(f"Пользователь «{username}» создан")
    except sqlite3.IntegrityError:
        flash("Такой логин уже занят")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@perm_required("manage_users")
def admin_delete_user(uid):
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        abort(404)
    if u["is_owner"]:
        flash("Нельзя удалить владельца")
        return redirect(url_for("admin_users"))
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    flash(f"Пользователь «{u['username']}» удалён")
    return redirect(url_for("admin_users"))


@app.route("/admin/invites/create", methods=["POST"])
@perm_required("manage_users")
def admin_create_invite():
    role_id = request.form.get("role_id") or None
    token = secrets.token_urlsafe(24)
    db = get_db()
    db.execute("INSERT INTO invites (token, created_by, role_id) VALUES (?, ?, ?)",
               (token, session["user"], role_id))
    db.commit()
    session["last_invite"] = f"{request.host_url.rstrip('/')}/invite/{token}"
    return redirect(url_for("admin_users"))


# ===== ПРОФИЛЬ =====
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    db = get_db()
    if request.method == "POST":
        f = request.files.get("avatar")
        name = save_avatar(f, session["user"])
        if not name:
            flash("Не удалось загрузить: проверь формат и размер")
            return redirect(url_for("profile"))
        old = db.execute("SELECT avatar FROM users WHERE username=?",
                         (session["user"],)).fetchone()["avatar"]
        if old:
            try: os.remove(os.path.join(UPLOAD_DIR, old))
            except OSError: pass
        db.execute("UPDATE users SET avatar=? WHERE username=?",
                   (name, session["user"]))
        db.commit()
        flash("Аватар обновлён")
        return redirect(url_for("profile"))
    return render_template_string(PROFILE_TPL)


@app.route("/profile/avatar/remove", methods=["POST"])
@login_required
def remove_avatar():
    db = get_db()
    old = db.execute("SELECT avatar FROM users WHERE username=?",
                     (session["user"],)).fetchone()["avatar"]
    if old:
        try: os.remove(os.path.join(UPLOAD_DIR, old))
        except OSError: pass
    db.execute("UPDATE users SET avatar='' WHERE username=?", (session["user"],))
    db.commit()
    flash("Аватар удалён")
    return redirect(url_for("profile"))


@app.route("/profile/password", methods=["POST"])
@login_required
def change_password():
    old = request.form["old"]
    new1 = request.form["new1"]
    new2 = request.form["new2"]
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?",
                      (session["user"],)).fetchone()
    if not verify_password(old, user["password"]):
        flash("Текущий пароль неверный")
        return redirect(url_for("profile"))
    if new1 != new2 or len(new1) < 4:
        flash("Пароли не совпадают или слишком короткие")
        return redirect(url_for("profile"))
    db.execute("UPDATE users SET password=? WHERE id=?",
               (hash_password(new1), user["id"]))
    db.commit()
    flash("Пароль изменён")
    return redirect(url_for("profile"))


# ===== ЧАТ =====
@app.route("/chat")
@login_required
def chat():
    db = get_db()
    rows = db.execute("""
        SELECT m.*, u.avatar AS avatar, u.last_seen AS last_seen
        FROM messages m
        LEFT JOIN users u ON u.username = m.author
        ORDER BY m.id DESC LIMIT 200
    """).fetchall()
    msgs = []
    for m in reversed(rows):
        d = dict(m)
        d["online"] = is_online(m["last_seen"])
        msgs.append(d)
    last_id = msgs[-1]["id"] if msgs else 0
    return render_template_string(CHAT_TPL, messages=msgs, last_id=last_id)


@app.route("/chat/delete/<int:mid>", methods=["POST"])
@perm_required("chat_delete")
def chat_delete(mid):
    db = get_db()
    db.execute("DELETE FROM messages WHERE id=?", (mid,))
    db.commit()
    return redirect(url_for("chat"))


# ===== ИНИЦИАЛИЗАЦИЯ =====
init_db()
migrate_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
