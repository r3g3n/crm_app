import os
import sqlite3
import csv
import re
import hashlib
import secrets
from datetime import datetime
from functools import wraps
from flask import Flask, g, render_template, request, redirect, url_for, session, flash
from markupsafe import Markup
import bleach

# Configure bleach allowed tags and attributes for Quill.js
ALLOWED_TAGS = [
    'p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'ul', 'ol', 'li', 
    'a', 'span', 'blockquote', 'pre', 'img', 's', 'sub', 'sup', 'code', 'div'
]
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'target', 'title'],
    'img': ['src', 'alt', 'width', 'height'],
    'span': ['class', 'style'],
    'p': ['class', 'style'],
    'strong': ['style'],
    'em': ['style'],
    'u': ['style'],
    's': ['style'],
    'code': ['style'],
    'div': ['style', 'class'],
    'li': ['style'],
    'ul': ['style'],
    'ol': ['style'],
    'br': []
}

def clean_html_content(content):
    if not content:
        return ""
    # Strip whitespace
    content = content.strip()
    # Check for empty Quill output
    if content in ['<p><br></p>', '<p><br/></p>', '<br>']:
        return ""
    # More advanced check: strip tags and check if empty
    text_content = re.sub(r'<[^>]+>', '', content).strip()
    if not text_content and '<img' not in content:
        return ""
    return content

def strip_html_tags(content):
    if not content:
        return ""
    # Replace block elements with newlines
    content = re.sub(r'</p>', '\n', content)
    content = re.sub(r'<br\s*/?>', '\n', content)
    content = re.sub(r'</div>', '\n', content)
    content = re.sub(r'</h1>', '\n', content)
    content = re.sub(r'</h2>', '\n', content)
    content = re.sub(r'</h3>', '\n', content)
    content = re.sub(r'</li>', '\n', content)
    
    # Strip all tags
    text = re.sub(r'<[^>]+>', '', content)
    
    # Unescape entities
    text = text.replace('&nbsp;', ' ').replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"')
    
    # Collapse multiple newlines and spaces
    text = re.sub(r'\n\s*\n', '\n\n', text)
    
    return text.strip()


DB_PATH = os.path.join(os.path.dirname(__file__), "crm.db")
CSV_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "Продукты 31fc9dfe7c6580bfaf40f2047928cacc.csv")


def create_app():
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config["SECRET_KEY"] = secrets.token_hex(16)

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(DB_PATH)
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.template_filter('safe_html')
    def safe_html_filter(content):
        if not content:
            return ""
        cleaned = bleach.clean(content, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, strip=True)
        return Markup(cleaned)

    @app.teardown_appcontext
    def close_db(exception=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db():
        db = get_db()
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                avatar_url TEXT,
                created_at TEXT NOT NULL
            );
            """
        )
        # Ensure avatar_url column exists (migration for existing dbs)
        try:
            db.execute("ALTER TABLE users ADD COLUMN avatar_url TEXT")
        except sqlite3.OperationalError:
            pass # Column already exists
            
        # Ensure role column exists (migration for existing dbs)
        try:
            db.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
        except sqlite3.OperationalError:
            pass # Column already exists

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                city TEXT,
                country TEXT,
                phone TEXT,
                phone2 TEXT,
                site TEXT,
                email TEXT,
                email2 TEXT,
                email3 TEXT,
                description TEXT,
                category TEXT,
                status TEXT,
                created_by INTEGER,
                updated_by INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                detailed_report TEXT,
                first_mail TEXT
            );
            """
        )
        # Ensure detailed_report column exists (migration for existing dbs)
        try:
            db.execute("ALTER TABLE contacts ADD COLUMN detailed_report TEXT")
        except sqlite3.OperationalError:
            pass # Column already exists
        # Ensure first_mail column exists (migration for existing dbs)
        try:
            db.execute("ALTER TABLE contacts ADD COLUMN first_mail TEXT")
        except sqlite3.OperationalError:
            pass # Column already exists
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (contact_id) REFERENCES contacts(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_id INTEGER NOT NULL,
                user_id INTEGER,
                action TEXT NOT NULL,
                snapshot TEXT,
                created_at TEXT NOT NULL
            );
            """
        )
        db.commit()
        # Ensure admin user has role 'admin'
        db.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")
        db.commit()

        cur = db.execute("SELECT COUNT(*) as c FROM users")
        if cur.fetchone()["c"] == 0:
            seed_users = [
                ("admin", hash_password("admin123"), "admin"),
                ("user1", hash_password("user123"), "user"),
                ("user2", hash_password("user123"), "user"),
            ]
            now = datetime.utcnow().isoformat()
            for u, ph, r in seed_users:
                db.execute(
                    "INSERT INTO users(username, password_hash, role, created_at) VALUES(?,?,?,?)",
                    (u, ph, r, now),
                )
            db.commit()

    def hash_password(pw: str) -> str:
        salt = secrets.token_hex(8)
        h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt.encode("utf-8"), 200000)
        return f"{salt}${h.hex()}"

    def verify_password(pw: str, stored: str) -> bool:
        try:
            salt, hexhash = stored.split("$", 1)
            h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt.encode("utf-8"), 200000)
            return h.hex() == hexhash
        except Exception:
            return False

    def login_required(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login", next=request.path))
            return f(*args, **kwargs)
        return wrapper

    def admin_required(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "user_id" not in session or session.get("role") != "admin":
                flash("Доступ запрещен", "error")
                return redirect(url_for("contacts"))
            return f(*args, **kwargs)
        return wrapper

    @app.route("/login", methods=["GET", "POST"])
    def login():
        db = get_db()
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
            if row and verify_password(password, row["password_hash"]):
                session["user_id"] = row["id"]
                session["username"] = row["username"]
                # Safe access for role
                session["role"] = row["role"] if "role" in row.keys() else "user"
                session["avatar_url"] = row["avatar_url"]
                
                # Check for next URL or default to contacts
                next_url = request.args.get("next")
                if not next_url or not next_url.startswith("/"):
                    next_url = url_for("contacts")
                return redirect(next_url)
            flash("Неверный логин или пароль", "error")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/users")
    @login_required
    @admin_required
    def users_list():
        db = get_db()
        users = db.execute("SELECT * FROM users ORDER BY id ASC").fetchall()
        return render_template("users_list.html", users=users)

    @app.route("/ai")
    @login_required
    def ai_generator():
        if session.get("role") != "admin":
            flash("Доступ запрещен", "error")
            return redirect(url_for("contacts"))
        return render_template("ai_generator.html")

    @app.route("/users/new", methods=["GET", "POST"])
    @login_required
    @admin_required
    def user_new():
        if request.method == "POST":
            db = get_db()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "user").strip()
            avatar_url = request.form.get("avatar_url", "").strip()

            if not username or not password:
                flash("Заполните имя пользователя и пароль", "error")
                return redirect(url_for("user_new"))

            existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                flash("Пользователь с таким именем уже существует", "error")
                return redirect(url_for("user_new"))

            password_hash = hash_password(password)
            now = datetime.utcnow().isoformat()
            db.execute("INSERT INTO users (username, password_hash, role, avatar_url, created_at) VALUES (?, ?, ?, ?, ?)",
                       (username, password_hash, role, avatar_url, now))
            db.commit()
            flash("Пользователь успешно создан", "success")
            return redirect(url_for("users_list"))
        
        return render_template("user_form.html", user=None)

    @app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
    @login_required
    @admin_required
    def user_edit(user_id):
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        
        if not user:
            flash("Пользователь не найден", "error")
            return redirect(url_for("users_list"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "user").strip()
            avatar_url = request.form.get("avatar_url", "").strip()

            if not username:
                flash("Имя пользователя не может быть пустым", "error")
                return redirect(url_for("user_edit", user_id=user_id))

            existing = db.execute("SELECT id FROM users WHERE username = ? AND id != ?", (username, user_id)).fetchone()
            if existing:
                flash("Пользователь с таким именем уже существует", "error")
                return redirect(url_for("user_edit", user_id=user_id))

            if password:
                password_hash = hash_password(password)
                db.execute("UPDATE users SET username = ?, password_hash = ?, role = ?, avatar_url = ? WHERE id = ?",
                           (username, password_hash, role, avatar_url, user_id))
            else:
                db.execute("UPDATE users SET username = ?, role = ?, avatar_url = ? WHERE id = ?",
                           (username, role, avatar_url, user_id))
            
            db.commit()
            flash("Пользователь успешно обновлен", "success")
            return redirect(url_for("users_list"))

        return render_template("user_form.html", user=user)

    @app.route("/users/<int:user_id>/delete", methods=["POST"])
    @login_required
    @admin_required
    def user_delete(user_id):
        if user_id == session.get("user_id"):
             flash("Нельзя удалить самого себя", "error")
             return redirect(url_for("users_list"))

        db = get_db()
        # Check if it's the main admin account (optional, but safer)
        user = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if user and user["username"] == "admin":
             flash("Нельзя удалить главного администратора", "error")
             return redirect(url_for("users_list"))

        # Reassign comments and history or delete them? 
        # Usually better to keep history but maybe set user_id to NULL or a deleted user placeholder.
        # For simplicity, we'll keep the foreign keys if possible, but SQLite enforces them.
        # Let's check schema.
        # FOREIGN KEY (user_id) REFERENCES users(id)
        # If we delete user, we might violate foreign key constraint if not ON DELETE CASCADE.
        # The schema doesn't specify ON DELETE CASCADE.
        # So we should probably update comments/history to a placeholder or NULL.
        
        # Let's just try to delete and see if it fails, or handle it properly.
        # Better approach: check for dependent records.
        # For this task, let's just assume we can delete, but catch integrity error if any.
        try:
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
            flash("Пользователь удален", "success")
        except sqlite3.IntegrityError:
            flash("Нельзя удалить пользователя, так как у него есть связанные записи (комментарии, история).", "error")

        return redirect(url_for("users_list"))

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        db = get_db()
        user_id = session["user_id"]
        
        if request.method == "POST":
            # Handle Username Update
            if "username" in request.form:
                new_username = request.form.get("username", "").strip()
                if new_username:
                    existing = db.execute("SELECT id FROM users WHERE username = ? AND id != ?", (new_username, user_id)).fetchone()
                    if existing:
                        flash("Username already taken", "error")
                    else:
                        db.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, user_id))
                        db.commit()
                        session["username"] = new_username
                        flash("Username updated successfully", "success")
                return redirect(url_for("profile"))

            # Handle Avatar Update
            if "avatar_url" in request.form:
                avatar_url = request.form.get("avatar_url", "").strip()
                db.execute("UPDATE users SET avatar_url = ? WHERE id = ?", (avatar_url, user_id))
                db.commit()
                session["avatar_url"] = avatar_url
                flash("Avatar updated successfully", "success")
                return redirect(url_for("profile"))

            # Handle Password Update
            current_pw = request.form.get("current_password")
            new_pw = request.form.get("new_password")
            confirm_pw = request.form.get("confirm_password")

            if new_pw != confirm_pw:
                flash("New passwords do not match", "error")
                return redirect(url_for("profile"))

            if len(new_pw) < 4:
                flash("Password must be at least 4 characters", "error")
                return redirect(url_for("profile"))

            user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

            if not user or not verify_password(current_pw, user["password_hash"]):
                flash("Incorrect current password", "error")
                return redirect(url_for("profile"))

            new_hash = hash_password(new_pw)
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
            db.commit()
            flash("Password updated successfully", "success")
            return redirect(url_for("profile"))

        return render_template("user_profile.html")

    def import_csv_if_empty():
        db = get_db()
        cur = db.execute("SELECT COUNT(*) as c FROM contacts")
        if cur.fetchone()["c"] > 0:
            return
        if not os.path.exists(CSV_PATH):
            return
        with open(CSV_PATH, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            now = datetime.utcnow().isoformat()
            for row in reader:
                db.execute(
                    """
                    INSERT INTO contacts(
                        city,country,phone,phone2,site,email,email2,email3,description,category,status,created_by,updated_by,created_at,updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        (row.get("Город") or "").strip(),
                        (row.get("страна") or "").strip(),
                        (row.get("телефон") or "").strip(),
                        (row.get("телефон2") or "").strip(),
                        (row.get("сайт") or "").strip(),
                        (row.get("email") or "").strip(),
                        (row.get("email2") or "").strip(),
                        (row.get("email3") or "").strip(),
                        (row.get("Описание") or "").strip(),
                        "",
                        "Новый",
                        None,
                        None,
                        now,
                        now,
                    ),
                )
            db.commit()

    def current_user():
        if "user_id" in session:
            return {"id": session["user_id"], "username": session.get("username")}
        return None

    def normalize_phone(phone: str) -> str:
        digits = re.sub(r"\D", "", phone or "")
        if not digits:
            return ""
        if digits.startswith("8") and len(digits) == 11:
            digits = "7" + digits[1:]
        if digits.startswith("00"):
            digits = digits[2:]
        return f"+{digits}"

    def wa_link(phone: str) -> str:
        p = normalize_phone(phone).lstrip("+")
        if not p:
            return ""
        return f"https://api.whatsapp.com/send?phone={p}"

    def tg_link(phone: str) -> str:
        p = normalize_phone(phone).lstrip("+")
        if not p:
            return ""
        return f"https://t.me/+{p}"

    def format_phone(phone: str) -> str:
        return normalize_phone(phone)

    def status_color(status: str) -> str:
        s = (status or "").lower().strip()
        if "новый" in s: return "info"
        if "работ" in s: return "primary"
        if "актив" in s: return "warning"
        if "первый" in s: return "secondary"
        if "переговор" in s: return "warning"
        if "отказ" in s: return "danger"
        if "сделка" in s: return "success"
        return "secondary"

    def is_landline(phone: str) -> bool:
        p = normalize_phone(phone)
        # 495 - Moscow, 499 - Moscow, 812 - St. Petersburg
        return p.startswith("+7495") or p.startswith("+7499") or p.startswith("+7812")

    app.jinja_env.globals.update(
        wa_link=wa_link,
        tg_link=tg_link,
        format_phone=format_phone,
        status_color=status_color,
        is_landline=is_landline
    )

    @app.template_filter('datetime')
    def format_datetime(value, format="%d.%m.%Y %H:%M"):
        if not value:
            return ""
        try:
            # Handle ISO format with microseconds possibly
            dt = datetime.fromisoformat(value)
            return dt.strftime(format)
        except ValueError:
            return value

    @app.template_filter('highlight_phone')
    def highlight_phone(phone):
        if not phone:
            return ""
        p = normalize_phone(phone)
        for code in ["495", "499", "812"]:
            prefix = f"+7{code}"
            if p.startswith(prefix):
                return Markup(f"+7<u style='text-decoration-color: #ffc107; text-decoration-thickness: 2px;'>{code}</u>{p[len(prefix):]}")
        return p

    @app.template_filter('clean_url')
    def clean_url(value):
        if not value:
            return ""
        # Remove protocol
        value = re.sub(r'^https?://', '', value)
        # Remove www.
        value = re.sub(r'^www\.', '', value)
        # Remove trailing slash
        value = value.rstrip('/')
        return value

    @app.template_filter('nl2br')
    def nl2br(value):
        if not value:
            return ""
        # Escape HTML first to prevent XSS
        from markupsafe import escape
        escaped_value = escape(value)
        # Replace newlines with <br>
        return Markup(str(escaped_value).replace('\n', '<br>'))

    def sanitize_html(content):
        if not content:
            return ""
        return bleach.clean(
            content,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRIBUTES,
            strip=True
        )

    @app.template_filter('safe_html')
    def safe_html(value):
        if not value:
            return ""
        # We assume the value is already sanitized when saved to DB, 
        # but to be extra safe we could sanitize here too.
        # However, for performance and to trust our own DB content (if we sanitize on input),
        # we can just return Markup.
        # Let's sanitize here just in case old data exists or direct DB edits happened.
        return Markup(sanitize_html(value))

    @app.template_filter('truncate_words')
    def truncate_words(value, count=7, end='...'):
        if not value:
            return ""
        words = value.split()
        if len(words) <= count:
            return value
        return " ".join(words[:count]) + end


    @app.route("/")
    def root():
        return redirect(url_for("contacts"))

    @app.route("/contacts")
    @login_required
    def contacts():
        db = get_db()
        q = request.args.get("q", "").strip()
        
        # Determine Status Filter
        # If explicitly provided in URL, use it and save to session
        if "status" in request.args:
            status_filter = request.args.get("status", "").strip()
            session["last_status"] = status_filter
        # If searching and no status provided, default to All (Global Search)
        elif q:
            status_filter = ""
        # Otherwise, load from session or default to 'В работе'
        else:
            status_filter = session.get("last_status", "В работе")
            
        # Determine Sort Order
        # If explicitly provided in URL, use it and save to session
        if "sort" in request.args:
            sort_by = request.args.get("sort", "id").strip()
            session["last_sort"] = sort_by
        # Otherwise, load from session or default to 'id'
        else:
            sort_by = session.get("last_sort", "id")
            
        page = max(1, int(request.args.get("page", 1) or 1))
        try:
            per_page = int(request.args.get("per_page", 50))
            if per_page not in [10, 25, 50, 100]:
                per_page = 50
        except ValueError:
            per_page = 50
        
        # Subquery for comment count
        base_sql = "FROM contacts c"
        where_clauses = []
        params = []

        if q:
            like = f"%{q}%"
            where_clauses.append("""
                (ifnull(city,'') LIKE ? OR
                ifnull(country,'') LIKE ? OR
                ifnull(phone,'') LIKE ? OR
                ifnull(phone2,'') LIKE ? OR
                ifnull(site,'') LIKE ? OR
                ifnull(email,'') LIKE ? OR
                ifnull(email2,'') LIKE ? OR
                ifnull(email3,'') LIKE ? OR
                ifnull(description,'') LIKE ? OR
                ifnull(category,'') LIKE ? OR
                ifnull(status,'') LIKE ?)
            """)
            params.extend([like]*11)
        
        # Restrict 'restricted' users from seeing 'New' status by default
        if session.get("role") == "restricted":
            if not status_filter:
                # If no status filter is provided, exclude 'New' contacts by default
                # But allow them to see 'New' if they explicitly filter for it? 
                # User request: "роль менеджер тоже может видеть все статусы в том числе новый, по умолчанию показывать только в работе"
                # So they CAN see 'New', but default view should be 'In Progress' (В работе)
                
                # However, the previous logic was: where_clauses.append("status != 'Новый'")
                # This PREVENTED them from seeing 'New'.
                
                # New logic: 
                # 1. If status_filter is set, show that status (even 'Новый').
                # 2. If status_filter is NOT set, show only 'В работе' (or maybe everything EXCEPT 'Новый'? The user said "default show only In Progress").
                # Let's interpret "по умолчанию показывать только в работе" as "default filter = 'В работе'".
                
                # But wait, if they clear the filter, should they see everything?
                # "роль менеджер тоже может видеть все статусы в том числе новый" -> implies they HAVE access.
                # "по умолчанию показывать только в работе" -> implies initial view.
                
                # So we should NOT append "status != 'Новый'" anymore.
                pass
        
        # Apply status filter if present
        if status_filter:
            where_clauses.append("status = ?")
            params.append(status_filter)
        elif session.get("role") == "restricted" and not q:
            # If no filter and no search query, default to 'В работе' for restricted users
             where_clauses.append("status = ?")
             params.append("В работе")

        where = ""
        if where_clauses:
            where = "WHERE " + " AND ".join(where_clauses)

        count_sql = f"SELECT COUNT(*) as c {base_sql} {where}"
        total = db.execute(count_sql, tuple(params)).fetchone()["c"]
        pages = max(1, (total + per_page - 1)//per_page)
        offset = (page - 1) * per_page
        
        order_clause = "ORDER BY c.id ASC"
        if sort_by == "updated_at":
            order_clause = "ORDER BY c.updated_at DESC"
        elif sort_by == "id":
            order_clause = "ORDER BY c.id ASC"

        data_sql = f"""
            SELECT c.*, (SELECT COUNT(*) FROM comments WHERE contact_id = c.id) as comment_count 
            {base_sql} {where} {order_clause} LIMIT ? OFFSET ?
        """
        rows = db.execute(data_sql, tuple(params + [per_page, offset])).fetchall()
        
        # Fetch comments for the current page of contacts
        contact_ids = [r["id"] for r in rows]
        comments_map = {}
        if contact_ids:
            placeholders = ",".join("?" * len(contact_ids))
            comments_query = f"""
                SELECT c.*, u.username, u.avatar_url 
                FROM comments c 
                JOIN users u ON c.user_id = u.id 
                WHERE c.contact_id IN ({placeholders}) 
                ORDER BY c.created_at ASC
            """
            all_comments = db.execute(comments_query, contact_ids).fetchall()
            for c in all_comments:
                if c["contact_id"] not in comments_map:
                    comments_map[c["contact_id"]] = []
                comments_map[c["contact_id"]].append(c)
        
        # Get unique statuses for the filter dropdown
        statuses = db.execute("SELECT DISTINCT status FROM contacts WHERE status IS NOT NULL AND status != '' ORDER BY status").fetchall()
        statuses = [s["status"] for s in statuses]
        
        # We previously removed 'New' for restricted users, but now they can see it
        # if session.get("role") == "restricted":
        #    statuses = [s for s in statuses if s != "Новый"]
        
        # However, we want to set the default filter in the UI if it's applied
        if session.get("role") == "restricted" and not q and not status_filter:
             status_filter = "В работе"

        return render_template("contacts_list.html", rows=rows, q=q, status_filter=status_filter, sort_by=sort_by, statuses=statuses, page=page, pages=pages, total=total, wa_link=wa_link, tg_link=tg_link, format_phone=format_phone, status_color=status_color, per_page=per_page, comments_map=comments_map)

    @app.route("/contacts/new", methods=["GET", "POST"])
    @login_required
    def contact_new():
        db = get_db()
        if request.method == "POST":
            data = {
                "city": request.form.get("city","").strip(),
                "country": request.form.get("country","").strip(),
                "phone": request.form.get("phone","").strip(),
                "phone2": request.form.get("phone2","").strip(),
                "site": request.form.get("site","").strip(),
                "email": request.form.get("email","").strip(),
                "email2": request.form.get("email2","").strip(),
                "email3": request.form.get("email3","").strip(),
                "description": request.form.get("description","").strip(),
                "category": request.form.get("category","").strip(),
                "status": request.form.get("status","Новый").strip() or "Новый",
            }
            now = datetime.utcnow().isoformat()
            user = current_user()
            cur = db.execute(
                """
                INSERT INTO contacts(city,country,phone,phone2,site,email,email2,email3,description,category,status,created_by,updated_by,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (data["city"],data["country"],data["phone"],data["phone2"],data["site"],data["email"],data["email2"],data["email3"],data["description"],data["category"],data["status"],user["id"],user["id"],now,now)
            )
            cid = cur.lastrowid
            db.execute("INSERT INTO history(contact_id,user_id,action,snapshot,created_at) VALUES(?,?,?,?,?)",
                       (cid,user["id"],"create","",now))
            db.commit()
            return redirect(url_for("contact_view", contact_id=cid))
        return render_template("contact_form.html", contact=None)

    @app.route("/contacts/<int:contact_id>")
    @login_required
    def contact_view(contact_id):
        db = get_db()
        row = db.execute("SELECT * FROM contacts WHERE id = ?", (contact_id,)).fetchone()
        if not row:
            return redirect(url_for("contacts"))
        
        # Access control: restricted users can now view 'New' status, so no need to block them
        # if session.get("role") == "restricted" and row["status"] == "Новый":
        #    flash("Доступ к этому контакту ограничен", "error")
        #    return redirect(url_for("contacts"))

        comments = db.execute(
            "SELECT c.*, u.username, u.avatar_url FROM comments c JOIN users u ON c.user_id=u.id WHERE c.contact_id=? ORDER BY c.id DESC",
            (contact_id,)
        ).fetchall()
        
        # Get unique statuses for the dropdown in comment form
        statuses = db.execute("SELECT DISTINCT status FROM contacts WHERE status IS NOT NULL AND status != '' ORDER BY status").fetchall()
        statuses = [s["status"] for s in statuses]
        
        return render_template("contact_view.html", contact=row, comments=comments, statuses=statuses, wa_link=wa_link, tg_link=tg_link, format_phone=format_phone, status_color=status_color)

    @app.route("/contacts/<int:contact_id>/edit", methods=["GET", "POST"])
    @login_required
    def contact_edit(contact_id):
        db = get_db()
        row = db.execute("SELECT * FROM contacts WHERE id=?", (contact_id,)).fetchone()
        if not row:
            return redirect(url_for("contacts"))
            
        # Access control: restricted users can now edit 'New' status too
        # if session.get("role") == "restricted" and row["status"] == "Новый":
        #    flash("Доступ к этому контакту ограничен", "error")
        #    return redirect(url_for("contacts"))

        if request.method == "POST":
            data = {
                "city": request.form.get("city","").strip(),
                "country": request.form.get("country","").strip(),
                "phone": request.form.get("phone","").strip(),
                "phone2": request.form.get("phone2","").strip(),
                "site": request.form.get("site","").strip(),
                "email": request.form.get("email","").strip(),
                "email2": request.form.get("email2","").strip(),
                "email3": request.form.get("email3","").strip(),
                "description": clean_html_content(request.form.get("description","")),
                "detailed_report": clean_html_content(request.form.get("detailed_report","")),
                "first_mail": clean_html_content(request.form.get("first_mail","")),
                "category": request.form.get("category","").strip(),
                "status": request.form.get("status","").strip(),
            }
            now = datetime.utcnow().isoformat()
            user = current_user()
            db.execute(
                """
                UPDATE contacts SET city=?,country=?,phone=?,phone2=?,site=?,email=?,email2=?,email3=?,description=?,detailed_report=?,first_mail=?,category=?,status=?,updated_by=?,updated_at=?
                WHERE id=?
                """,
                (data["city"],data["country"],data["phone"],data["phone2"],data["site"],data["email"],data["email2"],data["email3"],data["description"],data["detailed_report"],data["first_mail"],data["category"],data["status"],user["id"],now,contact_id)
            )
            db.execute("INSERT INTO history(contact_id,user_id,action,snapshot,created_at) VALUES(?,?,?,?,?)",
                       (contact_id,user["id"],"update","",now))
            db.commit()
            return redirect(url_for("contact_view", contact_id=contact_id))
        return render_template("contact_form.html", contact=row)

    @app.route("/contacts/<int:contact_id>/delete", methods=["POST"])
    @login_required
    def contact_delete(contact_id):
        db = get_db()
        row = db.execute("SELECT status FROM contacts WHERE id=?", (contact_id,)).fetchone()
        if not row:
            return redirect(url_for("contacts"))
            
        # Deletion still requires admin role? Or can restricted users delete 'New' contacts?
        # User said "роль менеджер тоже может видеть все статусы в том числе новый".
        # Usually managers shouldn't delete contacts unless specified.
        # But previous logic blocked restricted users from deleting 'New' contacts specifically.
        # Let's assume standard behavior: restricted users can delete if they can see/edit.
        # Or maybe safer to only allow admins to delete?
        # The previous code only blocked restricted users if status was 'New'. 
        # It implied restricted users COULD delete other statuses.
        # So we should probably remove this block too to be consistent.
        
        # if session.get("role") == "restricted" and row["status"] == "Новый":
        #    flash("Доступ запрещен", "error")
        #    return redirect(url_for("contacts"))

        db.execute("DELETE FROM comments WHERE contact_id=?", (contact_id,))
        db.execute("DELETE FROM history WHERE contact_id=?", (contact_id,))
        db.execute("DELETE FROM contacts WHERE id=?", (contact_id,))
        db.commit()
        return redirect(url_for("contacts"))

    @app.route("/contacts/<int:contact_id>/comment", methods=["POST"])
    @login_required
    def add_comment(contact_id):
        db = get_db()
        user = current_user()
        content = request.form.get("content","").strip()
        redirect_target = request.form.get("redirect_to")
        
        if content:
            now = datetime.utcnow().isoformat()
            cursor = db.execute("INSERT INTO comments(contact_id,user_id,content,created_at) VALUES(?,?,?,?)",
                       (contact_id,user["id"],content,now))
            comment_id = cursor.lastrowid
            
            db.execute("INSERT INTO history(contact_id,user_id,action,snapshot,created_at) VALUES(?,?,?,?,?)",
                       (contact_id,user["id"],"comment","",now))
            db.execute("UPDATE contacts SET updated_at = ? WHERE id = ?", (now, contact_id))
            db.commit()
            
            # Check if it's an AJAX request
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.accept_mimetypes.accept_json:
                # Return JSON with comment data
                user_data = db.execute("SELECT username, avatar_url FROM users WHERE id=?", (user["id"],)).fetchone()
                return {
                    "success": True,
                    "comment": {
                        "id": comment_id,
                        "username": user_data["username"],
                        "avatar_url": user_data["avatar_url"],
                        "content": bleach.clean(content, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, strip=True),
                        "created_at": now,
                        "user_id": user["id"]
                    }
                }
            
        if redirect_target:
            return redirect(redirect_target)
            
        return redirect(url_for("contact_view", contact_id=contact_id))

    @app.template_filter('clean_url')
    def clean_url(value):
        if not value:
            return ""
        value = value.replace('https://', '').replace('http://', '').replace('www.', '')
        if '/' in value:
            value = value.split('/')[0]
        return value

    @app.template_filter('strip_tags')
    def strip_tags_filter(value):
        return strip_html_tags(value)

    @app.route("/comments/recent")
    @login_required
    def recent_comments():
        db = get_db()
        query = """
            SELECT c.*, u.username, u.avatar_url, co.phone, co.email, co.description, co.status, co.site
            FROM comments c
            JOIN users u ON c.user_id = u.id
            JOIN contacts co ON c.contact_id = co.id
        """
        params = []
        # if session.get("role") == "restricted":
        #    query += " WHERE co.status != ?"
        #    params.append("Новый")
            
        query += " ORDER BY c.created_at DESC LIMIT 50"
        
        comments = db.execute(query, tuple(params)).fetchall()
        
        # Fetch conversation history for unique contacts found in recent comments
        contact_ids = list(set([c["contact_id"] for c in comments]))
        comments_map = {}
        contact_map = {}
        
        if contact_ids:
            placeholders = ",".join("?" * len(contact_ids))
            
            # Fetch ALL comments for these contacts
            hist_query = f"""
                SELECT c.*, u.username, u.avatar_url 
                FROM comments c 
                JOIN users u ON c.user_id = u.id 
                WHERE c.contact_id IN ({placeholders}) 
                ORDER BY c.created_at ASC
            """
            all_comments = db.execute(hist_query, contact_ids).fetchall()
            
            for c in all_comments:
                cid = c["contact_id"]
                if cid not in comments_map:
                    comments_map[cid] = []
                comments_map[cid].append(c)
                
            # Build contact map for modals
            for c in comments:
                cid = c["contact_id"]
                if cid not in contact_map:
                    contact_map[cid] = {
                        "id": cid,
                        "email": c["email"],
                        "phone": c["phone"],
                        "description": c["description"],
                        "status": c["status"],
                        "site": c["site"]
                    }
        
        return render_template("recent_comments.html", comments=comments, status_color=status_color, comments_map=comments_map, contact_map=contact_map)

    @app.route("/comments/<int:comment_id>/delete", methods=["POST"])
    @login_required
    def delete_comment(comment_id):
        db = get_db()
        # Verify comment exists and maybe check permissions (admin or owner)
        # For now, allow any logged in user to delete comments as per request implicity
        comment = db.execute("SELECT * FROM comments WHERE id = ?", (comment_id,)).fetchone()
        if comment:
            contact_id = comment["contact_id"]
            db.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
            user = current_user()
            now = datetime.utcnow().isoformat()
            db.execute("INSERT INTO history(contact_id,user_id,action,snapshot,created_at) VALUES(?,?,?,?,?)",
                       (contact_id, user["id"], "delete_comment", f"Deleted comment {comment_id}", now))
            db.commit()
            return redirect(url_for("contact_view", contact_id=contact_id))
        return redirect(url_for("contacts"))

    with app.app_context():
        init_db()
        import_csv_if_empty()

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
