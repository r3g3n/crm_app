import sqlite3
import os
import hashlib
import secrets
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'crm.db')

def hash_password(password: str) -> str:
    salt = secrets.token_hex(8)
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200000)
    return f"{salt}${h.hex()}"

def add_api_user():
    username = 'api'
    password = 'api_s3ctr3t-APPpro2019'
    role = 'api'
    
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        db = conn.cursor()
        
        # Проверяем и добавляем колонку role, если её нет
        cursor = conn.execute('PRAGMA table_info(users)')
        columns = [row[1] for row in cursor.fetchall()]
        
        if 'role' not in columns:
            print("Добавляем колонку 'role' в таблицу users...")
            db.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
            
        if 'avatar_url' not in columns:
            print("Добавляем колонку 'avatar_url' в таблицу users...")
            db.execute("ALTER TABLE users ADD COLUMN avatar_url TEXT")
        
        # Проверяем, существует ли пользователь api
        user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        
        now = datetime.utcnow().isoformat()
        
        if user:
            # Обновляем пароль и роль, если пользователь существует
            print(f"Пользователь '{username}' уже существует. Обновляем пароль и роль...")
            db.execute(
                "UPDATE users SET password_hash = ?, role = ? WHERE username = ?",
                (hash_password(password), role, username)
            )
        else:
            # Создаем нового пользователя
            print(f"Создаем пользователя '{username}'...")
            db.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (username, hash_password(password), role, now)
            )
            
        conn.commit()
        print("Готово! Пользователь 'api' настроен для работы.")
        
    except Exception as e:
        print(f"Произошла ошибка: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    add_api_user()