
import sqlite3
import os

# Path to database
DATABASE = os.path.join('instance', 'users.db')

# Make sure the 'instance' folder exists
os.makedirs(os.path.dirname(DATABASE), exist_ok=True)

# Remove old database if it exists (optional)
if os.path.exists(DATABASE):
    os.remove(DATABASE)

# Connect to SQLite (this creates a new file)
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()

# ---------------- USERS TABLE ----------------
# ---------------- USERS TABLE ----------------
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    bio TEXT DEFAULT '',
    profile_pic TEXT DEFAULT 'images/default_profile.png',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')


# ---------------- JOURNALS TABLE ----------------
cursor.execute('''
CREATE TABLE IF NOT EXISTS journals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT DEFAULT 'Untitled',
    content TEXT NOT NULL,
    is_private INTEGER DEFAULT 0,
    password TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
''')

# ---------------- NOTIFICATIONS TABLE ----------------
cursor.execute('''
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    read INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
''')

# ---------------- USER SETTINGS TABLE ----------------
cursor.execute('''
CREATE TABLE IF NOT EXISTS user_settings (
    user_id INTEGER PRIMARY KEY,
    theme TEXT DEFAULT 'light',
    default_view TEXT DEFAULT 'list',
    font_size INTEGER DEFAULT 16,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
''')

# ---------------- REMINDERS TABLE ----------------
cursor.execute('''
CREATE TABLE IF NOT EXISTS reminders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    date TEXT NOT NULL,
    time TEXT,
    completed INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
''')

# ---------------- CALENDAR EVENTS TABLE ----------------
cursor.execute('''
CREATE TABLE IF NOT EXISTS calendar_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    date TEXT NOT NULL,
    description TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
''')

# Commit changes and close connection
conn.commit()
conn.close()

print("Database 'users.db' created successfully with all tables inside 'instance/' folder!")
