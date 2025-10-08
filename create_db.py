import sqlite3
import os

# Path to database
DATABASE = os.path.join('instance', 'users.db')

# Make sure the 'instance' folder exists
os.makedirs(os.path.dirname(DATABASE), exist_ok=True)

# Remove old database if it exists (optional but avoids corruption)
if os.path.exists(DATABASE):
    os.remove(DATABASE)

# Connect to SQLite (this creates a new file)
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()

# Create Users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
''')

# Create Journals table
cursor.execute('''
CREATE TABLE IF NOT EXISTS journals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
''')

conn.commit()
conn.close()

print("Database 'users.db' created successfully inside 'instance/' folder!")