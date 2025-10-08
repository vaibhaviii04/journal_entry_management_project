from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
import random, os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# ------------------ DATABASE ------------------
DATABASE = os.path.join('instance', 'users.db')
os.makedirs(os.path.dirname(DATABASE), exist_ok=True)

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # Journals table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS journals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # Notifications table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            read INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # User settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_settings (
            user_id INTEGER PRIMARY KEY,
            theme TEXT DEFAULT 'light',
            default_view TEXT DEFAULT 'list',
            font_size INTEGER DEFAULT 16,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()

init_db()

# ------------------ Helper Functions ------------------
def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def get_user_by_email(email):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    return user

def get_user_settings(user_id):
    conn = get_db_connection()
    settings = conn.execute('SELECT * FROM user_settings WHERE user_id = ?', (user_id,)).fetchone()
    if not settings:
        conn.execute('INSERT INTO user_settings (user_id) VALUES (?)', (user_id,))
        conn.commit()
        settings = conn.execute('SELECT * FROM user_settings WHERE user_id = ?', (user_id,)).fetchone()
    conn.close()
    return settings

# ------------------ ROUTES ------------------
@app.route('/')
def home():
    return redirect(url_for('login'))

# ------------------ REGISTER ------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        if get_user_by_username(username):
            flash('Username already exists!', 'error')
        elif get_user_by_email(email):
            flash('Email already registered!', 'error')
        else:
            conn = get_db_connection()
            conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                         (username, email, password))
            conn.commit()
            conn.close()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

# ------------------ LOGIN ------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = get_user_by_username(username)
        if user and user['password'] == password:
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')

# ------------------ FORGOT PASSWORD ------------------
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = get_user_by_email(email)

        if not user:
            flash('Email not found!', 'error')
            return redirect(url_for('forgot_password'))

        otp = str(random.randint(100000, 999999))
        session['otp'] = otp
        session['username'] = user['username']

        flash(f'Your OTP (for testing) is: {otp}', 'info')
        return redirect(url_for('reset_password'))

    return render_template('forgot_password.html')

# ------------------ RESET PASSWORD ------------------
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        otp_entered = request.form['otp']
        new_password = request.form['new_password']

        if otp_entered == session.get('otp'):
            username = session.get('username')
            conn = get_db_connection()
            conn.execute('UPDATE users SET password = ? WHERE username = ?', (new_password, username))
            conn.commit()
            conn.close()
            flash('Password reset successful! Please log in.', 'success')
            session.pop('otp', None)
            session.pop('username', None)
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.', 'error')

    return render_template('reset_password.html')

# ------------------ DASHBOARD ------------------
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    username = session['username']
    conn = get_db_connection()
    user_id = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()['id']
    journals = conn.execute('SELECT * FROM journals WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()

    settings = get_user_settings(user_id)

    return render_template('dashboard.html', username=username, journals=journals, theme=settings['theme'])

# ------------------ LOGOUT ------------------
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# ------------------ ADD JOURNAL ------------------
@app.route('/add_journal', methods=['POST'])
def add_journal():
    if 'username' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    content = request.form.get('content', '')
    if content:
        conn = get_db_connection()
        user_id = conn.execute('SELECT id FROM users WHERE username = ?', (session['username'],)).fetchone()['id']
        conn.execute('INSERT INTO journals (user_id, content) VALUES (?, ?)', (user_id, content))
        conn.commit()
        conn.close()
        flash('Journal entry added!', 'success')

    return redirect(url_for('dashboard'))

# ------------------ ADD JOURNAL PAGE ------------------
@app.route('/add_journal_page/<username>')
def add_journal_page(username):
    if 'username' not in session or session['username'] != username:
        flash('Access denied.', 'error')
        return redirect(url_for('login'))
    return render_template('add_journal.html', username=username)

# ------------------ VIEW JOURNAL ------------------
@app.route('/view_journal/<username>')
def view_journal(username):
    if 'username' not in session or session['username'] != username:
        flash('Access denied.', 'error')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user_id = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()['id']
    journals = conn.execute('SELECT * FROM journals WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()
    return render_template('view_journal.html', journals=journals, username=username)

# ------------------ SEARCH JOURNAL ------------------
@app.route('/search_journal/<username>', methods=['GET', 'POST'])
def search_journal(username):
    if 'username' not in session or session['username'] != username:
        flash('Access denied.', 'error')
        return redirect(url_for('login'))

    keyword = request.args.get('query', '').lower()
    conn = get_db_connection()
    user_id = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()['id']
    results = conn.execute('SELECT * FROM journals WHERE user_id = ? AND LOWER(content) LIKE ?', 
                           (user_id, f'%{keyword}%')).fetchall()
    conn.close()
    return render_template('search_journal.html', results=results, username=username)

# ------------------ SETTINGS ------------------
@app.route('/settings/<username>', methods=['GET', 'POST'])
def settings(username):
    if 'username' not in session or session['username'] != username:
        flash('Access denied.', 'error')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user_id = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()['id']
    settings = get_user_settings(user_id)

    if request.method == 'POST':
        theme = request.form.get('theme', settings['theme'])
        default_view = request.form.get('default_view', settings['default_view'])
        font_size = request.form.get('font_size', settings['font_size'])
        conn.execute('''
            UPDATE user_settings SET theme = ?, default_view = ?, font_size = ? WHERE user_id = ?
        ''', (theme, default_view, font_size, user_id))
        conn.commit()
        flash('Settings updated!', 'success')

    conn.close()
    return render_template('settings.html', username=username, theme=settings['theme'], default_view=settings['default_view'], font_size=settings['font_size'])

# ------------------ REMINDERS ------------------
@app.route('/reminders/<username>')
def reminders(username):
    if 'username' not in session or session['username'] != username:
        flash('Access denied.', 'error')
        return redirect(url_for('login'))
    return render_template('reminders.html', username=username)

# ------------------ PROFILE ------------------
@app.route('/profile/<username>')
def profile(username):
    if 'username' not in session or session['username'] != username:
        flash('Access denied.', 'error')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    return render_template('profile.html',
                           username=user['username'],
                           email=user['email'],
                           profile_pic_url=url_for('static', filename='default_profile.png'))

# ------------------ NOTIFICATIONS ------------------
@app.route('/notifications/<username>')
def notifications(username):
    if 'username' not in session or session['username'] != username:
        flash('Access denied.', 'error')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user_id = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()['id']
    notifications = conn.execute('SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC', (user_id,)).fetchall()
    conn.close()

    return render_template('notifications.html', username=username, notifications=notifications)

@app.route('/notifications/mark_read/<int:notification_id>', methods=['POST'])
def mark_notification_read(notification_id):
    if 'username' not in session:
        return 'Unauthorized', 401
    conn = get_db_connection()
    conn.execute('UPDATE notifications SET read = 1 WHERE id = ?', (notification_id,))
    conn.commit()
    conn.close()
    return 'OK', 200

@app.route('/notifications/delete/<int:notification_id>', methods=['POST'])
def delete_notification(notification_id):
    if 'username' not in session:
        return 'Unauthorized', 401
    conn = get_db_connection()
    conn.execute('DELETE FROM notifications WHERE id = ?', (notification_id,))
    conn.commit()
    conn.close()
    return 'OK', 200

# ------------------ CALENDAR ------------------
@app.route('/calendar/<username>')
def calendar(username):
    if 'username' not in session or session['username'] != username:
        flash('Access denied.', 'error')
        return redirect(url_for('login'))
    return render_template('calendar.html', username=username)

# ------------------ STATS ------------------
@app.route('/stats/<username>')
def stats(username):
    if 'username' not in session or session['username'] != username:
        flash('Access denied.', 'error')
        return redirect(url_for('login'))
    return render_template('stats.html', username=username)

# ------------------ RUN SERVER ------------------
if __name__ == "__main__":
    app.run(debug=True)