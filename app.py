from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
import sqlite3, os, random
from functools import wraps
from io import StringIO
from io import BytesIO
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# PDF generation imports
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Email Configuration
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_ADDRESS = 'your_email@gmail.com'  # Change this
EMAIL_PASSWORD = 'your_app_password'    # Change this

# ---------------- DATABASE ----------------
DATABASE = os.path.join('instance', 'users.db')
os.makedirs(os.path.dirname(DATABASE), exist_ok=True)

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS journals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            read INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_settings (
            user_id INTEGER PRIMARY KEY,
            theme TEXT DEFAULT 'light',
            default_view TEXT DEFAULT 'list',
            font_size INTEGER DEFAULT 16,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reminders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            date TEXT NOT NULL,
            time TEXT,
            completed INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS calendar_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            date TEXT NOT NULL,
            description TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
    conn.commit()
    conn.close()

def update_database():
    """Add title column to journals table if it doesn't exist"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(journals)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'title' not in columns:
            cursor.execute('ALTER TABLE journals ADD COLUMN title TEXT DEFAULT "Untitled"')
            conn.commit()
            print("Title column added successfully!")
    except Exception as e:
        print(f"Error updating database: {e}")
    finally:
        conn.close()

def update_journal_privacy_column():
    """Add is_private column to journals table if it doesn't exist"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(journals)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'is_private' not in columns:
            cursor.execute('ALTER TABLE journals ADD COLUMN is_private INTEGER DEFAULT 0')
            conn.commit()
            print("is_private column added successfully!")
    except Exception as e:
        print(f"Error updating database: {e}")
    finally:
        conn.close()

def update_journal_password_column():
    """Add password column to journals table if it doesn't exist"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(journals)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'password' not in columns:
            cursor.execute('ALTER TABLE journals ADD COLUMN password TEXT')
            conn.commit()
            print("password column added successfully!")
    except Exception as e:
        print(f"Error updating database: {e}")
    finally:
        conn.close()

# ✅ ADD THIS WHOLE FUNCTION HERE:
def update_users_table():
    """Add bio, profile_pic, and created_at columns to users table if they don't exist"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'bio' not in columns:
            cursor.execute('ALTER TABLE users ADD COLUMN bio TEXT DEFAULT ""')
            conn.commit()
            print("Bio column added successfully!")
        
        if 'profile_pic' not in columns:
            cursor.execute('ALTER TABLE users ADD COLUMN profile_pic TEXT DEFAULT "default_profile.png"')
            conn.commit()
            print("Profile_pic column added successfully!")
            
        if 'created_at' not in columns:
            cursor.execute('ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
            conn.commit()
            print("Created_at column added successfully!")
    except Exception as e:
        print(f"Error updating users table: {e}")
    finally:
        conn.close()


init_db()
update_database()
update_journal_privacy_column()
update_journal_password_column()
update_users_table()  

# ---------------- HELPERS ----------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def get_user(username):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    conn.close()
    return user

def get_user_by_email(email):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
    conn.close()
    return user

def get_user_id(username):
    conn = get_db_connection()
    row = conn.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()
    conn.close()
    return row['id'] if row else None

def get_settings(user_id):
    conn = get_db_connection()
    settings = conn.execute('SELECT * FROM user_settings WHERE user_id=?', (user_id,)).fetchone()
    if not settings:
        conn.execute('INSERT INTO user_settings (user_id) VALUES (?)', (user_id,))
        conn.commit()
        settings = conn.execute('SELECT * FROM user_settings WHERE user_id=?', (user_id,)).fetchone()
    conn.close()
    return settings

def create_notification(user_id, message):
    conn = get_db_connection()
    conn.execute('INSERT INTO notifications (user_id, message) VALUES (?, ?)', (user_id, message))
    conn.commit()
    conn.close()

def send_email(to_email, subject, body):
    """Send email using SMTP"""
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_ADDRESS, to_email, text)
        server.quit()
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def generate_journal_pdf(journals, username):
    """Generate PDF from journal entries"""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                          rightMargin=72, leftMargin=72,
                          topMargin=72, bottomMargin=18)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title style
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'],
                                fontSize=24, textColor='darkblue',
                                spaceAfter=30, alignment=TA_CENTER)
    
    # Entry title style
    entry_title_style = ParagraphStyle('EntryTitle', parent=styles['Heading2'],
                                      fontSize=16, textColor='navy',
                                      spaceAfter=6, spaceBefore=12)
    
    # Body style
    body_style = ParagraphStyle('CustomBody', parent=styles['BodyText'],
                               fontSize=11, spaceAfter=12, alignment=TA_LEFT)
    
    # Add title
    title = Paragraph(f"Journal Entries - {username}", title_style)
    elements.append(title)
    elements.append(Spacer(1, 0.2*inch))
    
    # Add generation date
    date_text = Paragraph(f"Generated on: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}", 
                         styles['Normal'])
    elements.append(date_text)
    elements.append(Spacer(1, 0.3*inch))
    
    # Loop through journals
    for i, journal in enumerate(journals, 1):
        # FIX: Replace .get() with direct access
        title = journal['title'] if journal['title'] else 'Untitled'
        entry_title = Paragraph(f"<b>{title}</b>", entry_title_style)
        elements.append(entry_title)
        
        # Add date
        date_para = Paragraph(f"<i>{journal['created_at']}</i>", styles['Italic'])
        elements.append(date_para)
        elements.append(Spacer(1, 0.1*inch))
        
        # Add content
        content = journal['content'].replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        content = content.replace('\n', '<br/>')
        entry_content = Paragraph(content, body_style)
        elements.append(entry_content)
        elements.append(Spacer(1, 0.3*inch))
    
    doc.build(elements)
    buffer.seek(0)
    return buffer

def generate_single_entry_pdf(journal, username):
    """Generate PDF for a single journal entry"""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                          rightMargin=72, leftMargin=72,
                          topMargin=72, bottomMargin=18)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title style
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'],
                                fontSize=24, textColor='darkblue',
                                spaceAfter=30, alignment=TA_CENTER)
    
    # Entry title style
    entry_title_style = ParagraphStyle('EntryTitle', parent=styles['Heading2'],
                                      fontSize=16, textColor='navy',
                                      spaceAfter=6, spaceBefore=12)
    
    # Body style
    body_style = ParagraphStyle('CustomBody', parent=styles['BodyText'],
                               fontSize=11, spaceAfter=12, alignment=TA_LEFT)
    
    # Add title
    # FIX: Replace .get() with direct access
    title = journal['title'] if journal['title'] else 'Untitled'
    entry_title = Paragraph(f"<b>{title}</b>", entry_title_style)
    elements.append(entry_title)
    
    # Add date
    date_para = Paragraph(f"<i>{journal['created_at']}</i>", styles['Italic'])
    elements.append(date_para)
    elements.append(Spacer(1, 0.1*inch))
    
    # Add content
    content = journal['content'].replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    content = content.replace('\n', '<br/>')
    entry_content = Paragraph(content, body_style)
    elements.append(entry_content)
    
    doc.build(elements)
    buffer.seek(0)
    return buffer

# ---------------- ROUTES ----------------
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method=='POST':
        username, email, password = request.form['username'], request.form['email'], request.form['password']
        if get_user(username): flash('Username exists!', 'error')
        elif get_user_by_email(email): flash('Email registered!', 'error')
        else:
            conn = get_db_connection()
            conn.execute('INSERT INTO users (username,email,password) VALUES (?,?,?)',(username,email,password))
            conn.commit(); conn.close()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        username, password = request.form['username'], request.form['password']
        user = get_user(username)
        if user and user['password']==password:
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET','POST'])
def forgot_password():
    if request.method=='POST':
        email = request.form['email']
        user = get_user_by_email(email)
        if not user: 
            flash('Email not found!', 'error')
            return redirect(url_for('forgot_password'))
        
        otp = str(random.randint(100000, 999999))
        session['otp'] = otp
        session['reset_username'] = user['username']
        
        subject = "Password Reset OTP - Journal App"
        body = f"""Hello {user['username']},

Your OTP for password reset is: {otp}

This OTP is valid for 10 minutes.

Best regards,
Journal App Team"""
        
        if send_email(email, subject, body):
            flash('OTP has been sent to your email!', 'success')
        else:
            flash(f'Email service unavailable. Your OTP is: {otp}', 'warning')
        
        return redirect(url_for('reset_password'))
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET','POST'])
def reset_password():
    if request.method=='POST':
        otp, new_pass = request.form['otp'], request.form['new_password']
        if otp==session.get('otp'):
            conn = get_db_connection()
            conn.execute('UPDATE users SET password=? WHERE username=?',
                        (new_pass, session['reset_username']))
            conn.commit()
            conn.close()
            flash('Password reset successful!', 'success')
            session.pop('otp', None)
            session.pop('reset_username', None)
            return redirect(url_for('login'))
        flash('Invalid OTP.', 'error')
    return render_template('reset_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    username = session['username']
    user_id = get_user_id(username)
    conn = get_db_connection()
    journals = conn.execute('SELECT * FROM journals WHERE user_id=?',(user_id,)).fetchall()
    notifications = conn.execute('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 5',(user_id,)).fetchall()
    conn.close()
    settings = get_settings(user_id)
    return render_template('dashboard.html', username=username, journals=journals, theme=settings['theme'], notifications=notifications)
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    # Clear all unlock flags for private entries
    keys_to_remove = [key for key in session.keys() if key.startswith('unlocked_')]
    for key in keys_to_remove:
        session.pop(key, None)
    
    session.pop('username', None)
    flash('Logged out.', 'success')
    return redirect(url_for('login'))
# ---------------- Journals ----------------

@app.route('/add_journal/<username>', methods=['GET', 'POST'])
@login_required
def add_journal(username):
    # Check if the logged-in user matches the username in the URL
    if session['username'] != username:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    # Handle POST request (form submission)
    if request.method == 'POST':
        title = request.form.get('title', 'Untitled')
        content = request.form.get('content', '')
        is_private = 1 if request.form.get('is_private') else 0
        password = request.form.get('password', '') if is_private else ''
        
        if content:
            user_id = get_user_id(username)
            conn = get_db_connection()
            conn.execute('INSERT INTO journals (user_id, title, content, is_private, password) VALUES (?,?,?,?,?)',
                        (user_id, title, content, is_private, password))
            conn.commit()
            conn.close()
            
            privacy_msg = "🔒 Private" if is_private else "📖 Public"
            create_notification(user_id, f"✅ New {privacy_msg} journal entry added.")
            flash('Journal added!', 'success')
            return redirect(url_for('view_journal', username=username))
        else:
            flash('Content cannot be empty!', 'error')
    
    # Handle GET request (display the form)
    return render_template('add_journal.html', username=username)

@app.route('/view_journal/<username>')
@login_required
def view_journal(username):
    if session['username'] != username:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    journals = conn.execute('SELECT * FROM journals WHERE user_id=? ORDER BY created_at DESC', 
                          (get_user_id(username),)).fetchall()
    conn.close()
    return render_template('view_journal.html', journals=journals, username=username, filter='all')

@app.route('/view_journal/<username>/private')
@login_required
def view_private_journal(username):
    if session['username'] != username: 
        flash('Access denied','error')
        return redirect(url_for('login'))
    conn = get_db_connection()
    journals = conn.execute('SELECT * FROM journals WHERE user_id=? AND is_private=1',
                          (get_user_id(username),)).fetchall()
    conn.close()
    return render_template('view_journal.html', journals=journals, username=username, filter='private')

@app.route('/view_journal/<username>/public')
@login_required
def view_public_journal(username):
    if session['username'] != username: 
        flash('Access denied','error')
        return redirect(url_for('login'))
    conn = get_db_connection()
    journals = conn.execute('SELECT * FROM journals WHERE user_id=? AND is_private=0',
                          (get_user_id(username),)).fetchall()
    conn.close()
    return render_template('view_journal.html', journals=journals, username=username, filter='public')

@app.route('/search_journal/<username>', methods=['GET'])
@login_required
def search_journal(username):
    if session['username']!=username: flash('Access denied','error'); return redirect(url_for('login'))
    query = request.args.get('query','').lower()
    conn = get_db_connection()
    results = conn.execute('SELECT * FROM journals WHERE user_id=? AND LOWER(content) LIKE ?',(get_user_id(username),f'%{query}%')).fetchall()
    conn.close()
    if not results:
        flash('No matching entries found.', 'info')
    return render_template('search_journal.html', results=results, username=username)

@app.route('/update_journal/<username>/<int:id>', methods=['GET','POST'])
@login_required
def update_journal(username, id):
    if session['username'] != username:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    journal = conn.execute('SELECT * FROM journals WHERE id=?', (id,)).fetchone()
    if not journal or journal['user_id'] != get_user_id(username):
        conn.close()
        flash('Access denied or not found', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        title = request.form.get('title', 'Untitled')
        content = request.form['content']
        is_private = 1 if request.form.get('is_private') else 0
        password = request.form.get('password', '')
        
        # Get current password if not provided
        if not password and is_private:
            current_password = journal['password'] if journal else ''
        else:
            current_password = password
        
        conn.execute('UPDATE journals SET title=?, content=?, is_private=?, password=? WHERE id=?',
                    (title, content, is_private, current_password, id))
        conn.commit()
        conn.close()
        create_notification(get_user_id(username), 
                          "✏️ You edited one of your journal entries.")
        flash('Journal updated!', 'success')
        return redirect(url_for('view_journal', username=username))
    
    conn.close()
    return render_template('update_journal.html', journal=journal, username=username)

@app.route('/delete_journal/<username>/<int:id>', methods=['POST'])
@login_required
def delete_journal(username, id):
    if session['username'] != username:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    journal = conn.execute('SELECT * FROM journals WHERE id=?', (id,)).fetchone()
    if not journal or journal['user_id'] != get_user_id(username):
        conn.close()
        flash('Access denied or not found', 'error')
        return redirect(url_for('dashboard'))
    
    conn.execute('DELETE FROM journals WHERE id=?', (id,))
    conn.commit()
    conn.close()
    create_notification(get_user_id(username), "❌ A journal entry was deleted.")
    flash('Journal deleted!', 'success')
    return redirect(url_for('view_journal', username=username))

@app.route('/search_entry/<username>', methods=['GET', 'POST'])
@login_required
def search_entry(username):
    if session['username'] != username:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        search_title = request.form.get('search_title', '').strip()
        if not search_title:
            flash('Please enter a title to search', 'error')
            return render_template('search_entry.html', username=username)
        
        conn = get_db_connection()
        # Search for entries with titles containing the search term
        journals = conn.execute(
            'SELECT * FROM journals WHERE user_id=? AND LOWER(title) LIKE ?',
            (get_user_id(username), f'%{search_title.lower()}%')
        ).fetchall()
        conn.close()
        
        if not journals:
            flash('No entries found with that title', 'info')
            return render_template('search_entry.html', username=username)
        
        return render_template('search_entry.html', username=username, journals=journals, search_term=search_title)
    
    return render_template('search_entry.html', username=username)

@app.route('/export_journal/<username>')
@login_required
def export_journal(username):
    if session['username'] != username:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    journals = conn.execute('SELECT * FROM journals WHERE user_id=? ORDER BY created_at ASC',
                          (get_user_id(username),)).fetchall()
    conn.close()
    
    if not journals: 
        flash('No entries to export', 'info')
        return redirect(url_for('view_journal', username=username))
    
    from io import StringIO
    file_data = StringIO()
    file_data.write(f"Journal Entries for {username}\n\n")
    for i, e in enumerate(journals, 1): 
        title = e['title'] if e['title'] else 'Untitled'
        privacy = "Private" if e['is_private'] else "Public"
        file_data.write(f"Entry {i} - {e['created_at']} - {title} ({privacy})\n{e['content']}\n\n")
    file_data.seek(0)

    return send_file(
        BytesIO(file_data.getvalue().encode()), 
        as_attachment=True, 
        download_name=f"{username}_journal.txt", 
        mimetype='text/plain'
    )

@app.route('/export_journal_pdf/<username>')
@login_required
def export_journal_pdf(username):
    if session['username'] != username:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    journals = conn.execute('SELECT * FROM journals WHERE user_id=? ORDER BY created_at ASC',
                          (get_user_id(username),)).fetchall()
    conn.close()
    
    if not journals: 
        flash('No entries to export', 'info')
        return redirect(url_for('view_journal', username=username))
    
    pdf_buffer = generate_journal_pdf(journals, username)
    create_notification(get_user_id(username), "📄 Journal exported to PDF successfully.")
    
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f"{username}_journal_{datetime.now().strftime('%Y%m%d')}.pdf",
        mimetype='application/pdf'
    )

@app.route('/export_single_entry_txt/<username>/<int:entry_id>')
@login_required
def export_single_entry_txt(username, entry_id):
    if session['username'] != username:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    journal = conn.execute('SELECT * FROM journals WHERE id=? AND user_id=?', 
                          (entry_id, get_user_id(username))).fetchone()
    conn.close()
    
    if not journal:
        flash('Entry not found', 'error')
        return redirect(url_for('view_journal', username=username))
    
    from io import StringIO
    file_data = StringIO()
    title = journal['title'] if journal['title'] else 'Untitled'
    privacy = "Private" if journal['is_private'] else "Public"
    file_data.write(f"Journal Entry: {title} ({privacy})\n\n")
    file_data.write(f"Date: {journal['created_at']}\n\n")
    file_data.write(f"Content:\n{journal['content']}\n")
    file_data.seek(0)
    
    # Create a safe filename from the title
    safe_title = "".join(c for c in title if c.isalnum() or c in (' ', '-', '_')).rstrip()
    safe_title = safe_title.replace(' ', '_')
    
    return send_file(
        BytesIO(file_data.getvalue().encode()), 
        as_attachment=True, 
        download_name=f"{safe_title}.txt", 
        mimetype='text/plain'
    )

@app.route('/export_single_entry_pdf/<username>/<int:entry_id>')
@login_required
def export_single_entry_pdf(username, entry_id):
    if session['username'] != username:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    journal = conn.execute('SELECT * FROM journals WHERE id=? AND user_id=?', 
                          (entry_id, get_user_id(username))).fetchone()
    conn.close()
    
    if not journal:
        flash('Entry not found', 'error')
        return redirect(url_for('view_journal', username=username))
    
    # Create a safe filename from the title
    title = journal['title'] if journal['title'] else 'Untitled'
    safe_title = "".join(c for c in title if c.isalnum() or c in (' ', '-', '_')).rstrip()
    safe_title = safe_title.replace(' ', '_')
    
    # Generate PDF for a single entry
    pdf_buffer = generate_single_entry_pdf(journal, username)
    
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f"{safe_title}.pdf",
        mimetype='application/pdf'
    )

# Add these new routes for private entry functionality
@app.route('/unlock_entry/<username>/<int:entry_id>', methods=['GET', 'POST'])
@login_required
def unlock_entry(username, entry_id):
    if session['username'] != username:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    journal = conn.execute('SELECT * FROM journals WHERE id=? AND user_id=?', 
                          (entry_id, get_user_id(username))).fetchone()
    conn.close()
    
    if not journal:
        flash('Entry not found', 'error')
        return redirect(url_for('view_journal', username=username))
    
    if not journal['is_private']:
        # If not private, redirect to view page
        return redirect(url_for('view_single_entry', username=username, entry_id=entry_id))
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password == journal['password']:
            # Store unlock in session temporarily
            session[f'unlocked_{entry_id}'] = True
            flash('Entry unlocked successfully!', 'success')
            return redirect(url_for('view_single_entry', username=username, entry_id=entry_id))
        else:
            flash('Incorrect password!', 'error')
    
    return render_template('unlock_entry.html', journal=journal, username=username)

@app.route('/view_single_entry/<username>/<int:entry_id>')
@login_required
def view_single_entry(username, entry_id):
    if session['username'] != username:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    journal = conn.execute('SELECT * FROM journals WHERE id=? AND user_id=?', 
                          (entry_id, get_user_id(username))).fetchone()
    conn.close()
    
    if not journal:
        flash('Entry not found', 'error')
        return redirect(url_for('view_journal', username=username))
    
    # Check if private and not unlocked
    if journal['is_private'] and not session.get(f'unlocked_{entry_id}'):
        return redirect(url_for('unlock_entry', username=username, entry_id=entry_id))
    
    return render_template('view_single_entry.html', journal=journal, username=username)

# ---------------- Settings ----------------
@app.route('/settings/<username>', methods=['GET','POST'])
@login_required
def settings(username):
    if session['username']!=username: flash('Access denied','error'); return redirect(url_for('login'))
    user_id = get_user_id(username)
    settings = get_settings(user_id)
    if request.method=='POST':
        theme = request.form.get('theme',settings['theme'])
        default_view = request.form.get('default_view',settings['default_view'])
        font_size = request.form.get('font_size',settings['font_size'])
        conn = get_db_connection()
        conn.execute('UPDATE user_settings SET theme=?,default_view=?,font_size=? WHERE user_id=?',(theme,default_view,font_size,user_id))
        conn.commit(); conn.close(); flash('Settings updated!','success')
    return render_template('settings.html', username=username, theme=settings['theme'], default_view=settings['default_view'], font_size=settings['font_size'])

# ---------------- Reminders ----------------
@app.route('/reminders/<username>', methods=['GET','POST'])
@login_required
def reminders(username):
    if session['username']!=username: flash('Access denied','error'); return redirect(url_for('login'))
    user_id = get_user_id(username)
    conn = get_db_connection()
    if request.method=='POST':
        title,date,time = request.form['title'],request.form['date'],request.form.get('time','')
        conn.execute('INSERT INTO reminders (user_id,title,date,time) VALUES (?,?,?,?)',(user_id,title,date,time))
        conn.commit(); flash('Reminder added!','success')
    reminders = conn.execute('SELECT * FROM reminders WHERE user_id=? ORDER BY date ASC',(user_id,)).fetchall()
    conn.close()
    return render_template('reminders.html', username=username, reminders=reminders)

@app.route('/reminders/delete/<int:id>', methods=['POST'])
@login_required
def delete_reminder(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM reminders WHERE id=?',(id,))
    conn.commit(); conn.close()
    flash('Reminder deleted!','success')
    return redirect(url_for('reminders', username=session['username']))

# ---------------- Calendar ----------------
@app.route('/calendar/<username>', methods=['GET','POST'])
@login_required
def calendar(username):
    if session['username']!=username: flash('Access denied','error'); return redirect(url_for('login'))
    user_id = get_user_id(username)
    conn = get_db_connection()
    if request.method=='POST':
        title,date,desc = request.form['title'],request.form['date'],request.form.get('description','')
        conn.execute('INSERT INTO calendar_events (user_id,title,date,description) VALUES (?,?,?,?)',(user_id,title,date,desc))
        conn.commit(); flash('Event added!','success')
    events = conn.execute('SELECT * FROM calendar_events WHERE user_id=? ORDER BY date ASC',(user_id,)).fetchall()
    conn.close()
    return render_template('calendar.html', username=username, events=events)

@app.route('/calendar/delete/<int:id>', methods=['POST'])
@login_required
def delete_calendar_event(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM calendar_events WHERE id=?',(id,))
    conn.commit(); conn.close()
    flash('Event deleted!','success')
    return redirect(url_for('calendar', username=session['username']))

# ---------------- Profile ----------------
@app.route('/profile/<username>/upload_picture', methods=['POST'])
@login_required
def upload_profile_picture(username):
    if session['username'] != username:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    if 'profile_pic' not in request.files:
        flash('No file selected!', 'error')
        return redirect(url_for('profile', username=username))
    
    file = request.files['profile_pic']
    
    if file.filename == '':
        flash('No file selected!', 'error')
        return redirect(url_for('profile', username=username))
    
    # Check if file is an image
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    if '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
        # Create uploads directory if it doesn't exist
        upload_folder = os.path.join('static', 'uploads')
        os.makedirs(upload_folder, exist_ok=True)
        
        # Generate unique filename
        filename = f"{username}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{file.filename.rsplit('.', 1)[1].lower()}"
        filepath = os.path.join(upload_folder, filename)
        
        # Save file
        file.save(filepath)
        
        # Update database
        conn = get_db_connection()
        conn.execute('UPDATE users SET profile_pic=? WHERE username=?', 
                    (f'uploads/{filename}', username))
        conn.commit()
        conn.close()
        
        create_notification(get_user_id(username), "📸 Your profile picture has been updated.")
        flash('Profile picture updated!', 'success')
    else:
        flash('Invalid file type! Please upload an image (png, jpg, jpeg, gif).', 'error')
    
    return redirect(url_for('profile', username=username))


@app.route('/profile/<username>/save_bio', methods=['POST'])
@login_required
def save_bio(username):
    if session['username'] != username:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    bio = request.form.get('bio', '').strip()
    
    conn = get_db_connection()
    conn.execute('UPDATE users SET bio=? WHERE username=?', (bio, username))
    conn.commit()
    conn.close()
    
    create_notification(get_user_id(username), "📝 Your bio has been updated.")
    flash('Bio updated successfully!', 'success')
    return redirect(url_for('profile', username=username))


@app.route('/profile/<username>/edit_info', methods=['POST'])
@login_required
def edit_profile_info(username):
    if session['username'] != username:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    new_username = request.form.get('username', '').strip()
    new_email = request.form.get('email', '').strip()
    
    if not new_username or not new_email:
        flash('Username and email cannot be empty!', 'error')
        return redirect(url_for('profile', username=username))
    
    # Check if new username is taken (if changed)
    if new_username != username:
        existing_user = get_user(new_username)
        if existing_user:
            flash('Username already taken!', 'error')
            return redirect(url_for('profile', username=username))
    
    # Check if new email is taken (if changed)
    user = get_user(username)
    if new_email != user['email']:
        existing_email = get_user_by_email(new_email)
        if existing_email:
            flash('Email already registered!', 'error')
            return redirect(url_for('profile', username=username))
    
    # Update user info
    conn = get_db_connection()
    conn.execute('UPDATE users SET username=?, email=? WHERE username=?',
                (new_username, new_email, username))
    conn.commit()
    conn.close()
    
    # Update session if username changed
    if new_username != username:
        session['username'] = new_username
        create_notification(get_user_id(new_username), "✏️ Your profile information has been updated.")
        flash('Profile updated! Username changed.', 'success')
        return redirect(url_for('profile', username=new_username))
    
    create_notification(get_user_id(username), "✏️ Your profile information has been updated.")
    flash('Profile updated successfully!', 'success')
    return redirect(url_for('profile', username=username))


@app.route('/profile/<username>/update_preferences', methods=['POST'])
@login_required
def update_profile_preferences(username):
    if session['username'] != username:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    default_view = request.form.get('default_view', 'list')
    user_id = get_user_id(username)
    
    conn = get_db_connection()
    conn.execute('UPDATE user_settings SET default_view=? WHERE user_id=?',
                (default_view, user_id))
    conn.commit()
    conn.close()
    
    create_notification(user_id, "⚙️ Your preferences have been updated.")
    flash('Preferences updated successfully!', 'success')
    return redirect(url_for('profile', username=username))
@app.route('/profile/<username>')
@login_required
def profile(username):
    if session['username'] != username:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    user = get_user(username)
    settings = get_settings(get_user_id(username))
    
    # Count total journals
    conn = get_db_connection()
    journal_count = conn.execute('SELECT COUNT(*) as count FROM journals WHERE user_id=?', 
                                (get_user_id(username),)).fetchone()['count']
    conn.close()
    
    # Safely access columns that might not exist
    try:
        bio = user['bio'] if user['bio'] else ''
    except (KeyError, IndexError):
        bio = ''
    
    try:
        profile_pic = user['profile_pic'] if user['profile_pic'] else 'default_profile.png'
    except (KeyError, IndexError):
        profile_pic = 'default_profile.png'
    
    try:
        created_at = user['created_at'] if user['created_at'] else 'N/A'
    except (KeyError, IndexError):
        created_at = 'N/A'
    
    # Format the profile picture URL
    if profile_pic and not profile_pic.startswith('http'):
        profile_pic_url = url_for('static', filename=profile_pic)
    else:
        profile_pic_url = url_for('static', filename='images/default_profile.png')
    
    profile_data = {
        'username': user['username'],
        'email': user['email'],
        'bio': bio,
        'profile_pic': profile_pic,
        'profile_pic_url': profile_pic_url,
        'account_creation_date': created_at,
        'journal_count': journal_count,
        'default_view': settings['default_view']
    }
    
    return render_template('profile.html', **profile_data)


@app.route('/profile/<username>/delete_account', methods=['POST'])
@login_required
def delete_account(username):
    if session['username'] != username:
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    password = request.form.get('password', '')
    user = get_user(username)
    
    if password != user['password']:
        flash('Incorrect password! Account not deleted.', 'error')
        return redirect(url_for('profile', username=username))
    
    user_id = get_user_id(username)
    
    # Delete all user data
    conn = get_db_connection()
    conn.execute('DELETE FROM journals WHERE user_id=?', (user_id,))
    conn.execute('DELETE FROM notifications WHERE user_id=?', (user_id,))
    conn.execute('DELETE FROM reminders WHERE user_id=?', (user_id,))
    conn.execute('DELETE FROM calendar_events WHERE user_id=?', (user_id,))
    conn.execute('DELETE FROM user_settings WHERE user_id=?', (user_id,))
    conn.execute('DELETE FROM users WHERE id=?', (user_id,))
    conn.commit()
    conn.close()
    
    session.clear()
    flash('Account deleted successfully. We\'re sorry to see you go!', 'info')
    return redirect(url_for('register'))

# ---------------- Notifications ----------------
@app.route('/notifications/<username>')
@login_required
def notifications(username):
    if session['username']!=username: flash('Access denied','error'); return redirect(url_for('login'))
    conn = get_db_connection()
    notifications = conn.execute('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC',(get_user_id(username),)).fetchall()
    conn.close()
    return render_template('notifications.html', username=username, notifications=notifications)

@app.route('/notifications/mark_read/<int:id>', methods=['POST'])
@login_required
def mark_notification_read(id):
    conn = get_db_connection()
    conn.execute('UPDATE notifications SET read=1 WHERE id=?',(id,))
    conn.commit(); conn.close()
    return 'OK',200

@app.route('/notifications/delete/<int:id>', methods=['POST'])
@login_required
def delete_notification(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM notifications WHERE id=?',(id,))
    conn.commit(); conn.close()
    return 'OK',200

# ---------------- Run App ----------------
if __name__=='__main__':
    app.run(debug=True)