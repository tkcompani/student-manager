import os
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import pysqlite3 as sqlite3 
from functools import wraps

app = Flask(__name__)
app.secret_key = 'supersecretkey'
def init_db():
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    #users table
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL)''')
    # Grades table
    cur.execute('''CREATE TABLE IF NOT EXISTS grades (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_username TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    teacher_username TEXT NOT NULL)''')
    conn.commit()
    conn.close()

#security check for authorizations
def login_required(role=None):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if 'username' not in session:
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                return redirect(url_for('unauthorized')), 403
            return view_func(*args, **kwargs)
        return wrapper
    return decorator

#home page
@app.route('/')
#@login_required()
def home():
    return redirect(url_for("login"))

#login page    
@app.route("/register", methods = ['GET', 'POST'])
#@login_required()
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password= request.form['password']
        role = request.form['role']
        
        conn = sqlite3.connect('users.db')
        cur = conn.cursor()

        try:
            cur.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                        (username, generate_password_hash(password), role))
            conn.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = "Username already exists."
        finally:
            conn.close()
    return render_template('register.html', error=error)
    
#register page
@app.route("/login", methods = ['GET', 'POST'])
#@login_required()
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password= request.form['password']
        
        conn = sqlite3.connect('users.db')
        cur = conn.cursor()
        cur.execute('SELECT password_hash, role FROM users WHERE username = ?', (username,))
        result = cur.fetchone()
        conn.close()

        if result and check_password_hash(result[0], password):
            session['username'] = username
            session['role'] = result[1]
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid username or password"
    return render_template('login.html', error=error)
   
  #dashboard
@app.route('/dashboard')
#@login_required()
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
        
    role = session.get('role')

    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'teacher':
        return redirect(url_for('teacher_dashboard'))
    elif role == 'student':
        return redirect(url_for('student_dashboard'))
    else:
        return "Unknown role"
     
#logout func
@app.route('/logout')
#@login_required()
def logout():
    session.clear()
    return redirect(url_for('login'))

#roles dashboard 
#admin db  
@app.route('/admin')
@login_required(role='admin')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute('SELECT username, role FROM users ORDER BY role')
    users = cur.fetchall()
    conn.close()
    
    return render_template('admindb.html', users=users)
    
#admin feature - add users manually 
@app.route('/add_user', methods=['POST'])
@login_required(role='admin')
def add_user():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    username = request.form['username']
    password = request.form['password']
    role = request.form['role']

    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                    (username, generate_password_hash(password), role))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # you could flash a message like 'User already exists'
    finally:
        conn.close()

    return redirect(url_for('admin_dashboard'))
    
#admin feature - delete user
@app.route('/delete_user', methods=['POST'])
@login_required(role='admin')
def delete_user():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    username = request.form['username']

    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()

    return redirect(url_for('admin_dashboard'))

#teacher db
@app.route('/teacher')
@login_required(role='teacher')
def teacher_dashboard():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
        
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()

    # Get all students
    cur.execute("SELECT username FROM users WHERE role = 'student'")
    students = cur.fetchall()

    # Get existing grades
    cur.execute("SELECT student_username, subject, score FROM grades WHERE teacher_username = ?", (session['username'],))
    grades = cur.fetchall()

    conn.close()

    return render_template('teacherdb.html', students=students, grades=grades)

#teacher feature - assign grades
@app.route('/assign_grade', methods=['POST'])
@login_required(role='teacher')
def assign_grade():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))

    student = request.form['student']
    subject = request.form['subject']
    score = request.form['score']
    teacher = session['username']

    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute("INSERT INTO grades (student_username, subject, score, teacher_username) VALUES (?, ?, ?, ?)",
                (student, subject, score, teacher))
    conn.commit()
    conn.close()

    return redirect(url_for('teacher_dashboard'))
    
#teacher feature - edit grades
@app.route('/edit_grade', methods=['POST'])
@login_required(role='teacher')
def edit_grade():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))

    student = request.form['student']
    subject = request.form['subject']
    new_score = request.form['new_score']

    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute('''
        UPDATE grades SET score = ? 
        WHERE student_username = ? AND subject = ? AND teacher_username = ?
    ''', (new_score, student, subject, session['username']))
    conn.commit()
    conn.close()

    return redirect(url_for('teacher_dashboard'))

#...-.delete grades
@app.route('/delete_grade', methods=['POST'])
@login_required(role='teacher')
def delete_grade():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))

    student = request.form['student']
    subject = request.form['subject']

    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute('''
        DELETE FROM grades 
        WHERE student_username = ? AND subject = ? AND teacher_username = ?
    ''', (student, subject, session['username']))
    conn.commit()
    conn.close()

    return redirect(url_for('teacher_dashboard'))

#student db
@app.route('/student')
@login_required(role='student')
def student_dashboard():
    if session.get('role') != 'student':
        return redirect(url_for('login'))
        
    student = session['username']

    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute("SELECT subject, score, teacher_username FROM grades WHERE student_username = ?", (student,))
    grades = cur.fetchall()
    conn.close()
    return render_template('studentdb.html', grades=grades)
    
#unautorized access page
@app.route('/unauthorized_acess')
def unauthorized():
    return render_template('un_auto.html')
    
    
if __name__ == "__main__":
    init_db()
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))