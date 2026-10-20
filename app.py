from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, g, Response
import sqlite3
import time
import os
import secrets
import hmac
import csv
import io
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

DATABASE = 'tutoring.db'
SITE_NAME = os.environ.get('SITE_NAME', 'Peer Tutoring')

MIN_TUTOR_GRADE = 10
MIN_GRADE = 6
MAX_GRADE = 12

MAX_OPEN_REQUESTS = 3
MIN_WINDOW_MINUTES = 15
MAX_DAYS_AHEAD = 14

CHECKIN_LEAD_MINUTES = 30
CHECK_AFTER_SECONDS = 30 * 60
RESPONSE_WINDOW_SECONDS = 5 * 60
MAX_MESSAGES_PER_SESSION = 20

AUTO_CONFIRM_DAYS = 3
MAX_SESSION_MINUTES = 480

AUDIT_PAGE_SIZE = 50

MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 10 * 60
FAILED_LOGINS = {}

LOCATION_KINDS = {
    "school_library": "School library",
    "classroom": "Classroom",
    "cafeteria": "Cafeteria",
    "public_library": "Public library",
    "other": "Other",
}

ACTION_LABELS = {
    "tutor_review": "Tutor subject review",
    "location_added": "Location added",
    "location_changed": "Location changed",
    "password_reset": "Password reset",
    "student_removed": "Student removed",
    "student_restored": "Student restored",
    "report_reviewed": "Report marked reviewed",
    "session_edited": "Session edited",
}

SESSION_STATUSES = ["scheduled", "in_progress", "awaiting_confirmation", "completed", "cancelled"]

LOGOUT_MESSAGES = {
    "loggedout": "You have been logged out.",
}


def connect():
    if 'conn' not in g:
        g.conn = sqlite3.connect(DATABASE)
        g.conn.row_factory = sqlite3.Row
        g.conn.execute("PRAGMA foreign_keys = ON")
    return g.conn


@app.teardown_appcontext
def close_connection(error):
    conn = g.pop('conn', None)
    if conn is not None:
        conn.close()


def csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']


app.jinja_env.globals['csrf_token'] = csrf_token


@app.context_processor
def add_site_name():
    return {'site_name': SITE_NAME}


def get_user():
    if 'user' in g:
        return g.user
    if 'username' not in session:
        return None
    cursor = connect().cursor()
    cursor.execute("""
        SELECT users.id, users.username, users.role, users.school_id, users.must_change_password,
               users.removed_at, users.session_version, schools.name AS school_name,
               profiles.first_name, profiles.last_name, profiles.grade_level
        FROM users
        LEFT JOIN schools ON schools.id = users.school_id
        LEFT JOIN profiles ON profiles.user_id = users.id
        WHERE users.username = ?
    """, (session['username'],))
    user = cursor.fetchone()
    if user is None or user['removed_at'] is not None or user['session_version'] != session.get('version'):
        session.clear()
        return None
    g.user = user
    return user


def get_member():
    user = get_user()
    if user is None or user['role'] != 'member' or user['first_name'] is None:
        return None
    return user


def get_teacher():
    user = get_user()
    if user is None or user['role'] != 'teacher':
        return None
    return user


def settle_sessions():
    conn = connect()
    cursor = conn.cursor()
    now = int(time.time())
    cursor.execute("""
        UPDATE sessions SET status = 'awaiting_confirmation', end_time = last_confirmed + ?
        WHERE status = 'in_progress' AND ? > last_confirmed + ?
    """, (CHECK_AFTER_SECONDS, now, CHECK_AFTER_SECONDS + RESPONSE_WINDOW_SECONDS))
    cursor.execute("""
        UPDATE sessions SET status = 'completed', student_confirmed_at = ?, confirmed_how = 'auto',
               counted_minutes = ROUND((end_time - start_time) / 60.0, 2)
        WHERE status = 'awaiting_confirmation' AND end_time < ?
          AND NOT EXISTS (SELECT 1 FROM reports WHERE reports.session_id = sessions.id AND reports.status = 'open')
    """, (now, now - AUTO_CONFIRM_DAYS * 86400))
    conn.commit()


@app.before_request
def before_request():
    if request.endpoint is None or request.endpoint == 'static':
        return None
    if request.method == 'POST':
        token = session.get('csrf_token')
        if not token or not hmac.compare_digest(token, request.form.get('csrf_token', '')):
            abort(400)
    settle_sessions()
    if 'username' in session and request.endpoint not in ('change_password', 'logout'):
        user = get_user()
        if user is not None and user['must_change_password']:
            return redirect(url_for('change_password'))
    return None


def password_problem(password):
    if len(password) <= 5:
        return "Your password must be at least 6 characters long"
    elif not any(char.isdigit() for char in password):
        return "Your password must contain a number"
    elif not any(char.isupper() for char in password):
        return "Your password must include an uppercase letter"
    return None


def make_temp_password():
    letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    while True:
        temp = "".join(secrets.choice(letters) for i in range(10))
        if password_problem(temp) is None:
            return temp


def login_locked(key):
    now = time.time()
    recent = [t for t in FAILED_LOGINS.get(key, []) if now - t < LOCKOUT_SECONDS]
    FAILED_LOGINS[key] = recent
    return len(recent) >= MAX_FAILED_LOGINS


def get_subject_groups(cursor):
    cursor.execute("SELECT code, label, group_name FROM subjects ORDER BY group_name, sort_order")
    groups = {}
    for row in cursor.fetchall():
        groups.setdefault(row['group_name'], []).append((row['code'], row['label']))
    return groups


def log_action(cursor, user, action, target_user_id, target_label, details):
    cursor.execute("""
        INSERT INTO audit_log (school_id, actor_user_id, action, target_user_id, target_label, details)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user['school_id'], user['id'], action, target_user_id, target_label, details))


def member_label(cursor, user_id):
    cursor.execute("""
        SELECT users.username, profiles.first_name, profiles.last_name
        FROM users LEFT JOIN profiles ON profiles.user_id = users.id
        WHERE users.id = ?
    """, (user_id,))
    row = cursor.fetchone()
    if row['first_name']:
        return row['first_name'] + " " + row['last_name'] + " (" + row['username'] + ")"
    return row['username']


def get_school_member(cursor, user, user_id):
    cursor.execute("SELECT id, username, removed_at FROM users WHERE id = ? AND school_id = ? AND role = 'member'",
                   (user_id, user['school_id']))
    member = cursor.fetchone()
    if member is None:
        abort(404)
    return member


def get_number(name):
    try:
        return int(request.form[name])
    except (KeyError, ValueError):
        return None


def window_problem(start, end, now):
    if start is None or end is None:
        return "Please choose a start and end time", None
    start = max(start, now)
    if end - start < MIN_WINDOW_MINUTES * 60:
        return "Your time window must be at least " + str(MIN_WINDOW_MINUTES) + " minutes long and end in the future", None
    if end > now + MAX_DAYS_AHEAD * 86400:
        return "Your time window can't end more than " + str(MAX_DAYS_AHEAD) + " days from now", None
    return None, start


def board_rows(cursor, tutor_id, school_id, now, subject):
    cursor.execute("""
        SELECT requests.id, requests.subject_code, requests.window_start, requests.window_end,
               subjects.label AS subject, locations.name AS location, locations.requires_supervision,
               profiles.first_name, profiles.grade_level
        FROM requests
        JOIN subjects ON subjects.code = requests.subject_code
        JOIN locations ON locations.id = requests.location_id AND locations.active = 1
        JOIN users ON users.id = requests.student_user_id AND users.removed_at IS NULL
        JOIN profiles ON profiles.user_id = requests.student_user_id
        WHERE requests.school_id = ? AND requests.status = 'open' AND requests.window_end > ?
          AND requests.student_user_id != ?
          AND requests.subject_code IN (SELECT subject_code FROM tutor_subjects WHERE user_id = ? AND status = 'approved')
          AND (? IS NULL OR requests.subject_code = ?)
        ORDER BY requests.window_start
    """, (school_id, now, tutor_id, tutor_id, subject, subject))
    return cursor.fetchall()


def render_profile(groups, error):
    return render_template('new_profile.html', groups=groups, error=error, form=request.form,
                           selected=set(request.form.getlist('subjects')),
                           min_tutor_grade=MIN_TUTOR_GRADE, min_grade=MIN_GRADE, max_grade=MAX_GRADE)


def render_new_request(groups, locations, error):
    return render_template('request_new.html', groups=groups, locations=locations, error=error,
                           form=request.form, max_open=MAX_OPEN_REQUESTS)


def csv_safe(value):
    value = str(value)
    if value[:1] in ("=", "+", "-", "@"):
        return "'" + value
    return value


@app.route("/")
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route("/sign_up", methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        conn = connect()
        cursor = conn.cursor()

        username = request.form['username'].strip()
        password = request.form['password']
        code = request.form['join_code'].strip().upper()

        if len(username) < 3 or len(username) > 30:
            return render_template('sign_up.html', error="Your username must be 3 to 30 characters long", username=username, join_code=code)

        problem = password_problem(password)
        if problem:
            return render_template('sign_up.html', error=problem, username=username, join_code=code)

        cursor.execute("SELECT id, join_code, teacher_code FROM schools WHERE join_code = ? OR teacher_code = ?", (code, code))
        school = cursor.fetchone()

        if school is None:
            return render_template('sign_up.html', error="That school code was not recognized. Ask your teacher for the code.", username=username, join_code=code)

        if code == school['teacher_code']:
            role = 'teacher'
        else:
            role = 'member'

        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return render_template('sign_up.html', error="That username is already taken.", username=username, join_code=code)

        cursor.execute("INSERT INTO users (username, password_hash, role, school_id) VALUES (?, ?, ?, ?)",
                       (username, generate_password_hash(password), role, school['id']))
        conn.commit()

        session.clear()
        session['username'] = username
        session['version'] = 0

        return redirect(url_for('dashboard'))

    else:
        return render_template('sign_up.html')


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        conn = connect()
        cursor = conn.cursor()

        username = request.form['username'].strip()
        password = request.form['password']
        key = (request.remote_addr, username.lower())

        if login_locked(key):
            return render_template('login.html', error="Too many failed attempts. Please wait 10 minutes and try again.")

        cursor.execute("SELECT username, password_hash, removed_at, session_version FROM users WHERE username = ?", (username,))
        user_row = cursor.fetchone()

        if user_row is None or not check_password_hash(user_row['password_hash'], password):
            FAILED_LOGINS.setdefault(key, []).append(time.time())
            return render_template('login.html', error="Invalid username or password")
        elif user_row['removed_at'] is not None:
            return render_template('login.html', error="This account is no longer active. Please ask your teacher.")
        else:
            FAILED_LOGINS.pop(key, None)
            session.clear()
            session['username'] = user_row['username']
            session['version'] = user_row['session_version']
            return redirect(url_for('dashboard'))
    else:
        return render_template('login.html', message=LOGOUT_MESSAGES.get(request.args.get('reason')))


@app.route("/logout", methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect(url_for('login', reason='loggedout'))


@app.route("/change_password", methods=['GET', 'POST'])
def change_password():
    user = get_user()
    if user is None:
        return redirect(url_for('login'))

    forced = bool(user['must_change_password'])

    if request.method == 'POST':
        conn = connect()
        cursor = conn.cursor()

        current = request.form['current_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']

        cursor.execute("SELECT password_hash, session_version FROM users WHERE id = ?", (user['id'],))
        row = cursor.fetchone()

        if not check_password_hash(row['password_hash'], current):
            return render_template('change_password.html', forced=forced, error="Your current password is not correct")
        elif new != confirm:
            return render_template('change_password.html', forced=forced, error="The new passwords do not match")
        elif new == current:
            return render_template('change_password.html', forced=forced, error="Your new password must be different from the old one")

        problem = password_problem(new)
        if problem:
            return render_template('change_password.html', forced=forced, error=problem)

        new_version = row['session_version'] + 1
        cursor.execute("UPDATE users SET password_hash = ?, must_change_password = 0, session_version = ? WHERE id = ?",
                       (generate_password_hash(new), new_version, user['id']))
        conn.commit()

        session['version'] = new_version
        flash("Your password was changed.")
        return redirect(url_for('dashboard'))

    else:
        return render_template('change_password.html', forced=forced)


@app.route("/profile/new", methods=['GET', 'POST'])
def new_profile():
    user = get_user()
    if user is None:
        return redirect(url_for('login'))

    if user['role'] != 'member' or user['first_name'] is not None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()
    groups = get_subject_groups(cursor)
    valid_codes = set()
    for subjects in groups.values():
        for code, label in subjects:
            valid_codes.add(code)

    if request.method == 'POST':
        first = request.form['first_name'].strip()
        last = request.form['last_name'].strip()
        subjects = set(request.form.getlist('subjects'))

        try:
            grade = int(request.form['grade_level'])
        except (KeyError, ValueError):
            return render_profile(groups, "Please select your grade")

        if not first or not last or len(first) > 50 or len(last) > 50:
            return render_profile(groups, "Please enter your first and last name (50 characters max each)")
        elif grade < MIN_GRADE or grade > MAX_GRADE:
            return render_profile(groups, "Please select a valid grade")
        elif subjects and grade < MIN_TUTOR_GRADE:
            return render_profile(groups, "Tutoring is open to grades " + str(MIN_TUTOR_GRADE) + " and up. Uncheck the subjects to continue.")
        elif not subjects <= valid_codes:
            return render_profile(groups, "One of the selected subjects is not valid")

        cursor.execute("INSERT INTO profiles (user_id, first_name, last_name, grade_level) VALUES (?, ?, ?, ?)",
                       (user['id'], first, last, grade))
        for code in sorted(subjects):
            cursor.execute("INSERT INTO tutor_subjects (user_id, subject_code) VALUES (?, ?)", (user['id'], code))
        conn.commit()

        return redirect(url_for('dashboard'))

    else:
        return render_profile(groups, None)


@app.route("/dashboard")
def dashboard():
    user = get_user()
    if user is None:
        return redirect(url_for('login'))

    if user['role'] == 'member' and user['first_name'] is None:
        return redirect(url_for('new_profile'))

    conn = connect()
    cursor = conn.cursor()
    now = int(time.time())

    cursor.execute("""
        SELECT subjects.label, tutor_subjects.status FROM tutor_subjects
        JOIN subjects ON subjects.code = tutor_subjects.subject_code
        WHERE tutor_subjects.user_id = ? ORDER BY subjects.group_name, subjects.sort_order
    """, (user['id'],))
    tutor_rows = cursor.fetchall()

    pending_count = 0
    open_reports = 0
    unconfirmed_count = 0
    hours = 0
    passed = []
    my_requests = []
    my_sessions = []
    cancelled_notices = []
    board_count = 0

    if user['role'] == 'teacher':
        cursor.execute("""
            SELECT COUNT(*) FROM tutor_subjects JOIN users ON users.id = tutor_subjects.user_id
            WHERE users.school_id = ? AND tutor_subjects.status = 'pending'
        """, (user['school_id'],))
        pending_count = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(*) FROM reports
            JOIN sessions ON sessions.id = reports.session_id
            JOIN requests ON requests.id = sessions.request_id
            WHERE requests.school_id = ? AND reports.status = 'open'
        """, (user['school_id'],))
        open_reports = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(*) FROM sessions
            JOIN requests ON requests.id = sessions.request_id
            WHERE requests.school_id = ? AND sessions.status = 'awaiting_confirmation'
        """, (user['school_id'],))
        unconfirmed_count = cursor.fetchone()[0]

    elif user['role'] == 'member':
        cursor.execute("""
            SELECT requests.id, requests.window_start, requests.window_end, requests.status,
                   subjects.label AS subject, locations.name AS location,
                   tutor_profiles.first_name AS tutor_first, tutor_profiles.grade_level AS tutor_grade,
                   sessions.id AS session_id, sessions.status AS session_status
            FROM requests
            JOIN subjects ON subjects.code = requests.subject_code
            JOIN locations ON locations.id = requests.location_id
            LEFT JOIN sessions ON sessions.request_id = requests.id
                 AND sessions.status IN ('scheduled', 'in_progress', 'awaiting_confirmation')
            LEFT JOIN profiles AS tutor_profiles ON tutor_profiles.user_id = sessions.tutor_user_id
            WHERE requests.student_user_id = ? AND (requests.status = 'open' OR sessions.id IS NOT NULL)
            ORDER BY requests.window_start
        """, (user['id'],))
        for row in cursor.fetchall():
            if row['status'] == 'open' and row['window_end'] <= now:
                passed.append(row)
            else:
                my_requests.append(row)

        cursor.execute("""
            SELECT sessions.id, sessions.status, requests.window_start, requests.window_end,
                   subjects.label AS subject, locations.name AS location,
                   student_profiles.first_name AS student_first, student_profiles.grade_level AS student_grade
            FROM sessions
            JOIN requests ON requests.id = sessions.request_id
            JOIN subjects ON subjects.code = requests.subject_code
            JOIN locations ON locations.id = requests.location_id
            JOIN profiles AS student_profiles ON student_profiles.user_id = sessions.student_user_id
            WHERE sessions.tutor_user_id = ?
              AND sessions.status IN ('scheduled', 'in_progress', 'awaiting_confirmation')
            ORDER BY requests.window_start
        """, (user['id'],))
        my_sessions = cursor.fetchall()

        can_tutor = False
        for row in tutor_rows:
            if row['status'] == 'approved':
                can_tutor = True
        if can_tutor:
            board_count = len(board_rows(cursor, user['id'], user['school_id'], now, None))

        cursor.execute("""
            SELECT subjects.label AS subject, canceller.first_name AS canceller
            FROM sessions
            JOIN requests ON requests.id = sessions.request_id
            JOIN subjects ON subjects.code = requests.subject_code
            LEFT JOIN profiles AS canceller ON canceller.user_id = sessions.cancelled_by
            WHERE sessions.status = 'cancelled' AND sessions.cancelled_at > ? AND sessions.cancelled_by != ?
              AND (sessions.tutor_user_id = ? OR sessions.student_user_id = ?)
            ORDER BY sessions.cancelled_at DESC
        """, (now - 2 * 86400, user['id'], user['id'], user['id']))
        cancelled_notices = cursor.fetchall()

        cursor.execute("SELECT hours FROM tutor_hours WHERE tutor_user_id = ?", (user['id'],))
        hours_row = cursor.fetchone()
        if hours_row:
            hours = hours_row['hours']

    can_tutor = False
    for row in tutor_rows:
        if row['status'] == 'approved':
            can_tutor = True

    return render_template('dashboard.html', user=user, tutor_rows=tutor_rows, pending_count=pending_count,
                           open_reports=open_reports, unconfirmed_count=unconfirmed_count, passed=passed,
                           my_requests=my_requests, my_sessions=my_sessions, cancelled_notices=cancelled_notices,
                           board_count=board_count, hours=hours, can_tutor=can_tutor, auto_days=AUTO_CONFIRM_DAYS)


@app.route("/teacher/tutors")
def teacher_tutors():
    user = get_teacher()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT tutor_subjects.user_id, profiles.first_name, profiles.last_name, profiles.grade_level,
               subjects.label, tutor_subjects.subject_code, tutor_subjects.status
        FROM tutor_subjects
        JOIN users ON users.id = tutor_subjects.user_id
        JOIN profiles ON profiles.user_id = users.id
        JOIN subjects ON subjects.code = tutor_subjects.subject_code
        WHERE users.school_id = ? AND users.removed_at IS NULL
        ORDER BY profiles.last_name, profiles.first_name, subjects.group_name, subjects.sort_order
    """, (user['school_id'],))

    people = {}
    for row in cursor.fetchall():
        if row['user_id'] not in people:
            people[row['user_id']] = {'user_id': row['user_id'], 'first': row['first_name'], 'last': row['last_name'],
                                      'grade': row['grade_level'], 'subjects': [], 'pending': 0}
        people[row['user_id']]['subjects'].append(row)
        if row['status'] == 'pending':
            people[row['user_id']]['pending'] += 1

    ordered = sorted(people.values(), key=lambda p: (p['pending'] == 0, p['last'], p['first']))
    return render_template('teacher_tutors.html', people=ordered)


@app.route("/teacher/tutors/review", methods=['POST'])
def review_tutor_subject():
    user = get_teacher()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    decision = request.form.get('decision')
    subject_code = request.form.get('subject_code', '')
    target_id = get_number('user_id')

    if target_id is None or decision not in ('approved', 'denied'):
        abort(400)

    member = get_school_member(cursor, user, target_id)
    if member['removed_at'] is not None:
        abort(404)

    if subject_code == '__all_pending__':
        cursor.execute("""
            SELECT tutor_subjects.subject_code, tutor_subjects.status, subjects.label FROM tutor_subjects
            JOIN subjects ON subjects.code = tutor_subjects.subject_code
            WHERE tutor_subjects.user_id = ? AND tutor_subjects.status = 'pending'
        """, (target_id,))
    else:
        cursor.execute("""
            SELECT tutor_subjects.subject_code, tutor_subjects.status, subjects.label FROM tutor_subjects
            JOIN subjects ON subjects.code = tutor_subjects.subject_code
            WHERE tutor_subjects.user_id = ? AND tutor_subjects.subject_code = ?
        """, (target_id, subject_code))
    targets = cursor.fetchall()

    if not targets:
        abort(404)

    label = member_label(cursor, target_id)
    for target in targets:
        if target['status'] != decision:
            cursor.execute("""
                UPDATE tutor_subjects SET status = ?, reviewed_by = ?, reviewed_at = strftime('%s','now')
                WHERE user_id = ? AND subject_code = ?
            """, (decision, user['id'], target_id, target['subject_code']))
            log_action(cursor, user, 'tutor_review', target_id, label,
                       target['label'] + ": " + target['status'] + " -> " + decision)
    conn.commit()

    flash("Saved.")
    return redirect(url_for('teacher_tutors'))


@app.route("/teacher/locations", methods=['GET', 'POST'])
def teacher_locations():
    user = get_teacher()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()
    error = None

    if request.method == 'POST':
        name = request.form['name'].strip()
        kind = request.form.get('kind', '')
        if request.form.get('requires_supervision'):
            supervised = 1
        else:
            supervised = 0

        if not name or len(name) > 80:
            error = "Please enter a location name (80 characters max)"
        elif kind not in LOCATION_KINDS:
            error = "Please choose a location type"
        else:
            cursor.execute("SELECT id FROM locations WHERE school_id = ? AND name = ?", (user['school_id'], name))
            if cursor.fetchone():
                error = "Your school already has a location with that name"
            else:
                cursor.execute("""
                    INSERT INTO locations (school_id, name, kind, requires_supervision, approved_by)
                    VALUES (?, ?, ?, ?, ?)
                """, (user['school_id'], name, kind, supervised, user['id']))
                if supervised:
                    staff = "yes"
                else:
                    staff = "no"
                log_action(cursor, user, 'location_added', None, name, LOCATION_KINDS[kind] + ", staff present: " + staff)
                conn.commit()
                flash("Added " + name + ".")
                return redirect(url_for('teacher_locations'))

    cursor.execute("SELECT * FROM locations WHERE school_id = ? ORDER BY active DESC, name", (user['school_id'],))
    locations = cursor.fetchall()
    return render_template('teacher_locations.html', locations=locations, kinds=LOCATION_KINDS, error=error, form=request.form)


@app.route("/teacher/locations/<int:location_id>/toggle", methods=['POST'])
def toggle_location(location_id):
    user = get_teacher()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    field = request.form.get('field')
    if field == 'active':
        cursor.execute("SELECT name, active AS value FROM locations WHERE id = ? AND school_id = ?", (location_id, user['school_id']))
    elif field == 'requires_supervision':
        cursor.execute("SELECT name, requires_supervision AS value FROM locations WHERE id = ? AND school_id = ?", (location_id, user['school_id']))
    else:
        abort(400)

    location = cursor.fetchone()
    if location is None:
        abort(404)

    new_value = 1 - location['value']
    if field == 'active':
        cursor.execute("UPDATE locations SET active = ? WHERE id = ?", (new_value, location_id))
        if location['value']:
            before = "Active"
        else:
            before = "Hidden"
        if new_value:
            after = "Active"
        else:
            after = "Hidden"
        details = "Visibility: " + before + " -> " + after
    else:
        cursor.execute("UPDATE locations SET requires_supervision = ? WHERE id = ?", (new_value, location_id))
        if location['value']:
            before = "yes"
        else:
            before = "no"
        if new_value:
            after = "yes"
        else:
            after = "no"
        details = "Staff present: " + before + " -> " + after

    log_action(cursor, user, 'location_changed', None, location['name'], details)
    conn.commit()
    return redirect(url_for('teacher_locations'))


@app.route("/teacher/students")
def teacher_students():
    user = get_teacher()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    q = request.args.get('q', '').strip().lower()
    like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"

    cursor.execute("""
        SELECT users.id, users.username, users.removed_at, users.must_change_password,
               profiles.first_name, profiles.last_name, profiles.grade_level
        FROM users LEFT JOIN profiles ON profiles.user_id = users.id
        WHERE users.school_id = ? AND users.role = 'member'
          AND (? = '' OR lower(coalesce(profiles.first_name, '') || ' ' || coalesce(profiles.last_name, '')) LIKE ? ESCAPE '\\'
               OR lower(users.username) LIKE ? ESCAPE '\\')
        ORDER BY users.removed_at IS NOT NULL, profiles.last_name, profiles.first_name, users.username
        LIMIT 200
    """, (user['school_id'], q, like, like))
    students = cursor.fetchall()
    return render_template('teacher_students.html', students=students, q=request.args.get('q', ''))


@app.route("/teacher/students/<int:user_id>/reset_password", methods=['POST'])
def reset_password(user_id):
    user = get_teacher()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    member = get_school_member(cursor, user, user_id)
    if member['removed_at'] is not None:
        abort(404)

    temp = make_temp_password()
    cursor.execute("""
        UPDATE users SET password_hash = ?, must_change_password = 1, session_version = session_version + 1
        WHERE id = ?
    """, (generate_password_hash(temp), user_id))
    label = member_label(cursor, user_id)
    log_action(cursor, user, 'password_reset', user_id, label, "Temporary password issued")
    conn.commit()

    response = app.make_response(render_template('teacher_password_reset.html', label=label, temp=temp))
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route("/teacher/students/<int:user_id>/remove", methods=['GET', 'POST'])
def remove_student(user_id):
    user = get_teacher()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    member = get_school_member(cursor, user, user_id)
    if member['removed_at'] is not None:
        return redirect(url_for('teacher_students'))

    label = member_label(cursor, user_id)

    if request.method == 'POST':
        reason = request.form['reason'].strip()
        if not reason or len(reason) > 200:
            return render_template('teacher_remove.html', label=label, member=member, error="Please give a short reason (200 characters max)")

        cursor.execute("""
            UPDATE users SET removed_at = strftime('%s','now'), removed_by = ?, session_version = session_version + 1
            WHERE id = ?
        """, (user['id'], user_id))
        cursor.execute("UPDATE requests SET status = 'cancelled' WHERE student_user_id = ? AND status = 'open'", (user_id,))
        open_cancelled = cursor.rowcount
        cursor.execute("""
            UPDATE requests SET status = 'open' WHERE id IN
            (SELECT request_id FROM sessions WHERE status = 'scheduled' AND tutor_user_id = ?)
        """, (user_id,))
        cursor.execute("""
            UPDATE requests SET status = 'cancelled' WHERE id IN
            (SELECT request_id FROM sessions WHERE status = 'scheduled' AND student_user_id = ?)
        """, (user_id,))
        cursor.execute("""
            UPDATE sessions SET status = 'cancelled', cancelled_by = ?, cancelled_at = strftime('%s','now')
            WHERE status = 'scheduled' AND (tutor_user_id = ? OR student_user_id = ?)
        """, (user['id'], user_id, user_id))
        sessions_cancelled = cursor.rowcount
        log_action(cursor, user, 'student_removed', user_id, label,
                   "Reason: " + reason + ". Cancelled " + str(open_cancelled) + " open request(s) and " + str(sessions_cancelled) + " upcoming session(s).")
        conn.commit()

        flash(label + " was removed. You can restore them from this page.")
        return redirect(url_for('teacher_students'))

    else:
        return render_template('teacher_remove.html', label=label, member=member)


@app.route("/teacher/students/<int:user_id>/restore", methods=['POST'])
def restore_student(user_id):
    user = get_teacher()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    member = get_school_member(cursor, user, user_id)
    if member['removed_at'] is None:
        return redirect(url_for('teacher_students'))

    label = member_label(cursor, user_id)
    cursor.execute("UPDATE users SET removed_at = NULL, removed_by = NULL WHERE id = ?", (user_id,))
    log_action(cursor, user, 'student_restored', user_id, label, None)
    conn.commit()

    flash(label + " was restored.")
    return redirect(url_for('teacher_students'))


@app.route("/teacher/activity")
def teacher_activity():
    user = get_teacher()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    try:
        page = max(1, int(request.args.get('page', '1')))
    except ValueError:
        page = 1

    cursor.execute("""
        SELECT audit_log.created_at, audit_log.action, audit_log.target_label, audit_log.details, users.username AS actor
        FROM audit_log JOIN users ON users.id = audit_log.actor_user_id
        WHERE audit_log.school_id = ? ORDER BY audit_log.id DESC LIMIT ? OFFSET ?
    """, (user['school_id'], AUDIT_PAGE_SIZE + 1, (page - 1) * AUDIT_PAGE_SIZE))
    rows = cursor.fetchall()

    return render_template('teacher_activity.html', rows=rows[:AUDIT_PAGE_SIZE], page=page,
                           has_next=len(rows) > AUDIT_PAGE_SIZE, labels=ACTION_LABELS)


@app.route("/teacher/reports")
def teacher_reports():
    user = get_teacher()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT reports.id, reports.reason, reports.status, reports.created_at, sessions.id AS session_id,
               subjects.label AS subject,
               tutor_profiles.first_name || ' ' || tutor_profiles.last_name AS tutor,
               student_profiles.first_name || ' ' || student_profiles.last_name AS student,
               reporter_profiles.first_name || ' ' || reporter_profiles.last_name AS reporter
        FROM reports
        JOIN sessions ON sessions.id = reports.session_id
        JOIN requests ON requests.id = sessions.request_id AND requests.school_id = ?
        JOIN subjects ON subjects.code = requests.subject_code
        JOIN profiles AS tutor_profiles ON tutor_profiles.user_id = sessions.tutor_user_id
        JOIN profiles AS student_profiles ON student_profiles.user_id = sessions.student_user_id
        JOIN profiles AS reporter_profiles ON reporter_profiles.user_id = reports.reporter_user_id
        ORDER BY reports.status = 'reviewed', reports.id DESC LIMIT 100
    """, (user['school_id'],))
    reports = cursor.fetchall()
    return render_template('teacher_reports.html', reports=reports)


@app.route("/teacher/reports/<int:report_id>/reviewed", methods=['POST'])
def review_report(report_id):
    user = get_teacher()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT reports.id, reports.status, subjects.label AS subject FROM reports
        JOIN sessions ON sessions.id = reports.session_id
        JOIN requests ON requests.id = sessions.request_id AND requests.school_id = ?
        JOIN subjects ON subjects.code = requests.subject_code
        WHERE reports.id = ?
    """, (user['school_id'], report_id))
    report = cursor.fetchone()

    if report is None:
        abort(404)

    if report['status'] == 'open':
        cursor.execute("UPDATE reports SET status = 'reviewed' WHERE id = ?", (report_id,))
        log_action(cursor, user, 'report_reviewed', None, report['subject'] + " session", "Report #" + str(report_id))
        conn.commit()

    return redirect(url_for('teacher_reports'))


@app.route("/teacher/sessions")
def teacher_sessions():
    user = get_teacher()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    status = request.args.get('status', '')
    if status not in SESSION_STATUSES:
        status = ''

    cursor.execute("""
        SELECT sessions.id, sessions.status, sessions.confirmed_how,
               COALESCE(sessions.start_time, requests.window_start) AS when_ts,
               COALESCE(sessions.counted_minutes, ROUND((sessions.end_time - sessions.start_time) / 60.0, 1)) AS minutes,
               subjects.label AS subject,
               tutor_profiles.first_name || ' ' || tutor_profiles.last_name AS tutor,
               student_profiles.first_name || ' ' || student_profiles.last_name AS student
        FROM sessions
        JOIN requests ON requests.id = sessions.request_id
        JOIN subjects ON subjects.code = requests.subject_code
        JOIN profiles AS tutor_profiles ON tutor_profiles.user_id = sessions.tutor_user_id
        JOIN profiles AS student_profiles ON student_profiles.user_id = sessions.student_user_id
        WHERE requests.school_id = ? AND (? = '' OR sessions.status = ?)
        ORDER BY when_ts DESC LIMIT 100
    """, (user['school_id'], status, status))
    sessions_list = cursor.fetchall()

    return render_template('teacher_sessions.html', sessions=sessions_list, status=status, statuses=SESSION_STATUSES)


@app.route("/teacher/sessions/<int:session_id>/edit", methods=['GET', 'POST'])
def edit_session(session_id):
    user = get_teacher()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT sessions.id, sessions.status, sessions.start_time, sessions.end_time, sessions.counted_minutes,
               sessions.confirmed_how, sessions.tutor_user_id, subjects.label AS subject,
               tutor_profiles.first_name || ' ' || tutor_profiles.last_name AS tutor,
               student_profiles.first_name || ' ' || student_profiles.last_name AS student
        FROM sessions
        JOIN requests ON requests.id = sessions.request_id AND requests.school_id = ?
        JOIN subjects ON subjects.code = requests.subject_code
        JOIN profiles AS tutor_profiles ON tutor_profiles.user_id = sessions.tutor_user_id
        JOIN profiles AS student_profiles ON student_profiles.user_id = sessions.student_user_id
        WHERE sessions.id = ?
    """, (user['school_id'], session_id))
    row = cursor.fetchone()

    if row is None:
        abort(404)

    if row['status'] not in ('awaiting_confirmation', 'completed'):
        flash("Only finished sessions can be edited.")
        return redirect(url_for('teacher_sessions'))

    measured = round((row['end_time'] - row['start_time']) / 60, 2)
    if row['status'] == 'completed':
        current = row['counted_minutes']
    else:
        current = measured

    cursor.execute("""
        SELECT session_edits.field, session_edits.old_value, session_edits.new_value, session_edits.reason,
               session_edits.edited_at, users.username
        FROM session_edits JOIN users ON users.id = session_edits.edited_by
        WHERE session_edits.session_id = ? ORDER BY session_edits.id DESC
    """, (session_id,))
    history = cursor.fetchall()

    if request.method == 'POST':
        reason = request.form['reason'].strip()
        try:
            minutes = round(float(request.form['minutes']), 2)
        except (KeyError, ValueError):
            minutes = None

        if minutes is None or minutes < 0 or minutes > MAX_SESSION_MINUTES:
            return render_template('teacher_session_edit.html', s=row, current=current, measured=measured, history=history,
                                   max_minutes=MAX_SESSION_MINUTES, error="Minutes must be a number from 0 to " + str(MAX_SESSION_MINUTES))
        elif not reason or len(reason) > 200:
            return render_template('teacher_session_edit.html', s=row, current=current, measured=measured, history=history,
                                   max_minutes=MAX_SESSION_MINUTES, error="Please give a short reason (200 characters max)")

        if row['status'] == 'awaiting_confirmation':
            cursor.execute("""
                UPDATE sessions SET status = 'completed', student_confirmed_at = ?, confirmed_how = 'teacher', counted_minutes = ?
                WHERE id = ?
            """, (int(time.time()), minutes, session_id))
            cursor.execute("""
                INSERT INTO session_edits (session_id, edited_by, field, old_value, new_value, reason)
                VALUES (?, ?, 'status', 'awaiting_confirmation', 'completed', ?)
            """, (session_id, user['id'], reason))
        elif minutes == current:
            flash("Nothing was changed.")
            return redirect(url_for('teacher_sessions'))
        else:
            cursor.execute("UPDATE sessions SET counted_minutes = ? WHERE id = ?", (minutes, session_id))

        cursor.execute("""
            INSERT INTO session_edits (session_id, edited_by, field, old_value, new_value, reason)
            VALUES (?, ?, 'counted_minutes', ?, ?, ?)
        """, (session_id, user['id'], str(current), str(minutes), reason))
        log_action(cursor, user, 'session_edited', row['tutor_user_id'], row['tutor'],
                   row['subject'] + " session: " + str(current) + " -> " + str(minutes) + " minutes. Reason: " + reason)
        conn.commit()

        flash("Session updated.")
        return redirect(url_for('teacher_sessions'))

    else:
        return render_template('teacher_session_edit.html', s=row, current=current, measured=measured, history=history,
                               max_minutes=MAX_SESSION_MINUTES)


def hours_rows(cursor, school_id):
    cursor.execute("""
        SELECT profiles.first_name, profiles.last_name, profiles.grade_level, users.removed_at,
               COUNT(sessions.id) AS session_count,
               ROUND(COALESCE(SUM(sessions.counted_minutes), 0) / 60.0, 2) AS hours
        FROM users
        JOIN profiles ON profiles.user_id = users.id
        LEFT JOIN sessions ON sessions.tutor_user_id = users.id AND sessions.status = 'completed'
        WHERE users.school_id = ? AND users.role = 'member'
        GROUP BY users.id
        HAVING session_count > 0
            OR EXISTS (SELECT 1 FROM tutor_subjects WHERE tutor_subjects.user_id = users.id AND tutor_subjects.status = 'approved')
        ORDER BY hours DESC, profiles.last_name, profiles.first_name
    """, (school_id,))
    return cursor.fetchall()


@app.route("/teacher/hours")
def teacher_hours():
    user = get_teacher()
    if user is None:
        return redirect(url_for('dashboard'))

    cursor = connect().cursor()
    return render_template('teacher_hours.html', tutors=hours_rows(cursor, user['school_id']))


@app.route("/teacher/hours.csv")
def teacher_hours_csv():
    user = get_teacher()
    if user is None:
        return redirect(url_for('dashboard'))

    cursor = connect().cursor()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["First name", "Last name", "Grade", "Sessions", "Hours", "Status"])
    for row in hours_rows(cursor, user['school_id']):
        if row['removed_at']:
            state = "Removed"
        else:
            state = "Active"
        writer.writerow([csv_safe(row['first_name']), csv_safe(row['last_name']), row['grade_level'],
                         row['session_count'], row['hours'], state])

    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=tutoring_hours.csv'})


@app.route("/requests/new", methods=['GET', 'POST'])
def new_request():
    user = get_member()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    groups = get_subject_groups(cursor)
    valid_subjects = set()
    for subjects in groups.values():
        for code, label in subjects:
            valid_subjects.add(code)

    cursor.execute("SELECT id, name, requires_supervision FROM locations WHERE school_id = ? AND active = 1 ORDER BY name",
                   (user['school_id'],))
    locations = cursor.fetchall()
    location_ids = [location['id'] for location in locations]

    if request.method == 'POST':
        now = int(time.time())
        subject = request.form.get('subject', '')
        location_id = get_number('location_id')

        if subject not in valid_subjects:
            return render_new_request(groups, locations, "Please choose a subject")
        elif location_id not in location_ids:
            return render_new_request(groups, locations, "Please choose a meeting location from the list")

        end = get_number('end_ts')
        problem, start = window_problem(get_number('start_ts'), end, now)
        if problem:
            return render_new_request(groups, locations, problem)

        cursor.execute("SELECT COUNT(*) FROM requests WHERE student_user_id = ? AND status = 'open' AND window_end > ?",
                       (user['id'], now))
        if cursor.fetchone()[0] >= MAX_OPEN_REQUESTS:
            return render_new_request(groups, locations, "You can have " + str(MAX_OPEN_REQUESTS) + " requests waiting at a time. Cancel one to make another.")

        cursor.execute("""
            INSERT INTO requests (school_id, student_user_id, subject_code, location_id, window_start, window_end)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user['school_id'], user['id'], subject, location_id, start, end))
        conn.commit()

        flash("Your request is posted. Approved tutors at your school can now see it.")
        return redirect(url_for('dashboard'))

    else:
        return render_new_request(groups, locations, None)


@app.route("/requests/<int:request_id>/cancel", methods=['POST'])
def cancel_request(request_id):
    user = get_member()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    cursor.execute("UPDATE requests SET status = 'cancelled' WHERE id = ? AND student_user_id = ? AND status = 'open'",
                   (request_id, user['id']))
    conn.commit()

    if cursor.rowcount == 0:
        abort(404)

    flash("Request removed.")
    return redirect(url_for('dashboard'))


@app.route("/requests/<int:request_id>/extend", methods=['POST'])
def extend_request(request_id):
    user = get_member()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()
    now = int(time.time())

    cursor.execute("SELECT window_start FROM requests WHERE id = ? AND student_user_id = ? AND status = 'open'",
                   (request_id, user['id']))
    row = cursor.fetchone()
    if row is None:
        abort(404)

    new_end = get_number('end_ts')
    problem, start = window_problem(row['window_start'], new_end, now)
    if problem:
        flash(problem)
        return redirect(url_for('dashboard'))

    cursor.execute("UPDATE requests SET window_start = ?, window_end = ? WHERE id = ?", (start, new_end, request_id))
    conn.commit()

    flash("Your request has been extended.")
    return redirect(url_for('dashboard'))


@app.route("/requests")
def request_board():
    user = get_member()
    if user is None:
        return redirect(url_for('dashboard'))

    cursor = connect().cursor()

    cursor.execute("""
        SELECT tutor_subjects.subject_code, subjects.label FROM tutor_subjects
        JOIN subjects ON subjects.code = tutor_subjects.subject_code
        WHERE tutor_subjects.user_id = ? AND tutor_subjects.status = 'approved'
        ORDER BY subjects.group_name, subjects.sort_order
    """, (user['id'],))
    approved = cursor.fetchall()

    selected = request.args.get('subject')
    if selected not in [row['subject_code'] for row in approved]:
        selected = None

    if approved:
        rows = board_rows(cursor, user['id'], user['school_id'], int(time.time()), selected)
    else:
        rows = []

    return render_template('request_board.html', rows=rows, approved=approved, selected=selected)


@app.route("/requests/<int:request_id>/accept", methods=['POST'])
def accept_request(request_id):
    user = get_member()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()
    now = int(time.time())

    cursor.execute("""
        SELECT requests.id, requests.status, requests.subject_code, requests.window_end, requests.student_user_id,
               locations.active AS location_active, users.removed_at AS student_removed
        FROM requests
        JOIN locations ON locations.id = requests.location_id
        JOIN users ON users.id = requests.student_user_id
        WHERE requests.id = ? AND requests.school_id = ?
    """, (request_id, user['school_id']))
    row = cursor.fetchone()

    if row is None:
        abort(404)
    if row['student_user_id'] == user['id']:
        abort(403)

    cursor.execute("SELECT 1 FROM tutor_subjects WHERE user_id = ? AND subject_code = ? AND status = 'approved'",
                   (user['id'], row['subject_code']))
    if not cursor.fetchone():
        abort(403)

    if row['status'] != 'open' or row['window_end'] <= now or row['student_removed'] or not row['location_active']:
        flash("Sorry, that request is no longer available.")
        return redirect(url_for('request_board'))

    cursor.execute("UPDATE requests SET status = 'accepted' WHERE id = ? AND status = 'open'", (request_id,))
    if cursor.rowcount == 0:
        flash("Someone else just accepted that request.")
        return redirect(url_for('request_board'))

    cursor.execute("INSERT INTO sessions (request_id, tutor_user_id, student_user_id) VALUES (?, ?, ?)",
                   (request_id, user['id'], row['student_user_id']))
    conn.commit()

    flash("You accepted the request. It is listed under Your tutoring sessions.")
    return redirect(url_for('dashboard'))


def load_session(cursor, user, session_id):
    cursor.execute("""
        SELECT sessions.*, requests.window_start, requests.window_end, subjects.label AS subject,
               locations.name AS location, locations.requires_supervision,
               other_profiles.first_name AS other_first, other_profiles.grade_level AS other_grade
        FROM sessions
        JOIN requests ON requests.id = sessions.request_id
        JOIN subjects ON subjects.code = requests.subject_code
        JOIN locations ON locations.id = requests.location_id
        JOIN profiles AS other_profiles ON other_profiles.user_id =
             CASE WHEN sessions.tutor_user_id = :me THEN sessions.student_user_id ELSE sessions.tutor_user_id END
        WHERE sessions.id = :sid AND requests.school_id = :school
          AND (sessions.tutor_user_id = :me OR sessions.student_user_id = :me)
    """, {'me': user['id'], 'sid': session_id, 'school': user['school_id']})
    row = cursor.fetchone()
    if row is None:
        abort(404)
    return row


def add_message(cursor, user, session_id, preset_id, detail_id, force):
    if not force:
        cursor.execute("SELECT COUNT(*) FROM session_messages WHERE session_id = ? AND sender_user_id = ?",
                       (session_id, user['id']))
        if cursor.fetchone()[0] >= MAX_MESSAGES_PER_SESSION:
            return False
    cursor.execute("INSERT INTO session_messages (session_id, sender_user_id, preset_id, detail_preset_id) VALUES (?, ?, ?, ?)",
                   (session_id, user['id'], preset_id, detail_id))
    return True


def preset_id_for(cursor, action_key):
    cursor.execute("SELECT id FROM message_presets WHERE action_key = ?", (action_key,))
    return cursor.fetchone()['id']


def get_detail_id(cursor):
    detail_id = get_number('detail_id')
    if detail_id is None:
        return None
    cursor.execute("SELECT 1 FROM message_presets WHERE id = ? AND kind = 'spot_detail' AND active = 1", (detail_id,))
    if cursor.fetchone():
        return detail_id
    return None


@app.route("/sessions/<int:session_id>")
def session_page(session_id):
    user = get_member()
    if user is None:
        return redirect(url_for('dashboard'))

    cursor = connect().cursor()
    now = int(time.time())

    sess = load_session(cursor, user, session_id)
    is_tutor = sess['tutor_user_id'] == user['id']

    cursor.execute("""
        SELECT session_messages.created_at, session_messages.sender_user_id, profiles.first_name,
               message_presets.text, detail_presets.text AS detail
        FROM session_messages
        JOIN profiles ON profiles.user_id = session_messages.sender_user_id
        JOIN message_presets ON message_presets.id = session_messages.preset_id
        LEFT JOIN message_presets AS detail_presets ON detail_presets.id = session_messages.detail_preset_id
        WHERE session_messages.session_id = ? ORDER BY session_messages.id
    """, (session_id,))
    messages = cursor.fetchall()

    cursor.execute("SELECT id, text FROM message_presets WHERE kind = 'status' AND action_key IS NULL AND active = 1 ORDER BY id")
    presets = cursor.fetchall()
    cursor.execute("SELECT id, text FROM message_presets WHERE kind = 'spot_detail' AND active = 1 ORDER BY id")
    spots = cursor.fetchall()

    elapsed = 0
    until_prompt = 0
    until_end = 0
    if sess['status'] == 'in_progress':
        elapsed = now - sess['start_time']
        until_prompt = sess['last_confirmed'] + CHECK_AFTER_SECONDS - now
        until_end = sess['last_confirmed'] + CHECK_AFTER_SECONDS + RESPONSE_WINDOW_SECONDS - now

    refresh = None
    if sess['status'] == 'scheduled':
        refresh = 20
    elif sess['status'] == 'in_progress' and not is_tutor:
        refresh = 30
    elif sess['status'] == 'awaiting_confirmation' and is_tutor:
        refresh = 30

    minutes = None
    if sess['end_time'] and sess['start_time']:
        minutes = round((sess['end_time'] - sess['start_time']) / 60, 1)

    can_check_in = sess['window_start'] - CHECKIN_LEAD_MINUTES * 60 <= now <= sess['window_end']

    return render_template('session.html', sess=sess, is_tutor=is_tutor, messages=messages, presets=presets,
                           spots=spots, elapsed=elapsed, until_prompt=until_prompt, until_end=until_end,
                           refresh=refresh, minutes=minutes, can_check_in=can_check_in, lead=CHECKIN_LEAD_MINUTES,
                           check_minutes=CHECK_AFTER_SECONDS // 60, auto_days=AUTO_CONFIRM_DAYS, me=user['id'])


@app.route("/sessions/<int:session_id>/here", methods=['POST'])
def session_here(session_id):
    user = get_member()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()
    now = int(time.time())

    sess = load_session(cursor, user, session_id)
    if sess['status'] != 'scheduled':
        flash("This session is no longer waiting to start.")
        return redirect(url_for('session_page', session_id=session_id))

    if sess['tutor_user_id'] != user['id']:
        if now < sess['window_start'] - CHECKIN_LEAD_MINUTES * 60:
            flash("Check-in opens " + str(CHECKIN_LEAD_MINUTES) + " minutes before your time window starts.")
            return redirect(url_for('session_page', session_id=session_id))
        elif now > sess['window_end']:
            flash("Your time window has ended. You can cancel this session.")
            return redirect(url_for('session_page', session_id=session_id))
        cursor.execute("UPDATE sessions SET student_here_at = ? WHERE id = ? AND student_here_at IS NULL", (now, session_id))

    if not add_message(cursor, user, session_id, preset_id_for(cursor, 'here'), get_detail_id(cursor), False):
        flash("You've reached the message limit for this session.")
    conn.commit()

    return redirect(url_for('session_page', session_id=session_id))


@app.route("/sessions/<int:session_id>/message", methods=['POST'])
def session_message(session_id):
    user = get_member()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    sess = load_session(cursor, user, session_id)
    if sess['status'] not in ('scheduled', 'in_progress'):
        flash("Messages can only be sent before or during a session.")
        return redirect(url_for('session_page', session_id=session_id))

    preset_id = get_number('preset_id')
    if preset_id is None:
        abort(400)

    cursor.execute("SELECT 1 FROM message_presets WHERE id = ? AND kind = 'status' AND action_key IS NULL AND active = 1", (preset_id,))
    if not cursor.fetchone():
        abort(400)

    if not add_message(cursor, user, session_id, preset_id, get_detail_id(cursor), False):
        flash("You've reached the message limit for this session.")
    conn.commit()

    return redirect(url_for('session_page', session_id=session_id))


@app.route("/sessions/<int:session_id>/cancel", methods=['POST'])
def cancel_session(session_id):
    user = get_member()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    sess = load_session(cursor, user, session_id)
    cursor.execute("""
        UPDATE sessions SET status = 'cancelled', cancelled_by = ?, cancelled_at = strftime('%s','now')
        WHERE id = ? AND status = 'scheduled'
    """, (user['id'], session_id))

    if cursor.rowcount == 0:
        flash("This session can't be cancelled anymore.")
        return redirect(url_for('session_page', session_id=session_id))

    add_message(cursor, user, session_id, preset_id_for(cursor, 'cancel'), None, True)

    if sess['tutor_user_id'] == user['id']:
        cursor.execute("UPDATE requests SET status = 'open' WHERE id = ?", (sess['request_id'],))
        flash("Session cancelled. The student's request is back on the board.")
    else:
        cursor.execute("UPDATE requests SET status = 'cancelled' WHERE id = ?", (sess['request_id'],))
        flash("Session cancelled.")
    conn.commit()

    return redirect(url_for('dashboard'))


@app.route("/sessions/<int:session_id>/start", methods=['POST'])
def start_session(session_id):
    user = get_member()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()
    now = int(time.time())

    sess = load_session(cursor, user, session_id)
    if sess['tutor_user_id'] != user['id']:
        abort(403)

    if sess['status'] != 'scheduled':
        flash("This session can't be started.")
        return redirect(url_for('session_page', session_id=session_id))
    elif sess['student_here_at'] is None:
        flash("The student needs to tap \"I'm here\" before you can start.")
        return redirect(url_for('session_page', session_id=session_id))

    cursor.execute("SELECT 1 FROM sessions WHERE tutor_user_id = ? AND status = 'in_progress'", (user['id'],))
    if cursor.fetchone():
        flash("You already have a session in progress. Finish it first.")
        return redirect(url_for('session_page', session_id=session_id))

    cursor.execute("UPDATE sessions SET status = 'in_progress', start_time = ?, last_confirmed = ? WHERE id = ? AND status = 'scheduled'",
                   (now, now, session_id))
    conn.commit()

    return redirect(url_for('session_page', session_id=session_id))


@app.route("/sessions/<int:session_id>/continue", methods=['POST'])
def continue_session(session_id):
    user = get_member()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    sess = load_session(cursor, user, session_id)
    if sess['tutor_user_id'] != user['id']:
        abort(403)

    cursor.execute("UPDATE sessions SET last_confirmed = ? WHERE id = ? AND status = 'in_progress'", (int(time.time()), session_id))
    conn.commit()

    return redirect(url_for('session_page', session_id=session_id))


@app.route("/sessions/<int:session_id>/stop", methods=['POST'])
def stop_session(session_id):
    user = get_member()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    sess = load_session(cursor, user, session_id)
    if sess['tutor_user_id'] != user['id']:
        abort(403)

    cursor.execute("UPDATE sessions SET status = 'awaiting_confirmation', end_time = ? WHERE id = ? AND status = 'in_progress'",
                   (int(time.time()), session_id))
    conn.commit()

    if cursor.rowcount:
        flash("Session ended. It counts toward your hours once the student confirms it.")
    return redirect(url_for('session_page', session_id=session_id))


@app.route("/sessions/<int:session_id>/confirm", methods=['POST'])
def confirm_session(session_id):
    user = get_member()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    sess = load_session(cursor, user, session_id)
    if sess['student_user_id'] != user['id']:
        abort(403)

    cursor.execute("""
        UPDATE sessions SET status = 'completed', student_confirmed_at = ?, confirmed_how = 'student',
               counted_minutes = ROUND((end_time - start_time) / 60.0, 2)
        WHERE id = ? AND status = 'awaiting_confirmation'
    """, (int(time.time()), session_id))
    conn.commit()

    if cursor.rowcount:
        flash("Thanks! Your confirmation was saved.")
    return redirect(url_for('dashboard'))


@app.route("/sessions/<int:session_id>/report", methods=['POST'])
def report_session(session_id):
    user = get_member()
    if user is None:
        return redirect(url_for('dashboard'))

    conn = connect()
    cursor = conn.cursor()

    load_session(cursor, user, session_id)

    reason = request.form['reason'].strip()
    if not reason or len(reason) > 300:
        flash("Please describe the problem in 300 characters or less.")
        return redirect(url_for('session_page', session_id=session_id))

    cursor.execute("SELECT 1 FROM reports WHERE session_id = ? AND reporter_user_id = ? AND status = 'open'", (session_id, user['id']))
    if cursor.fetchone():
        flash("You already sent a report for this session. A teacher will look at it.")
        return redirect(url_for('session_page', session_id=session_id))

    cursor.execute("INSERT INTO reports (session_id, reporter_user_id, reason) VALUES (?, ?, ?)", (session_id, user['id'], reason))
    conn.commit()

    flash("Your report was sent to the teachers at your school.")
    return redirect(url_for('session_page', session_id=session_id))


if __name__ == "__main__":
    app.run(debug=True)
