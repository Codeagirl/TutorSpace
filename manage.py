import sqlite3
import sys
import os
import secrets
from werkzeug.security import generate_password_hash

DATABASE = 'tutoring.db'
CODE_LETTERS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
PASSWORD_LETTERS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

SUBJECTS = [
    ("math6", "Math 6", "Math"),
    ("math7", "Math 7", "Math"),
    ("math8", "Math 8", "Math"),
    ("algebra", "Algebra", "Math"),
    ("geometry", "Geometry", "Math"),
    ("algebra2", "Algebra 2", "Math"),
    ("english6", "English 6", "English"),
    ("english7", "English 7", "English"),
    ("english8", "English 8", "English"),
    ("english9", "English 9", "English"),
    ("english10", "English 10", "English"),
    ("english11", "English 11", "English"),
    ("history6", "History 6", "History"),
    ("history7", "History 7", "History"),
    ("history8", "History 8", "History"),
    ("history9", "History 9", "History"),
    ("history10", "History 10", "History"),
    ("history11", "History 11", "History"),
    ("science6", "Science 6", "Science"),
    ("science7", "Science 7", "Science"),
    ("science8", "Science 8", "Science"),
    ("biology", "Biology", "Science"),
    ("earth_science", "Earth Science", "Science"),
    ("chemistry", "Chemistry", "Science"),
    ("spanish_1-A", "Spanish 1-A", "Spanish"),
    ("spanish_1-B", "Spanish 1-B", "Spanish"),
    ("spanish_2", "Spanish 2", "Spanish"),
    ("spanish_3", "Spanish 3", "Spanish"),
    ("spanish_4", "Spanish 4", "Spanish"),
]

PRESETS = [
    ("status", "I'm here", "here"),
    ("status", "I need to cancel", "cancel"),
    ("status", "Running about 5 minutes late", None),
    ("status", "Can we move to a different time?", None),
    ("status", "I can't find you", None),
    ("spot_detail", "Front desk", None),
    ("spot_detail", "Table by the windows", None),
    ("spot_detail", "In the classroom", None),
]


def connect():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def new_code():
    return "".join(secrets.choice(CODE_LETTERS) for i in range(6))


def init():
    if os.path.exists(DATABASE):
        print(DATABASE + " already exists. Delete it first if you want to start over.")
        return

    conn = connect()
    with open("schema.sql") as f:
        conn.executescript(f.read())

    for number, subject in enumerate(SUBJECTS):
        conn.execute("INSERT INTO subjects (code, label, group_name, sort_order) VALUES (?, ?, ?, ?)",
                     (subject[0], subject[1], subject[2], number))

    for preset in PRESETS:
        conn.execute("INSERT INTO message_presets (kind, text, action_key) VALUES (?, ?, ?)", preset)

    conn.commit()
    print("Created " + DATABASE)


def create_school(name):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM schools WHERE name = ?", (name,))
    if cursor.fetchone():
        print("A school with that name already exists.")
        return

    join_code = new_code()
    teacher_code = new_code()
    while join_code == teacher_code:
        teacher_code = new_code()

    cursor.execute("INSERT INTO schools (name, join_code, teacher_code) VALUES (?, ?, ?)", (name, join_code, teacher_code))
    conn.commit()

    print("School: " + name)
    print("  Student and tutor code: " + join_code)
    print("  Teacher code:           " + teacher_code)


def list_schools():
    cursor = connect().cursor()
    cursor.execute("SELECT name, join_code, teacher_code FROM schools ORDER BY name")
    schools = cursor.fetchall()

    if not schools:
        print("No schools yet.")
    for school in schools:
        print(school['name'] + "  |  students: " + school['join_code'] + "  |  teachers: " + school['teacher_code'])


def new_codes(name):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM schools WHERE name = ?", (name,))
    school = cursor.fetchone()
    if school is None:
        print("No school with that name. Run list-schools to see the names.")
        return

    join_code = new_code()
    teacher_code = new_code()
    while join_code == teacher_code:
        teacher_code = new_code()

    cursor.execute("UPDATE schools SET join_code = ?, teacher_code = ? WHERE id = ?", (join_code, teacher_code, school['id']))
    conn.commit()

    print("New codes for " + name)
    print("  Student and tutor code: " + join_code)
    print("  Teacher code:           " + teacher_code)
    print("Existing accounts are not affected.")


def reset_password(username):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if user is None:
        print("No account with that username.")
        return

    while True:
        temp = "".join(secrets.choice(PASSWORD_LETTERS) for i in range(10))
        if any(char.isdigit() for char in temp) and any(char.isupper() for char in temp):
            break

    cursor.execute("""
        UPDATE users SET password_hash = ?, must_change_password = 1, session_version = session_version + 1
        WHERE id = ?
    """, (generate_password_hash(temp), user['id']))
    conn.commit()

    print("Temporary password for " + username + ": " + temp)
    print("They will be asked to choose a new password when they log in.")


def deactivate_user(username):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("SELECT id, role FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if user is None:
        print("No account with that username.")
        return

    cursor.execute("""
        UPDATE users SET removed_at = strftime('%s','now'), session_version = session_version + 1
        WHERE id = ? AND removed_at IS NULL
    """, (user['id'],))
    conn.commit()

    if cursor.rowcount:
        print(username + " can no longer log in.")
    else:
        print(username + " was already deactivated.")


def show_help():
    print("Commands:")
    print("  python manage.py init")
    print("  python manage.py create-school \"School Name\"")
    print("  python manage.py list-schools")
    print("  python manage.py new-codes \"School Name\"")
    print("  python manage.py reset-password username")
    print("  python manage.py deactivate-user username")


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else ""

    if command == "init":
        init()
    elif command == "create-school" and len(sys.argv) == 3:
        create_school(sys.argv[2])
    elif command == "list-schools":
        list_schools()
    elif command == "new-codes" and len(sys.argv) == 3:
        new_codes(sys.argv[2])
    elif command == "reset-password" and len(sys.argv) == 3:
        reset_password(sys.argv[2])
    elif command == "deactivate-user" and len(sys.argv) == 3:
        deactivate_user(sys.argv[2])
    else:
        show_help()
