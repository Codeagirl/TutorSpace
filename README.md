# Peer Tutoring

Tutor space is a website that allows tutors to connnect people who are struggling. The websites communication and tutoring locations are managed by an admin. To be a tutor you must be in at least 10th grade, and max 12th grade. A student can not be in a grade lower then 6th, because it was designed for middle to high school students.

## What is in this folder

- `app.py` - the website
- `manage.py` - admin commands (create schools, reset passwords, and so on)
- `schema.sql` - the database layout
- `requirements.txt` - what to install
- `templates/` and `static/` - the pages and the styling

## Run it on your own computer

You need Python 3.9 or newer (python.org/downloads). On Windows, tick "Add Python to PATH" when installing.

1. Open a terminal (Command Prompt, PowerShell, or Terminal) and go to this folder:

2. Create a private Python environment and turn it on.

   Windows:

       python -m venv venv
       venv\Scripts\activate

   Mac or Linux:

       python3 -m venv venv
       source venv/bin/activate

3. Install what the app needs:

       pip install -r requirements.txt
    
    This is for those who might not understand code are able to set up the server, it is installing flask.

4. Create a secret key. This signs everyone's login. Make one:

       python -c "import secrets; print(secrets.token_hex(32))"

   Then set it. Use the same key every time you start the app, or everyone gets logged out.

   Windows (Command Prompt):

       set SECRET_KEY=paste-your-key-here

   Windows (PowerShell):

       $env:SECRET_KEY="paste-your-key-here"

   Mac or Linux:

       export SECRET_KEY=paste-your-key-here

5. Create the database (do this once):

       python manage.py init

6. Create your first school. This prints two codes:

       python manage.py create-school "Lincoln High School"

   The student and tutor code goes to students. The teacher code goes only to the admin of who is managing tutoring.

7. Start the website:

       python app.py

   Open http://127.0.0.1:5000 in your browser.

## First-time setup in the browser

1. Click Sign Up and use the **teacher code**. This makes a teacher account.
2. Go to Meeting Locations and add the places students may meet (school library, cafeteria, a public library, and so on). Students can only pick from this list.
3. Students sign up with the **student code** and fill in their profile. Students in grade 10 and up can choose subjects they want to tutor.
4. Go to Tutor Approvals and approve the subjects each tutor is allowed to teach. Tutors can only accept requests for approved subjects.

## How it works

- A student posts a request (subject, time window, location). Approved tutors at the same school see it and one accepts.
- The student taps "I'm here" when they arrive. The tutor can start the timer only after that.
- Every 30 minutes the tutor is asked "Still tutoring?". If they do not answer within 5 minutes, the session ends and only the time up to that check counts.
- The student confirms the session. If they do nothing for 3 days it is confirmed automatically, unless a report is open on it.
- Teachers can edit the minutes of any finished session, or confirm one for a student. Every edit needs a reason and is saved in the Activity Log.
- Messages between students are limited to preset phrases only.

## Admin commands

Run these from this folder with the environment turned on:

    python manage.py list-schools
    python manage.py create-school "School Name"
    python manage.py new-codes "School Name"
    python manage.py reset-password username
    python manage.py deactivate-user username

`new-codes` changes the codes for new sign-ups only. It does not affect existing accounts. Use it if a teacher code gets shared by accident.

`reset-password` works on any account, including teachers. The person must choose a new password at their next login.

## Settings you can change

Near the top of `app.py`:

- `MIN_TUTOR_GRADE` - lowest grade allowed to tutor
- `MAX_OPEN_REQUESTS` - requests one student can have waiting
- `CHECK_AFTER_SECONDS` and `RESPONSE_WINDOW_SECONDS` - the "Still tutoring?" timing
- `AUTO_CONFIRM_DAYS` - days before an unconfirmed session confirms itself
- `MAX_FAILED_LOGINS` and `LOCKOUT_SECONDS` - login attempt limit

The site name shown on the home page is "Peer Tutoring". Change it by setting `SITE_NAME` the same way you set `SECRET_KEY`.

## Before real students use it

`python app.py` is for testing on your own computer only. To put it on the internet:

1. Host it on a server or hosting service that supports Python, and use HTTPS. Never run `python app.py` on a public server.
2. Run it with a production server instead. On Windows: `pip install waitress` then `waitress-serve --port=8000 app:app`. On Linux or Mac: `pip install gunicorn` then `gunicorn -w 1 -b 0.0.0.0:8000 app:app`. Keep it to one worker, because the login attempt limit is remembered in memory.
3. Set `SECRET_KEY` on the server.
4. Back up the file `tutoring.db` regularly. It holds everything.
5. Check with your school or district about rules for student data and for students meeting each other before you launch.

## Starting over

Stop the app, delete `tutoring.db`, and run `python manage.py init` again. This erases all data.
