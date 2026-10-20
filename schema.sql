CREATE TABLE schools (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE,
    join_code     TEXT NOT NULL UNIQUE,
    teacher_code  TEXT NOT NULL UNIQUE,
    created_at    INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('member','teacher','admin')),
    school_id      INTEGER REFERENCES schools(id),
    must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0,1)),
    session_version      INTEGER NOT NULL DEFAULT 0,
    removed_at     INTEGER,
    removed_by     INTEGER REFERENCES users(id),
    created_at     INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    CHECK (role = 'admin' OR school_id IS NOT NULL)
);

CREATE TABLE profiles (
    user_id      INTEGER PRIMARY KEY REFERENCES users(id),
    first_name   TEXT NOT NULL,
    last_name    TEXT NOT NULL,
    grade_level  INTEGER NOT NULL CHECK (grade_level BETWEEN 6 AND 12)
);

CREATE TABLE subjects (
    code         TEXT PRIMARY KEY,
    label        TEXT NOT NULL,
    group_name   TEXT NOT NULL,
    sort_order   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE tutor_subjects (
    user_id       INTEGER NOT NULL REFERENCES users(id),
    subject_code  TEXT NOT NULL REFERENCES subjects(code),
    status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied')),
    reviewed_by   INTEGER REFERENCES users(id),
    reviewed_at   INTEGER,
    PRIMARY KEY (user_id, subject_code)
);

CREATE TABLE locations (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    school_id             INTEGER NOT NULL REFERENCES schools(id),
    name                  TEXT NOT NULL,
    kind                  TEXT NOT NULL CHECK (kind IN ('school_library','classroom','cafeteria','public_library','other')),
    requires_supervision  INTEGER NOT NULL DEFAULT 0 CHECK (requires_supervision IN (0,1)),
    active                INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
    approved_by           INTEGER REFERENCES users(id),
    UNIQUE (school_id, name)
);

CREATE TABLE requests (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    school_id        INTEGER NOT NULL REFERENCES schools(id),
    student_user_id  INTEGER NOT NULL REFERENCES users(id),
    subject_code     TEXT NOT NULL REFERENCES subjects(code),
    location_id      INTEGER NOT NULL REFERENCES locations(id),
    window_start     INTEGER NOT NULL,
    window_end       INTEGER NOT NULL,
    status           TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','accepted','cancelled','expired')),
    created_at       INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    CHECK (window_end > window_start)
);

CREATE TABLE sessions (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id            INTEGER NOT NULL REFERENCES requests(id),
    tutor_user_id         INTEGER NOT NULL REFERENCES users(id),
    student_user_id       INTEGER NOT NULL REFERENCES users(id),
    status                TEXT NOT NULL DEFAULT 'scheduled'
                          CHECK (status IN ('scheduled','in_progress','awaiting_confirmation','completed','cancelled')),
    start_time            INTEGER,
    end_time              INTEGER,
    last_confirmed        INTEGER,
    student_confirmed_at  INTEGER,
    counted_minutes       REAL,
    cancelled_by          INTEGER REFERENCES users(id),
    cancelled_at          INTEGER,
    confirmed_how         TEXT CHECK (confirmed_how IN ('student','auto','teacher')),
    student_here_at       INTEGER,
    created_at            INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    CHECK (tutor_user_id <> student_user_id)
);

CREATE TABLE message_presets (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    kind      TEXT NOT NULL CHECK (kind IN ('status','spot_detail')),
    action_key TEXT UNIQUE CHECK (action_key IN ('here','cancel')),
    text      TEXT NOT NULL UNIQUE,
    active    INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1))
);

CREATE TABLE session_messages (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id         INTEGER NOT NULL REFERENCES sessions(id),
    sender_user_id     INTEGER NOT NULL REFERENCES users(id),
    preset_id          INTEGER NOT NULL REFERENCES message_presets(id),
    detail_preset_id   INTEGER REFERENCES message_presets(id),
    created_at         INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE session_edits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id),
    edited_by   INTEGER NOT NULL REFERENCES users(id),
    field       TEXT NOT NULL,
    old_value   TEXT,
    new_value   TEXT,
    reason      TEXT NOT NULL,
    edited_at   INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE reports (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id        INTEGER NOT NULL REFERENCES sessions(id),
    reporter_user_id  INTEGER NOT NULL REFERENCES users(id),
    reason            TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','reviewed')),
    created_at        INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE audit_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    school_id      INTEGER NOT NULL REFERENCES schools(id),
    actor_user_id  INTEGER NOT NULL REFERENCES users(id),
    action         TEXT NOT NULL,
    target_user_id INTEGER REFERENCES users(id),
    target_label   TEXT,
    details        TEXT,
    created_at     INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE UNIQUE INDEX one_live_session_per_request ON sessions(request_id) WHERE status != 'cancelled';
CREATE INDEX idx_audit_school     ON audit_log(school_id, id);
CREATE INDEX idx_requests_board   ON requests(school_id, status, subject_code);
CREATE INDEX idx_sessions_tutor   ON sessions(tutor_user_id, status);
CREATE INDEX idx_tutor_subj_code  ON tutor_subjects(subject_code, status);

CREATE VIEW tutor_hours AS
SELECT tutor_user_id, ROUND(SUM(counted_minutes) / 60.0, 2) AS hours
FROM sessions
WHERE status = 'completed' AND student_confirmed_at IS NOT NULL
GROUP BY tutor_user_id;
