import sqlite3
import os

DATABASE_NAME = "attendance.db"


def get_db_connection():
    """Establishes and returns a database connection."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row  # This allows us to access columns by name
    return conn


def execute_query(query, params=()):
    """Executes an INSERT, UPDATE, or DELETE query and commits the changes."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(query, params)
        conn.commit()
        return cursor.lastrowid  # Returns the ID of the last inserted row
    except sqlite3.IntegrityError as e:
        # Handle unique constraint violations or other integrity errors
        raise ValueError(f"Database Integrity Error: {e}")
    except sqlite3.Error as e:
        # Catch other SQLite errors
        raise RuntimeError(f"Database Error: {e}")
    finally:
        conn.close()


def fetch_one(query, params=()):
    """Executes a SELECT query and fetches a single row."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(query, params)
        return cursor.fetchone()
    except sqlite3.Error as e:
        raise RuntimeError(f"Database Error: {e}")
    finally:
        conn.close()


def fetch_all(query, params=()):
    """Executes a SELECT query and fetches all rows."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(query, params)
        return cursor.fetchall()
    except sqlite3.Error as e:
        raise RuntimeError(f"Database Error: {e}")
    finally:
        conn.close()


def create_tables():
    """Creates all necessary tables in the database if they don't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users Table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS Users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at INTEGER DEFAULT (strftime('%s', 'now'))
        );
    """
    )

    # Courses Table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS Courses (
            course_id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            join_code TEXT NOT NULL UNIQUE,
            geolocation_latitude REAL,
            geolocation_longitude REAL,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            late_threshold_minutes INTEGER DEFAULT 10,
            present_threshold_minutes INTEGER DEFAULT 0,
            FOREIGN KEY (host_id) REFERENCES Users(user_id) ON DELETE CASCADE
        );
    """
    )

    # Enrollments Table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS Enrollments (
            user_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,
            enrolled_at INTEGER DEFAULT (strftime('%s', 'now')),
            PRIMARY KEY (user_id, course_id),
            FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE,
            FOREIGN KEY (course_id) REFERENCES Courses(course_id) ON DELETE CASCADE
        );
    """
    )

    # Sessions Table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS Sessions (
            session_id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_id INTEGER NOT NULL,
            start_time INTEGER NOT NULL,
            end_time INTEGER,
            FOREIGN KEY (course_id) REFERENCES Courses(course_id) ON DELETE CASCADE
        );
    """
    )

    # Attendances Table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS Attendances (
            attendance_id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            status TEXT NOT NULL, -- 'Present', 'Late', 'Absent'
            late_minutes INTEGER,
            user_geolocation_latitude REAL,
            user_geolocation_longitude REAL,
            proof_base64 BLOB,
            joined_at INTEGER DEFAULT (strftime('%s', 'now')),
            UNIQUE (session_id, user_id),
            FOREIGN KEY (session_id) REFERENCES Sessions(session_id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE
        );
    """
    )

    conn.commit()
    conn.close()
    print(f"Database '{DATABASE_NAME}' and tables created/verified.")


def initialize_db():
    """Initializes the database by creating tables."""
    create_tables()


if __name__ == "__main__":
    initialize_db()
