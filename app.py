from flask import Flask, jsonify, request, session, redirect, url_for, g
from werkzeug.security import generate_password_hash, check_password_hash
from database import (
    get_db_connection,
    initialize_db,
    execute_query,
    fetch_one,
    fetch_all,
)
import os
import time
from functools import wraps
import math

app = Flask(__name__)
app.secret_key = os.urandom(24)  # CHANGE THIS IN PRODUCTION!

# Initialize the database when the app starts
with app.app_context():
    initialize_db()


# --- Utility Functions ---
def login_required(f):
    """Decorator to ensure a user is logged in."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized, please log in."}), 401
        g.user_id = session["user_id"]
        g.user_name = session["user_name"]
        g.user_email = session["user_email"]
        return f(*args, **kwargs)

    return decorated_function


def haversine_distance(lat1, lon1, lat2, lon2):
    """
    Calculate the distance between two points on Earth using the Haversine formula.
    Returns distance in kilometers.
    """
    R = 6371  # Radius of Earth in kilometers

    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)

    dlon = lon2_rad - lon1_rad
    dlat = lat2_rad - lat1_rad

    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    distance = R * c
    return distance


# --- General Routes ---
@app.route("/")
def home():
    return jsonify({"message": "Welcome to the Attendance App API!"})


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.pop("user_id", None)
    session.pop("user_name", None)
    session.pop("user_email", None)
    return jsonify({"message": "Logged out successfully."}), 200


@app.route("/auth/status", methods=["GET"])
def auth_status():
    """
    Checks if a user is logged in and returns their basic info.
    """
    if "user_id" in session:
        return (
            jsonify(
                {
                    "isLoggedIn": True,
                    "user": {
                        "id": session["user_id"],
                        "name": session["user_name"],
                        "email": session["user_email"],
                    },
                }
            ),
            200,
        )
    else:
        return jsonify({"isLoggedIn": False}), 200


# --- User Management (CRUD for Users) ---


@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if not all([name, email, password]):
        return jsonify({"error": "Name, email, and password are required."}), 400

    hashed_password = generate_password_hash(password)

    try:
        query = "INSERT INTO Users (name, email, password_hash) VALUES (?, ?, ?)"
        user_id = execute_query(query, (name, email, hashed_password))
        return (
            jsonify(
                {
                    "message": "User registered successfully.",
                    "user_id": user_id,
                    "name": name,
                    "email": email,
                }
            ),
            201,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 409
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


@app.route("/signin", methods=["POST"])
def signin():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not all([email, password]):
        return jsonify({"error": "Email and password are required."}), 400

    user = fetch_one(
        "SELECT user_id, name, email, password_hash FROM Users WHERE email = ?",
        (email,),
    )

    if user and check_password_hash(user["password_hash"], password):
        session["user_id"] = user["user_id"]
        session["user_name"] = user["name"]
        session["user_email"] = user["email"]
        return (
            jsonify(
                {
                    "message": "Logged in successfully.",
                    "user_id": user["user_id"],
                    "name": user["name"],
                    "email": user["email"],
                }
            ),
            200,
        )
    else:
        return jsonify({"error": "Invalid email or password."}), 401


@app.route("/users/<int:user_id>", methods=["GET"])
@login_required
def get_user(user_id):
    if g.user_id != user_id:
        return (
            jsonify({"error": "Access denied. You can only view your own profile."}),
            403,
        )

    user = fetch_one(
        "SELECT user_id, name, email, created_at FROM Users WHERE user_id = ?",
        (user_id,),
    )
    if user:
        return jsonify(dict(user)), 200
    else:
        return jsonify({"error": "User not found."}), 404


@app.route("/users/<int:user_id>", methods=["PUT"])
@login_required
def update_user(user_id):
    if g.user_id != user_id:
        return (
            jsonify({"error": "Access denied. You can only update your own profile."}),
            403,
        )

    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    updates = []
    params = []

    if name:
        updates.append("name = ?")
        params.append(name)
        session["user_name"] = name
    if email:
        existing_user_with_email = fetch_one(
            "SELECT user_id FROM Users WHERE email = ? AND user_id != ?",
            (email, user_id),
        )
        if existing_user_with_email:
            return jsonify({"error": "Email already in use by another user."}), 409
        updates.append("email = ?")
        params.append(email)
        session["user_email"] = email
    if password:
        hashed_password = generate_password_hash(password)
        updates.append("password_hash = ?")
        params.append(hashed_password)

    if not updates:
        return jsonify({"message": "No data provided for update."}), 200

    params.append(user_id)
    query = f"UPDATE Users SET {', '.join(updates)} WHERE user_id = ?"

    try:
        execute_query(query, tuple(params))
        return jsonify({"message": "User updated successfully."}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 409
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


@app.route("/users/<int:user_id>", methods=["DELETE"])
@login_required
def delete_user(user_id):
    if g.user_id != user_id:
        return (
            jsonify({"error": "Access denied. You can only delete your own profile."}),
            403,
        )

    data = request.get_json()
    password_confirmation = data.get("password_confirmation")

    if not password_confirmation:
        return (
            jsonify({"error": "Password confirmation is required to delete account."}),
            400,
        )

    user = fetch_one("SELECT password_hash FROM Users WHERE user_id = ?", (user_id,))
    if not user or not check_password_hash(
        user["password_hash"], password_confirmation
    ):
        return jsonify({"error": "Incorrect password confirmation."}), 401

    try:
        execute_query("DELETE FROM Users WHERE user_id = ?", (user_id,))
        session.pop("user_id", None)
        session.pop("user_name", None)
        session.pop("user_email", None)
        return jsonify({"message": "User deleted successfully."}), 200
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


# --- Course Management (CRUD for Courses) ---


@app.route("/courses", methods=["POST"])
@login_required
def create_course():
    data = request.get_json()
    name = data.get("name")
    join_code = data.get("join_code")
    geolocation_latitude = data.get("geolocation_latitude")
    geolocation_longitude = data.get("geolocation_longitude")
    late_threshold_minutes = data.get("late_threshold_minutes", 10)
    present_threshold_minutes = data.get("present_threshold_minutes", 0)

    if not all([name, join_code]):
        return jsonify({"error": "Course name and join code are required."}), 400

    host_id = g.user_id

    try:
        query = """
            INSERT INTO Courses (
                host_id, name, join_code, geolocation_latitude, geolocation_longitude,
                late_threshold_minutes, present_threshold_minutes
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        course_id = execute_query(
            query,
            (
                host_id,
                name,
                join_code,
                geolocation_latitude,
                geolocation_longitude,
                late_threshold_minutes,
                present_threshold_minutes,
            ),
        )
        return (
            jsonify(
                {
                    "message": "Course created successfully.",
                    "course_id": course_id,
                    "name": name,
                    "host_id": host_id,
                }
            ),
            201,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 409
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


@app.route("/courses", methods=["GET"])
@login_required
def get_courses():
    query = """
        SELECT DISTINCT C.*, U.name AS host_name FROM Courses C
        JOIN Users U ON C.host_id = U.user_id
        LEFT JOIN Enrollments E ON C.course_id = E.course_id
        WHERE C.host_id = ? OR E.user_id = ?
    """
    courses = fetch_all(query, (g.user_id, g.user_id))

    if courses:
        return jsonify([dict(course) for course in courses]), 200
    else:
        return (
            jsonify(
                {
                    "message": "No courses found for this user (as host or attendee). Please create or join one."
                }
            ),
            404,
        )


@app.route("/courses/<int:course_id>", methods=["GET"])
@login_required
def get_course(course_id):
    course = fetch_one(
        "SELECT C.*, U.name AS host_name FROM Courses C JOIN Users U ON C.host_id = U.user_id WHERE course_id = ?",
        (course_id,),
    )
    if not course:
        return jsonify({"error": "Course not found."}), 404

    is_host = course["host_id"] == g.user_id
    is_enrolled = fetch_one(
        "SELECT 1 FROM Enrollments WHERE user_id = ? AND course_id = ?",
        (g.user_id, course_id),
    )

    if not is_host and not is_enrolled:
        return (
            jsonify(
                {"error": "Access denied. You are not authorized to view this course."}
            ),
            403,
        )

    return jsonify(dict(course)), 200


@app.route("/courses/<int:course_id>", methods=["PUT"])
@login_required
def update_course(course_id):
    data = request.get_json()
    name = data.get("name")
    join_code = data.get("join_code")
    geolocation_latitude = data.get("geolocation_latitude")
    geolocation_longitude = data.get("geolocation_longitude")
    late_threshold_minutes = data.get("late_threshold_minutes")
    present_threshold_minutes = data.get("present_threshold_minutes")

    course = fetch_one("SELECT host_id FROM Courses WHERE course_id = ?", (course_id,))
    if not course:
        return jsonify({"error": "Course not found."}), 404
    if course["host_id"] != g.user_id:
        return (
            jsonify({"error": "Access denied. You are not the host of this course."}),
            403,
        )

    updates = []
    params = []

    if name:
        updates.append("name = ?")
        params.append(name)
    if join_code:
        existing_course_with_code = fetch_one(
            "SELECT course_id FROM Courses WHERE join_code = ? AND course_id != ?",
            (join_code, course_id),
        )
        if existing_course_with_code:
            return (
                jsonify({"error": "Join code already in use by another course."}),
                409,
            )
        updates.append("join_code = ?")
        params.append(join_code)
    if geolocation_latitude is not None:
        updates.append("geolocation_latitude = ?")
        params.append(geolocation_latitude)
    if geolocation_longitude is not None:
        updates.append("geolocation_longitude = ?")
        params.append(geolocation_longitude)
    if late_threshold_minutes is not None:
        updates.append("late_threshold_minutes = ?")
        params.append(late_threshold_minutes)
    if present_threshold_minutes is not None:
        updates.append("present_threshold_minutes = ?")
        params.append(present_threshold_minutes)

    if not updates:
        return jsonify({"message": "No data provided for update."}), 200

    params.append(course_id)
    query = f"UPDATE Courses SET {', '.join(updates)} WHERE course_id = ?"

    try:
        execute_query(query, tuple(params))
        return jsonify({"message": "Course updated successfully."}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 409
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


@app.route("/courses/<int:course_id>", methods=["DELETE"])
@login_required
def delete_course(course_id):
    course = fetch_one("SELECT host_id FROM Courses WHERE course_id = ?", (course_id,))
    if not course:
        return jsonify({"error": "Course not found."}), 404
    if course["host_id"] != g.user_id:
        return (
            jsonify({"error": "Access denied. You are not the host of this course."}),
            403,
        )

    try:
        execute_query("DELETE FROM Courses WHERE course_id = ?", (course_id,))
        return jsonify({"message": "Course deleted successfully."}), 200
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


# --- Enrollment Management (CRUD for Enrollments) ---


@app.route("/enrollments", methods=["POST"])
@login_required
def enroll_in_course():
    data = request.get_json()
    join_code = data.get("join_code")

    if not join_code:
        return jsonify({"error": "Join code is required to enroll in a course."}), 400

    course = fetch_one(
        "SELECT course_id, name, host_id FROM Courses WHERE join_code = ?", (join_code,)
    )
    if not course:
        return jsonify({"error": "Course not found with this join code."}), 404

    if course["host_id"] == g.user_id:
        return (
            jsonify(
                {
                    "error": "You are the host of this course; you cannot enroll as an attendee."
                }
            ),
            400,
        )

    try:
        query = "INSERT INTO Enrollments (user_id, course_id) VALUES (?, ?)"
        execute_query(query, (g.user_id, course["course_id"]))
        return (
            jsonify(
                {
                    "message": f"Successfully enrolled in course '{course['name']}'.",
                    "course_id": course["course_id"],
                    "user_id": g.user_id,
                }
            ),
            201,
        )
    except ValueError as e:
        return jsonify({"error": "You are already enrolled in this course."}), 409
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


@app.route("/users/<int:user_id>/enrollments", methods=["GET"])
@login_required
def get_user_enrollments(user_id):
    if g.user_id != user_id:
        return (
            jsonify(
                {"error": "Access denied. You can only view your own enrollments."}
            ),
            403,
        )

    query = """
        SELECT C.course_id, C.name, C.join_code, C.host_id, U.name AS host_name, E.enrolled_at
        FROM Enrollments E
        JOIN Courses C ON E.course_id = C.course_id
        JOIN Users U ON C.host_id = U.user_id
        WHERE E.user_id = ?
    """
    enrollments = fetch_all(query, (user_id,))

    if enrollments:
        return jsonify([dict(e) for e in enrollments]), 200
    else:
        return jsonify({"message": "No enrollments found for this user."}), 404


@app.route("/courses/<int:course_id>/enrollments", methods=["GET"])
@login_required
def get_course_attendees(course_id):
    course = fetch_one(
        "SELECT host_id, name FROM Courses WHERE course_id = ?", (course_id,)
    )
    if not course:
        return jsonify({"error": "Course not found."}), 404
    if course["host_id"] != g.user_id:
        return (
            jsonify({"error": "Access denied. You are not the host of this course."}),
            403,
        )

    query = """
        SELECT U.user_id, U.name, U.email, E.enrolled_at
        FROM Enrollments E
        JOIN Users U ON E.user_id = U.user_id
        WHERE E.course_id = ?
    """
    attendees = fetch_all(query, (course_id,))

    if attendees:
        return (
            jsonify(
                {
                    "course_id": course_id,
                    "course_name": course["name"],
                    "attendees": [dict(a) for a in attendees],
                }
            ),
            200,
        )
    else:
        return jsonify({"message": "No attendees found for this course yet."}), 404


@app.route("/enrollments", methods=["DELETE"])
@login_required
def unenroll_from_course():
    data = request.get_json()
    course_id = data.get("course_id")

    if not course_id:
        return jsonify({"error": "Course ID is required to unenroll."}), 400

    enrollment = fetch_one(
        "SELECT * FROM Enrollments WHERE user_id = ? AND course_id = ?",
        (g.user_id, course_id),
    )
    if not enrollment:
        return jsonify({"error": "You are not enrolled in this course."}), 404

    try:
        execute_query(
            "DELETE FROM Enrollments WHERE user_id = ? AND course_id = ?",
            (g.user_id, course_id),
        )
        return jsonify({"message": "Successfully unenrolled from course."}), 200
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


# --- Session Management (CRUD for Sessions) ---


@app.route("/courses/<int:course_id>/sessions", methods=["POST"])
@login_required
def create_session(course_id):
    # Only the course host can create sessions
    course = fetch_one(
        "SELECT host_id, name FROM Courses WHERE course_id = ?", (course_id,)
    )
    if not course:
        return jsonify({"error": "Course not found."}), 404
    if course["host_id"] != g.user_id:
        return (
            jsonify({"error": "Access denied. You are not the host of this course."}),
            403,
        )

    data = request.get_json()
    start_time = data.get("start_time")
    end_time = data.get("end_time")  # Optional

    if not start_time:
        return jsonify({"error": "Session start time is required."}), 400

    # Validate timestamps (optional, but good practice)
    try:
        # Assuming timestamps are provided as Unix epoch integers
        start_time = int(start_time)
        if end_time is not None:
            end_time = int(end_time)
            if end_time < start_time:
                return jsonify({"error": "End time cannot be before start time."}), 400
    except (ValueError, TypeError):
        return (
            jsonify(
                {
                    "error": "Invalid start_time or end_time format. Use Unix epoch integers."
                }
            ),
            400,
        )

    try:
        query = (
            "INSERT INTO Sessions (course_id, start_time, end_time) VALUES (?, ?, ?)"
        )
        session_id = execute_query(query, (course_id, start_time, end_time))
        return (
            jsonify(
                {
                    "message": f"Session created successfully for course '{course['name']}'.",
                    "session_id": session_id,
                    "course_id": course_id,
                    "start_time": start_time,
                    "end_time": end_time,
                }
            ),
            201,
        )
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


@app.route("/courses/<int:course_id>/sessions", methods=["GET"])
@login_required
def get_course_sessions(course_id):
    # Check if user is host or enrolled in the course to view sessions
    course = fetch_one("SELECT host_id FROM Courses WHERE course_id = ?", (course_id,))
    if not course:
        return jsonify({"error": "Course not found."}), 404

    is_host = course["host_id"] == g.user_id
    is_enrolled = fetch_one(
        "SELECT 1 FROM Enrollments WHERE user_id = ? AND course_id = ?",
        (g.user_id, course_id),
    )

    if not is_host and not is_enrolled:
        return (
            jsonify(
                {
                    "error": "Access denied. You are not authorized to view sessions for this course."
                }
            ),
            403,
        )

    sessions = fetch_all(
        "SELECT * FROM Sessions WHERE course_id = ? ORDER BY start_time DESC",
        (course_id,),
    )
    if sessions:
        return jsonify([dict(s) for s in sessions]), 200
    else:
        return jsonify({"message": "No sessions found for this course."}), 404


@app.route("/sessions/<int:session_id>", methods=["GET"])
@login_required
def get_session(session_id):
    session_data = fetch_one(
        "SELECT * FROM Sessions WHERE session_id = ?", (session_id,)
    )
    if not session_data:
        return jsonify({"error": "Session not found."}), 404

    # Check if user is host or enrolled in the course to view session details
    course_id = session_data["course_id"]
    course = fetch_one("SELECT host_id FROM Courses WHERE course_id = ?", (course_id,))
    if not course:  # Should not happen if data integrity is maintained
        return jsonify({"error": "Associated course not found."}), 500

    is_host = course["host_id"] == g.user_id
    is_enrolled = fetch_one(
        "SELECT 1 FROM Enrollments WHERE user_id = ? AND course_id = ?",
        (g.user_id, course_id),
    )

    if not is_host and not is_enrolled:
        return (
            jsonify(
                {"error": "Access denied. You are not authorized to view this session."}
            ),
            403,
        )

    return jsonify(dict(session_data)), 200


@app.route("/sessions/<int:session_id>", methods=["PUT"])
@login_required
def update_session(session_id):
    session_data = fetch_one(
        "SELECT course_id, start_time, end_time FROM Sessions WHERE session_id = ?",
        (session_id,),
    )
    if not session_data:
        return jsonify({"error": "Session not found."}), 404

    course_id = session_data["course_id"]
    course = fetch_one("SELECT host_id FROM Courses WHERE course_id = ?", (course_id,))
    if not course or course["host_id"] != g.user_id:
        return (
            jsonify(
                {
                    "error": "Access denied. You are not the host of this course or course not found."
                }
            ),
            403,
        )

    data = request.get_json()
    start_time = data.get("start_time")
    end_time = data.get("end_time")

    updates = []
    params = []

    if start_time is not None:
        try:
            start_time = int(start_time)
            updates.append("start_time = ?")
            params.append(start_time)
        except (ValueError, TypeError):
            return (
                jsonify(
                    {"error": "Invalid start_time format. Use Unix epoch integer."}
                ),
                400,
            )

    if end_time is not None:
        try:
            end_time = int(end_time)
            updates.append("end_time = ?")
            params.append(end_time)
        except (ValueError, TypeError):
            return (
                jsonify({"error": "Invalid end_time format. Use Unix epoch integer."}),
                400,
            )

    # If both start_time and end_time are updated, re-validate order
    current_start_time = session_data["start_time"]
    current_end_time = session_data["end_time"]

    proposed_start_time = start_time if start_time is not None else current_start_time
    proposed_end_time = end_time if end_time is not None else current_end_time

    if (
        proposed_end_time is not None
        and proposed_start_time is not None
        and proposed_end_time < proposed_start_time
    ):
        return jsonify({"error": "End time cannot be before start time."}), 400

    if not updates:
        return jsonify({"message": "No data provided for update."}), 200

    params.append(session_id)
    query = f"UPDATE Sessions SET {', '.join(updates)} WHERE session_id = ?"

    try:
        execute_query(query, tuple(params))
        return jsonify({"message": "Session updated successfully."}), 200
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


@app.route("/sessions/<int:session_id>", methods=["DELETE"])
@login_required
def delete_session(session_id):
    session_data = fetch_one(
        "SELECT course_id FROM Sessions WHERE session_id = ?", (session_id,)
    )
    if not session_data:
        return jsonify({"error": "Session not found."}), 404

    course_id = session_data["course_id"]
    course = fetch_one("SELECT host_id FROM Courses WHERE course_id = ?", (course_id,))
    if not course or course["host_id"] != g.user_id:
        return (
            jsonify(
                {
                    "error": "Access denied. You are not the host of this course or course not found."
                }
            ),
            403,
        )

    try:
        execute_query("DELETE FROM Sessions WHERE session_id = ?", (session_id,))
        return jsonify({"message": "Session deleted successfully."}), 200
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


# --- Attendance Management (CRUD for Attendances) ---


@app.route("/sessions/<int:session_id>/attendances", methods=["POST"])
@login_required
def mark_attendance(session_id):
    attendee_id = g.user_id

    session_data = fetch_one(
        "SELECT course_id, start_time, end_time FROM Sessions WHERE session_id = ?",
        (session_id,),
    )
    if not session_data:
        return jsonify({"error": "Session not found."}), 404

    # Check if user is enrolled in the course
    course_id = session_data["course_id"]
    enrollment = fetch_one(
        "SELECT 1 FROM Enrollments WHERE user_id = ? AND course_id = ?",
        (attendee_id, course_id),
    )
    if not enrollment:
        return jsonify({"error": "You are not enrolled in this course."}), 403

    # Check if user is the host
    course = fetch_one(
        "SELECT host_id, geolocation_latitude, geolocation_longitude, late_threshold_minutes, present_threshold_minutes FROM Courses WHERE course_id = ?",
        (course_id,),
    )
    if course["host_id"] == attendee_id:
        return (
            jsonify({"error": "Hosts cannot mark attendance for their own sessions."}),
            400,
        )

    data = request.get_json()
    user_latitude = data.get("user_geolocation_latitude")
    user_longitude = data.get("user_geolocation_longitude")
    proof_base64 = data.get("proof_base64")

    current_time = int(time.time())

    # Determine attendance status
    status = "Absent"
    is_within_time = False

    session_start_time = session_data["start_time"]
    session_end_time = (
        session_data["end_time"]
        if session_data["end_time"]
        else (session_start_time + 3600)
    )  # Default to 1 hour if no end_time

    late_threshold_seconds = course["late_threshold_minutes"] * 60
    present_threshold_seconds = course["present_threshold_minutes"] * 60

    if (
        session_start_time - present_threshold_seconds
        <= current_time
        <= session_end_time + late_threshold_seconds
    ):
        is_within_time = True
        if current_time <= session_start_time + present_threshold_seconds:
            status = "Present"
        elif current_time <= session_start_time + late_threshold_seconds:
            status = "Late"
        else:
            status = "Absent"  # Should not happen if within time, but good as fallback

    if not is_within_time:
        return (
            jsonify(
                {
                    "error": "Attendance cannot be marked. Session is not active or has ended."
                }
            ),
            400,
        )

    # Geolocation check
    if (
        course["geolocation_latitude"] is not None
        and course["geolocation_longitude"] is not None
    ):
        if user_latitude is None or user_longitude is None:
            return jsonify({"error": "Geolocation is required for this session."}), 400

        try:
            distance = haversine_distance(
                course["geolocation_latitude"],
                course["geolocation_longitude"],
                user_latitude,
                user_longitude,
            )
            # Assuming a small radius for "present", e.g., 0.1 km (100 meters)
            # You might want to make this configurable in Course settings
            if distance > 0.1:  # Example: 100 meters radius
                return (
                    jsonify(
                        {
                            "error": "You are not within the required proximity to mark attendance."
                        }
                    ),
                    400,
                )
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid geolocation coordinates."}), 400

    # Proof check (if needed) - currently not implemented as required in schema
    # if proof_required and not proof_base64:
    #     return jsonify({"error": "Proof is required for attendance."}), 400

    # Check if attendance already exists for this user and session
    existing_attendance = fetch_one(
        "SELECT * FROM Attendances WHERE user_id = ? AND session_id = ?",
        (attendee_id, session_id),
    )
    if existing_attendance:
        return (
            jsonify({"error": "You have already marked attendance for this session."}),
            409,
        )

    try:
        query = """
            INSERT INTO Attendances (
                user_id, session_id, status, joined_at, user_geolocation_latitude,
                user_geolocation_longitude, proof_base64
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        attendance_id = execute_query(
            query,
            (
                attendee_id,
                session_id,
                status,
                current_time,
                user_latitude,
                user_longitude,
                proof_base64,
            ),
        )
        return (
            jsonify(
                {
                    "message": f"Attendance marked successfully as {status}.",
                    "attendance_id": attendance_id,
                    "session_id": session_id,
                    "user_id": attendee_id,
                    "status": status,
                    "joined_at": current_time,
                }
            ),
            201,
        )
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


@app.route("/sessions/<int:session_id>/mark_absent_for_unattended", methods=["POST"])
@login_required
def mark_absent_for_unattended(session_id):
    """
    Allows a course host to mark all enrolled attendees who did not mark attendance
    for a specific session as 'Absent'. This can only be done after the session's
    attendance marking window has closed.
    """
    user_id = g.user_id

    # 1. Fetch session details to get course_id and times
    session_data = fetch_one(
        "SELECT * FROM Sessions WHERE session_id = ?", (session_id,)
    )
    if not session_data:
        return jsonify({"error": "Session not found."}), 404

    course_id = session_data["course_id"]

    # 2. Verify user is the host of the course
    course_data = fetch_one(
        "SELECT host_id, late_threshold_minutes, present_threshold_minutes FROM Courses WHERE course_id = ?",
        (course_id,),
    )
    if not course_data:
        return (
            jsonify({"error": "Course not found."}),
            404,
        )  # Should not happen if session_data was found

    if course_data["host_id"] != user_id:
        return (
            jsonify(
                {
                    "error": "Forbidden: Only the course host can mark unattended attendees absent."
                }
            ),
            403,
        )

    # 3. Check if the session's attendance marking window has closed
    # This prevents marking absent while students can still mark themselves
    current_time = int(time.time())
    session_start_time = session_data["start_time"]
    session_end_time = (
        session_data["end_time"]
        if session_data["end_time"]
        else (session_start_time + 3600)
    )  # Default to 1 hour if no end_time

    # Calculate the end of the extended attendance marking window
    # From previous logic: `current_time <= session_end_time + late_threshold_seconds`
    # So, for the window to be closed, `current_time > session_end_time + late_threshold_seconds`
    late_threshold_seconds = (
        course_data["late_threshold_minutes"] * 60
        if course_data["late_threshold_minutes"] is not None
        else 0
    )

    if current_time <= (session_end_time + late_threshold_seconds):
        return (
            jsonify(
                {
                    "error": "Cannot mark absent: Session attendance window is still open or has not started."
                }
            ),
            400,
        )

    conn = get_db_connection()
    cursor = conn.cursor()
    marked_absent_count = 0
    errors = []

    try:
        # 4. Identify enrolled attendees who do NOT have an attendance record for this session
        unmarked_attendees_query = """
            SELECT U.user_id, U.name, U.email
            FROM Users U
            JOIN Enrollments E ON U.user_id = E.user_id
            WHERE E.course_id = ?
            AND NOT EXISTS (
                SELECT 1 FROM Attendances A
                WHERE A.session_id = ? AND A.user_id = U.user_id
            );
        """
        cursor.execute(unmarked_attendees_query, (course_id, session_id))
        unmarked_attendees = cursor.fetchall()

        if not unmarked_attendees:
            return (
                jsonify(
                    {
                        "message": "No unattended attendees found to mark absent for this session."
                    }
                ),
                200,
            )

        # 5. Insert 'Absent' records for each identified user
        for attendee in unmarked_attendees:
            attendee_id = attendee["user_id"]
            try:
                execute_query(
                    """
                    INSERT INTO Attendances (session_id, user_id, status, joined_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (session_id, attendee_id, "Absent", int(time.time())),
                )
                marked_absent_count += 1
            except ValueError as e:
                # Handle cases where an attendee might have concurrent access or other integrity issues
                errors.append(
                    f"Failed to mark {attendee['name']} ({attendee['email']}) absent: {e}"
                )
            except RuntimeError as e:
                errors.append(
                    f"Database error for {attendee['name']} ({attendee['email']}): {e}"
                )

        conn.commit()  # Commit changes after loop

        response_message = (
            f"Successfully marked {marked_absent_count} unattended attendees as Absent."
        )
        if errors:
            response_message += " Some errors occurred: " + "; ".join(errors)

        return (
            jsonify(
                {
                    "message": response_message,
                    "marked_absent_count": marked_absent_count,
                    "errors": errors,
                }
            ),
            200,
        )

    except Exception as e:
        conn.rollback()  # Rollback on any major error
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        conn.close()


@app.route("/attendances/<int:attendance_id>", methods=["GET"])
@login_required
def get_attendance(attendance_id):
    attendance = fetch_one(
        "SELECT * FROM Attendances WHERE attendance_id = ?", (attendance_id,)
    )
    if not attendance:
        return jsonify({"error": "Attendance record not found."}), 404

    # Get associated session and course to check authorization
    session_data = fetch_one(
        "SELECT course_id FROM Sessions WHERE session_id = ?",
        (attendance["session_id"],),
    )
    if not session_data:
        return jsonify({"error": "Associated session not found."}), 500
    course = fetch_one(
        "SELECT host_id FROM Courses WHERE course_id = ?", (session_data["course_id"],)
    )
    if not course:
        return jsonify({"error": "Associated course not found."}), 500

    # User can view their own attendance, or course host can view attendance for their course
    if attendance["user_id"] != g.user_id and course["host_id"] != g.user_id:
        return (
            jsonify(
                {
                    "error": "Access denied. You are not authorized to view this attendance record."
                }
            ),
            403,
        )

    return jsonify(dict(attendance)), 200


@app.route("/users/<int:user_id>/attendances", methods=["GET"])
@login_required
def get_user_all_attendances(user_id):
    if g.user_id != user_id:
        return (
            jsonify(
                {
                    "error": "Access denied. You can only view your own attendance records."
                }
            ),
            403,
        )

    query = """
        SELECT A.*, S.start_time AS session_start_time, S.end_time AS session_end_time,
               C.name AS course_name, C.course_id
        FROM Attendances A
        JOIN Sessions S ON A.session_id = S.session_id
        JOIN Courses C ON S.course_id = C.course_id
        WHERE A.user_id = ?
        ORDER BY A.joined_at DESC
    """
    attendances = fetch_all(query, (user_id,))

    if attendances:
        return jsonify([dict(a) for a in attendances]), 200
    else:
        return jsonify({"message": "No attendance records found for this user."}), 404


@app.route("/sessions/<int:session_id>/attendances", methods=["GET"])
@login_required
def get_session_attendances(session_id):
    session_data = fetch_one(
        "SELECT course_id, start_time, end_time FROM Sessions WHERE session_id = ?",
        (session_id,),
    )
    if not session_data:
        return jsonify({"error": "Session not found."}), 404

    # Only course host can view session attendances
    course_id = session_data["course_id"]
    course = fetch_one("SELECT host_id FROM Courses WHERE course_id = ?", (course_id,))
    if not course or course["host_id"] != g.user_id:
        return (
            jsonify({"error": "Access denied. You are not the host of this course."}),
            403,
        )

    query = """
        SELECT A.*, U.name AS user_name, U.email AS user_email
        FROM Attendances A
        JOIN Users U ON A.user_id = U.user_id
        WHERE A.session_id = ?
        ORDER BY A.joined_at ASC
    """
    attendances = fetch_all(query, (session_id,))

    if attendances:
        return (
            jsonify(
                {
                    "session_id": session_id,
                    "course_id": course_id,
                    "session_start_time": session_data["start_time"],
                    "session_end_time": session_data["end_time"],
                    "attendances": [dict(a) for a in attendances],
                }
            ),
            200,
        )
    else:
        return (
            jsonify({"message": "No attendance records found for this session."}),
            404,
        )


@app.route("/courses/<int:course_id>/attendance_summary", methods=["GET"])
@login_required
def get_course_attendance_summary(course_id):
    course = fetch_one(
        "SELECT host_id, name FROM Courses WHERE course_id = ?", (course_id,)
    )
    if not course:
        return jsonify({"error": "Course not found."}), 404

    is_host = course["host_id"] == g.user_id
    is_enrolled = fetch_one(
        "SELECT 1 FROM Enrollments WHERE user_id = ? AND course_id = ?",
        (g.user_id, course_id),
    )

    if not is_host and not is_enrolled:
        return (
            jsonify(
                {
                    "error": "Access denied. You are not authorized to view this course's attendance summary."
                }
            ),
            403,
        )

    # For host: get summary for all attendees
    if is_host:
        summary_query = """
            SELECT U.user_id, U.name, U.email,
                   COUNT(CASE WHEN A.status = 'Present' THEN 1 END) AS present_count,
                   COUNT(CASE WHEN A.status = 'Late' THEN 1 END) AS late_count,
                   COUNT(CASE WHEN A.status = 'Absent' THEN 1 END) AS absent_count,
                   COUNT(DISTINCT S.session_id) AS total_sessions
            FROM Users U
            JOIN Enrollments E ON U.user_id = E.user_id
            LEFT JOIN Sessions S ON E.course_id = S.course_id AND S.course_id = ?
            LEFT JOIN Attendances A ON S.session_id = A.session_id AND U.user_id = A.user_id
            WHERE E.course_id = ?
            GROUP BY U.user_id, U.name, U.email
            ORDER BY U.name
        """
        summary_data = fetch_all(summary_query, (course_id, course_id))
        if summary_data:
            return (
                jsonify(
                    {
                        "course_id": course_id,
                        "course_name": course["name"],
                        "summary_for_all_attendees": [
                            dict(row) for row in summary_data
                        ],
                    }
                ),
                200,
            )
        else:
            return (
                jsonify(
                    {"message": "No attendance summary available for this course yet."}
                ),
                404,
            )
    # For attendee: get their own summary
    else:
        summary_query = """
            SELECT U.user_id, U.name, U.email,
                   COUNT(CASE WHEN A.status = 'Present' THEN 1 END) AS present_count,
                   COUNT(CASE WHEN A.status = 'Late' THEN 1 END) AS late_count,
                   COUNT(CASE WHEN A.status = 'Absent' THEN 1 END) AS absent_count,
                   COUNT(DISTINCT S.session_id) AS total_sessions
            FROM Users U
            JOIN Enrollments E ON U.user_id = E.user_id
            LEFT JOIN Sessions S ON E.course_id = S.course_id AND S.course_id = ?
            LEFT JOIN Attendances A ON S.session_id = A.session_id AND U.user_id = A.user_id
            WHERE E.course_id = ? AND U.user_id = ?
            GROUP BY U.user_id, U.name, U.email
        """
        summary_data = fetch_one(summary_query, (course_id, course_id, g.user_id))
        if summary_data:
            return (
                jsonify(
                    {
                        "course_id": course_id,
                        "course_name": course["name"],
                        "your_attendance_summary": dict(summary_data),
                    }
                ),
                200,
            )
        else:
            return (
                jsonify(
                    {
                        "message": "No attendance summary available for you in this course yet."
                    }
                ),
                404,
            )


if __name__ == "__main__":
    app.run(debug=True)
