from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo
import sqlite3
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = "medicare_secret_key_change_later"

DATABASE = "appointments.db"
INDIA_TZ = ZoneInfo("Asia/Kolkata")

DEFAULT_START_TIME = time(10, 0)
DEFAULT_END_TIME = time(18, 0)
LUNCH_START = time(13, 0)
LUNCH_END = time(14, 0)
SLOT_MINUTES = 30


def india_now():
    return datetime.now(INDIA_TZ)


def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS doctor_date_availability (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                doctor_id INTEGER NOT NULL,
                availability_date TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Available',
                UNIQUE(doctor_id, availability_date),
                FOREIGN KEY(doctor_id) REFERENCES doctors(id)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS doctor_slot_availability (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                doctor_id INTEGER NOT NULL,
                availability_date TEXT NOT NULL,
                slot_time TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Not Available',
                UNIQUE(doctor_id, availability_date, slot_time),
                FOREIGN KEY(doctor_id) REFERENCES doctors(id)
            )
        """)


def verify_password(stored_password, entered_password):
    if not stored_password:
        return False

    if stored_password.startswith(("scrypt:", "pbkdf2:")):
        try:
            return check_password_hash(stored_password, entered_password)
        except (ValueError, TypeError):
            return False

    return stored_password == entered_password


def login_required(role=None):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                flash("Please log in first.")
                return redirect(url_for("login"))

            if role and session.get("role") != role:
                flash("You are not allowed to access that page.")
                return redirect(url_for("home"))

            return view(*args, **kwargs)
        return wrapped
    return decorator


def normalize_time(value):
    if not value:
        return ""

    value = value.strip()

    for fmt in ("%H:%M", "%I:%M %p", "%I:%M%p"):
        try:
            return datetime.strptime(value, fmt).strftime("%H:%M")
        except ValueError:
            continue

    return value


def generate_time_slots():
    slots = []
    current = datetime.combine(date.today(), DEFAULT_START_TIME)
    end = datetime.combine(date.today(), DEFAULT_END_TIME)

    while current < end:
        slot_time = current.time()

        if not (LUNCH_START <= slot_time < LUNCH_END):
            slots.append(current.strftime("%H:%M"))

        current += timedelta(minutes=SLOT_MINUTES)

    return slots


def is_past_slot(selected_date, slot_time):
    try:
        slot_date = date.fromisoformat(selected_date)
        slot_clock = datetime.strptime(slot_time, "%H:%M").time()
    except ValueError:
        return True

    current = india_now()

    if slot_date < current.date():
        return True

    if slot_date > current.date():
        return False

    slot_datetime = datetime.combine(
        slot_date, slot_clock, tzinfo=INDIA_TZ
    )
    return slot_datetime <= current


@app.route("/")
def home():
    with get_db() as db:
        doctors = db.execute("""
            SELECT id, name, specialization, experience, fee, available_days
            FROM doctors
            ORDER BY name
        """).fetchall()

    return render_template("home.html", doctors=doctors)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or len(password) < 6:
            flash(
                "Enter your name and email, and use a password "
                "of at least 6 characters."
            )
            return redirect(url_for("register"))

        try:
            with get_db() as db:
                existing = db.execute(
                    "SELECT id FROM users WHERE LOWER(email) = ?",
                    (email,)
                ).fetchone()

                if existing:
                    flash(
                        "An account with this email already exists. "
                        "Please log in."
                    )
                    return redirect(url_for("login"))

                hashed_password = generate_password_hash(password)

                db.execute("""
                    INSERT INTO users (name, email, password, role)
                    VALUES (?, ?, ?, 'patient')
                """, (name, email, hashed_password))

                db.execute("""
                    INSERT INTO patients (name, email, password)
                    VALUES (?, ?, ?)
                """, (name, email, hashed_password))

            flash("Registration successful. Please log in.")
            return redirect(url_for("login"))

        except sqlite3.Error:
            app.logger.exception("Registration failed")
            flash("Registration could not be completed. Please try again.")
            return redirect(url_for("register"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if email == "admin@clinic.com" and password == "Admin@123":
            session.clear()
            session["user_id"] = -1
            session["name"] = "Administrator"
            session["role"] = "admin"
            return redirect(url_for("admin_dashboard"))

        with get_db() as db:
            user = db.execute("""
                SELECT id, name, email, password, role
                FROM users
                WHERE LOWER(email) = LOWER(?)
            """, (email,)).fetchone()

            if not user or not verify_password(user["password"], password):
                flash("Invalid email or password.")
                return redirect(url_for("login"))

            if not user["password"].startswith(("scrypt:", "pbkdf2:")):
                db.execute(
                    "UPDATE users SET password = ? WHERE id = ?",
                    (generate_password_hash(password), user["id"])
                )

            session.clear()
            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["role"] = user["role"]

            if user["role"] == "doctor":
                doctor = db.execute(
                    "SELECT id FROM doctors WHERE user_id = ?",
                    (user["id"],)
                ).fetchone()

                if not doctor:
                    session.clear()
                    flash("Doctor profile not found for this account.")
                    return redirect(url_for("login"))

                session["doctor_id"] = doctor["id"]
                return redirect(url_for("doctor_dashboard"))

            if user["role"] == "patient":
                return redirect(url_for("patient_dashboard"))

            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))

            session.clear()
            flash("Unknown account role.")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("home"))


def get_user_email(user_id):
    with get_db() as db:
        row = db.execute(
            "SELECT email FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
        return row["email"] if row else ""


@app.route("/patient", methods=["GET", "POST"])
@login_required("patient")
def patient_dashboard():
    with get_db() as db:
        patient = db.execute(
            "SELECT id FROM patients WHERE LOWER(email) = LOWER(?)",
            (get_user_email(session["user_id"]),)
        ).fetchone()

        if not patient:
            flash("Patient profile not found.")
            return redirect(url_for("logout"))

        patient_id = patient["id"]

        doctors = db.execute("""
            SELECT id, name, specialization, experience, fee, available_days
            FROM doctors
            ORDER BY name
        """).fetchall()

        if request.method == "POST":
            doctor_id = request.form.get("doctor_id", type=int)
            appointment_date = request.form.get(
                "appointment_date", ""
            ).strip()
            appointment_time = normalize_time(
                request.form.get("appointment_time", "").strip()
            )

            if not doctor_id or not appointment_date or not appointment_time:
                flash("Please select a doctor, date, and time.")
                return redirect(url_for("patient_dashboard"))

            try:
                selected_date = date.fromisoformat(appointment_date)
                selected_time = datetime.strptime(
                    appointment_time, "%H:%M"
                ).time()
            except ValueError:
                flash("Please select a valid appointment date and time.")
                return redirect(url_for("patient_dashboard"))

            if selected_date < india_now().date():
                flash("Appointment date cannot be in the past.")
                return redirect(url_for("patient_dashboard"))

            if (
                selected_time < DEFAULT_START_TIME
                or selected_time >= DEFAULT_END_TIME
                or LUNCH_START <= selected_time < LUNCH_END
                or appointment_time not in generate_time_slots()
            ):
                flash("Please select a valid clinic time slot.")
                return redirect(url_for("patient_dashboard"))

            if is_past_slot(appointment_date, appointment_time):
                flash("This time slot has already passed.")
                return redirect(url_for("patient_dashboard"))

            doctor = db.execute(
                "SELECT id FROM doctors WHERE id = ?",
                (doctor_id,)
            ).fetchone()

            if not doctor:
                flash("Selected doctor was not found.")
                return redirect(url_for("patient_dashboard"))

            day_availability = db.execute("""
                SELECT status FROM doctor_date_availability
                WHERE doctor_id = ? AND availability_date = ?
            """, (doctor_id, appointment_date)).fetchone()

            if not day_availability or day_availability["status"] != "Available":
                flash("This doctor is not available on the selected date.")
                return redirect(url_for("patient_dashboard"))

            slot_availability = db.execute("""
                SELECT status FROM doctor_slot_availability
                WHERE doctor_id = ?
                  AND availability_date = ?
                  AND slot_time = ?
            """, (doctor_id, appointment_date, appointment_time)).fetchone()

            if not slot_availability or slot_availability["status"] != "Available":
                flash("This time slot is not available. Please choose another.")
                return redirect(url_for("patient_dashboard"))

            conflict = db.execute("""
                SELECT id FROM appointments
                WHERE doctor_id = ?
                  AND appointment_date = ?
                  AND appointment_time = ?
                  AND status NOT IN ('Cancelled', 'Rejected')
            """, (doctor_id, appointment_date, appointment_time)).fetchone()

            if conflict:
                flash("That appointment slot is already booked.")
                return redirect(url_for("patient_dashboard"))

            db.execute("""
                INSERT INTO appointments
                    (patient_id, doctor_id, appointment_date,
                     appointment_time, status)
                VALUES (?, ?, ?, ?, 'Booked')
            """, (
                patient_id, doctor_id,
                appointment_date, appointment_time
            ))

            flash("Appointment booked successfully.")
            return redirect(url_for("patient_dashboard"))

        appointments = db.execute("""
            SELECT a.id, a.appointment_date, a.appointment_time, a.status,
                   d.name AS doctor_name, d.specialization, d.fee
            FROM appointments a
            JOIN doctors d ON d.id = a.doctor_id
            WHERE a.patient_id = ?
            ORDER BY a.appointment_date DESC, a.appointment_time DESC
        """, (patient_id,)).fetchall()

    return render_template(
        "patient.html",
        doctors=doctors,
        appointments=appointments,
        today=india_now().date().isoformat()
    )


# NEW ROUTE: Return actual slot availability to the patient page.
@app.route("/patient/slot-availability")
@login_required("patient")
def patient_slot_availability():
    doctor_id = request.args.get("doctor_id", type=int)
    selected_date = request.args.get("appointment_date", "").strip()

    if not doctor_id:
        return jsonify({"error": "Please select a doctor."}), 400

    try:
        parsed_date = date.fromisoformat(selected_date)
    except ValueError:
        return jsonify({"error": "Please select a valid date."}), 400

    if parsed_date < india_now().date():
        return jsonify({
            "slots": [],
            "message": "Past dates cannot be booked."
        })

    with get_db() as db:
        doctor = db.execute(
            "SELECT id FROM doctors WHERE id = ?",
            (doctor_id,)
        ).fetchone()

        if not doctor:
            return jsonify({"error": "Doctor not found."}), 404

        day_availability = db.execute("""
            SELECT status
            FROM doctor_date_availability
            WHERE doctor_id = ? AND availability_date = ?
        """, (doctor_id, selected_date)).fetchone()

        # A date must be marked Available by the doctor first.
        if not day_availability or day_availability["status"] != "Available":
            return jsonify({
                "slots": [],
                "message": "This doctor has not marked this date Available yet."
            })

        saved_rows = db.execute("""
            SELECT slot_time, status
            FROM doctor_slot_availability
            WHERE doctor_id = ? AND availability_date = ?
        """, (doctor_id, selected_date)).fetchall()

        saved_statuses = {
            normalize_time(row["slot_time"]): row["status"]
            for row in saved_rows
        }

        appointment_rows = db.execute("""
            SELECT appointment_time
            FROM appointments
            WHERE doctor_id = ?
              AND appointment_date = ?
              AND status NOT IN ('Cancelled', 'Rejected')
        """, (doctor_id, selected_date)).fetchall()

        booked_times = {
            normalize_time(row["appointment_time"])
            for row in appointment_rows
        }

    slots = []

    for slot in generate_time_slots():
        label = datetime.strptime(slot, "%H:%M").strftime("%I:%M %p")

        if slot in booked_times:
            status = "Booked"
        elif is_past_slot(selected_date, slot):
            status = "Not Available"
        else:
            # Missing saved status defaults to Available for an
            # Available date, matching the doctor's default slots.
            status = saved_statuses.get(slot, "Available")

        slots.append({
            "time": slot,
            "label": label,
            "status": status
        })

    return jsonify({
        "slots": slots,
        "message": "Select a slot marked Available."
    })


@app.route("/cancel_appointment/<int:appointment_id>", methods=["POST"])
@login_required("patient")
def cancel_appointment(appointment_id):
    with get_db() as db:
        patient = db.execute(
            "SELECT id FROM patients WHERE LOWER(email) = LOWER(?)",
            (get_user_email(session["user_id"]),)
        ).fetchone()

        if not patient:
            flash("Patient profile not found.")
            return redirect(url_for("patient_dashboard"))

        result = db.execute("""
            UPDATE appointments
            SET status = 'Cancelled'
            WHERE id = ? AND patient_id = ?
              AND status NOT IN ('Cancelled', 'Rejected')
        """, (appointment_id, patient["id"]))

        flash(
            "Appointment cancelled."
            if result.rowcount else "Appointment could not be cancelled."
        )

    return redirect(url_for("patient_dashboard"))


@app.route("/doctor", methods=["GET", "POST"])
@login_required("doctor")
def doctor_dashboard():
    doctor_id = session.get("doctor_id")

    if request.method == "POST":
        appointment_id = request.form.get("appointment_id", type=int)
        status = request.form.get("status", "").strip()

        if status not in ("Booked", "Approved", "Rejected", "Completed"):
            flash("Invalid appointment status.")
            return redirect(url_for("doctor_dashboard"))

        with get_db() as db:
            result = db.execute("""
                UPDATE appointments
                SET status = ?
                WHERE id = ? AND doctor_id = ?
            """, (status, appointment_id, doctor_id))

        flash(
            "Appointment status updated."
            if result.rowcount else "Appointment not found."
        )
        return redirect(url_for("doctor_dashboard"))

    selected_date = request.args.get("date", india_now().date().isoformat())

    try:
        selected_date = date.fromisoformat(selected_date).isoformat()
    except ValueError:
        selected_date = india_now().date().isoformat()

    now = india_now()
    today = now.date().isoformat()

    with get_db() as db:
        doctor = db.execute("""
            SELECT id, name, specialization, available_days
            FROM doctors
            WHERE id = ?
        """, (doctor_id,)).fetchone()

        if not doctor:
            flash("Doctor profile not found.")
            return redirect(url_for("logout"))

        # Automatically enable new future dates and their missing slots.
        # Existing date and slot choices are never overwritten here.
        if selected_date > today:
            db.execute("""
                INSERT OR IGNORE INTO doctor_date_availability
                    (doctor_id, availability_date, status)
                VALUES (?, ?, 'Available')
            """, (doctor_id, selected_date))

            current_date_status = db.execute("""
                SELECT status FROM doctor_date_availability
                WHERE doctor_id = ? AND availability_date = ?
            """, (doctor_id, selected_date)).fetchone()

            if current_date_status and current_date_status["status"] == "Available":
                for slot in generate_time_slots():
                    db.execute("""
                        INSERT OR IGNORE INTO doctor_slot_availability
                            (doctor_id, availability_date, slot_time, status)
                        VALUES (?, ?, ?, 'Available')
                    """, (doctor_id, selected_date, slot))

        availability = db.execute("""
            SELECT status FROM doctor_date_availability
            WHERE doctor_id = ? AND availability_date = ?
        """, (doctor_id, selected_date)).fetchone()

        availability_status = (
            availability["status"] if availability else "Not Set"
        )

        appointments = db.execute("""
            SELECT a.id, a.appointment_date, a.appointment_time, a.status,
                   p.name AS patient_name, p.email AS patient_email
            FROM appointments a
            JOIN patients p ON p.id = a.patient_id
            WHERE a.doctor_id = ?
            ORDER BY a.appointment_date DESC, a.appointment_time DESC
        """, (doctor_id,)).fetchall()

        date_appointments = db.execute("""
            SELECT appointment_time, status
            FROM appointments
            WHERE doctor_id = ?
              AND appointment_date = ?
              AND status NOT IN ('Cancelled', 'Rejected')
        """, (doctor_id, selected_date)).fetchall()

        saved_dates = db.execute("""
            SELECT availability_date, status
            FROM doctor_date_availability
            WHERE doctor_id = ?
            ORDER BY availability_date DESC
        """, (doctor_id,)).fetchall()

        slot_rows = db.execute("""
            SELECT slot_time, status
            FROM doctor_slot_availability
            WHERE doctor_id = ? AND availability_date = ?
        """, (doctor_id, selected_date)).fetchall()

    saved_slot_status = {
        normalize_time(row["slot_time"]): row["status"]
        for row in slot_rows
    }

    booked_slots = {
        normalize_time(row["appointment_time"]): row["status"]
        for row in date_appointments
    }

    slots = []

    for slot in generate_time_slots():
        label = datetime.strptime(slot, "%H:%M").strftime("%I:%M %p")
        past = is_past_slot(selected_date, slot)
        booked_status = booked_slots.get(slot)

        if booked_status:
            slot_status = "Booked"
        elif past:
            slot_status = "Not Available"
        elif availability_status != "Available":
            slot_status = "Not Available"
        else:
            slot_status = saved_slot_status.get(slot, "Available")

        slots.append({
            "time": slot,
            "label": label,
            "status": slot_status,
            "past": past,
            "booked": bool(booked_status),
            "can_edit": (
                availability_status == "Available"
                and not past
                and not booked_status
            )
        })

    return render_template(
        "doctor.html",
        doctor=doctor,
        appointments=appointments,
        selected_date=selected_date,
        today=today,
        availability_status=availability_status,
        slots=slots,
        saved_dates=saved_dates,
        india_time=now.strftime("%I:%M %p")
    )


@app.route("/update_appointment/<int:appointment_id>", methods=["POST"])
@login_required("doctor")
def update_appointment(appointment_id):
    status = request.form.get("status", "").strip()

    if status not in ("Booked", "Approved", "Rejected", "Completed"):
        flash("Invalid appointment status.")
        return redirect(url_for("doctor_dashboard"))

    with get_db() as db:
        result = db.execute("""
            UPDATE appointments
            SET status = ?
            WHERE id = ? AND doctor_id = ?
        """, (status, appointment_id, session.get("doctor_id")))

    flash(
        "Appointment updated."
        if result.rowcount else "Appointment not found."
    )
    return redirect(url_for("doctor_dashboard"))


@app.route("/update_doctor_availability", methods=["POST"])
@login_required("doctor")
def update_doctor_availability():
    selected_date = request.form.get("availability_date", "").strip()
    status = request.form.get("availability_status", "").strip()
    slot_time = normalize_time(request.form.get("slot_time", "").strip())
    slot_status = request.form.get("slot_status", "").strip()
    doctor_id = session.get("doctor_id")

    try:
        parsed_date = date.fromisoformat(selected_date)
    except ValueError:
        flash("Please select a valid date.")
        return redirect(url_for("doctor_dashboard"))

    if parsed_date < india_now().date():
        flash("You cannot change availability for a past date.")
        return redirect(url_for("doctor_dashboard", date=selected_date))

    if slot_time:
        if slot_time not in generate_time_slots():
            flash("Invalid time slot.")
            return redirect(url_for("doctor_dashboard", date=selected_date))

        if slot_status not in ("Available", "Not Available"):
            flash("Please choose a valid slot status.")
            return redirect(url_for("doctor_dashboard", date=selected_date))

        if is_past_slot(selected_date, slot_time):
            flash("Past time slots cannot be made available.")
            return redirect(url_for("doctor_dashboard", date=selected_date))

        with get_db() as db:
            day_status = db.execute("""
                SELECT status FROM doctor_date_availability
                WHERE doctor_id = ? AND availability_date = ?
            """, (doctor_id, selected_date)).fetchone()

            if not day_status or day_status["status"] != "Available":
                flash("Mark this date Available before changing its slots.")
                return redirect(url_for("doctor_dashboard", date=selected_date))

            existing_booking = db.execute("""
                SELECT id FROM appointments
                WHERE doctor_id = ?
                  AND appointment_date = ?
                  AND appointment_time = ?
                  AND status NOT IN ('Cancelled', 'Rejected')
            """, (doctor_id, selected_date, slot_time)).fetchone()

            if existing_booking:
                flash("This slot already has an appointment and cannot be changed.")
                return redirect(url_for("doctor_dashboard", date=selected_date))

            db.execute("""
                INSERT INTO doctor_slot_availability
                    (doctor_id, availability_date, slot_time, status)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(doctor_id, availability_date, slot_time)
                DO UPDATE SET status = excluded.status
            """, (doctor_id, selected_date, slot_time, slot_status))

        flash(f"{slot_time} marked as {slot_status}.")
        return redirect(url_for("doctor_dashboard", date=selected_date))

    if status not in ("Available", "Not Available"):
        flash("Please choose Available or Not Available.")
        return redirect(url_for("doctor_dashboard", date=selected_date))

    with get_db() as db:
        db.execute("""
            INSERT INTO doctor_date_availability
                (doctor_id, availability_date, status)
            VALUES (?, ?, ?)
            ON CONFLICT(doctor_id, availability_date)
            DO UPDATE SET status = excluded.status
        """, (doctor_id, selected_date, status))

        if status == "Available":
            for slot in generate_time_slots():
                if not is_past_slot(selected_date, slot):
                    db.execute("""
                        INSERT OR IGNORE INTO doctor_slot_availability
                            (doctor_id, availability_date, slot_time, status)
                        VALUES (?, ?, ?, 'Available')
                    """, (doctor_id, selected_date, slot))

    flash(
        f"{selected_date} marked as {status}. "
        "Existing appointments have been preserved."
    )
    return redirect(url_for("doctor_dashboard", date=selected_date))


@app.route("/admin")
@login_required("admin")
def admin_dashboard():
    with get_db() as db:
        doctors = db.execute(
            "SELECT * FROM doctors ORDER BY name"
        ).fetchall()

        patients = db.execute("""
            SELECT id, name, email
            FROM users
            WHERE role = 'patient'
            ORDER BY name
        """).fetchall()

        appointments = db.execute("""
            SELECT a.*, u.name AS patient_name, d.name AS doctor_name
            FROM appointments a
            JOIN patients p ON p.id = a.patient_id
            JOIN users u ON LOWER(u.email) = LOWER(p.email)
            JOIN doctors d ON d.id = a.doctor_id
            ORDER BY a.appointment_date DESC, a.appointment_time
        """).fetchall()

    return render_template(
        "admin.html",
        doctors=doctors,
        patients=patients,
        appointments=appointments
    )


@app.route("/admin/add-doctor", methods=["POST"])
@login_required("admin")
def add_doctor():
    name = request.form.get("name", "").strip()
    specialization = request.form.get("specialization", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not name or not specialization or not email or len(password) < 6:
        flash("Complete all fields. Password must have at least 6 characters.")
        return redirect(url_for("admin_dashboard"))

    try:
        experience = int(request.form.get("experience", 0))
        fee = float(request.form.get("fee", 500))

        if experience < 0 or fee < 0:
            raise ValueError

        with get_db() as db:
            cursor = db.execute("""
                INSERT INTO users (name, email, password, role)
                VALUES (?, ?, ?, 'doctor')
            """, (name, email, generate_password_hash(password)))
            user_id = cursor.lastrowid

            db.execute("""
                INSERT INTO doctors
                    (user_id, name, specialization, experience, fee)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, name, specialization, experience, fee))

        flash("Doctor added. They can now log in.")

    except sqlite3.IntegrityError:
        flash("Could not add doctor. This email may already be registered.")
    except ValueError:
        flash("Enter valid non-negative numbers for experience and fee.")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete-doctor/<int:doctor_id>", methods=["POST"])
@login_required("admin")
def delete_doctor(doctor_id):
    with get_db() as db:
        doctor = db.execute(
            "SELECT * FROM doctors WHERE id = ?",
            (doctor_id,)
        ).fetchone()

        if doctor:
            db.execute(
                "DELETE FROM appointments WHERE doctor_id = ?",
                (doctor_id,)
            )
            db.execute(
                "DELETE FROM doctor_slot_availability WHERE doctor_id = ?",
                (doctor_id,)
            )
            db.execute(
                "DELETE FROM doctor_date_availability WHERE doctor_id = ?",
                (doctor_id,)
            )
            db.execute(
                "DELETE FROM doctors WHERE id = ?",
                (doctor_id,)
            )

            if doctor["user_id"] is not None:
                db.execute(
                    "DELETE FROM users WHERE id = ? AND role = 'doctor'",
                    (doctor["user_id"],)
                )

    flash("Doctor profile and associated appointment records removed.")
    return redirect(url_for("admin_dashboard"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
