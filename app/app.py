from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_wtf.csrf import CSRFProtect
from db import init_db, get_db
import bcrypt
import os
import re

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production-12345")
csrf = CSRFProtect(app)

init_db()

# ================= SECURITY HELPERS =================
def hash_password(password):
    """Hash password với bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hash):
    """Verify password với bcrypt"""
    return bcrypt.checkpw(password.encode('utf-8'), hash.encode('utf-8'))

def validate_username(username):
    """Validate username: 3-20 chars, alphanumeric + underscore"""
    if not username or len(username) < 3 or len(username) > 20:
        return False
    return re.match(r'^[a-zA-Z0-9_]+$', username) is not None

def validate_password(password):
    """Validate password: min 6 chars, có số, chữ thường, chữ hoa"""
    if len(password) < 6:
        return False
    return bool(re.search(r'\d', password)) and bool(re.search(r'[a-z]', password)) and bool(re.search(r'[A-Z]', password))

# ================= REGISTER =================
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        # Validate username
        if not validate_username(username):
            error = "Username phải có 3-20 ký tự, chỉ gồm chữ, số, dấu gạch dưới"
        # Validate password
        elif not validate_password(password):
            error = "Mật khẩu tối thiểu 6 ký tự (có số, chữ thường, chữ hoa)"
        elif password != confirm_password:
            error = "Mật khẩu không khớp"

        if not error:
            conn = get_db()
            cur = conn.cursor()

            try:
                hashed_pw = hash_password(password)
                cur.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, hashed_pw)
                )
                conn.commit()
                conn.close()
                return redirect(url_for("login"))
            except Exception as e:
                error = "Username đã tồn tại"
                conn.close()

    return render_template("register.html", error=error)


# ================= LOGIN =================
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            "SELECT id, password FROM users WHERE username=?",
            (username,)
        )
        user = cur.fetchone()
        conn.close()

        if user and verify_password(password, user[1]):
            session["user_id"] = user[0]
            session.permanent = False
            return redirect(url_for("index"))
        else:
            error = "Sai tài khoản hoặc mật khẩu"

    return render_template("login.html", error=error)


# ================= INDEX =================
@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT id, name, status FROM tasks WHERE user_id=?",
        (session["user_id"],)
    )
    tasks = cur.fetchall()
    conn.close()

    return render_template("index.html", tasks=tasks)


# ================= ADD TASK =================
@app.route("/add", methods=["POST"])
def add():
    if "user_id" not in session:
        return redirect(url_for("login"))

    name = request.form.get("name", "").strip()
    
    # Validate task name
    if not name or len(name) > 200:
        return redirect(url_for("index"))

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO tasks (name, user_id) VALUES (?, ?)",
        (name, session["user_id"])
    )

    conn.commit()
    conn.close()

    return redirect(url_for("index"))


# ================= TOGGLE DONE =================
@app.route("/toggle/<int:task_id>")
def toggle(task_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT status FROM tasks WHERE id=? AND user_id=?",
        (task_id, session["user_id"])
    )
    task = cur.fetchone()

    if task:
        new_status = "done" if task[0] == "pending" else "pending"

        cur.execute(
            "UPDATE tasks SET status=? WHERE id=? AND user_id=?",
            (new_status, task_id, session["user_id"])
        )
        conn.commit()

    conn.close()
    return redirect(url_for("index"))


# ================= EDIT TASK (API) =================
@app.route("/edit/<int:task_id>", methods=["POST"])
def edit(task_id):
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    new_name = request.form.get("name", "").strip()
    new_status = request.form.get("status", "pending").strip()
    
    # Validate
    if not new_name or len(new_name) > 200:
        return jsonify({"error": "Invalid task name"}), 400
    if new_status not in ["pending", "done"]:
        return jsonify({"error": "Invalid status"}), 400

    conn = get_db()
    cur = conn.cursor()

    # Check ownership
    cur.execute(
        "SELECT id FROM tasks WHERE id=? AND user_id=?",
        (task_id, session["user_id"])
    )
    if not cur.fetchone():
        conn.close()
        return jsonify({"error": "Task not found"}), 404

    # Update
    cur.execute(
        "UPDATE tasks SET name=?, status=? WHERE id=? AND user_id=?",
        (new_name, new_status, task_id, session["user_id"])
    )
    conn.commit()
    conn.close()
    
    return jsonify({"success": True})


# ================= DELETE TASK =================
@app.route("/delete/<int:task_id>")
def delete(task_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "DELETE FROM tasks WHERE id=? AND user_id=?",
        (task_id, session["user_id"])
    )

    conn.commit()
    conn.close()

    return redirect(url_for("index"))


# ================= API GET TASKS =================
@app.route("/api/tasks")
def api_tasks():
    if "user_id" not in session:
        return {"error": "Not logged in"}, 401

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT id, name, status FROM tasks WHERE user_id=?",
        (session["user_id"],)
    )
    tasks = cur.fetchall()
    conn.close()

    # Convert to dict format
    task_list = []
    for task in tasks:
        task_list.append({
            "id": task[0],
            "text": task[1],
            "done": task[2] == "done",
        })

    return jsonify({"tasks": task_list})


# ================= LOGOUT =================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ================= RUN APP (PHẢI Ở CUỐI) =================
if __name__ == "__main__":
    app.run(debug=True)
