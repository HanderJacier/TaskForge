from flask import Flask, render_template, request, redirect, url_for, session
from db import init_db, get_db

app = Flask(__name__)
app.secret_key = "secret_key_123"

init_db()

# ================= REGISTER =================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor()

        try:
            cur.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password)
            )
            conn.commit()
        except:
            return "Username đã tồn tại"

        conn.close()
        return redirect(url_for("login"))

    return render_template("register.html")


# ================= LOGIN =================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            "SELECT id FROM users WHERE username=? AND password=?",
            (username, password)
        )
        user = cur.fetchone()
        conn.close()

        if user:
            session["user_id"] = user[0]
            return redirect(url_for("index"))
        else:
            return "Sai tài khoản hoặc mật khẩu"

    return render_template("login.html")


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

    name = request.form["name"]

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


# ================= EDIT TASK =================
@app.route("/edit/<int:task_id>", methods=["GET", "POST"])
def edit(task_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()

    if request.method == "POST":
        new_name = request.form["name"]
        new_status = request.form["status"] # Lấy status mới từ form

        cur.execute(
            "UPDATE tasks SET name=?, status=? WHERE id=? AND user_id=?",
            (new_name, new_status, task_id, session["user_id"])
        )
        conn.commit()
        conn.close()
        return redirect(url_for("index"))

    # Lấy cả name và status để hiển thị lên form
    cur.execute(
        "SELECT name, status FROM tasks WHERE id=? AND user_id=?",
        (task_id, session["user_id"])
    )
    task = cur.fetchone()
    conn.close()

    if task is None:
        return redirect(url_for("index"))

    return render_template("edit.html", task=task)


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


# ================= LOGOUT =================
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("login"))

# ================= RUN APP (PHẢI Ở CUỐI) =================
if __name__ == "__main__":
    app.run(debug=True)
