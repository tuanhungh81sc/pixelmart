"""
PixelMart - Vulnerable Lab Application (v2 - full shop)
==========================================================
LAB NOTE: Ung dung nay co MOT lo hong duy nhat, cai dat co chu dich
cho muc dich hoc tap:

  RACE CONDITION (CWE-367, Time-of-Check to Time-of-Use) o endpoint
  ap ma giam gia POST /api/cart/apply-coupon

Toan bo cac chuc nang khac (dang ky, dang nhap, tim kiem, trang chi
tiet san pham, trang ca nhan, lich su don hang...) deu duoc viet an
toan co chu dich: kiem tra quyen so huu (ownership check) tren moi
du lieu rieng tu, mat khau duoc hash, khong co SQL injection (dung
parameterized query xuyen suot), khong co XSS (Jinja2 tu dong escape
va khong dung |safe o bat ky dau), de khong gay nhieu cho bai lab.

Chi tiet lo hong va cach khai thac: xem README.md.
"""

import os
import sqlite3
import time
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, g, request, jsonify, render_template, session, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DB_PATH = os.path.join(os.path.dirname(__file__), "pixelmart.db")

COUPON_CODE = "SALE20"
COUPON_PERCENT = 20  # giam 20% moi lan ap dung thanh cong

CATEGORIES = ["Bàn phím", "Chuột", "Tai nghe", "Màn hình", "Loa", "Webcam", "Phụ kiện"]

SEED_PRODUCTS = [
    # (name, category, price, description, img_emoji, stock)
    ("Bàn phím cơ PixelMart K1", "Bàn phím", 1200000,
     "Bàn phím cơ 87 phím, switch Blue, keycap PBT, đèn RGB 16 triệu màu. "
     "Phù hợp cho cả gaming lẫn làm việc văn phòng.", "⌨️", 25),
    ("Bàn phím cơ PixelMart K1 Pro", "Bàn phím", 1850000,
     "Phiên bản nâng cấp của K1 với kết nối không dây 2.4GHz + Bluetooth, "
     "pin 4000mAh dùng được 2 tháng.", "⌨️", 12),
    ("Chuột không dây PixelMart M2", "Chuột", 450000,
     "Chuột quang không dây, cảm biến 16000 DPI, pin AA dùng 18 tháng, "
     "thiết kế công thái học cho tay phải.", "🖱️", 40),
    ("Chuột gaming PixelMart M2 Lite", "Chuột", 690000,
     "Chuột gaming có dây, 6 nút lập trình, cảm biến quang học chính xác cao.", "🖱️", 30),
    ("Tai nghe PixelMart H3", "Tai nghe", 890000,
     "Tai nghe chụp tai chống ồn chủ động, pin 30 giờ, driver 40mm âm bass sâu.", "🎧", 18),
    ("Tai nghe nhét tai PixelMart H3 Air", "Tai nghe", 590000,
     "Tai nghe true wireless, chống nước IPX5, kết nối Bluetooth 5.3.", "🎧", 22),
    ("Webcam PixelMart C4", "Webcam", 650000,
     "Webcam Full HD 1080p 60fps, tự động lấy nét, mic khử tiếng ồn tích hợp.", "📷", 15),
    ("Màn hình PixelMart V5 27inch", "Màn hình", 4500000,
     "Màn hình IPS 27 inch, 144Hz, 1ms, chuẩn màu 99% sRGB, hỗ trợ FreeSync.", "🖥️", 8),
    ("Loa PixelMart S6", "Loa", 980000,
     "Loa bluetooth 2.1, công suất 30W, bass mạnh, pin 12 giờ, chống nước IPX6.", "🔊", 20),
    ("Lót chuột PixelMart X1 XL", "Phụ kiện", 180000,
     "Lót chuột cỡ lớn 900x400mm, bề mặt vải dệt chống trượt, viền may cẩn thận.", "🟫", 60),
]


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL,
            full_name TEXT NOT NULL DEFAULT '',
            address TEXT NOT NULL DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price INTEGER NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            img TEXT NOT NULL DEFAULT '📦',
            stock INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE carts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE REFERENCES users(id),
            coupon_applied INTEGER NOT NULL DEFAULT 0,
            coupon_uses INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE cart_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cart_id INTEGER NOT NULL REFERENCES carts(id),
            product_id INTEGER NOT NULL REFERENCES products(id),
            quantity INTEGER NOT NULL DEFAULT 1,
            UNIQUE(cart_id, product_id)
        );

        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            subtotal INTEGER NOT NULL,
            discount INTEGER NOT NULL,
            final_price INTEGER NOT NULL,
            coupon_uses INTEGER NOT NULL DEFAULT 0,
            shipping_address TEXT NOT NULL DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL REFERENCES orders(id),
            product_name TEXT NOT NULL,
            unit_price INTEGER NOT NULL,
            quantity INTEGER NOT NULL
        );

        CREATE TABLE reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL REFERENCES products(id),
            user_id INTEGER NOT NULL REFERENCES users(id),
            username TEXT NOT NULL,
            rating INTEGER NOT NULL,
            comment TEXT NOT NULL DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)

    for name, category, price, desc, img, stock in SEED_PRODUCTS:
        conn.execute(
            "INSERT INTO products (name, category, price, description, img, stock) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (name, category, price, desc, img, stock),
        )

    # Tai khoan demo
    conn.execute(
        "INSERT INTO users (username, password_hash, email, full_name, address) VALUES (?, ?, ?, ?, ?)",
        ("tester", generate_password_hash("Password123!"), "tester@example.com",
         "Nguyễn Văn Tester", "123 Đường ABC, Quận 1, TP.HCM"),
    )

    # Vai review mau cho san pham dau tien de trang chi tiet khong trong
    conn.execute(
        "INSERT INTO reviews (product_id, user_id, username, rating, comment) VALUES (1, 1, 'tester', 5, ?)",
        ("Gõ rất sướng tay, đáng tiền.",),
    )

    conn.commit()
    conn.close()


def current_user_id():
    return session.get("user_id")


def get_or_create_cart(db, user_id):
    cart = db.execute("SELECT * FROM carts WHERE user_id = ?", (user_id,)).fetchone()
    if cart is None:
        db.execute("INSERT INTO carts (user_id) VALUES (?)", (user_id,))
        db.commit()
        cart = db.execute("SELECT * FROM carts WHERE user_id = ?", (user_id,)).fetchone()
    return cart


def calc_cart_subtotal_and_items(db, cart_id):
    rows = db.execute(
        """
        SELECT ci.product_id, ci.quantity, p.name, p.price, p.img
        FROM cart_items ci
        JOIN products p ON p.id = ci.product_id
        WHERE ci.cart_id = ?
        """,
        (cart_id,),
    ).fetchall()
    items = []
    subtotal = 0
    for r in rows:
        line_total = r["price"] * r["quantity"]
        subtotal += line_total
        items.append({
            "product_id": r["product_id"],
            "name": r["name"],
            "img": r["img"],
            "unit_price": r["price"],
            "quantity": r["quantity"],
            "line_total": line_total,
        })
    return subtotal, items


def cart_item_count(db, user_id):
    cart = get_or_create_cart(db, user_id)
    row = db.execute(
        "SELECT COALESCE(SUM(quantity), 0) AS c FROM cart_items WHERE cart_id = ?",
        (cart["id"],),
    ).fetchone()
    return row["c"]


@app.context_processor
def inject_globals():
    ctx = {"cart_count": 0, "logged_in": False, "username": None}
    if current_user_id():
        db = get_db()
        ctx["cart_count"] = cart_item_count(db, current_user_id())
        ctx["logged_in"] = True
        ctx["username"] = session.get("username")
    return ctx


def login_required_page(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user_id():
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    email = (request.form.get("email") or "").strip()
    full_name = (request.form.get("full_name") or "").strip()

    if len(username) < 3 or len(username) > 30:
        return render_template("register.html", error="Tên đăng nhập phải từ 3-30 ký tự."), 400
    if len(password) < 8:
        return render_template("register.html", error="Mật khẩu phải có ít nhất 8 ký tự."), 400
    if "@" not in email:
        return render_template("register.html", error="Email không hợp lệ."), 400

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        return render_template("register.html", error="Tên đăng nhập đã tồn tại."), 409

    cur = db.execute(
        "INSERT INTO users (username, password_hash, email, full_name) VALUES (?, ?, ?, ?)",
        (username, generate_password_hash(password), email, full_name),
    )
    db.commit()
    user_id = cur.lastrowid
    get_or_create_cart(db, user_id)

    session["user_id"] = user_id
    session["username"] = username
    return redirect(url_for("index"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        return render_template("login.html", error="Sai tài khoản hoặc mật khẩu."), 401
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    get_or_create_cart(db, user["id"])
    next_url = request.args.get("next")
    if next_url and next_url.startswith("/"):
        return redirect(next_url)
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Shop pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    db = get_db()
    q = (request.args.get("q") or "").strip()
    category = (request.args.get("category") or "").strip()

    sql = "SELECT * FROM products WHERE 1=1"
    params = []
    if q:
        sql += " AND name LIKE ?"
        params.append(f"%{q}%")
    if category:
        sql += " AND category = ?"
        params.append(category)
    sql += " ORDER BY id"

    products = db.execute(sql, params).fetchall()
    return render_template(
        "home.html", products=products, categories=CATEGORIES,
        q=q, selected_category=category,
    )


@app.route("/product/<int:product_id>")
def product_detail(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if product is None:
        return render_template("404.html"), 404

    reviews = db.execute(
        "SELECT * FROM reviews WHERE product_id = ? ORDER BY created_at DESC",
        (product_id,),
    ).fetchall()
    avg_rating = None
    if reviews:
        avg_rating = round(sum(r["rating"] for r in reviews) / len(reviews), 1)

    related = db.execute(
        "SELECT * FROM products WHERE category = ? AND id != ? LIMIT 4",
        (product["category"], product_id),
    ).fetchall()

    return render_template(
        "product_detail.html", product=product, reviews=reviews,
        avg_rating=avg_rating, related=related,
    )


@app.route("/product/<int:product_id>/review", methods=["POST"])
@login_required_page
def add_review(product_id):
    db = get_db()
    product = db.execute("SELECT id FROM products WHERE id = ?", (product_id,)).fetchone()
    if product is None:
        return render_template("404.html"), 404

    try:
        rating = int(request.form.get("rating", 0))
    except ValueError:
        rating = 0
    comment = (request.form.get("comment") or "").strip()[:500]

    if rating < 1 or rating > 5:
        flash("Số sao đánh giá không hợp lệ.", "error")
        return redirect(url_for("product_detail", product_id=product_id))

    db.execute(
        "INSERT INTO reviews (product_id, user_id, username, rating, comment) VALUES (?, ?, ?, ?, ?)",
        (product_id, current_user_id(), session.get("username"), rating, comment),
    )
    db.commit()
    flash("Cảm ơn bạn đã đánh giá sản phẩm!", "success")
    return redirect(url_for("product_detail", product_id=product_id))


@app.route("/cart")
@login_required_page
def cart_page():
    return render_template("cart.html")


@app.route("/profile", methods=["GET", "POST"])
@login_required_page
def profile():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (current_user_id(),)).fetchone()

    if request.method == "POST":
        full_name = (request.form.get("full_name") or "").strip()
        email = (request.form.get("email") or "").strip()
        address = (request.form.get("address") or "").strip()

        if "@" not in email:
            return render_template("profile.html", user=user, error="Email không hợp lệ."), 400

        db.execute(
            "UPDATE users SET full_name = ?, email = ?, address = ? WHERE id = ?",
            (full_name, email, address, current_user_id()),
        )
        db.commit()
        user = db.execute("SELECT * FROM users WHERE id = ?", (current_user_id(),)).fetchone()
        flash("Cập nhật thông tin thành công.", "success")

    return render_template("profile.html", user=user)


@app.route("/profile/password", methods=["POST"])
@login_required_page
def change_password():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (current_user_id(),)).fetchone()

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")

    if not check_password_hash(user["password_hash"], current_password):
        flash("Mật khẩu hiện tại không đúng.", "error")
        return redirect(url_for("profile"))
    if len(new_password) < 8:
        flash("Mật khẩu mới phải có ít nhất 8 ký tự.", "error")
        return redirect(url_for("profile"))

    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), current_user_id()),
    )
    db.commit()
    flash("Đổi mật khẩu thành công.", "success")
    return redirect(url_for("profile"))


@app.route("/orders")
@login_required_page
def order_history():
    db = get_db()
    # Chi lay don hang CUA CHINH user dang dang nhap (ownership check dung cach)
    orders = db.execute(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC",
        (current_user_id(),),
    ).fetchall()
    return render_template("orders.html", orders=orders)


@app.route("/orders/<int:order_id>")
@login_required_page
def order_detail(order_id):
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    # Kiem tra quyen so huu: chi chu don hang moi xem duoc (tranh IDOR)
    if order is None or order["user_id"] != current_user_id():
        return render_template("404.html"), 404
    items = db.execute("SELECT * FROM order_items WHERE order_id = ?", (order_id,)).fetchall()
    return render_template("order_detail.html", order=order, items=items)


# ---------------------------------------------------------------------------
# API: cart (JSON, dung cho trang /cart va cac nut "them vao gio" o moi noi)
# ---------------------------------------------------------------------------

def require_login():
    if not current_user_id():
        return jsonify({"error": "unauthorized"}), 401
    return None


@app.route("/api/cart", methods=["GET"])
def api_get_cart():
    err = require_login()
    if err:
        return err
    db = get_db()
    cart = get_or_create_cart(db, current_user_id())
    subtotal, items = calc_cart_subtotal_and_items(db, cart["id"])
    discount = subtotal * COUPON_PERCENT // 100 * cart["coupon_uses"]
    final_price = max(subtotal - discount, 0)
    return jsonify({
        "items": items,
        "subtotal": subtotal,
        "coupon_applied": bool(cart["coupon_applied"]),
        "coupon_uses": cart["coupon_uses"],
        "discount": discount,
        "final_price": final_price,
    })


@app.route("/api/cart/add", methods=["POST"])
def api_add_to_cart():
    err = require_login()
    if err:
        return err
    data = request.get_json(force=True, silent=True) or {}
    product_id = data.get("product_id")
    quantity = data.get("quantity", 1)

    try:
        product_id = int(product_id)
        quantity = int(quantity)
    except (TypeError, ValueError):
        return jsonify({"error": "invalid input"}), 400

    if quantity < 1 or quantity > 20:
        return jsonify({"error": "invalid quantity"}), 400

    db = get_db()
    product = db.execute("SELECT id FROM products WHERE id = ?", (product_id,)).fetchone()
    if product is None:
        return jsonify({"error": "product not found"}), 404

    cart = get_or_create_cart(db, current_user_id())
    existing = db.execute(
        "SELECT * FROM cart_items WHERE cart_id = ? AND product_id = ?",
        (cart["id"], product_id),
    ).fetchone()
    if existing:
        db.execute(
            "UPDATE cart_items SET quantity = quantity + ? WHERE id = ?",
            (quantity, existing["id"]),
        )
    else:
        db.execute(
            "INSERT INTO cart_items (cart_id, product_id, quantity) VALUES (?, ?, ?)",
            (cart["id"], product_id, quantity),
        )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/cart/remove", methods=["POST"])
def api_remove_from_cart():
    err = require_login()
    if err:
        return err
    data = request.get_json(force=True, silent=True) or {}
    try:
        product_id = int(data.get("product_id"))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid input"}), 400

    db = get_db()
    cart = get_or_create_cart(db, current_user_id())
    db.execute(
        "DELETE FROM cart_items WHERE cart_id = ? AND product_id = ?",
        (cart["id"], product_id),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/cart/apply-coupon", methods=["POST"])
def api_apply_coupon():
    """
    *** DAY LA ENDPOINT CHUA LO HONG (RACE CONDITION / TOCTOU) ***

    Luong xu ly (co tinh viet khong an toan, giong loi thuc te hay gap):

      1. TIME OF CHECK: doc cart.coupon_applied tu DB.
      2. (mo phong xu ly nghiep vu ton thoi gian: validate ma, log, v.v.)
      3. TIME OF USE: UPDATE cart SET coupon_applied = 1, coupon_uses += 1

    Giua buoc 1 va buoc 3 co mot do tre nhan tao (time.sleep). Day chinh
    la race window. Neu nhieu request den trong khoang thoi gian do,
    tat ca deu doc thay coupon_applied = 0 o buoc 1 (vi chua ai kip
    UPDATE), nen tat ca deu vuot qua dieu kien va cong don giam gia.

    Chi tiet khai thac: xem README.md.
    """
    err = require_login()
    if err:
        return err
    data = request.get_json(force=True, silent=True) or {}
    code = (data.get("code") or "").strip().upper()

    if code != COUPON_CODE:
        return jsonify({"error": "invalid coupon code"}), 400

    db = get_db()
    cart = get_or_create_cart(db, current_user_id())

    # ---- TIME OF CHECK ----
    row = db.execute(
        "SELECT coupon_applied FROM carts WHERE id = ?", (cart["id"],)
    ).fetchone()

    if row["coupon_applied"]:
        return jsonify({"error": "coupon already applied"}), 409

    # ---- mo phong do tre xu ly nghiep vu (validate, audit log, v.v.) ----
    # Day la race window: trong khoang thoi gian sleep nay, cac request
    # khac gui gan nhu dong thoi cung se doc thay coupon_applied = 0
    # o buoc TIME OF CHECK phia tren, vi request hien tai CHUA kip ghi.
    time.sleep(0.35)

    # ---- TIME OF USE ----
    db.execute(
        "UPDATE carts SET coupon_applied = 1, coupon_uses = coupon_uses + 1 WHERE id = ?",
        (cart["id"],),
    )
    db.commit()

    return jsonify({"ok": True, "message": f"Áp dụng mã {COUPON_CODE} thành công (-{COUPON_PERCENT}%)."})


@app.route("/api/cart/checkout", methods=["POST"])
def api_checkout():
    err = require_login()
    if err:
        return err
    db = get_db()
    user_id = current_user_id()
    cart = get_or_create_cart(db, user_id)

    subtotal, items = calc_cart_subtotal_and_items(db, cart["id"])
    if subtotal == 0 or not items:
        return jsonify({"error": "cart is empty"}), 400

    discount = subtotal * COUPON_PERCENT // 100 * cart["coupon_uses"]
    final_price = max(subtotal - discount, 0)

    user = db.execute("SELECT address FROM users WHERE id = ?", (user_id,)).fetchone()

    cur = db.execute(
        "INSERT INTO orders (user_id, subtotal, discount, final_price, coupon_uses, shipping_address) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, subtotal, discount, final_price, cart["coupon_uses"], user["address"] or ""),
    )
    order_id = cur.lastrowid
    for item in items:
        db.execute(
            "INSERT INTO order_items (order_id, product_name, unit_price, quantity) VALUES (?, ?, ?, ?)",
            (order_id, item["name"], item["unit_price"], item["quantity"]),
        )

    # reset gio hang sau khi dat hang
    db.execute("DELETE FROM cart_items WHERE cart_id = ?", (cart["id"],))
    db.execute(
        "UPDATE carts SET coupon_applied = 0, coupon_uses = 0 WHERE id = ?",
        (cart["id"],),
    )
    db.commit()

    flag = None
    if final_price <= subtotal * 10 // 100 and cart["coupon_uses"] >= 3:
        flag = "LAB{race_cond1tion_t0ctou_coupon_stack_pixelmart}"

    return jsonify({
        "ok": True,
        "order_id": order_id,
        "subtotal": subtotal,
        "discount": discount,
        "final_price": final_price,
        "coupon_uses": cart["coupon_uses"],
        "flag": flag,
    })


@app.route("/api/whoami")
def api_whoami():
    if not current_user_id():
        return jsonify({"logged_in": False})
    return jsonify({"logged_in": True, "username": session.get("username")})


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
