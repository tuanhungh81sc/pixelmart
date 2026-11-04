"""
PixelMart - Vulnerable Lab Application
========================================
LAB NOTE (không phải lỗi thật của sản phẩm nào, viết riêng cho mục đích học tập):

Lỗ hổng duy nhất trong ứng dụng này là:
  RACE CONDITION (CWE-367, Time-of-Check to Time-of-Use) ở endpoint
  áp mã giảm giá /api/cart/apply-coupon

Mã giảm giá "SALE20" được thiết kế chỉ áp dụng được MỘT LẦN cho mỗi
giỏ hàng. Nhưng việc kiểm tra "đã áp dụng chưa" và việc "ghi nhận đã
áp dụng" được thực hiện KHÔNG NGUYÊN TỬ (not atomic) - có một khoảng
thời gian (race window) giữa hai bước đó. Nếu gửi nhiều request áp mã
cùng lúc, nhiều request có thể cùng đọc thấy "chưa áp dụng" trước khi
bất kỳ request nào kịp ghi "đã áp dụng", khiến mã giảm giá được cộng
dồn nhiều lần, biến giỏ hàng gần 2.000.000đ thành gần như 0đ.

Toàn bộ các phần khác của app (auth, session, input khác) đều được
viết an toàn một cách có chủ đích để không gây nhiễu, không có lỗi
nào khác được cài vào.
"""

import os
import sqlite3
import time
import secrets
from flask import Flask, g, request, jsonify, render_template, session, redirect, url_for

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DB_PATH = os.path.join(os.path.dirname(__file__), "pixelmart.db")

PRODUCTS = [
    {"id": 1, "name": "Bàn phím cơ PixelMart K1", "price": 1200000, "img": "keyboard"},
    {"id": 2, "name": "Chuột không dây PixelMart M2", "price": 450000, "img": "mouse"},
    {"id": 3, "name": "Tai nghe PixelMart H3", "price": 890000, "img": "headphone"},
    {"id": 4, "name": "Webcam PixelMart C4", "price": 650000, "img": "webcam"},
]

COUPON_CODE = "SALE20"
COUPON_PERCENT = 20  # giảm 20% mỗi lần áp dụng thành công


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
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
    conn.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE carts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            coupon_applied INTEGER NOT NULL DEFAULT 0,
            coupon_uses INTEGER NOT NULL DEFAULT 0,
            total_price INTEGER NOT NULL DEFAULT 0,
            UNIQUE(user_id)
        )
    """)
    conn.execute("""
        CREATE TABLE cart_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cart_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 1
        )
    """)
    conn.execute("""
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            final_price INTEGER NOT NULL,
            coupon_uses INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # demo user
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        ("tester", "Password123!"),
    )
    conn.commit()
    conn.close()


def current_user_id():
    return session.get("user_id")


def get_or_create_cart(db, user_id):
    cart = db.execute("SELECT * FROM carts WHERE user_id = ?", (user_id,)).fetchone()
    if cart is None:
        db.execute("INSERT INTO carts (user_id, total_price) VALUES (?, 0)", (user_id,))
        db.commit()
        cart = db.execute("SELECT * FROM carts WHERE user_id = ?", (user_id,)).fetchone()
    return cart


def calc_cart_subtotal(db, cart_id):
    items = db.execute("SELECT product_id, quantity FROM cart_items WHERE cart_id = ?", (cart_id,)).fetchall()
    subtotal = 0
    product_map = {p["id"]: p for p in PRODUCTS}
    for item in items:
        p = product_map.get(item["product_id"])
        if p:
            subtotal += p["price"] * item["quantity"]
    return subtotal


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if not current_user_id():
        return redirect(url_for("login"))
    return render_template("shop.html", products=PRODUCTS)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    data = request.form
    username = data.get("username", "")
    password = data.get("password", "")
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()
    if user is None:
        return render_template("login.html", error="Sai tài khoản hoặc mật khẩu."), 401
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    get_or_create_cart(db, user["id"])
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# API: cart
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
    items = db.execute(
        "SELECT product_id, quantity FROM cart_items WHERE cart_id = ?", (cart["id"],)
    ).fetchall()
    product_map = {p["id"]: p for p in PRODUCTS}
    cart_items = []
    subtotal = 0
    for item in items:
        p = product_map.get(item["product_id"])
        if not p:
            continue
        line_total = p["price"] * item["quantity"]
        subtotal += line_total
        cart_items.append({
            "product_id": p["id"],
            "name": p["name"],
            "unit_price": p["price"],
            "quantity": item["quantity"],
            "line_total": line_total,
        })
    discount = subtotal * COUPON_PERCENT // 100 * cart["coupon_uses"]
    final_price = max(subtotal - discount, 0)
    return jsonify({
        "items": cart_items,
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

    product_ids = {p["id"] for p in PRODUCTS}
    if product_id not in product_ids:
        return jsonify({"error": "product not found"}), 404

    db = get_db()
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


@app.route("/api/cart/apply-coupon", methods=["POST"])
def api_apply_coupon():
    """
    *** ĐÂY LÀ ENDPOINT CHỨA LỖ HỔNG (RACE CONDITION / TOCTOU) ***

    Luồng xử lý (cố tình viết không an toàn, giống lỗi thực tế hay gặp):

      1. TIME OF CHECK: đọc cart.coupon_applied từ DB.
      2. (mô phỏng xử lý nghiệp vụ tốn thời gian: validate mã, log, v.v.)
      3. TIME OF USE: UPDATE cart SET coupon_applied = 1, coupon_uses += 1

    Giữa bước 1 và bước 3 có một độ trễ nhân tạo (time.sleep). Đây chính
    là race window. Nếu nhiều request đến trong khoảng thời gian đó,
    tất cả đều đọc thấy coupon_applied = 0 ở bước 1 (vì chưa ai kịp
    UPDATE), nên tất cả đều vượt qua điều kiện và cộng dồn giảm giá.

    Trong một ứng dụng viết đúng, bước kiểm tra + ghi nhận phải nằm
    trong MỘT transaction có khóa (SELECT ... FOR UPDATE / UPDATE có
    điều kiện WHERE coupon_applied = 0 và kiểm tra rowcount), để đảm
    bảo tính nguyên tử (atomicity).
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

    # ---- mô phỏng độ trễ xử lý nghiệp vụ (validate, audit log, v.v.) ----
    # Đây là race window: trong khoảng thời gian sleep này, các request
    # khác gửi gần như đồng thời cũng sẽ đọc thấy coupon_applied = 0
    # ở bước TIME OF CHECK phía trên, vì request hiện tại CHƯA kịp ghi.
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

    subtotal = calc_cart_subtotal(db, cart["id"])
    if subtotal == 0:
        return jsonify({"error": "cart is empty"}), 400

    discount = subtotal * COUPON_PERCENT // 100 * cart["coupon_uses"]
    final_price = max(subtotal - discount, 0)

    db.execute(
        "INSERT INTO orders (user_id, final_price, coupon_uses) VALUES (?, ?, ?)",
        (user_id, final_price, cart["coupon_uses"]),
    )
    # reset cart sau khi đặt hàng
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
