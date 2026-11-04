"""
PixelMart - Vulnerable Lab Application (v4 - chained privesc + race condition)
==========================================================
LAB NOTE: Ung dung nay co HAI lo hong duoc cai dat co chu dich, THIET
KE DE NOI TIEP NHAU thanh MOT chuoi tan cong duy nhat, xoay quanh ma
giam gia:

  1. VUOT QUYEN / BROKEN FUNCTION LEVEL AUTHORIZATION (CWE-862) o
     GET /api/admin/coupon - API duy nhat trong khu vuc /api/admin/*
     bi QUEN goi require_admin() (chi con check dang nhap). Moi
     endpoint quan tri khac (/admin, /admin/orders, GET
     /api/admin/orders, POST /api/admin/orders/<id>/update-status) deu
     kiem tra quyen admin dung cach - CHI MOT CHO SOT duy nhat nay.

  2. RACE CONDITION (CWE-367, Time-of-Check to Time-of-Use) o endpoint
     ap ma giam gia POST /api/cart/apply-coupon.

  Diem ket noi: ma giam gia hop le KHONG CON la hang so cong khai
  "SALE20" nua, ma duoc sinh ngau nhien va chi luu trong CSDL, chi
  admin xem duoc qua /admin. De khai thac duoc race condition (lo hong
  #2), attacker BAT BUOC phai co ma that truoc - va con duong thuc te
  duy nhat de co duoc no la khai thac lo hong vuot quyen (lo hong #1)
  o GET /api/admin/coupon. Hai lo hong rieng le, chi nghiem trong khi
  ket hop lai. Xem README muc 2b/2c de biet chi tiet + kich ban tan
  cong day du.

Toan bo cac chuc nang khac (dang ky, dang nhap, tim kiem, trang chi
tiet san pham, trang ca nhan, lich su don hang, quan ly don hang cua
admin...) deu duoc viet an toan co chu dich: kiem tra quyen so huu
(ownership check) tren moi du lieu rieng tu, kiem tra quyen admin dung
cach tren moi endpoint /api/admin/* (tru endpoint noi tren), mat khau
duoc hash, khong co SQL injection (dung parameterized query xuyen
suot), khong co XSS (Jinja2 tu dong escape va khong dung |safe o bat
ky dau), de khong gay nhieu cho bai lab.

Chi tiet lo hong va cach khai thac: xem README.md.
"""

import os
import sqlite3
import time
import secrets
from datetime import datetime, timezone
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, g, request, jsonify, render_template, session, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Hash gia (khong gan voi user nao) dung de SO SANH THOI GIAN khi username
# khong ton tai, nham khong de lo thong tin "username co ton tai hay khong"
# qua thoi gian phan hoi cua endpoint dang nhap (CWE-208 - Observable Timing
# Discrepancy). Tao MOT LAN luc khoi dong app, khong phai hash thuc cua ai.
_DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_hex(16))


def is_safe_redirect_target(next_url):
    """Chi cho phep redirect noi bo (cung host, duong dan tuong doi thuc su).

    Mot kiem tra ngay tho nhu `next_url.startswith("/")` se bi qua mat boi
    URL "protocol-relative" dang `//evil.com/...` - gia tri nay VAN bat dau
    bang ky tu "/" nhung trinh duyet lai dieu huong sang host `evil.com`
    (CWE-601 - Open Redirect). Dung urlparse de dam bao ca scheme va netloc
    deu rong (tuc la khong tro sang host/scheme khac) truoc khi redirect.
    """
    if not next_url:
        return False
    if next_url.startswith("/\\") or next_url.startswith("//"):
        return False
    parsed = urlparse(next_url)
    return parsed.scheme == "" and parsed.netloc == "" and next_url.startswith("/")

DB_PATH = os.path.join(os.path.dirname(__file__), "pixelmart.db")

# Ma giam gia KHONG CON la hang so cong khai trong code/giao dien nua.
# Ma thuc te duoc sinh ngau nhien va luu trong bang `coupons`, CHI admin
# moi xem duoc qua khu vuc quan tri (xem muc 2b/2c README). Hang so duoi
# day chi la PHAN TRAM giam gia (khong phai bi mat), dung chung cho ma
# dang hoat dong.
COUPON_PERCENT = 20  # giam 20% moi lan ap dung thanh cong

CATEGORIES = ["Bàn phím", "Chuột", "Tai nghe", "Màn hình", "Loa", "Webcam", "Phụ kiện"]

SEED_PRODUCTS = [
    # (name, category, price, description, img_emoji, stock, sold_count)
    ("Bàn phím cơ PixelMart K1", "Bàn phím", 1200000,
     "Bàn phím cơ 87 phím, switch Blue, keycap PBT, đèn RGB 16 triệu màu. "
     "Phù hợp cho cả gaming lẫn làm việc văn phòng.", "⌨️", 25, 312),
    ("Bàn phím cơ PixelMart K1 Pro", "Bàn phím", 1850000,
     "Phiên bản nâng cấp của K1 với kết nối không dây 2.4GHz + Bluetooth, "
     "pin 4000mAh dùng được 2 tháng.", "⌨️", 12, 87),
    ("Chuột không dây PixelMart M2", "Chuột", 450000,
     "Chuột quang không dây, cảm biến 16000 DPI, pin AA dùng 18 tháng, "
     "thiết kế công thái học cho tay phải.", "🖱️", 40, 541),
    ("Chuột gaming PixelMart M2 Lite", "Chuột", 690000,
     "Chuột gaming có dây, 6 nút lập trình, cảm biến quang học chính xác cao.", "🖱️", 30, 203),
    ("Tai nghe PixelMart H3", "Tai nghe", 890000,
     "Tai nghe chụp tai chống ồn chủ động, pin 30 giờ, driver 40mm âm bass sâu.", "🎧", 18, 156),
    ("Tai nghe nhét tai PixelMart H3 Air", "Tai nghe", 590000,
     "Tai nghe true wireless, chống nước IPX5, kết nối Bluetooth 5.3.", "🎧", 22, 278),
    ("Webcam PixelMart C4", "Webcam", 650000,
     "Webcam Full HD 1080p 60fps, tự động lấy nét, mic khử tiếng ồn tích hợp.", "📷", 15, 94),
    ("Màn hình PixelMart V5 27inch", "Màn hình", 4500000,
     "Màn hình IPS 27 inch, 144Hz, 1ms, chuẩn màu 99% sRGB, hỗ trợ FreeSync.", "🖥️", 8, 41),
    ("Loa PixelMart S6", "Loa", 980000,
     "Loa bluetooth 2.1, công suất 30W, bass mạnh, pin 12 giờ, chống nước IPX6.", "🔊", 20, 132),
    ("Lót chuột PixelMart X1 XL", "Phụ kiện", 180000,
     "Lót chuột cỡ lớn 900x400mm, bề mặt vải dệt chống trượt, viền may cẩn thận.", "🟫", 60, 405),
    ("Bàn phím cơ PixelMart K1 Mini 60%", "Bàn phím", 1050000,
     "Bàn phím cơ 61 phím bố cục 60%, switch Red êm tay, kết nối Type-C, "
     "gọn nhẹ phù hợp mang theo laptop.", "⌨️", 33, 198),
    ("Bàn phím giả cơ PixelMart K2 Office", "Bàn phím", 420000,
     "Bàn phím giả cơ full-size cho văn phòng, chống nước nhẹ, đèn nền trắng.", "⌨️", 45, 267),
    ("Chuột đứng PixelMart M3 Ergo", "Chuột", 760000,
     "Chuột công thái học dạng đứng, giảm mỏi cổ tay, cảm biến 4000 DPI.", "🖱️", 20, 73),
    ("Tai nghe gaming PixelMart H4 7.1", "Tai nghe", 1150000,
     "Tai nghe gaming âm thanh ảo 7.1, mic tách rời khử ồn, đèn RGB, đệm tai mát.",
     "🎧", 16, 121),
    ("Webcam PixelMart C5 Pro 4K", "Webcam", 1390000,
     "Webcam 4K 30fps, HDR, 2 mic stereo, kẹp xoay 360 độ, phù hợp livestream.",
     "📷", 10, 58),
    ("Màn hình PixelMart V6 24inch", "Màn hình", 2890000,
     "Màn hình IPS 24 inch Full HD 100Hz, viền mỏng 3 cạnh, chân đế xoay gọn.",
     "🖥️", 14, 76),
    ("Màn hình cong PixelMart V7 32inch", "Màn hình", 7200000,
     "Màn hình cong 32 inch QHD 165Hz, cong 1500R, HDR400, 2 cổng HDMI 2.1.",
     "🖥️", 6, 19),
    ("Loa vi tính PixelMart S7 2.0", "Loa", 420000,
     "Loa vi tính 2.0 để bàn, công suất 10W, jack 3.5mm, đèn viền LED dịu mắt.",
     "🔊", 28, 164),
    ("Hub chuyển đổi PixelMart U1 Type-C 7in1", "Phụ kiện", 520000,
     "Hub USB-C 7 trong 1: HDMI 4K, 3 cổng USB 3.0, đọc thẻ SD/TF, sạc PD 100W.",
     "🔌", 35, 221),
    ("Giá đỡ laptop PixelMart L1 nhôm", "Phụ kiện", 390000,
     "Giá đỡ laptop hợp kim nhôm, 6 mức góc nghiêng, tản nhiệt tốt, gấp gọn.",
     "💻", 42, 189),
]

FREE_SHIPPING_THRESHOLD = 300000
FLAT_SHIPPING_FEE = 30000

PAYMENT_METHODS = {
    "cod": "Thanh toán khi nhận hàng (COD)",
    "bank_transfer": "Chuyển khoản ngân hàng",
}


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
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price INTEGER NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            img TEXT NOT NULL DEFAULT '📦',
            stock INTEGER NOT NULL DEFAULT 0,
            sold_count INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE carts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE REFERENCES users(id),
            coupon_applied INTEGER NOT NULL DEFAULT 0,
            coupon_uses INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE coupons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL,
            percent INTEGER NOT NULL DEFAULT 20,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
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
            shipping_fee INTEGER NOT NULL DEFAULT 0,
            final_price INTEGER NOT NULL,
            coupon_uses INTEGER NOT NULL DEFAULT 0,
            payment_method TEXT NOT NULL DEFAULT 'cod',
            shipping_address TEXT NOT NULL DEFAULT '',
            payment_verified INTEGER NOT NULL DEFAULT 0,
            admin_note TEXT NOT NULL DEFAULT '',
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

    for name, category, price, desc, img, stock, sold_count in SEED_PRODUCTS:
        conn.execute(
            "INSERT INTO products (name, category, price, description, img, stock, sold_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (name, category, price, desc, img, stock, sold_count),
        )

    # Tai khoan demo
    conn.execute(
        "INSERT INTO users (username, password_hash, email, full_name, address) VALUES (?, ?, ?, ?, ?)",
        ("tester", generate_password_hash("Password123!"), "tester@example.com",
         "Nguyễn Văn Tester", "123 Đường ABC, Quận 1, TP.HCM"),
    )

    # Tai khoan admin demo (dung cho trang quan tri /admin, xem muc 6 README)
    conn.execute(
        "INSERT INTO users (username, password_hash, email, full_name, address, role) "
        "VALUES (?, ?, ?, ?, ?, 'admin')",
        ("admin", generate_password_hash("AdminPixelMart#2026!"), "admin@pixelmart.local",
         "Quản trị viên PixelMart", "Trụ sở PixelMart"),
    )

    # Vai review mau cho san pham dau tien de trang chi tiet khong trong
    conn.execute(
        "INSERT INTO reviews (product_id, user_id, username, rating, comment) VALUES (1, 1, 'tester', 5, ?)",
        ("Gõ rất sướng tay, đáng tiền.",),
    )

    # Ma giam gia dang hoat dong - sinh NGAU NHIEN moi lan container khoi
    # dong (giong moi du lieu khac trong lab), KHONG hardcode, KHONG hien
    # thi o bat ky dau tren giao dien cong khai. Chi admin xem duoc qua
    # /admin (hoac qua khai thac lo hong vuot quyen - xem README muc 2c).
    active_coupon_code = "VIP" + secrets.token_hex(3).upper()
    conn.execute(
        "INSERT INTO coupons (code, percent, active) VALUES (?, ?, 1)",
        (active_coupon_code, COUPON_PERCENT),
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


def get_active_coupon(db):
    """Ma giam gia dang hoat dong duy nhat cua lab - chi admin duoc xem
    (dung) hop phap qua /admin. Khong co endpoint cong khai nao tra ve
    gia tri nay cho user thuong."""
    return db.execute(
        "SELECT * FROM coupons WHERE active = 1 ORDER BY id DESC LIMIT 1"
    ).fetchone()


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


def calc_shipping_fee(price_after_discount):
    """Phí ship tinh server-side (khong bao gio tin gia tri tu client)."""
    if price_after_discount >= FREE_SHIPPING_THRESHOLD:
        return 0
    return FLAT_SHIPPING_FEE


ORDER_STATUS_STEPS = [
    (0, "Đang xác nhận đơn hàng", "#e0a847"),
    (60, "Đang đóng gói", "#4f7cff"),
    (300, "Đang giao hàng", "#2bb3c0"),
    (900, "Đã giao thành công", "#2fbf71"),
]


def compute_order_status(created_at_str):
    """
    Trang thai don hang la gia lap cho muc dich minh hoa (khong co don
    vi van chuyen that), tinh dua tren thoi gian da troi qua ke tu luc
    tao don, de don "gia" di qua cac buoc giong mot don hang that.
    """
    try:
        created = datetime.strptime(created_at_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return ORDER_STATUS_STEPS[0][1], ORDER_STATUS_STEPS[0][2]

    elapsed = (datetime.now(timezone.utc) - created).total_seconds()
    label, color = ORDER_STATUS_STEPS[0][1], ORDER_STATUS_STEPS[0][2]
    for threshold, step_label, step_color in ORDER_STATUS_STEPS:
        if elapsed >= threshold:
            label, color = step_label, step_color
    return label, color


def cart_item_count(db, user_id):
    cart = get_or_create_cart(db, user_id)
    row = db.execute(
        "SELECT COALESCE(SUM(quantity), 0) AS c FROM cart_items WHERE cart_id = ?",
        (cart["id"],),
    ).fetchone()
    return row["c"]


@app.context_processor
def inject_globals():
    # Purely cosmetic globals for the shared layout (subnav category links,
    # free-shipping hint in footer/topbar) — read-only constants, no DB write,
    # no effect on any route's logic or the lab's single vulnerability.
    ctx = {
        "cart_count": 0, "logged_in": False, "username": None, "is_admin_user": False,
        "nav_categories": CATEGORIES, "nav_free_shipping_threshold": FREE_SHIPPING_THRESHOLD,
    }
    if current_user_id():
        db = get_db()
        ctx["cart_count"] = cart_item_count(db, current_user_id())
        ctx["logged_in"] = True
        ctx["username"] = session.get("username")
        ctx["is_admin_user"] = is_admin()
    return ctx


def login_required_page(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user_id():
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


def is_admin():
    uid = current_user_id()
    if not uid:
        return False
    row = get_db().execute("SELECT role FROM users WHERE id = ?", (uid,)).fetchone()
    return bool(row) and row["role"] == "admin"


def admin_required_page(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user_id():
            return redirect(url_for("login", next=request.path))
        if not is_admin():
            return render_template("404.html"), 404
        return fn(*args, **kwargs)
    return wrapper


def require_admin():
    """Dung cho cac API /api/admin/* - BAT BUOC goi o moi endpoint quan tri.
    (Xem README muc 6: mot endpoint da VO Y QUEN goi ham nay.)"""
    if not current_user_id():
        return jsonify({"error": "unauthorized"}), 401
    if not is_admin():
        return jsonify({"error": "forbidden"}), 403
    return None


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
    # Luon goi check_password_hash (voi hash gia neu khong tim thay user) de
    # thoi gian phan hoi KHONG tiet lo username co ton tai hay khong.
    password_ok = check_password_hash(
        user["password_hash"] if user else _DUMMY_PASSWORD_HASH, password
    )
    if user is None or not password_ok:
        return render_template("login.html", error="Sai tài khoản hoặc mật khẩu."), 401
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    get_or_create_cart(db, user["id"])
    next_url = request.args.get("next")
    if is_safe_redirect_target(next_url):
        return redirect(next_url)
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Shop pages
# ---------------------------------------------------------------------------

PRODUCTS_PER_PAGE = 6


@app.route("/")
def index():
    db = get_db()
    q = (request.args.get("q") or "").strip()
    category = (request.args.get("category") or "").strip()
    try:
        page = max(int(request.args.get("page", 1)), 1)
    except ValueError:
        page = 1

    where_sql = "WHERE 1=1"
    params = []
    if q:
        where_sql += " AND name LIKE ?"
        params.append(f"%{q}%")
    if category:
        where_sql += " AND category = ?"
        params.append(category)

    total = db.execute(f"SELECT COUNT(*) AS c FROM products {where_sql}", params).fetchone()["c"]
    total_pages = max((total + PRODUCTS_PER_PAGE - 1) // PRODUCTS_PER_PAGE, 1)
    page = min(page, total_pages)
    offset = (page - 1) * PRODUCTS_PER_PAGE

    products = db.execute(
        f"SELECT * FROM products {where_sql} ORDER BY id LIMIT ? OFFSET ?",
        params + [PRODUCTS_PER_PAGE, offset],
    ).fetchall()

    return render_template(
        "home.html", products=products, categories=CATEGORIES,
        q=q, selected_category=category,
        page=page, total_pages=total_pages,
        free_shipping_threshold=FREE_SHIPPING_THRESHOLD,
    )


@app.route("/product/<int:product_id>")
def product_detail(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if product is None:
        return render_template("404.html"), 404

    review_rows = db.execute(
        "SELECT * FROM reviews WHERE product_id = ? ORDER BY created_at DESC",
        (product_id,),
    ).fetchall()
    avg_rating = None
    if review_rows:
        avg_rating = round(sum(r["rating"] for r in review_rows) / len(review_rows), 1)

    # Lam giau du lieu review voi avatar (chu cai dau + mau nen) de hien
    # thi dep hon, tinh server-side de template chi can render.
    avatar_palette = ["#4f7cff", "#2fbf71", "#e0a847", "#e05a7a", "#7a5ae0", "#2bb3c0"]
    reviews = []
    for r in review_rows:
        username = r["username"] or "?"
        color_idx = sum(ord(c) for c in username) % len(avatar_palette)
        reviews.append({
            "username": username,
            "rating": r["rating"],
            "comment": r["comment"],
            "created_at": r["created_at"],
            "initial": username[0].upper(),
            "avatar_color": avatar_palette[color_idx],
        })

    related = db.execute(
        "SELECT * FROM products WHERE category = ? AND id != ? LIMIT 4",
        (product["category"], product_id),
    ).fetchall()

    return render_template(
        "product_detail.html", product=product, reviews=reviews,
        avg_rating=avg_rating, related=related,
        free_shipping_threshold=FREE_SHIPPING_THRESHOLD,
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
    order_rows = db.execute(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC",
        (current_user_id(),),
    ).fetchall()
    orders = []
    for row in order_rows:
        status, status_color = compute_order_status(row["created_at"])
        orders.append({**dict(row), "status": status, "status_color": status_color})
    return render_template("orders.html", orders=orders)


@app.route("/orders/<int:order_id>")
@login_required_page
def order_detail(order_id):
    db = get_db()
    order_row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    # Kiem tra quyen so huu: chi chu don hang moi xem duoc (tranh IDOR)
    if order_row is None or order_row["user_id"] != current_user_id():
        return render_template("404.html"), 404
    status, status_color = compute_order_status(order_row["created_at"])
    order = {**dict(order_row), "status": status, "status_color": status_color,
              "payment_method_label": PAYMENT_METHODS.get(order_row["payment_method"], order_row["payment_method"])}
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
    price_after_discount = max(subtotal - discount, 0)
    shipping_fee = calc_shipping_fee(price_after_discount) if items else 0
    final_price = price_after_discount + shipping_fee
    return jsonify({
        "items": items,
        "subtotal": subtotal,
        "coupon_applied": bool(cart["coupon_applied"]),
        "coupon_uses": cart["coupon_uses"],
        "discount": discount,
        "shipping_fee": shipping_fee,
        "free_shipping_threshold": FREE_SHIPPING_THRESHOLD,
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

    Luu y: ma giam gia hop le (`coupons.code`) la BI MAT, sinh ngau nhien,
    CHI admin xem duoc qua /admin (muc 2b) - endpoint nay khong tiet lo
    ma dung la gi, chi tra ve loi "invalid coupon code" cho ma sai. De
    khai thac duoc race condition o day, attacker phai co ma hop le
    truoc - thong thuong la bang cach khai thac lo hong vuot quyen o muc
    2c de "muon" ma giam gia cua admin. Hai lo hong duoc thiet ke de noi
    tiep nhau thanh MOT kich ban tan cong hoan chinh (xem README).

    Luong xu ly o CHINH endpoint nay (co tinh viet khong an toan, giong
    loi thuc te hay gap):

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

    db = get_db()
    coupon = get_active_coupon(db)
    if coupon is None or code != coupon["code"]:
        return jsonify({"error": "invalid coupon code"}), 400

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

    return jsonify({"ok": True, "message": f"Áp dụng mã {coupon['code']} thành công (-{coupon['percent']}%)."})


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

    data = request.get_json(force=True, silent=True) or {}
    payment_method = data.get("payment_method", "cod")
    if payment_method not in PAYMENT_METHODS:
        payment_method = "cod"

    discount = subtotal * COUPON_PERCENT // 100 * cart["coupon_uses"]
    price_after_discount = max(subtotal - discount, 0)
    # Phi ship luon duoc tinh lai o server dua tren gia sau giam, khong
    # bao gio nhan gia tri shipping_fee tu client (tranh them 1 vector
    # thao tung gia ngoai y muon).
    shipping_fee = calc_shipping_fee(price_after_discount)
    final_price = price_after_discount + shipping_fee

    user = db.execute("SELECT address FROM users WHERE id = ?", (user_id,)).fetchone()

    cur = db.execute(
        "INSERT INTO orders (user_id, subtotal, discount, shipping_fee, final_price, "
        "coupon_uses, payment_method, shipping_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, subtotal, discount, shipping_fee, final_price,
         cart["coupon_uses"], payment_method, user["address"] or ""),
    )
    order_id = cur.lastrowid
    for item in items:
        db.execute(
            "INSERT INTO order_items (order_id, product_name, unit_price, quantity) VALUES (?, ?, ?, ?)",
            (order_id, item["name"], item["unit_price"], item["quantity"]),
        )
        db.execute(
            "UPDATE products SET sold_count = sold_count + ? WHERE id = ?",
            (item["quantity"], item["product_id"]),
        )

    # reset gio hang sau khi dat hang
    db.execute("DELETE FROM cart_items WHERE cart_id = ?", (cart["id"],))
    db.execute(
        "UPDATE carts SET coupon_applied = 0, coupon_uses = 0 WHERE id = ?",
        (cart["id"],),
    )
    db.commit()

    flag = None
    if price_after_discount <= subtotal * 10 // 100 and cart["coupon_uses"] >= 3:
        flag = "LAB{race_cond1tion_t0ctou_coupon_stack_pixelmart}"

    user_row = db.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()

    return jsonify({
        "ok": True,
        "order_id": order_id,
        "subtotal": subtotal,
        "discount": discount,
        "shipping_fee": shipping_fee,
        "final_price": final_price,
        "coupon_uses": cart["coupon_uses"],
        "payment_method": PAYMENT_METHODS.get(payment_method, payment_method),
        "confirmation_email": user_row["email"] if user_row else None,
        "flag": flag,
    })


@app.route("/api/whoami")
def api_whoami():
    if not current_user_id():
        return jsonify({"logged_in": False})
    return jsonify({"logged_in": True, "username": session.get("username")})


# ---------------------------------------------------------------------------
# Khu vuc quan tri (/admin/*) - CHI danh cho role = 'admin'.
#
# Tat ca cac trang HTML va API o day deu kiem tra quyen dung cach bang
# admin_required_page() / require_admin() - KE CA API quan ly don hang
# (da tung la lo hong o ban truoc, nay da duoc SUA, xem README muc 6).
#
# CHI RIENG API GET /api/admin/coupon (de xem ma giam gia dang hoat
# dong) o cuoi file nay la thieu kiem tra quyen admin - day la lo hong
# "vuot quyen" DUY NHAT con lai cua lab, duoc thiet ke de noi tiep voi
# race condition o /api/cart/apply-coupon thanh MOT chuoi tan cong hoan
# chinh. Xem README muc 2b/2c.
# ---------------------------------------------------------------------------

@app.route("/admin")
@admin_required_page
def admin_dashboard():
    db = get_db()
    total_users = db.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    total_orders = db.execute("SELECT COUNT(*) AS c FROM orders").fetchone()["c"]
    total_revenue = db.execute("SELECT COALESCE(SUM(final_price), 0) AS s FROM orders").fetchone()["s"]
    verified_count = db.execute("SELECT COUNT(*) AS c FROM orders WHERE payment_verified = 1").fetchone()["c"]
    return render_template(
        "admin_dashboard.html",
        total_users=total_users, total_orders=total_orders,
        total_revenue=total_revenue, verified_count=verified_count,
    )


@app.route("/admin/orders")
@admin_required_page
def admin_orders_page():
    return render_template("admin_orders.html")


@app.route("/api/admin/orders", methods=["GET"])
def api_admin_list_orders():
    # Dung cach: kiem tra quyen admin truoc khi tra ve du lieu CUA MOI user.
    auth = require_admin()
    if auth:
        return auth
    db = get_db()
    rows = db.execute(
        """
        SELECT o.id, o.user_id, u.username, u.full_name, u.email,
               o.subtotal, o.discount, o.final_price, o.payment_method,
               o.payment_verified, o.admin_note, o.shipping_address, o.created_at
        FROM orders o
        JOIN users u ON u.id = o.user_id
        ORDER BY o.created_at DESC
        """
    ).fetchall()
    return jsonify({"orders": [dict(r) for r in rows]})


@app.route("/api/admin/orders/<int:order_id>/update-status", methods=["POST"])
def api_admin_update_order_status(order_id):
    # Dung cach (DA SUA so voi ban truoc - xem README muc 6): kiem tra
    # quyen admin dung nhu moi endpoint /api/admin/* khac. Endpoint nay
    # la mot vi du doi chung: cung nam trong /api/admin/*, cung thao tac
    # tren du lieu nhay cam cua nguoi khac, nhung duoc bao ve dung cach -
    # chi mot minh /api/admin/coupon ben duoi la con lo.
    auth = require_admin()
    if auth:
        return auth

    data = request.get_json(silent=True) or {}
    payment_verified = bool(data.get("payment_verified"))
    admin_note = (data.get("admin_note") or "")[:300]

    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if order is None:
        return jsonify({"error": "not found"}), 404

    db.execute(
        "UPDATE orders SET payment_verified = ?, admin_note = ? WHERE id = ?",
        (1 if payment_verified else 0, admin_note, order_id),
    )
    db.commit()

    return jsonify({"ok": True, "order_id": order_id, "payment_verified": payment_verified, "admin_note": admin_note})


@app.route("/api/admin/coupon", methods=["GET"])
def api_admin_coupon():
    # !!! VULN NOTE (CWE-862 - Broken Function Level Authorization) !!!
    # Day la API DUY NHAT trong khu vuc /api/admin/* QUEN goi
    # require_admin() - chi goi require_login() (kiem tra da dang nhap).
    # Moi API /api/admin/* khac phia tren deu goi require_admin() dung
    # cach; day la "mot cho sot" duy nhat, dung y de minh hoa loi BFLA
    # that: du hau het endpoint duoc bao ve dung, chi can QUEN mot cho
    # la toan bo "bi mat quan tri" (ma giam gia cua admin) bi lo ra cho
    # BAT KY user da dang nhap nao - khong can la admin.
    #
    # Hau qua nghiem trong hon ban than no: ma giam gia lo ra o day la
    # dau vao de khai thac tiep lo hong RACE CONDITION o
    # /api/cart/apply-coupon (vi ma khong con la hang so cong khai
    # "SALE20" nua) - hai lo hong duoc thiet ke noi tiep nhau thanh MOT
    # chuoi tan cong hoan chinh. Xem README muc 2c.
    auth = require_login()
    if auth:
        return auth

    db = get_db()
    coupon = get_active_coupon(db)
    if coupon is None:
        return jsonify({"error": "no active coupon"}), 404

    result = {"code": coupon["code"], "percent": coupon["percent"], "active": bool(coupon["active"])}

    # Flag rieng cho buoc "vuot quyen ro ri ma giam gia" - chi cap khi
    # nguoi goi KHONG PHAI admin (chung minh day thuc su la mot lan khai
    # thac, khong phai hanh vi hop le cua admin).
    if not is_admin():
        result["flag"] = "LAB{bfla_leaked_admin_voucher_pixelmart}"

    return jsonify(result)


@app.route("/robots.txt")
def robots_txt():
    # robots.txt tiet lo su ton tai cua khu vuc /admin va bundle JS cua no
    # - day la mot "dau vet" trinh sat rat thuc te (nhieu website vo tinh
    # lam lo cau truc thu muc nhay cam qua robots.txt khi co y dinh an no
    # khoi cong cu tim kiem, chu khong phai khoi nguoi dung).
    body = "User-agent: *\nDisallow: /admin\nDisallow: /static/js/\n"
    return app.response_class(body, mimetype="text/plain")


# ---------------------------------------------------------------------------
# Trang tinh (gioi thieu, chinh sach, lien he)
# ---------------------------------------------------------------------------

@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/policy")
def policy():
    return render_template("policy.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()[:100]
        message = (request.form.get("message") or "").strip()[:1000]
        if not name or not message:
            flash("Vui lòng điền đầy đủ họ tên và nội dung.", "error")
            return redirect(url_for("contact"))
        # Day la form demo: khong luu DB, khong gui email that, chi
        # phan hoi cho giong trai nghiem mot website that.
        flash(f"Cảm ơn {name}, chúng tôi đã nhận được tin nhắn và sẽ phản hồi sớm nhất!", "success")
        return redirect(url_for("contact"))
    return render_template("contact.html")


@app.errorhandler(404)
def handle_404(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def handle_500(e):
    return render_template("500.html"), 500


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
