#!/usr/bin/env python3
"""
Tải ảnh SẢN PHẨM THẬT (ảnh chụp, miễn phí bản quyền) để thay thế ảnh minh
hoạ vector đang có trong static/products/, cho giao diện PixelMart giống
thật hơn.

TẠI SAO LÀ SCRIPT RIÊNG, KHÔNG CHẠY TỰ ĐỘNG TRONG DOCKER?
-----------------------------------------------------------------------
Script này cần kết nối Internet để tải ảnh từ Openverse (kho ảnh tổng hợp
các ảnh có giấy phép mở: CC0 / Public Domain / CC-BY...). Môi trường build
Docker của lab này được thiết kế để chạy offline, không phụ thuộc mạng khi
`docker compose up --build`, nên việc tải ảnh được tách thành bước THỦ CÔNG,
chạy MỘT LẦN trên máy có Internet (ví dụ máy Windows của bạn, hoặc chính VM
Debian nếu nó có mạng), trước khi build.

CÁCH DÙNG
-----------------------------------------------------------------------
    pip install requests pillow
    python3 scripts/fetch_real_product_images.py

Script sẽ:
  1. Với mỗi sản phẩm (10 sản phẩm, 7 danh mục), tìm ảnh thật qua Openverse
     API (https://openverse.org) - CHỈ lấy ảnh có license cho phép dùng
     thương mại (license_type=commercial), không cần API key.
  2. Tải 3 ảnh / sản phẩm, resize + center-crop về 800x600 cho đồng bộ với
     CSS hiện có (.thumb, .pd-image, .related-card .thumb-sm).
  3. Lưu đè vào static/products/p<id>_1.jpg, _2.jpg, _3.jpg (ảnh minh hoạ
     vector cũ sẽ bị thay thế - có thể chạy lại gen_product_images.py nếu
     muốn quay lại ảnh vector).
  4. Ghi static/products/SOURCES.md liệt kê nguồn/tác giả/giấy phép từng
     ảnh đã tải, để tra cứu lại khi cần (minh bạch về nguồn gốc ảnh dùng
     trong lab).

LƯU Ý VỀ BẢN QUYỀN
-----------------------------------------------------------------------
Openverse chỉ index ảnh có giấy phép mở do người đăng công bố - script lọc
license_type=commercial (CC0, Public Domain, CC-BY, CC-BY-SA...) nên dùng
lại được kể cả cho mục đích thương mại, nhưng:
  - Một số giấy phép (CC-BY, CC-BY-SA) YÊU CẦU ghi công tác giả. SOURCES.md
    đã ghi sẵn thông tin này - nếu bạn public lab lên nơi khác, nên đính
    kèm/liên kết file đó.
  - Vì đây là tìm kiếm tự động theo từ khoá, bạn nên tự mở lại ảnh trong
    SOURCES.md và xem qua trước khi dùng cho mục đích ngoài phạm vi học tập,
    để chắc chắn ảnh phù hợp (không dính logo/nhãn hiệu của hãng khác).
"""
import io
import json
import os
import sys
import time

try:
    import requests
    from PIL import Image
except ImportError:
    print("Thiếu thư viện. Chạy: pip install requests pillow")
    sys.exit(1)

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "products")
os.makedirs(OUT_DIR, exist_ok=True)

OPENVERSE_API = "https://api.openverse.org/v1/images/"
TARGET_SIZE = (800, 600)

# (product_id, danh mục, các truy vấn tìm kiếm - ưu tiên theo thứ tự)
PRODUCTS = [
    (1, "Bàn phím cơ", ["mechanical keyboard", "computer keyboard"]),
    (2, "Bàn phím cơ không dây", ["wireless keyboard", "mechanical keyboard"]),
    (3, "Chuột không dây", ["wireless mouse", "computer mouse"]),
    (4, "Chuột gaming", ["gaming mouse", "computer mouse"]),
    (5, "Tai nghe chụp tai", ["headphones", "over ear headphones"]),
    (6, "Tai nghe nhét tai", ["wireless earbuds", "earphones"]),
    (7, "Webcam", ["webcam", "computer camera"]),
    (8, "Màn hình máy tính", ["computer monitor", "pc monitor"]),
    (9, "Loa bluetooth", ["bluetooth speaker", "portable speaker"]),
    (10, "Lót chuột", ["mouse pad", "desk mat"]),
]

HEADERS = {"User-Agent": "PixelMart-Lab-ImageFetcher/1.0 (educational use)"}


def search_openverse(query, needed=3, tried=None):
    tried = tried or set()
    params = {
        "q": query,
        "license_type": "commercial",
        "mature": "false",
        "page_size": 20,
        "extension": "jpg,jpeg,png",
    }
    try:
        r = requests.get(OPENVERSE_API, params=params, headers=HEADERS, timeout=20)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        print(f"    [!] Lỗi tìm kiếm '{query}': {e}")
        return []

    results = []
    for item in data.get("results", []):
        url = item.get("url")
        if not url or url in tried:
            continue
        w, h = item.get("width") or 0, item.get("height") or 0
        if w and h and (w < 400 or h < 300):
            continue  # ảnh quá nhỏ, bỏ qua
        results.append(item)
        if len(results) >= needed:
            break
    return results


def center_crop_resize(img, size):
    img = img.convert("RGB")
    target_ratio = size[0] / size[1]
    w, h = img.size
    cur_ratio = w / h
    if cur_ratio > target_ratio:
        new_w = int(h * target_ratio)
        left = (w - new_w) // 2
        img = img.crop((left, 0, left + new_w, h))
    else:
        new_h = int(w / target_ratio)
        top = (h - new_h) // 2
        img = img.crop((0, top, w, top + new_h))
    return img.resize(size, Image.LANCZOS)


def download_image(url):
    r = requests.get(url, headers=HEADERS, timeout=25)
    r.raise_for_status()
    return Image.open(io.BytesIO(r.content))


def main():
    sources_log = []
    total_ok, total_fail = 0, 0

    for pid, label, queries in PRODUCTS:
        print(f"[{pid:>2}] {label} ...")
        collected = []
        seen_urls = set()
        for q in queries:
            if len(collected) >= 3:
                break
            found = search_openverse(q, needed=3 - len(collected), tried=seen_urls)
            for item in found:
                seen_urls.add(item["url"])
                collected.append(item)
            if len(collected) < 3:
                time.sleep(0.3)

        if not collected:
            print(f"    [!] Không tìm được ảnh phù hợp cho '{label}', giữ nguyên ảnh cũ.")
            continue

        for idx, item in enumerate(collected[:3], start=1):
            out_path = os.path.join(OUT_DIR, f"p{pid}_{idx}.jpg")
            try:
                img = download_image(item["url"])
                img = center_crop_resize(img, TARGET_SIZE)
                img.save(out_path, quality=87)
                print(f"    [OK] {out_path}  (nguồn: {item.get('foreign_landing_url', item['url'])})")
                sources_log.append({
                    "file": f"p{pid}_{idx}.jpg",
                    "product": label,
                    "title": item.get("title"),
                    "creator": item.get("creator"),
                    "license": f"{item.get('license', '?')} {item.get('license_version', '')}".strip(),
                    "source_page": item.get("foreign_landing_url"),
                    "direct_url": item.get("url"),
                })
                total_ok += 1
            except Exception as e:
                print(f"    [!] Lỗi tải ảnh {idx} cho '{label}': {e}")
                total_fail += 1
            time.sleep(0.2)

    sources_path = os.path.join(OUT_DIR, "SOURCES.md")
    with open(sources_path, "w", encoding="utf-8") as f:
        f.write("# Nguồn ảnh sản phẩm (tải tự động qua Openverse API)\n\n")
        f.write("Ảnh trong thư mục này được tìm và tải tự động bằng "
                "`scripts/fetch_real_product_images.py`, chỉ lấy ảnh có "
                "giấy phép cho phép dùng thương mại (CC0 / Public Domain / "
                "CC-BY / CC-BY-SA...). Vui lòng kiểm tra lại giấy phép từng "
                "ảnh trước khi dùng ngoài phạm vi học tập/demo nội bộ.\n\n")
        f.write("| File | Sản phẩm | Tiêu đề | Tác giả | Giấy phép | Trang nguồn |\n")
        f.write("|---|---|---|---|---|---|\n")
        for s in sources_log:
            f.write(
                f"| {s['file']} | {s['product']} | {s['title'] or ''} | "
                f"{s['creator'] or ''} | {s['license']} | "
                f"{s['source_page'] or s['direct_url']} |\n"
            )

    print(f"\nHoàn tất: {total_ok} ảnh tải thành công, {total_fail} lỗi.")
    print(f"Danh sách nguồn/giấy phép: {sources_path}")


if __name__ == "__main__":
    main()
