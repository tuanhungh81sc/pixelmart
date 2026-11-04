#!/bin/sh
set -e
# Khởi tạo DB sạch mỗi lần container start (đảm bảo lab luôn ở trạng thái ban đầu)
python -c "from app import init_db; init_db()"
exec python app.py
