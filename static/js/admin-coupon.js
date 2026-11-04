// static/js/admin-coupon.js
// JS cho khối "Mã giảm giá đang hoạt động" trên /admin (bảng điều khiển
// quản trị). Lưu ý: file tĩnh này được phục vụ qua cơ chế /static/ mặc
// định của Flask, giống mọi file static khác — nó KHÔNG được bảo vệ
// bởi admin_required_page(), dù chỉ được dùng trên trang đã được bảo
// vệ đó.

// Moi gia tri tu server deu phai duoc escape truoc khi dua vao innerHTML.
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str == null ? '' : String(str);
  return div.innerHTML;
}

async function loadAdminCoupon() {
  const box = document.getElementById('admin-coupon-box');
  const res = await fetch('/api/admin/coupon');
  if (!res.ok) {
    box.innerHTML = `Không có quyền truy cập (${res.status}).`;
    return;
  }
  const data = await res.json();
  box.innerHTML = `
    <div style="display:flex; align-items:center; gap:10px;">
      <span class="admin-coupon-code">${escapeHtml(data.code)}</span>
      <span class="verify-pill ${data.active ? 'yes' : 'no'}">${data.active ? 'Đang hoạt động' : 'Đã tắt'}</span>
    </div>
    <div class="muted text-sm" style="margin-top:6px;">Giảm ${escapeHtml(data.percent)}% mỗi lần áp dụng.</div>
  `;
}

loadAdminCoupon();
