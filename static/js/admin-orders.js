// static/js/admin-orders.js
// JS cho trang quản lý đơn hàng (/admin/orders). Lưu ý: file tĩnh này
// được phục vụ qua cơ chế /static/ mặc định của Flask, giống mọi file
// static khác — nó KHÔNG được bảo vệ bởi admin_required_page(), dù chỉ
// được dùng trên trang đã được bảo vệ đó.

// Moi gia tri den tu server (username, ghi chu...) deu PHAI duoc escape
// truoc khi dua vao innerHTML - day la DOM, Jinja autoescape KHONG ap
// dung o day. Khong lam vay se mo ra mot XSS luu tru moi (ngoai y muon,
// khong thuoc bo 2 lo hong chinh thuc cua lab).
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str == null ? '' : String(str);
  return div.innerHTML;
}

async function loadAdminOrders() {
  const tbody = document.getElementById('admin-orders-tbody');
  const res = await fetch('/api/admin/orders');
  if (!res.ok) {
    tbody.innerHTML = `<tr><td colspan="7" class="muted">Không có quyền truy cập (${res.status}).</td></tr>`;
    return;
  }
  const data = await res.json();
  if (!data.orders.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="muted">Chưa có đơn hàng nào.</td></tr>';
    return;
  }
  tbody.innerHTML = data.orders.map(o => `
    <tr id="order-row-${o.id}">
      <td>#${o.id}</td>
      <td>${escapeHtml(o.username)} (${escapeHtml(o.full_name)})</td>
      <td>${Number(o.final_price).toLocaleString('vi-VN')}đ</td>
      <td>${escapeHtml(o.payment_method)}</td>
      <td><span class="verify-pill ${o.payment_verified ? 'yes' : 'no'}" id="verify-pill-${o.id}">${o.payment_verified ? 'Đã xác minh' : 'Chưa xác minh'}</span></td>
      <td><input class="admin-note-input" id="note-${o.id}" value="${escapeHtml(o.admin_note)}" placeholder="Ghi chú..."></td>
      <td><button class="btn btn-primary btn-xs" onclick="verifyOrderPayment(${o.id})">Xác minh thanh toán</button></td>
    </tr>
  `).join('');
}

// Admin bấm nút này để xác minh thanh toán + lưu ghi chú nội bộ cho MỘT
// đơn hàng cụ thể. Gọi thẳng đến API quản trị tương ứng.
async function verifyOrderPayment(orderId) {
  const note = document.getElementById(`note-${orderId}`).value;
  const res = await fetch(`/api/admin/orders/${orderId}/update-status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ payment_verified: true, admin_note: note }),
  });
  const data = await res.json();
  const msg = document.getElementById('admin-orders-msg');
  if (res.ok) {
    document.getElementById(`verify-pill-${orderId}`).textContent = 'Đã xác minh';
    document.getElementById(`verify-pill-${orderId}`).className = 'verify-pill yes';
    msg.style.color = 'var(--success)';
    msg.textContent = `Đã xác minh thanh toán cho đơn #${orderId}.`;
  } else {
    msg.style.color = 'var(--danger)';
    msg.textContent = data.error || 'Có lỗi xảy ra.';
  }
}

loadAdminOrders();
