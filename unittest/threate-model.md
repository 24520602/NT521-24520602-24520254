# Threat Model — `json_search()`

**Nhóm 03 — NT521 Lab 1 (Yêu cầu 3)**
**Framework sử dụng:** STRIDE
**Đối tượng phân tích:** hàm `json_search(key, input_object, role=None)` trong `recursive_json_search.py`, tra cứu trên dữ liệu JSON trả về từ một API giám sát hạ tầng mạng (mẫu trong `test_data.py`).

> Các security requirement rút ra từ threat model này được phát biểu và ánh xạ sang test ở `security-requirements.md`.

---

## 1. Bối cảnh sử dụng

`json_search()` nhận một `key` và một JSON object, duyệt đệ quy để trả về danh sách các cặp `key/value` khớp. Dữ liệu đầu vào là bản ghi sự kiện mạng từ hệ thống kiểu Cisco DNA Center. Cùng một bản ghi chứa lẫn lộn dữ liệu vô hại (mô tả sự cố) và dữ liệu nhạy cảm (chuỗi cộng đồng SNMP, IP quản trị). Vì vậy điểm kiểm soát an toàn phải nằm ngay tại hàm tra cứu, trước khi giá trị được trả cho lời gọi.

---

## 2. (a) Actor / Role được phép gọi hàm và mục đích

| Role       | Mục đích sử dụng hợp lệ                                                  | Trường được phép đọc (theo `policy.py`)                     |
|------------|-------------------------------------------------------------------------|------------------------------------------------------------|
| `admin`    | Vận hành, cấu hình, khắc phục sự cố ở mức cao nhất                        | `apiKey`, `managementIpAddress`, `issueSummary` (tất cả)   |
| `operator` | Theo dõi và xử lý sự cố vận hành, không chạm tới bí mật xác thực         | `managementIpAddress`, `issueSummary`                      |
| `viewer`   | Chỉ xem tình trạng/tóm tắt sự cố ở mức giám sát                          | `issueSummary`                                             |
| `None` / không xác định | Không phải actor hợp lệ                                     | Không được đọc trường nhạy cảm nào                          |

Mô hình phân quyền là **least privilege**: quyền tăng dần `viewer < operator < admin`, và mặc định là từ chối (deny by default) khi role không nằm trong danh sách cho phép.

---

## 3. (b) Asset nhạy cảm có thể xuất hiện trong dữ liệu trả về

Đối chiếu trực tiếp với `test_data.py`:

| Asset                      | Vị trí trong dữ liệu mẫu                                  | Giá trị mẫu                          | Mức nhạy cảm |
|----------------------------|----------------------------------------------------------|--------------------------------------|--------------|
| Chuỗi xác thực SNMP (`apiKey`) | `enrichmentInfo.connectedDevice[0].deviceDetails.apiKey` | `SNMP-COMMUNITY-STRING-7f3a9c`       | Cao (secret) |
| IP quản trị thiết bị (`managementIpAddress`) | `...deviceDetails.managementIpAddress`     | `10.10.20.21`                        | Trung bình   |
| Tóm tắt sự cố (`issueSummary`) | `...issueDetails.issue[0].issueSummary`               | `Network Device 10.10.20.82 Is Unreachable...` | Thấp |

`apiKey` (chuỗi cộng đồng SNMP) là asset cần bảo vệ nhất: lộ ra là để lộ credential điều khiển thiết bị mạng. `managementIpAddress` giúp kẻ tấn công định vị mặt phẳng quản trị. `issueSummary` là dữ liệu vận hành mức giám sát, ai cũng đọc được.

---

## 4. (c) Trust boundary bị bỏ qua nếu không kiểm tra role

Trust boundary nằm giữa **người gọi hàm (đã xác thực với một role nào đó)** và **kho dữ liệu JSON chứa lẫn secret**. `json_search()` là điểm gác (policy enforcement point) tại ranh giới này.

Phiên bản gốc của hàm không có tham số `role` và không tham chiếu `policy.py`, nên nó trả về **mọi** giá trị khớp `key` bất kể ai gọi. Trust boundary bị vô hiệu hóa: một `viewer` gọi `json_search("apiKey", data)` vẫn nhận được chuỗi SNMP. Việc phân quyền bị đẩy ngầm sang tầng gọi, trong khi tầng đó có thể không kiểm tra — đây chính là lỗ hổng cần đóng ở Bước 7 (thêm `role` và enforce theo `POLICY`).

---

## 5. (d) STRIDE — Threat Model

Trọng tâm bắt buộc là **Information Disclosure** và **Elevation of Privilege**.

| # | Loại STRIDE | Threat | Asset bị ảnh hưởng | Mức rủi ro | Đối phó |
|---|-------------|--------|--------------------|------------|---------|
| T1 | **Information Disclosure** | Role thấp (`viewer`/`operator`) gọi `json_search("apiKey", data)` và nhận được chuỗi cộng đồng SNMP do hàm không lọc theo role | `apiKey` | **Cao** | Enforce `POLICY` trong hàm; role không được phép → trả về `[]` |
| T2 | **Elevation of Privilege** | Người gọi ẩn danh (`role=None`) hoặc role rác vẫn đọc được trường chỉ dành cho `admin`, coi như tự nâng quyền qua hàm tra cứu | `apiKey`, `managementIpAddress` | **Cao** | Deny by default: role không hợp lệ / `None` → không trả trường nhạy cảm |
| T3 | Information Disclosure | `operator` truy cập `managementIpAddress` là hợp lệ, nhưng cần chặn `operator` đọc `apiKey` | `apiKey` | Trung bình | Kiểm tra theo từng key, không cấp trọn gói theo role |
| T4 | Tampering | Dữ liệu JSON đầu vào bị chỉnh sửa để chèn thêm khóa trùng tên `apiKey` ở nhánh lồng khác nhằm né bộ lọc | `apiKey` | Thấp–TB | Lọc theo key **sau khi** gom kết quả, áp policy cho mọi kết quả khớp bất kể độ sâu |
| T5 | Repudiation | Không ghi log ai truy cập trường nhạy cảm nên khó truy vết khi rò rỉ | Toàn bộ | Thấp | (Ngoài phạm vi hàm) khuyến nghị log lời gọi role→key nhạy cảm |

Hai threat bắt buộc: **T1 (Information Disclosure)** và **T2 (Elevation of Privilege)**.
