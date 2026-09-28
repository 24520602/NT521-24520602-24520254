# Security Requirements — `json_search()`

**Nhóm 03 — NT521 Lab 1 (Yêu cầu 3)**
**Đối tượng:** hàm `json_search(key, input_object, role=None)` trong `recursive_json_search.py`.
**Căn cứ:** các threat T1–T5 trong `threate-model.md` (STRIDE). File này phát biểu security requirement và ánh xạ sang security test (Yêu cầu 5).

---

## 1. Security Requirements

Phát biểu cụ thể, có thể kiểm chứng bằng unit test:

- **SR-1 (chống T1/T3):** Hệ thống chỉ trả về giá trị của một trường cho các role nằm trong danh sách được phép của trường đó trong `POLICY`. Ví dụ: `json_search("apiKey", data, role="viewer")` phải trả về `[]`.
- **SR-2 (chống T2):** Khi `role=None` hoặc role không tồn tại trong `POLICY[key]`, hàm không được trả về giá trị của trường nhạy cảm; kết quả cho trường đó phải rỗng.
- **SR-3 (least privilege):** `operator` được đọc `managementIpAddress` và `issueSummary` nhưng **không** được đọc `apiKey`; `json_search("apiKey", data, role="operator")` phải trả về `[]`.
- **SR-4 (quyền hợp lệ vẫn hoạt động):** `admin` gọi `json_search("apiKey", data, role="admin")` phải trả về giá trị `apiKey` (đảm bảo kiểm soát truy cập không phá vỡ chức năng đúng).
- **SR-5 (trường công khai):** Trường không nhạy cảm như `issueSummary` được trả về cho mọi role hợp lệ (`admin`, `operator`, `viewer`).

---

## 2. Ánh xạ requirement → security test (Yêu cầu 5)

| Security requirement | Threat liên quan | Test case gợi ý | Kỳ vọng |
|----------------------|------------------|-----------------|---------|
| SR-1 | T1 / T3 | `test_wrong_role_cannot_read_secret` → `json_search("apiKey", data, role="viewer")` | `[]` |
| SR-2 | T2 | `test_no_role_cannot_read_secret` → `json_search("apiKey", data, role=None)` | `[]` |
| SR-3 | T3 | `test_operator_cannot_read_apikey` → `json_search("apiKey", data, role="operator")` | `[]` |
| SR-4 | — | `test_admin_can_read_secret` → `json_search("apiKey", data, role="admin")` | không rỗng |
| SR-5 | — | `test_viewer_can_read_summary` → `json_search("issueSummary", data, role="viewer")` | không rỗng |
