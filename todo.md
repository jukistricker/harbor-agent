# 📋 Harbor Agent Monitoring Strategy

## 1. Design Philosophy

### ✅ Find Once, Track Forever

Chỉ tốn chi phí **Discovery** một lần duy nhất.

### ✅ Resource Zen

-   RAM \< **50MB**
-   CPU \< **2%** trong điều kiện bình thường.

### ✅ Evidence-based

Mọi báo cáo về sức khỏe process phải dựa trên **OS execution handle**,
không dựa vào các chỉ số gián tiếp.

------------------------------------------------------------------------

## 2. Approach: Target Locking & Lifecycle Management

Thay vì dùng **Port** như một định danh lâu dài, Agent sử dụng chuỗi
chuyển đổi:

    Input (Port) → Lookup (PID) → Locking (Handle) → Monitoring (Metrics)

------------------------------------------------------------------------

### A. Discovery Phase (Quick Start)

**Trigger:**\
Khi Server gửi yêu cầu giám sát **Port X**

**Method:**\
Gọi `GetExtendedTcpTable` để ánh xạ:

    Port → PID

**Optimization:** - Chỉ chạy khi: - Bắt đầu monitoring - Hoặc mất kết
nối tới process mục tiêu

------------------------------------------------------------------------

### B. Locking Phase (Acquire Handle)

**Action:**\
Mở Process Handle với các quyền tối thiểu:

-   `PROCESS_QUERY_LIMITED_INFORMATION`\
    → Lấy RAM / CPU / IO

-   `SYNCHRONIZE`\
    → Biết chính xác **nano-giây process crash/tắt**

**Safety:**\
Lưu Handle vào một **state management struct**.

👉 Handle này là:

> 🎯 **Single Source of Truth**

------------------------------------------------------------------------

## 3. Monitoring Modes (State Machine)

Agent vận hành theo **3 trạng thái** để tối ưu tài nguyên.

------------------------------------------------------------------------

### 🟢 IDLE Mode --- Dashboard Inactive

**Frequency:** `15s`

**Responsibilities:** - Kiểm tra handle còn hiệu lực:

``` cpp
WaitForSingleObject(handle, 0)
```

**Payload:**

    PID, Status: Alive / Dead

👉 Chỉ gửi **Heartbeat**.

------------------------------------------------------------------------

### 🟡 NORMAL Mode --- Standard Monitoring

**Frequency:** `5s`

**Metrics:**

-   **CPU:** `process.cpu_usage()` (sysinfo)
-   **RAM:** `PrivateUsage`\
    \> Tránh Working Set vì bao gồm RAM dùng chung.
-   **Network:** TCP connect latency tới port đích.

------------------------------------------------------------------------

### 🔴 HYPER Mode --- Deep Health Scan

**Frequency:** `1s`

**Advanced Metrics:**

-   **Handle Count** → Phát hiện resource leak\
-   **I/O Counters** → Bytes/sec để tìm disk throttling\
-   **Context Switches** → Độ "vất vả" của CPU\
-   **Thread Count** → Phát hiện thread leak / deadlock

(Sử dụng `GetProcessInformation` như hiện tại.)

------------------------------------------------------------------------

## 4. Communication Strategy

  -----------------------------------------------------------------------
  Component         Proposed Solution                       Why
  ----------------- --------------------------------------- -------------
  Data Format       **MessagePack (mpack)**                 Nhẹ hơn JSON
                                                            \~30--50%,
                                                            serialize cực
                                                            nhanh

  Protocol          **WebSocket**                           Server có thể
                                                            push lệnh
                                                            (Mode Switch)
                                                            realtime

  Compression       **Zstd (level 1)**                      Giảm băng
                                                            thông khi cần
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 5. Core Windows APIs (Cheat Sheet)

### Lifecycle Management

-   `OpenProcess` → Khởi tạo tracking\
-   `GetExitCodeProcess` → Phân biệt crash vs normal exit

------------------------------------------------------------------------

### Deep Inspection

-   `GetProcessMemoryInfo` → Private bytes, page file\
-   `GetProcessIoCounters` → I/O chi tiết\
-   `GetProcessHandleCount` → Phát hiện handle leak

------------------------------------------------------------------------

### Networking

-   `GetExtendedTcpTable`\
    👉 **Chỉ dùng khi cần discovery lại PID**

------------------------------------------------------------------------

## 6. Critical Edge Cases

### ⚠️ Port Reuse

Process cũ chết → process mới chiếm port.

✅ Handle cũ sẽ báo **Dead**\
👉 Agent phải báo ngay, **không được lấy dữ liệu từ process mới**.

------------------------------------------------------------------------

### ⚠️ Privilege Issues

Không có quyền Admin → một số metrics bị từ chối.

👉 Agent cần hỗ trợ:

> 🟡 **Degraded Mode** --- vẫn chạy nhưng báo thiếu chỉ số.

------------------------------------------------------------------------

### ⚠️ Ghost Process

Process chết nhưng còn trong TCP table (`TIME_WAIT`).

✅ Handle tracking giải quyết triệt để.
