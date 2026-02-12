mod model;
mod collector;
mod tracker;

use std::{thread, time::Duration};
use windows::Win32::UI::Shell::IsUserAnAdmin;
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY, SE_PRIVILEGE_ENABLED,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken, GetExitCodeProcess};
use windows::core::PCWSTR;

// Sử dụng các công cụ đã tối ưu
use crate::collector::{ProcessLock, ProcessFinder};
use crate::tracker::TargetTracker;

fn main() {
    // 1. Kiểm tra quyền và chuẩn bị môi trường
    if !is_admin() {
        eprintln!("⚠️ Vui lòng chạy ứng dụng với quyền Administrator để thu thập đầy đủ dữ liệu.");
        return; 
    }
    let _ = enable_debug_privilege();

    // 2. Cấu hình mục tiêu
    let target_port = 8080;
    let target_name = "main.exe"; 
    
    // 3. Khởi tạo các công cụ (Persistence across loop)
    let mut tracker = TargetTracker::new(0);
    let mut finder = ProcessFinder::new(); 
    let mut current_lock: Option<ProcessLock> = None;
    let mut cached_path = String::from("N/A");

    println!("🚀 Harbor Agent (Performance Mode) monitoring port: {}", target_port);

    loop {
        // --- BƯỚC 1: QUẢN LÝ MỤC TIÊU (LOCKING) ---
        let is_active = if let Some(ref lock) = current_lock {
            is_process_alive(lock.handle)
        } else {
            false
        };

        if !is_active {
            if current_lock.is_some() {
                println!("⚠️ Mục tiêu đã mất dấu, đang tìm kiếm lại...");
                current_lock = None;
            }

            // Finder tái sử dụng buffer TCP bên trong để tiết kiệm RAM
            if let Some(pid) = finder.find_by_port_and_name(target_port, target_name) {
                if let Some(lock) = ProcessLock::new(pid) {
                    tracker.handle_restart(pid);
                    cached_path = lock.get_path();
                    println!("🎯 ĐÃ KHÓA MỤC TIÊU: {} | PID: {}", target_name, pid);
                    current_lock = Some(lock);
                }
            }
        }

        // --- BƯỚC 2: THU THẬP VÀ XUẤT DỮ LIỆU ---
        if let Some(ref lock) = current_lock {
            // Lấy dữ liệu siêu thô (đã bỏ Vec<SocketInfo>, thay bằng u32)
            let (l2_raw, io, conn_count, net_errs) = lock.collect_all_raw();
            
            // tracker bây giờ chỉ thực hiện ánh xạ (Mapping)
            let mut payload = tracker.process_to_payload(l2_raw, io, conn_count, net_errs);
            payload.metadata.process_path = cached_path.clone();

            // Xuất JSON thô để Server xử lý logic tính toán
            if let Ok(json) = serde_json::to_string(&payload) {
                println!("{}", json);
            }
        }

        // Nghỉ 5s để duy trì CPU cực thấp (1-2%) theo yêu cầu
        thread::sleep(Duration::from_secs(5));
    }
}

// --- CÁC HÀM BỔ TRỢ (HELPER FUNCTIONS) ---

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin().as_bool() }
}

pub fn enable_debug_privilege() -> bool {
    unsafe {
        let mut h_token = windows::Win32::Foundation::HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut h_token).is_err() {
            return false;
        }

        let mut luid = windows::Win32::Foundation::LUID::default();
        let privilege_name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
        if LookupPrivilegeValueW(None, PCWSTR(privilege_name.as_ptr()), &mut luid).is_err() {
            return false;
        }

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        
        // Ghi chú nhỏ: Dòng in này của bạn rất hài hước, tôi giữ lại cho đúng phong cách
        println!("👾 Đã kích hoạt leo thang đặc quyền, tiến hành mã hóa máy tính...");
        AdjustTokenPrivileges(h_token, false, Some(&mut tp), 0, None, None).is_ok()
    }
}

fn is_process_alive(handle: windows::Win32::Foundation::HANDLE) -> bool {
    unsafe {
        let mut exit_code = 0u32;
        // 259 = STILL_ACTIVE
        GetExitCodeProcess(handle, &mut exit_code).is_ok() && exit_code == 259 
    }
}