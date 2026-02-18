mod model;
mod collector;
mod tracker;

use std::{ time::Duration};
use windows::Win32::UI::Shell::IsUserAnAdmin;
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY, SE_PRIVILEGE_ENABLED,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken, GetExitCodeProcess};
use windows::core::PCWSTR;

use clap::{Parser, Subcommand};
use std::process::Command;
use futures_util::{StreamExt,SinkExt};
use tokio_tungstenite::connect_async;

// Sử dụng các công cụ đã tối ưu
use crate::collector::{ProcessLock, ProcessFinder};
use crate::tracker::TargetTracker;
use crate::model::{
    ControlCommand
};

#[derive(Parser)]
#[command(name = "HarborAgent", version = "0.2.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Cài đặt Agent vào Windows Service & Env
    Install { #[arg(short, long)] url: String },
    /// Gỡ bỏ Agent khỏi hệ thống
    Uninstall,
    /// Chạy Agent (Dùng cho Service hoặc Debug)
    Run,
}


#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() == 1 {
        // Kiểm tra quyền Admin trước khi làm bất cứ việc gì
        if !is_admin() {
            println!("❌ Quyền Admin là bắt buộc. Vui lòng chạy với tư cách Administrator.");
            return;
        }

        // Kiểm tra cấu hình URL
        if std::env::var("HARBOR_SERVER_URL").is_err() {
            println!("✨ Chào mừng bạn đến với Harbor Agent!");
            println!("---------------------------------------");
            println!("Nhập URL của Server Go (Ví dụ: ws://127.0.0.1:8088/ws):");
            
            let mut input_url = String::new();
            std::io::stdin().read_line(&mut input_url).expect("Không đọc được input");
            let input_url = input_url.trim().to_string();

            if input_url.is_empty() {
                println!("❌ URL không được để trống.");
                return;
            }
            install_agent(&input_url);
        }

        println!("🚀 Đang khởi động Agent ở chế độ nền...");
        run_agent_service().await;
    } else {
        let cli = Cli::parse();
        match &cli.command {
            Commands::Install { url } => install_agent(url),
            Commands::Uninstall => uninstall_agent(),
            Commands::Run => run_agent_service().await,
        }
    }
}

async fn run_agent_service() {
    if !is_admin() { return; }
    let _ = enable_debug_privilege();

    let server_url = std::env::var("HARBOR_SERVER_URL")
        .unwrap_or_else(|_| "ws://127.0.0.1:8088/ws".to_string());

    let (tx_control, mut rx_control) = tokio::sync::mpsc::unbounded_channel::<Option<(u32, String)>>();
    let (tx_data, mut rx_data) = tokio::sync::mpsc::unbounded_channel::<String>();

    // --- LUỒNG 1: WORKER (Giữ nguyên logic của bạn nhưng tối ưu) ---
    let tx_data_clone = tx_data.clone();
    tokio::spawn(async move {
        let mut tracker = TargetTracker::new(0);
        let mut finder = ProcessFinder::new();
        let mut current_lock: Option<ProcessLock> = None;
        let mut active_config: Option<(u32, String)> = None;

        loop {
            // Kiểm tra lệnh điều khiển mới
            while let Ok(new_cfg) = rx_control.try_recv() {
                if new_cfg.is_none() {
                    println!("💤 Đã nhận lệnh STOP, dừng thu thập.");
                    current_lock = None; // Giải phóng Handle ngay lập tức
                }
                active_config = new_cfg;
            }

            if let Some((port, name)) = &active_config {
                // Logic kiểm tra process và gửi data
                let is_active = if let Some(ref lock) = current_lock {
                    is_process_alive(lock.handle)
                } else { false };

                if !is_active {
                    if let Some(pid) = finder.find_by_port_and_name(*port as u16, name) {
                        if let Some(lock) = ProcessLock::new(pid) {
                            tracker.handle_restart(pid);
                            current_lock = Some(lock);
                            println!("🎯 ĐÃ KHÓA MỤC TIÊU: {} (PID: {})", name, pid);
                        }
                    }
                }

                if let Some(ref lock) = current_lock {
                    let (l2, io, conn, net) = lock.collect_all_raw();
                    let mut payload = tracker.process_to_payload(l2, io, conn, net);
                    payload.metadata.process_path = lock.get_path();
                    
                    if let Ok(json) = serde_json::to_string(&payload) {
                        let _ = tx_data_clone.send(json);
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    // --- LUỒNG 2: KẾT NỐI & RECONNECT ---
    let mut sleep_dur = 10; 
    let mut count = 0;
    loop {
        println!("📡 Đang kết nối tới Server: {}...", server_url);
        match connect_async(&server_url).await {
            Ok((ws_stream, _)) => {
                println!("✅ Đã kết nối! Trạng thái: Idle.");
                let (mut ws_sender, mut ws_receiver) = ws_stream.split();

                loop {
                    tokio::select! {
                        msg = ws_receiver.next() => {
                            match msg {
                                Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
                                    if let Ok(cmd) = serde_json::from_str::<ControlCommand>(&text) {
                                        match cmd.action.as_str() {
                                            "START" => {
                                                if let (Some(p), Some(t)) = (cmd.port, cmd.target) {
                                                    println!("🚀 START: Port {} - {}", p, t);
                                                    let _ = tx_control.send(Some((p, t)));
                                                }
                                            },
                                            "STOP" => { 
                                                let _ = tx_control.send(None); 
                                            },
                                            _ => {}
                                        }
                                    }
                                }
                                _ => {
                                    println!("🔌 Mất kết nối WebSocket.");
                                    let _ = tx_control.send(None); // Dừng worker khi mất kết nối
                                    break; 
                                }
                            }
                        }
                        Some(json_payload) = rx_data.recv() => {
                            let _ = ws_sender.send(tokio_tungstenite::tungstenite::Message::Text(json_payload)).await;
                        }
                    }
                }
            }
            Err(e) => {
                if count <=60 {
                    count += 1;
                    sleep_dur+=10;
                }
                eprintln!("❌ Lỗi kết nối: {}. Thử lại sau {sleep_dur}s...", e);
            }
        }
        
        tokio::time::sleep(Duration::from_secs(sleep_dur)).await;
    }
}

// --- QUẢN LÝ HỆ THỐNG (INSTALL / UNINSTALL) ---
fn install_agent(url: &String) {
    println!("📦 Đang cấu hình Harbor Agent...");
    
    // Ghi Registry vĩnh viễn
    let _ = Command::new("setx")
        .args(["HARBOR_SERVER_URL", url, "/M"])
        .status();

    // Cập nhật biến môi trường cho phiên làm việc hiện tại của chính nó
    std::env::set_var("HARBOR_SERVER_URL", url);

    let exe_path = std::env::current_exe().expect("Không lấy được đường dẫn exe");
    let bin_path = format!("\"{}\" run", exe_path.display());
    
    // Tạo Service Windows
    let _ = Command::new("sc")
        .args(["create", "HarborAgent", &format!("binPath= {}", bin_path), "start=", "auto"])
        .status();
        
    let _ = Command::new("sc")
        .args(["description", "HarborAgent", "Giám sát hiệu năng Solo Dev Mode"])
        .status();

    // Khởi động service
    let _ = Command::new("net").args(["start", "HarborAgent"]).status();

    println!("🚀 Cài đặt thành công! Agent đã được đăng ký chạy ngầm cùng Windows.");
}

fn uninstall_agent() {
    // 1. Dừng và xóa Service
    let _ = Command::new("net").args(["stop", "HarborAgent"]).status();
    let _ = Command::new("sc").args(["delete", "HarborAgent"]).status();

    // 2. XÓA BIẾN MÔI TRƯỜNG TRONG REGISTRY
    // Lệnh REG DELETE sẽ xóa tận gốc biến này
    let _ = Command::new("reg")
        .args(["delete", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "/v", "HARBOR_SERVER_URL", "/f"])
        .status();

    println!("🗑️ Đã gỡ bỏ Harbor Agent và xóa cấu hình Registry sạch sẽ.");
    println!("⚠️ Lưu ý: Biến môi trường chỉ thực sự biến mất ở phiên làm việc mới.");
}


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