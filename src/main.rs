mod collector;
mod model;
mod tracker;
mod pdh_system;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;

use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::IsUserAnAdmin;
use windows::core::PCWSTR;

use clap::{Parser, Subcommand};

use crate::model::ControlCommand;
use crate::tracker::AgentLoop;

// =============================================================================
// CLI
// =============================================================================

#[derive(Parser)]
#[command(name = "HarborAgent", version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Cai dat Agent vao Windows Service
    Install {
        #[arg(short, long)]
        url: String,
    },
    /// Go bo Agent khoi he thong
    Uninstall,
    /// Chay Agent (dung cho Service hoac debug)
    Run,
}

// =============================================================================
// ENTRY POINT
// =============================================================================

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() == 1 {
        // Chay truc tiep khong co subcommand: huong dan setup
        if !is_admin() {
            eprintln!("Quyen Admin la bat buoc. Vui long chay voi tu cach Administrator.");
            return;
        }

        if std::env::var("HARBOR_SERVER_URL").is_err() {
            println!("Nhap URL cua Server (Vi du: ws://127.0.0.1:8088/ws):");
            let mut url = String::new();
            std::io::stdin().read_line(&mut url).expect("Khong doc duoc input");
            let url = url.trim().to_string();
            if url.is_empty() {
                eprintln!("URL khong duoc de trong.");
                return;
            }
            install_agent(&url);
        }

        run_agent_service().await;
        return;
    }

    let cli = Cli::parse();
    match &cli.command {
        Commands::Install { url } => install_agent(url),
        Commands::Uninstall => uninstall_agent(),
        Commands::Run => {
            if !is_admin() {
                eprintln!("Quyen Admin la bat buoc.");
                return;
            }
            run_agent_service().await;
        }
    }
}

// =============================================================================
// CORE SERVICE
// =============================================================================

async fn run_agent_service() {
    let _ = enable_debug_privilege();

    let server_url = std::env::var("HARBOR_SERVER_URL")
        .unwrap_or_else(|_| "ws://127.0.0.1:8088/ws".to_string());

    // Channel: server -> worker (lệnh START/STOP)
    // Option<(port, name)>: Some = START, None = STOP
    let (tx_control, rx_control) = mpsc::unbounded_channel::<Option<(u16, String)>>();

    // Channel: worker -> websocket (json payload)
    let (tx_data, rx_data) = mpsc::unbounded_channel::<String>();

    // Shutdown signal dung chung giua worker va ws loop
    let shutdown = Arc::new(AtomicBool::new(false));

    // Spawn worker thread rieng (blocking loop, khong dung tokio thread)
    let shutdown_worker = Arc::clone(&shutdown);
    let tx_data_worker = tx_data.clone();
    std::thread::spawn(move || {
        worker_loop(rx_control, tx_data_worker, shutdown_worker);
    });

    // WS loop chay tren tokio
    ws_loop(server_url, tx_control, rx_data, shutdown).await;
}

// =============================================================================
// WORKER LOOP - chay tren OS thread rieng, khong block tokio runtime
// =============================================================================

fn worker_loop(
    mut rx_control: mpsc::UnboundedReceiver<Option<(u16, String)>>,
    tx_data: mpsc::UnboundedSender<String>,
    shutdown: Arc<AtomicBool>,
) {
    let collect_interval = Duration::from_secs(5);

    // Trang thai hien tai: chua co target
    let mut agent_loop: Option<AgentLoop> = None;
    let mut active_config: Option<(u16, String)> = None;

    while !shutdown.load(Ordering::Relaxed) {
        // --- Nhan lenh dieu khien (non-blocking drain) ---
        while let Ok(cmd) = rx_control.try_recv() {
            match cmd {
                Some((port, name)) => {
                    println!("START: port={} name={}", port, name);
                    agent_loop = Some(AgentLoop::new(
                        0, // PID se duoc tim qua finder
                        name.clone(),
                        port,
                        collect_interval,
                    ));
                    active_config = Some((port, name));
                }
                None => {
                    println!("STOP: dung thu thap.");
                    agent_loop = None;
                    active_config = None;
                }
            }
        }

        // --- Collect va gui neu dang active ---
        if let Some(ref mut aloop) = agent_loop {
            let shutdown_inner = Arc::new(AtomicBool::new(false));
            let tx = tx_data.clone();

            // Chay 1 iteration cua AgentLoop: collect 1 lan roi tra ve
            aloop.run_once(|payload| {
                match serde_json::to_string(&payload) {
                    Ok(json) => {
                        if tx.send(json).is_err() {
                            // WS da dong, ghi log nhung khong crash
                            eprintln!("WS channel closed, payload dropped.");
                        }
                    }
                    Err(e) => eprintln!("Serialize error: {}", e),
                }
            });
        }

        std::thread::sleep(collect_interval);
    }
}

// =============================================================================
// WEBSOCKET LOOP - reconnect co backoff
// =============================================================================

async fn ws_loop(
    server_url: String,
    tx_control: mpsc::UnboundedSender<Option<(u16, String)>>,
    mut rx_data: mpsc::UnboundedReceiver<String>,
    shutdown: Arc<AtomicBool>,
) {
    let mut backoff_secs: u64 = 2;
    const MAX_BACKOFF: u64 = 60;

    while !shutdown.load(Ordering::Relaxed) {
        println!("Dang ket noi toi: {}", server_url);

        match connect_async(&server_url).await {
            Ok((ws_stream, _)) => {
                println!("Ket noi thanh cong.");
                backoff_secs = 2; // reset backoff khi ket noi thanh cong

                let (mut ws_sender, mut ws_receiver) = ws_stream.split();

                let result = tokio::select! {
                    // Nhan lenh tu server
                    r = handle_incoming(&mut ws_receiver, &tx_control) => r,
                    // Gui payload len server
                    r = handle_outgoing(&mut ws_sender, &mut rx_data) => r,
                };

                match result {
                    Err(e) => eprintln!("WS error: {}. Dang ket noi lai...", e),
                    Ok(_) => {}
                }

                // Mat ket noi: yeu cau worker tam dung
                let _ = tx_control.send(None);
            }
            Err(e) => {
                eprintln!("Loi ket noi: {}. Thu lai sau {}s...", e, backoff_secs);
            }
        }

        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF);
    }
}

async fn handle_incoming(
    ws_receiver: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    tx_control: &mpsc::UnboundedSender<Option<(u16, String)>>,
) -> Result<(), String> {
    while let Some(msg) = ws_receiver.next().await {
        match msg {
            Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                match serde_json::from_str::<ControlCommand>(&text) {
                    Ok(cmd) => handle_command(cmd, tx_control),
                    Err(e) => eprintln!("Lenh khong hop le: {} | raw: {}", e, text),
                }
            }
            Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => {
                return Err("Server dong ket noi.".to_string());
            }
            Err(e) => return Err(e.to_string()),
            _ => {} // Ping/Pong/Binary: bo qua
        }
    }
    Err("WS stream ket thuc.".to_string())
}

async fn handle_outgoing(
    ws_sender: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tokio_tungstenite::tungstenite::Message,
    >,
    rx_data: &mut mpsc::UnboundedReceiver<String>,
) -> Result<(), String> {
    while let Some(json) = rx_data.recv().await {
        ws_sender
            .send(tokio_tungstenite::tungstenite::Message::Text(json))
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn handle_command(
    cmd: ControlCommand,
    tx_control: &mpsc::UnboundedSender<Option<(u16, String)>>,
) {
    match cmd.action.as_str() {
        "START" => {
            match (cmd.port, cmd.target) {
                (Some(port), Some(name)) if port <= u16::MAX as u32 => {
                    println!("Lenh START: port={} target={}", port, name);
                    let _ = tx_control.send(Some((port as u16, name)));
                }
                _ => eprintln!("START thieu port hoac target."),
            }
        }
        "STOP" => {
            println!("Lenh STOP.");
            let _ = tx_control.send(None);
        }
        other => eprintln!("Lenh khong ro: {}", other),
    }
}

// =============================================================================
// INSTALL / UNINSTALL
// =============================================================================

fn install_agent(url: &str) {
    use std::process::Command;

    println!("Dang cai dat Harbor Agent...");

    let _ = Command::new("setx")
        .args(["HARBOR_SERVER_URL", url, "/M"])
        .status();
    std::env::set_var("HARBOR_SERVER_URL", url);

    let exe = std::env::current_exe().expect("Khong lay duoc duong dan exe");
    let bin_path = format!("\"{}\" run", exe.display());

    let _ = Command::new("sc")
        .args(["create", "HarborAgent", &format!("binPath= {}", bin_path), "start=", "auto"])
        .status();
    let _ = Command::new("sc")
        .args(["description", "HarborAgent", "Harbor Performance Monitor"])
        .status();
    let _ = Command::new("net").args(["start", "HarborAgent"]).status();

    println!("Cai dat thanh cong. Agent dang chay ngam.");
}

fn uninstall_agent() {
    use std::process::Command;

    let _ = Command::new("net").args(["stop", "HarborAgent"]).status();
    let _ = Command::new("sc").args(["delete", "HarborAgent"]).status();
    let _ = Command::new("reg").args([
        "delete",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
        "/v", "HARBOR_SERVER_URL",
        "/f",
    ]).status();

    println!("Da go bo Harbor Agent.");
}

// =============================================================================
// SYSTEM HELPERS
// =============================================================================

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin().as_bool() }
}

pub fn enable_debug_privilege() -> bool {
    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .is_err()
        {
            return false;
        }

        let mut luid = windows::Win32::Foundation::LUID::default();
        let name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
        if LookupPrivilegeValueW(None, PCWSTR(name.as_ptr()), &mut luid).is_err() {
            return false;
        }

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        println!("Đã kích hoạt leo thang đặc quyền, tiến hành mã hóa máy tính...");
        AdjustTokenPrivileges(token, false, Some(&mut tp), 0, None, None).is_ok()
    }
}