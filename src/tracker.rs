use std::time::{Instant, SystemTime, UNIX_EPOCH};
use crate::model::{
    AgentMetadata, AppInternalsRaw, DependencyRaw, HarborFullPayload, InfraRaw
};
use windows::Win32::System::Threading::IO_COUNTERS;

/// 🧠 TRẠNG THÁI NỘI BỘ: Chỉ giữ lại những gì thực sự cần để duy trì danh tính Agent
pub struct TargetTracker {
    pub restart_count: u32,
    pub start_time: Instant,
    pub current_pid: u32,
}

impl TargetTracker {
    pub fn new(pid: u32) -> Self {
        Self {
            restart_count: 0,
            start_time: Instant::now(),
            current_pid: pid,
        }
    }

    /// Phát hiện Restart dựa trên PID
    pub fn handle_restart(&mut self, new_pid: u32) {
        if self.current_pid != 0 && self.current_pid != new_pid {
            self.restart_count += 1;
            self.start_time = Instant::now();
        }
        self.current_pid = new_pid;
    }

    pub fn build_metadata(&self) -> AgentMetadata {
        AgentMetadata {
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            target_pid: self.current_pid,
            process_path: String::from("N/A"), // Sẽ gán lại ở hàm main
            uptime_seconds: self.start_time.elapsed().as_secs(),
            restart_count: self.restart_count,
        }
    }

    /// Gom dữ liệu thô vào Payload mà KHÔNG thực hiện bất kỳ phép tính số thực nào
    // tracker.rs
    pub fn process_to_payload(
        &mut self, 
        l2_raw: AppInternalsRaw, 
        io: IO_COUNTERS, 
        conn_count: u32, 
        net_errs: (u64, u64)
    ) -> HarborFullPayload {
        
        let infra = InfraRaw {
            disk_read_bytes: io.ReadTransferCount,
            disk_write_bytes: io.WriteTransferCount,
            net_in_errors: net_errs.0,
            net_out_errors: net_errs.1,
        };

        let dep = DependencyRaw {
            active_connections: conn_count,
        };

        HarborFullPayload {
            metadata: self.build_metadata(),
            layer2_raw: l2_raw, 
            layer3_raw: dep,
            layer4_raw: infra,
            mode: String::from("Normal"),
        }
    }
}