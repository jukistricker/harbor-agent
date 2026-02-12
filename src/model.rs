use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct HarborFullPayload {
    pub metadata: AgentMetadata,
    // pub layer1_user_impact: UserImpactLayer,
    pub layer2_raw: AppInternalsRaw,
    pub layer3_raw: DependencyRaw,
    pub layer4_raw: InfraRaw,
    pub mode: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct AgentMetadata {
    pub agent_version: String,
    pub timestamp: u64,      // Thời điểm lấy mẫu (Server dùng để tính delta_time)
    pub target_pid: u32,
    pub process_path: String,
    pub uptime_seconds: u64,
    pub restart_count: u32, // Tracking PID changes
}

// LAYER 1: USER IMPACT
// #[derive(Serialize, Deserialize, Debug, Default)]
// pub struct UserImpactLayer {
//     pub p95_latency_ms: f64,
//     pub error_rate_percent: f32,
//     pub apdex_score: f32,
//     pub requests_per_second: f32,
// }

// LAYER 2: APPLICATION INTERNALS (Deep Win32)
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct AppInternalsRaw {
    pub handle_count: u32,
    pub thread_count: u32,
    pub memory_private_bytes: u64, // Đổi sang bytes (u64) thay vì MB (f64) để tránh chia ở Agent
    pub working_set_bytes: u64,    // Gửi thô từ Win32 API
    pub total_cycles: u64,        
}

// LAYER 3: DEPENDENCIES
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct DependencyRaw {
    // pub db_latency_ms: f64,
    // pub redis_latency_ms: f64,
    pub active_connections: u32,
    // pub connection_pool_usage_percent: f32,
    // pub dns_resolve_time_ms: f64,
}

// LAYER 4: INFRASTRUCTURE SIGNALS
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct InfraRaw {
    // pub cpu_usage_percent: f32,       // Server sẽ tính
    pub disk_read_bytes: u64,      // Tương ứng với ReadTransferCount
    pub disk_write_bytes: u64,     // Tương ứng với WriteTransferCount
    pub net_in_errors: u64,
    pub net_out_errors: u64,
}