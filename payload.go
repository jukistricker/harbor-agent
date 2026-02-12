use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct HarborFullPayload {
    pub metadata: AgentMetadata,
    pub layer1_user_impact: UserImpactLayer,
    pub layer2_app_internals: AppInternalsLayer,
    pub layer3_dependencies: DependencyLayer,
    pub layer4_infra: InfraLayer,
    pub mode: String, // Idle, Normal, Hyper
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct AgentMetadata {
    pub agent_version: String,
    pub timestamp: u64,
    pub target_pid: u32,
    pub process_path: String,
    pub uptime_seconds: u64,
    pub restart_count: u32, // Tracking PID changes
}

// ✅ LAYER 1: USER IMPACT
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct UserImpactLayer {
    pub p95_latency_ms: f64,
    pub error_rate_percent: f32,
    pub apdex_score: f32,
    pub requests_per_second: f32,
}

// ✅ LAYER 2: APPLICATION INTERNALS (Deep Win32)
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct AppInternalsLayer {
    pub handle_count: u32,
    pub thread_count: u32,
    pub memory_private_bytes_mb: f64,
    pub memory_growth_rate_kb_sec: f64,
    pub context_switches_per_sec: u64, // Độ vất vả của CPU
    pub working_set_mb: f64,
}

// ✅ LAYER 3: DEPENDENCIES
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct DependencyLayer {
    pub db_latency_ms: f64,
    pub redis_latency_ms: f64,
    pub active_connections: u32,
    pub connection_pool_usage_percent: f32,
    pub dns_resolve_time_ms: f64,
}

// ✅ LAYER 4: INFRASTRUCTURE SIGNALS
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct InfraLayer {
    pub cpu_usage_percent: f32,
    pub disk_read_latency_ms: f64,
    pub disk_write_latency_ms: f64,
    pub network_in_errors: u64,
    pub network_out_errors: u64,
}