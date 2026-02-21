use serde::{Serialize, Deserialize};

/// =======================================================
/// ROOT PAYLOAD
/// =======================================================

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct HarborFullPayload {
    pub metadata: AgentMetadata,

    pub system: SystemMetrics,          // OS level
    pub process: ProcessMetrics,        // Target process
    pub traffic: TrafficMetrics,        // App traffic (counter)
    pub latency: LatencyMetrics,        // Histogram
    pub runtime: Option<RuntimeMetrics>,// Optional runtime stats
    pub container: Option<ContainerMetrics>, // If running in container

    pub mode: String, // "process" | "system"
}

/// =======================================================
/// METADATA
/// =======================================================

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct AgentMetadata {
    pub agent_version: String,
    pub hostname: String,
    pub os: String,

    pub timestamp: u64,          // epoch millis
    pub uptime_seconds: u64,

    pub target_pid: u32,
    pub parent_pid: u32,
    pub process_path: String,
    pub cmdline: String,

    pub process_start_time: u64,
    pub restart_count: u32,
    pub last_exit_code: i32,
}

/// =======================================================
/// SYSTEM LEVEL (BẮT BUỘC)
/// =======================================================

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct SystemMetrics {
    pub cpu: SystemCpuMetrics,
    pub memory: SystemMemoryMetrics,
    pub disk: SystemDiskMetrics,
    pub network: SystemNetworkMetrics,
    pub stability: SystemStabilityMetrics,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct SystemCpuMetrics {
    pub user_percent: f32,
    pub system_percent: f32,
    pub iowait_percent: f32,
    pub steal_percent: f32,

    pub load_avg_1m: f32,
    pub load_avg_5m: f32,
    pub load_avg_15m: f32,

    pub run_queue_length: u32,

    pub context_switches_per_sec: f64,
    pub interrupts_per_sec: f64,
    pub softirq_total: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct SystemMemoryMetrics {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,

    pub swap_used_bytes: u64,

    pub page_faults_major_total: u64,
    pub page_faults_minor_total: u64,

    pub oom_kill_total: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct SystemDiskMetrics {
    pub read_bytes_total: u64,
    pub write_bytes_total: u64,

    pub read_iops_total: u64,
    pub write_iops_total: u64,

    pub queue_length: u32,
    pub latency_ms_avg: f32,

    pub fs_usage_percent: f32,
    pub inode_usage_percent: f32,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct SystemNetworkMetrics {
    pub rx_bytes_total: u64,
    pub tx_bytes_total: u64,

    pub rx_packets_total: u64,
    pub tx_packets_total: u64,

    pub dropped_packets_total: u64,
    pub retransmissions_total: u64,

    pub tcp_established: u32,
    pub tcp_time_wait: u32,
    pub syn_backlog_usage: u32,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct SystemStabilityMetrics {
    pub kernel_error_events_total: u64,
    pub dmesg_error_count: u64,
}

/// =======================================================
/// PROCESS LEVEL (CỰC KỲ QUAN TRỌNG)
/// =======================================================

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ProcessMetrics {
    pub cpu_percent: f32,
    pub memory_rss_bytes: u64,
    pub memory_virtual_bytes: u64,

    pub thread_count: u32,
    pub open_fds: u32,
    pub handle_count: u32,

    pub total_cpu_cycles: u64,

    pub zombie_children: u32,

    pub process_spawn_total: u64,
    pub process_exit_total: u64,
}

/// =======================================================
/// TRAFFIC (COUNTER ONLY)
/// =======================================================

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct TrafficMetrics {
    pub requests_total: u64,

    pub requests_success_total: u64,
    pub requests_client_error_total: u64,
    pub requests_server_error_total: u64,

    pub timeout_total: u64,
    pub retry_total: u64,

    pub bytes_in_total: u64,
    pub bytes_out_total: u64,

    pub connections_opened_total: u64,
    pub connections_closed_total: u64,
}

/// =======================================================
/// LATENCY (HISTOGRAM ONLY – DELTA BASED)
/// =======================================================

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct LatencyMetrics {
    pub ingress: LatencyBuckets,
    pub queue: LatencyBuckets,
    pub execution: LatencyBuckets,
    pub egress: LatencyBuckets,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct LatencyBuckets {
    pub lt_1ms: u64,
    pub lt_5ms: u64,
    pub lt_10ms: u64,
    pub lt_50ms: u64,
    pub lt_100ms: u64,
    pub lt_500ms: u64,
    pub lt_1s: u64,
    pub lt_2s: u64,
    pub lt_5s: u64,
    pub ge_5s: u64,
}

/// =======================================================
/// RUNTIME (OPTIONAL – CROSS LANGUAGE)
/// =======================================================

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct RuntimeMetrics {
    pub runtime_thread_count: u32,
    pub runtime_active_threads: u32,
    pub runtime_max_threads: u32,

    pub runtime_event_loop_latency_ms: f32,
    pub runtime_queue_depth: u32,
    pub runtime_backlog_size: u32,

    pub runtime_heap_alloc_bytes: u64,
    pub runtime_heap_used_bytes: u64,
    pub runtime_gc_pause_ms: f32,
    pub runtime_gc_count_total: u64,
}

/// =======================================================
/// CONTAINER (OPTIONAL)
/// =======================================================

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ContainerMetrics {
    pub container_cpu_percent: f32,
    pub container_memory_usage_bytes: u64,
    pub container_memory_limit_bytes: u64,

    pub container_fs_usage_percent: f32,
    pub container_restart_total: u64,

    pub cgroup_cpu_throttled_total: u64,
    pub container_rx_bytes_total: u64,
    pub container_tx_bytes_total: u64,
}

/// =======================================================
/// CONTROL CHANNEL
/// =======================================================

#[derive(Serialize, Deserialize, Debug)]
pub struct ControlCommand {
    pub action: String, // START | STOP | RELOAD
    pub port: Option<u32>,
    pub target: Option<String>,
}