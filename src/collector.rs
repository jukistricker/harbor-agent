// collector.rs
// Generic Windows collector -> maps thang vao HarborFullPayload
use crate::pdh_system::PdhSystemCollector;
use std::cell::RefCell;
use std::mem;
use std::time::{SystemTime, UNIX_EPOCH};

use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetExtendedTcpTable, GetIfTable2, MIB_IF_TABLE2, MIB_TCPTABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
};

use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows::Win32::System::Threading::{
    GetProcessHandleCount, GetProcessIoCounters, GetProcessTimes, OpenProcess,
    PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    IO_COUNTERS,
};

use sysinfo::{CpuRefreshKind, Disks, Pid, ProcessRefreshKind, RefreshKind, System};

use crate::model::{
    AgentMetadata, ContainerMetrics, HarborFullPayload, LatencyBuckets, LatencyMetrics,
    ProcessMetrics, RuntimeMetrics, SystemCpuMetrics, SystemDiskMetrics, SystemMemoryMetrics,
    SystemMetrics, SystemNetworkMetrics, SystemStabilityMetrics, TrafficMetrics,
};

// =============================================================================
// STATE: giu raw counter cua lan truoc de tinh DELTA
// =============================================================================

#[derive(Default)]
struct CounterSnapshot {
    cpu_ticks: u64,
    io_read_bytes: u64,
    io_write_bytes: u64,
    timestamp_ms: u64,
    net_rx_bytes: u64,
    net_tx_bytes: u64,
    net_rx_packets: u64,
    net_tx_packets: u64,
    net_dropped: u64,
    net_retrans: u64,
    disk_read_bytes: u64,
    disk_write_bytes: u64,
    disk_read_ops: u64,
    disk_write_ops: u64,
}

// =============================================================================
// ProcessFinder - tim PID qua port + ten process
// =============================================================================

pub struct ProcessFinder {
    buffer: Vec<u8>,
}

impl ProcessFinder {
    pub fn new() -> Self {
        Self { buffer: vec![0u8; 8192] }
    }

    pub fn find_by_port_and_name(&mut self, target_port: u16, target_name: &str) -> Option<u32> {
        let mut dw_size = self.buffer.len() as u32;
        let target_lower = target_name.to_lowercase();

        unsafe {
            let mut ret = GetExtendedTcpTable(
                Some(self.buffer.as_mut_ptr() as *mut _),
                &mut dw_size,
                false,
                2,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if ret == 122 {
                self.buffer.resize(dw_size as usize, 0);
                ret = GetExtendedTcpTable(
                    Some(self.buffer.as_mut_ptr() as *mut _),
                    &mut dw_size,
                    false,
                    2,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );
            }
            if ret != 0 {
                return None;
            }

            let table = &*(self.buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let entries = std::slice::from_raw_parts(
                table.table.as_ptr(),
                table.dwNumEntries as usize,
            );
            for row in entries {
                if u16::from_be(row.dwLocalPort as u16) == target_port {
                    let pid = row.dwOwningPid;
                    if pid == 0 {
                        continue;
                    }
                    if let Some(handle) = Collector::open_handle(pid) {
                        let path = get_process_path(handle);
                        // Dong handle ngay sau khi dung xong trong finder
                        let _ = CloseHandle(handle);
                        if path.to_lowercase().contains(&target_lower) {
                            return Some(pid);
                        }
                    }
                }
            }
        }
        None
    }
}

// =============================================================================
// Collector - agent duy nhat, generic, stateful
// =============================================================================

pub struct Collector {
    pub pid: u32,
    handle: HANDLE,
    // Fix: kieu la System, khong phai 's'
    sys: RefCell<System>,
    prev: RefCell<CounterSnapshot>,
    pdh: PdhSystemCollector,

    // Metadata co dinh - chi doc 1 lan khi khoi tao
    agent_version: String,
    hostname: String,
    os_name: String,
    process_path: String,
    cmdline: String,
    process_start_time: u64,
    restart_count: u32,
    last_exit_code: i32,
}

impl Collector {
    /// Mo process handle. Tra None neu khong co quyen.
    pub(crate) fn open_handle(pid: u32) -> Option<HANDLE> {
        unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()
        }
    }

    pub fn new(
        pid: u32,
        agent_version: impl Into<String>,
        restart_count: u32,
        last_exit_code: i32,
    ) -> Option<Self> {
        let handle = Self::open_handle(pid)?;

        let sys = System::new_with_specifics(
            RefreshKind::new()
                .with_cpu(CpuRefreshKind::everything())
                .with_processes(ProcessRefreshKind::everything()),
        );
        let pdh = PdhSystemCollector::new()
            .expect("Failed to init PDH collector");

        let process_path = get_process_path(handle);
        let hostname = System::host_name().unwrap_or_default();
        let os_name = System::long_os_version().unwrap_or_default();

        // cmdline - lay tu sysinfo de dam bao cung nguon voi process_path (cung refresh_process truoc)
        let mut sys_tmp = System::new();
        sys_tmp.refresh_process(Pid::from(pid as usize));
        let cmdline = sys_tmp
            .process(Pid::from(pid as usize))
            .map(|p| {
                p.cmd()
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();

        let process_start_time = sys_tmp
            .process(Pid::from(pid as usize))
            .map(|p| p.start_time())
            .unwrap_or(0);

        Some(Self {
            pid,
            handle,
            sys: RefCell::new(sys),
            prev: RefCell::new(CounterSnapshot::default()),
            pdh,
            agent_version: agent_version.into(),
            hostname,
            os_name,
            process_path,
            cmdline,
            process_start_time,
            restart_count,
            last_exit_code,
        })
    }

    // =========================================================================
    // PUBLIC: thu thap toan bo -> HarborFullPayload
    // =========================================================================

    pub fn collect(&self) -> HarborFullPayload {
        let now_ms = epoch_ms();
        let mut sys = self.sys.borrow_mut();

        sys.refresh_cpu_specifics(CpuRefreshKind::everything());
        sys.refresh_memory();
        sys.refresh_process_specifics(
            Pid::from(self.pid as usize),
            ProcessRefreshKind::everything(),
        );

        let mut prev = self.prev.borrow_mut();
        let elapsed_ms = now_ms.saturating_sub(prev.timestamp_ms).max(1);

        // Metadata
        let metadata = AgentMetadata {
            agent_version: self.agent_version.clone(),
            hostname: self.hostname.clone(),
            os: self.os_name.clone(),
            timestamp: now_ms,
            uptime_seconds: System::uptime(),
            target_pid: self.pid,
            parent_pid: sys
                .process(Pid::from(self.pid as usize))
                .and_then(|p| p.parent())
                .map(|p| p.as_u32())
                .unwrap_or(0),
            process_path: self.process_path.clone(),
            cmdline: self.cmdline.clone(),
            process_start_time: self.process_start_time,
            restart_count: self.restart_count,
            last_exit_code: self.last_exit_code,
        };

        // CPU
        let load = System::load_average();
        let (runqueue, ctx_switch, interrupts) = self.pdh.collect();
        let cpu = {
            let cpus = sys.cpus();
            let n = cpus.len().max(1) as f32;
            let user: f32 = cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / n;
            SystemCpuMetrics {
                user_percent: user,
                system_percent: 0.0,
                iowait_percent: 0.0,
                steal_percent: 0.0,
                load_avg_1m: load.one as f32,
                load_avg_5m: load.five as f32,
                load_avg_15m: load.fifteen as f32,
                run_queue_length: runqueue,
                context_switches_per_sec: ctx_switch,
                interrupts_per_sec: interrupts,
                softirq_total: 0,
            }
        };

        let memory = collect_system_memory(&sys);
        let (disk, disk_raw) = collect_disk();
        let (network, net_raw) = collect_network();

        let stability = SystemStabilityMetrics {
            kernel_error_events_total: 0,
            dmesg_error_count: 0,
        };

        let (process, proc_cpu_ticks, io) = self.collect_process(&sys, &prev, elapsed_ms);

        let traffic = TrafficMetrics::default();
        let latency = LatencyMetrics {
            ingress: LatencyBuckets::default(),
            queue: LatencyBuckets::default(),
            execution: LatencyBuckets::default(),
            egress: LatencyBuckets::default(),
        };

        let runtime = self.collect_runtime();
        let container = self.collect_container();

        // Cap nhat prev snapshot
        *prev = CounterSnapshot {
            cpu_ticks: proc_cpu_ticks,
            io_read_bytes: io.ReadTransferCount,
            io_write_bytes: io.WriteTransferCount,
            timestamp_ms: now_ms,
            net_rx_bytes: net_raw.0,
            net_tx_bytes: net_raw.1,
            net_rx_packets: net_raw.2,
            net_tx_packets: net_raw.3,
            net_dropped: net_raw.4,
            net_retrans: net_raw.5,
            disk_read_bytes: disk_raw.0,
            disk_write_bytes: disk_raw.1,
            disk_read_ops: disk_raw.2,
            disk_write_ops: disk_raw.3,
        };

        HarborFullPayload {
            metadata,
            system: SystemMetrics { cpu, memory, disk, network, stability },
            process,
            traffic,
            latency,
            runtime,
            container,
            mode: "process".to_string(),
        }
    }

    // =========================================================================
    // PRIVATE helpers (nhan &self vi can self.handle, self.pid)
    // =========================================================================

    fn collect_process(
        &self,
        sys: &System,
        prev: &CounterSnapshot,
        elapsed_ms: u64,
    ) -> (ProcessMetrics, u64, IO_COUNTERS) {
        let mut cpu_ticks = 0u64;
        let mut io = IO_COUNTERS::default();
        let mut handle_count = 0u32;
        let mut mem_rss = 0u64;
        let mut mem_virt = 0u64;

        unsafe {
            let _ = GetProcessHandleCount(self.handle, &mut handle_count);

            let mut mem_ex = PROCESS_MEMORY_COUNTERS_EX::default();
            if GetProcessMemoryInfo(
                self.handle,
                &mut mem_ex as *mut _ as *mut PROCESS_MEMORY_COUNTERS,
                mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
            )
            .is_ok()
            {
                mem_rss = mem_ex.WorkingSetSize as u64;
                mem_virt = mem_ex.PrivateUsage as u64;
            }

            let mut ct = FILETIME::default();
            let mut et = FILETIME::default();
            let mut kt = FILETIME::default();
            let mut ut = FILETIME::default();
            if GetProcessTimes(self.handle, &mut ct, &mut et, &mut kt, &mut ut).is_ok() {
                let k = ((kt.dwHighDateTime as u64) << 32) | kt.dwLowDateTime as u64;
                let u = ((ut.dwHighDateTime as u64) << 32) | ut.dwLowDateTime as u64;
                cpu_ticks = k + u;
            }

            let _ = GetProcessIoCounters(self.handle, &mut io);
        }

        let thread_count = self.count_threads();

        // cpu_percent: delta FILETIME ticks (100ns) / elapsed
        let tick_delta = cpu_ticks.saturating_sub(prev.cpu_ticks);
        let num_cpus = sys.cpus().len().max(1) as u64;
        let cpu_percent = if prev.timestamp_ms > 0 && elapsed_ms > 0 {
            (tick_delta as f64 / (elapsed_ms * 10_000 * num_cpus) as f64 * 100.0) as f32
        } else {
            0.0
        };

        let proc_count = sys.processes().len() as u64;
        let zombie_children = sys
            .processes()
            .values()
            .filter(|p| {
                p.parent() == Some(Pid::from(self.pid as usize))
                    && p.status() == sysinfo::ProcessStatus::Zombie
            })
            .count() as u32;

        let pm = ProcessMetrics {
            cpu_percent,
            memory_rss_bytes: mem_rss,
            memory_virtual_bytes: mem_virt,
            thread_count,
            open_fds: handle_count,
            handle_count,
            total_cpu_cycles: cpu_ticks,
            zombie_children,
            process_spawn_total: sys
                .processes()
                .values()
                .filter(|p| p.parent() == Some(Pid::from(self.pid as usize)))
                .count() as u64,
                        process_exit_total: 0,
                    };

        (pm, cpu_ticks, io)
    }

    fn count_threads(&self) -> u32 {
        let mut count = 0u32;
        unsafe {
            if let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                let mut te = THREADENTRY32::default();
                te.dwSize = mem::size_of::<THREADENTRY32>() as u32;
                if Thread32First(snap, &mut te).is_ok() {
                    loop {
                        if te.th32OwnerProcessID == self.pid {
                            count += 1;
                        }
                        if Thread32Next(snap, &mut te).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snap);
            }
        }
        count
    }

    fn collect_runtime(&self) -> Option<RuntimeMetrics> {
        // Pattern: HTTP GET localhost:<port>/debug/vars (Go), JMX (Java), v.v.
        // Neu khong lay duoc -> None
        None
    }

    fn collect_container(&self) -> Option<ContainerMetrics> {
        // Tren Windows native -> None
        // Tren Linux trong container: doc /sys/fs/cgroup/...
        None
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

// =============================================================================
// Free functions - khong can self, dung boi collect()
// =============================================================================

fn collect_system_memory(sys: &System) -> SystemMemoryMetrics {
    let mut ms = MEMORYSTATUSEX::default();
    ms.dwLength = mem::size_of::<MEMORYSTATUSEX>() as u32;
    unsafe {
        let _ = GlobalMemoryStatusEx(&mut ms);
    }
    SystemMemoryMetrics {
        total_bytes: ms.ullTotalPhys,
        used_bytes: ms.ullTotalPhys - ms.ullAvailPhys,
        free_bytes: ms.ullAvailPhys,
        available_bytes: ms.ullAvailPhys,
        swap_used_bytes: sys.used_swap(),
        page_faults_major_total: 0,
        page_faults_minor_total: 0,
        oom_kill_total: 0,
    }
}

/// Tra ve (SystemDiskMetrics, (read_bytes, write_bytes, read_ops, write_ops))
fn collect_disk() -> (SystemDiskMetrics, (u64, u64, u64, u64)) {
    let disks = Disks::new_with_refreshed_list();
    let mut fs_used_pct = 0f32;
    let mut disk_count = 0u32;

    for disk in disks.list() {
        let total = disk.total_space();
        let avail = disk.available_space();
        if total > 0 {
            fs_used_pct += 100.0 - (avail as f32 / total as f32 * 100.0);
            disk_count += 1;
        }
    }

    let fs_pct = if disk_count > 0 { fs_used_pct / disk_count as f32 } else { 0.0 };
    let raw = (0u64, 0u64, 0u64, 0u64); // PDH: PhysicalDisk counters

    let disk = SystemDiskMetrics {
        read_bytes_total: 0,
        write_bytes_total: 0,
        read_iops_total: 0,
        write_iops_total: 0,
        queue_length: 0,
        latency_ms_avg: 0.0,
        fs_usage_percent: fs_pct,
        inode_usage_percent: 0.0,
    };
    (disk, raw)
}

/// Tra ve (SystemNetworkMetrics, (rx_bytes, tx_bytes, rx_pkts, tx_pkts, dropped, retrans))
fn collect_network() -> (SystemNetworkMetrics, (u64, u64, u64, u64, u64, u64)) {
    let mut rx_bytes = 0u64;
    let mut tx_bytes = 0u64;
    let mut rx_packets = 0u64;
    let mut tx_packets = 0u64;
    let mut dropped = 0u64;
    let mut retrans = 0u64;

    unsafe {
        let mut if_table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        if GetIfTable2(&mut if_table).is_ok() {
            let t = &*if_table;
            let table_ptr = t.Table.as_ptr();
            for i in 0..t.NumEntries as usize {
                let row = &*table_ptr.add(i);
                rx_bytes += row.InOctets;
                tx_bytes += row.OutOctets;
                rx_packets += row.InUcastPkts + row.InNUcastPkts;
                tx_packets += row.OutUcastPkts + row.OutNUcastPkts;
                dropped += row.InDiscards + row.OutDiscards;
                retrans += row.InErrors + row.OutErrors;
            }
            let _ = FreeMibTable(if_table as *const _);
        }
    }

    let (established, time_wait, syn_backlog) = collect_tcp_states_global();
    let raw = (rx_bytes, tx_bytes, rx_packets, tx_packets, dropped, retrans);

    let net = SystemNetworkMetrics {
        rx_bytes_total: rx_bytes,
        tx_bytes_total: tx_bytes,
        rx_packets_total: rx_packets,
        tx_packets_total: tx_packets,
        dropped_packets_total: dropped,
        retransmissions_total: retrans,
        tcp_established: established,
        tcp_time_wait: time_wait,
        syn_backlog_usage: syn_backlog,
    };
    (net, raw)
}

fn collect_tcp_states_global() -> (u32, u32, u32) {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetTcpTable2, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_SYN_RCVD, MIB_TCP_STATE_TIME_WAIT,
        MIB_TCPTABLE2,
    };
    let mut established = 0u32;
    let mut time_wait = 0u32;
    let mut syn_backlog = 0u32;

    unsafe {
        let mut size = 0u32;
        // First call: lay kich thuoc buffer
        let _ = GetTcpTable2(None, &mut size, false);
        if size == 0 {
            return (0, 0, 0);
        }
        let mut buf = vec![0u8; size as usize];
        // Fix: GetTcpTable2 tra ve u32 (ERROR code), khong phai Result -> dung == 0
        let result = GetTcpTable2(
            Some(buf.as_mut_ptr() as *mut MIB_TCPTABLE2),
            &mut size,
            false,
        );
        if result == 0 {
            let table = &*(buf.as_ptr() as *const MIB_TCPTABLE2);
            let entries = std::slice::from_raw_parts(
                table.table.as_ptr(),
                table.dwNumEntries as usize,
            );
            for row in entries {
                match row.dwState {
                    s if s == MIB_TCP_STATE_ESTAB.0 as u32 => established += 1,
                    s if s == MIB_TCP_STATE_TIME_WAIT.0 as u32 => time_wait += 1,
                    s if s == MIB_TCP_STATE_SYN_RCVD.0 as u32 => syn_backlog += 1,
                    _ => {}
                }
            }
        }
    }
    (established, time_wait, syn_backlog)
}

fn get_process_path(handle: HANDLE) -> String {
    let mut buf = [0u16; 1024];
    let mut size = buf.len() as u32;
    unsafe {
        if QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut size,
        )
        .is_ok()
        {
            String::from_utf16_lossy(&buf[..size as usize])
        } else {
            "N/A".to_string()
        }
    }
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// =============================================================================
// HistogramBuilder - build LatencyBuckets tu raw samples
// Caller (middleware/interceptor) goi observe(), flush() moi 5-10s
// =============================================================================

#[derive(Default)]
pub struct HistogramBuilder {
    buckets: LatencyBuckets,
}

impl HistogramBuilder {
    pub fn observe(&mut self, ms: f64) {
        if ms < 1.0 {
            self.buckets.lt_1ms += 1;
        } else if ms < 5.0 {
            self.buckets.lt_5ms += 1;
        } else if ms < 10.0 {
            self.buckets.lt_10ms += 1;
        } else if ms < 50.0 {
            self.buckets.lt_50ms += 1;
        } else if ms < 100.0 {
            self.buckets.lt_100ms += 1;
        } else if ms < 500.0 {
            self.buckets.lt_500ms += 1;
        } else if ms < 1000.0 {
            self.buckets.lt_1s += 1;
        } else if ms < 2000.0 {
            self.buckets.lt_2s += 1;
        } else if ms < 5000.0 {
            self.buckets.lt_5s += 1;
        } else {
            self.buckets.ge_5s += 1;
        }
    }

    /// Lay delta snapshot va reset ve 0 (flush moi 5-10s)
    /// Fix: LatencyBuckets khong derive Clone -> copy tung field
    pub fn flush(&mut self) -> LatencyBuckets {
        let snapshot = LatencyBuckets {
            lt_1ms: self.buckets.lt_1ms,
            lt_5ms: self.buckets.lt_5ms,
            lt_10ms: self.buckets.lt_10ms,
            lt_50ms: self.buckets.lt_50ms,
            lt_100ms: self.buckets.lt_100ms,
            lt_500ms: self.buckets.lt_500ms,
            lt_1s: self.buckets.lt_1s,
            lt_2s: self.buckets.lt_2s,
            lt_5s: self.buckets.lt_5s,
            ge_5s: self.buckets.ge_5s,
        };
        self.buckets = LatencyBuckets::default();
        snapshot
    }
}

// =============================================================================
// TrafficCounter - dem request/error/bytes, caller flush delta
// =============================================================================

#[derive(Default)]
pub struct TrafficCounter {
    inner: TrafficMetrics,
}

impl TrafficCounter {
    pub fn record_request(&mut self, status: u16, bytes_in: u64, bytes_out: u64, timed_out: bool) {
        self.inner.requests_total += 1;
        self.inner.bytes_in_total += bytes_in;
        self.inner.bytes_out_total += bytes_out;
        if status < 400 {
            self.inner.requests_success_total += 1;
        } else if status < 500 {
            self.inner.requests_client_error_total += 1;
        } else {
            self.inner.requests_server_error_total += 1;
        }
        if timed_out {
            self.inner.timeout_total += 1;
        }
    }

    pub fn record_retry(&mut self) {
        self.inner.retry_total += 1;
    }

    pub fn connection_opened(&mut self) {
        self.inner.connections_opened_total += 1;
    }

    pub fn connection_closed(&mut self) {
        self.inner.connections_closed_total += 1;
    }

    /// Flush delta va reset
    pub fn flush(&mut self) -> TrafficMetrics {
        let snapshot = TrafficMetrics {
            requests_total: self.inner.requests_total,
            requests_success_total: self.inner.requests_success_total,
            requests_client_error_total: self.inner.requests_client_error_total,
            requests_server_error_total: self.inner.requests_server_error_total,
            timeout_total: self.inner.timeout_total,
            retry_total: self.inner.retry_total,
            bytes_in_total: self.inner.bytes_in_total,
            bytes_out_total: self.inner.bytes_out_total,
            connections_opened_total: self.inner.connections_opened_total,
            connections_closed_total: self.inner.connections_closed_total,
        };
        self.inner = TrafficMetrics::default();
        snapshot
    }
}