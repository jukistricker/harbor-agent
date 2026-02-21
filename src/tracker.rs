// tracker.rs
// Trach nhiem duy nhat: theo doi danh tinh + vong doi cua target process.
// KHONG thu thap metrics - viec do la cua Collector.
// KHONG build payload truc tiep - chi cung cap state cho Collector.

use std::time::Instant;

// =============================================================================
// TargetTracker - giu trang thai qua cac lan restart
// =============================================================================

pub struct TargetTracker {
    /// PID hien tai dang duoc monitor
    pub current_pid: u32,

    /// So lan process bi restart tu khi agent bat dau chay
    pub restart_count: u32,

    /// So lan process exit voi non-zero code (crash)
    pub crash_count: u32,

    /// Exit code cua lan ket thuc gan nhat
    pub last_exit_code: i32,

    /// Thoi diem agent bat dau chay (khong thay doi)
    agent_start: Instant,

    /// Thoi diem lan restart gan nhat (reset moi khi detect restart)
    last_restart: Instant,
}

impl TargetTracker {
    pub fn new(initial_pid: u32) -> Self {
        let now = Instant::now();
        Self {
            current_pid: initial_pid,
            restart_count: 0,
            crash_count: 0,
            last_exit_code: 0,
            agent_start: now,
            last_restart: now,
        }
    }

    // =========================================================================
    // Restart detection
    // =========================================================================

    /// Goi khi phat hien PID moi (process da restart).
    /// Caller truyen exit_code cua process cu (doc tu WaitForSingleObject / GetExitCodeProcess).
    pub fn on_restart(&mut self, new_pid: u32, exit_code: i32) {
        if self.current_pid != 0 && self.current_pid != new_pid {
            self.restart_count += 1;
            self.last_exit_code = exit_code;

            // Non-zero exit code = crash / OOM / signal
            if exit_code != 0 {
                self.crash_count += 1;
            }

            self.last_restart = Instant::now();
        }
        self.current_pid = new_pid;
    }

    /// Goi khi process exit ma chua co PID moi (dang cho respawn).
    pub fn on_exit(&mut self, exit_code: i32) {
        self.last_exit_code = exit_code;
        if exit_code != 0 {
            self.crash_count += 1;
        }
    }

    // =========================================================================
    // State accessors - Collector doc nhung gia tri nay khi build payload
    // =========================================================================

    /// Tong so giay agent da chay (uptime cua agent, khong phai process)
    pub fn agent_uptime_secs(&self) -> u64 {
        self.agent_start.elapsed().as_secs()
    }

    /// So giay ke tu lan restart gan nhat
    pub fn secs_since_last_restart(&self) -> u64 {
        self.last_restart.elapsed().as_secs()
    }

    /// Crash loop detection: >= threshold crashes trong window giay gan day.
    /// Simple heuristic: neu crash_count >= threshold va uptime ngan -> crash loop.
    pub fn is_crash_looping(&self, threshold: u32, window_secs: u64) -> bool {
        self.crash_count >= threshold
            && self.secs_since_last_restart() < window_secs
    }
}

// =============================================================================
// AgentLoop - vong lap chinh cua agent, su dung ca Tracker + Collector
// Dat o day de thu gom logic dieu phoi vao 1 cho.
// =============================================================================

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::collector::{Collector, ProcessFinder};
use crate::model::HarborFullPayload;

pub struct AgentLoop {
    tracker: TargetTracker,
    collector: Option<Collector>,
    finder: ProcessFinder,

    /// Ten process de xac dinh lai sau khi restart
    target_name: String,
    /// Port process dang listen (de tim lai PID)
    target_port: u16,

    /// Interval giua cac lan collect (default 5s)
    collect_interval: Duration,
}

impl AgentLoop {
    pub fn new(
        initial_pid: u32,
        target_name: impl Into<String>,
        target_port: u16,
        collect_interval: Duration,
    ) -> Self {
        let collector = Collector::new(initial_pid, env!("CARGO_PKG_VERSION"), 0, 0);

        Self {
            tracker: TargetTracker::new(initial_pid),
            collector,
            finder: ProcessFinder::new(),
            target_name: target_name.into(),
            target_port,
            collect_interval,
        }
    }

    /// Collect 1 lan va goi callback. Sleep do caller quyet dinh.
    /// Dung trong worker_loop cua main de ket hop voi drain lenh dieu khien.
    pub fn run_once<F>(&mut self, mut on_payload: F)
    where
        F: FnMut(HarborFullPayload),
    {
        if self.collector.is_none() || !self.process_alive() {
            self.try_reattach();
        }

        if let Some(ref collector) = self.collector {
            let mut payload = collector.collect();
            payload.metadata.restart_count = self.tracker.restart_count;
            payload.metadata.last_exit_code = self.tracker.last_exit_code;
            payload.metadata.uptime_seconds = self.tracker.agent_uptime_secs();

            if self.tracker.is_crash_looping(3, 60) {
                payload.system.stability.kernel_error_events_total =
                    self.tracker.crash_count as u64;
            }

            on_payload(payload);
        }
    }

    /// Vong lap day du voi sleep tich hop. Dung khi AgentLoop tu quan ly thread.
    pub fn run<F>(&mut self, shutdown: Arc<AtomicBool>, mut on_payload: F)
    where
        F: FnMut(HarborFullPayload),
    {
        while !shutdown.load(Ordering::Relaxed) {
            self.run_once(&mut on_payload);
            std::thread::sleep(self.collect_interval);
        }
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    fn process_alive(&self) -> bool {
        if self.tracker.current_pid == 0 {
            return false;
        }
        // Mo handle toi thieu de check: neu OpenProcess that bai = process da chet
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        unsafe {
            match OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                self.tracker.current_pid,
            ) {
                Ok(h) => {
                    // Co the mo duoc = dang chay
                    // Kiem tra them exit code de loai truong hop zombie
                    let mut code = 0u32;
                    let alive = windows::Win32::System::Threading::GetExitCodeProcess(h, &mut code)
                        .is_ok()
                        && code == 259; // STILL_ACTIVE = 259
                    let _ = CloseHandle(h);
                    alive
                }
                Err(_) => false,
            }
        }
    }

    fn try_reattach(&mut self) {
        // Lay exit code truoc khi drop collector cu
        let exit_code = self.get_last_exit_code();
        self.collector = None; // Drop cu, dong handle

        // Tim PID moi qua port + ten
        if let Some(new_pid) = self
            .finder
            .find_by_port_and_name(self.target_port, &self.target_name)
        {
            self.tracker.on_restart(new_pid, exit_code);

            // Tao collector moi voi thong tin tu tracker
            self.collector = Collector::new(
                new_pid,
                env!("CARGO_PKG_VERSION"),
                self.tracker.restart_count,
                self.tracker.last_exit_code,
            );
        } else {
            // Process chua respawn, ghi nhan exit
            self.tracker.on_exit(exit_code);
        }
    }

    fn get_last_exit_code(&self) -> i32 {
        let pid = self.tracker.current_pid;
        if pid == 0 {
            return 0;
        }
        unsafe {
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::Threading::{
                GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            };
            if let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                let mut code = 0u32;
                let _ = GetExitCodeProcess(h, &mut code);
                let _ = CloseHandle(h);
                // 259 = STILL_ACTIVE, chua thoat
                if code == 259 { 0 } else { code as i32 }
            } else {
                -1 // Khong mo duoc = bi kill
            }
        }
    }
}