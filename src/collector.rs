use windows::Win32::Foundation::{CloseHandle, HANDLE, FILETIME};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, FreeMibTable, GetIfTable2, MIB_IF_TABLE2, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX
};
use windows::Win32::System::Threading::{
    GetProcessHandleCount, GetProcessIoCounters, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, IO_COUNTERS, PROCESS_NAME_FORMAT,
    QueryFullProcessImageNameW, GetProcessTimes,
    // GetProcessInformation, PROCESS_INFORMATION_CLASS,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32
};

// Import đúng struct Raw mới
use crate::model::AppInternalsRaw;

// #[repr(C)]
// #[derive(Default)]
// struct PROCESS_CYCLE_TIME_INFORMATION {
//     pub accumulated_cycles: u64,
// }

pub struct ProcessLock {
    pub pid: u32,
    pub handle: HANDLE,
    socket_buffer: std::cell::RefCell<Vec<u8>>,
}

/// Struct chuyên trách tìm kiếm PID với cơ chế Buffer Reuse
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
            let mut ret = GetExtendedTcpTable(Some(self.buffer.as_mut_ptr() as *mut _), &mut dw_size, false, 2, TCP_TABLE_OWNER_PID_ALL, 0);
            
            if ret == 122 {
                self.buffer.resize(dw_size as usize, 0);
                ret = GetExtendedTcpTable(Some(self.buffer.as_mut_ptr() as *mut _), &mut dw_size, false, 2, TCP_TABLE_OWNER_PID_ALL, 0);
            }

            if ret == 0 {
                let table = &*(self.buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                let entries = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
                
                for row in entries {
                    if u16::from_be(row.dwLocalPort as u16) == target_port {
                        let pid = row.dwOwningPid;
                        if pid == 0 { continue; }
                        
                        if let Some(lock) = ProcessLock::new(pid) {
                            if lock.get_path().to_lowercase().contains(&target_lower) {
                                return Some(pid);
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

impl ProcessLock {
    pub fn new(pid: u32) -> Option<Self> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            Some(Self {
                pid, 
                handle,
                socket_buffer: std::cell::RefCell::new(vec![0u8; 4096])
            })
        }
    }

    pub fn get_path(&self) -> String {
        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;
        unsafe {
            if QueryFullProcessImageNameW(self.handle, PROCESS_NAME_FORMAT(0), windows::core::PWSTR(buffer.as_mut_ptr()), &mut size).is_ok() {
                String::from_utf16_lossy(&buffer[..size as usize])
            } else {
                "N/A".to_string()
            }
        }
    }

    /// THU THẬP DỮ LIỆU THÔ: Không tính toán, không cấp phát mảng thừa
    pub fn collect_all_raw(&self) -> (AppInternalsRaw, IO_COUNTERS, u32, (u64, u64)) {
        let mut l2 = AppInternalsRaw::default();
        let mut io = IO_COUNTERS::default();
        let mut active_connections = 0u32;
        let mut net_errs = (0, 0);

        unsafe {
            // 1. Handles & RAM (Gửi Bytes thô)
            let mut handle_count = 0;
            let _ = GetProcessHandleCount(self.handle, &mut handle_count);
            l2.handle_count = handle_count;

            let mut mem_ex = PROCESS_MEMORY_COUNTERS_EX::default();
            if GetProcessMemoryInfo(self.handle, &mut mem_ex as *mut _ as *mut PROCESS_MEMORY_COUNTERS, std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32).is_ok() {
                l2.memory_private_bytes = mem_ex.PrivateUsage as u64; // RAW Bytes
                l2.working_set_bytes = mem_ex.WorkingSetSize as u64;  // RAW Bytes
            }

            // 2. Thread Count (Dùng snapshot)
            if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                let mut te = THREADENTRY32::default();
                te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                if Thread32First(snapshot, &mut te).is_ok() {
                    loop {
                        if te.th32OwnerProcessID == self.pid {
                            l2.thread_count += 1;
                        }
                        if Thread32Next(snapshot, &mut te).is_err() { break; }
                    }
                }
                let _ = CloseHandle(snapshot);
            }

            // 3. CPU Cycles & I/O
            let mut creation_time = FILETIME::default();
            let mut exit_time = FILETIME::default();
            let mut kernel_time = FILETIME::default();
            let mut user_time = FILETIME::default();

            // GetProcessTimes là hàm "nồi đồng cối đá" nhất của Windows để lấy CPU
            if GetProcessTimes(self.handle, &mut creation_time, &mut exit_time, &mut kernel_time, &mut user_time).is_ok() {
                // FILETIME là struct gồm 2 phần 32-bit, cần gộp lại thành u64
                let k_ticks = ((kernel_time.dwHighDateTime as u64) << 32) | (kernel_time.dwLowDateTime as u64);
                let u_ticks = ((user_time.dwHighDateTime as u64) << 32) | (user_time.dwLowDateTime as u64);
                
                // Gán tổng Ticks thô vào trường total_cycles
                l2.total_cycles = k_ticks + u_ticks; 
            }
            let _ = GetProcessIoCounters(self.handle, &mut io);

            // 4. TCP Table: CHỈ ĐẾM, không lưu Vec
            let mut buf = self.socket_buffer.borrow_mut();
            let mut dw_size = buf.len() as u32;
            let mut ret = GetExtendedTcpTable(Some(buf.as_mut_ptr() as *mut _), &mut dw_size, false, 2, TCP_TABLE_OWNER_PID_ALL, 0);
            
            if ret == 122 {
                buf.resize(dw_size as usize, 0);
                ret = GetExtendedTcpTable(Some(buf.as_mut_ptr() as *mut _), &mut dw_size, false, 2, TCP_TABLE_OWNER_PID_ALL, 0);
            }

            if ret == 0 {
                let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                let entries = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
                for row in entries {
                    if row.dwOwningPid == self.pid {
                        active_connections += 1; // Chỉ tăng biến đếm, cực nhẹ
                    }
                }
            }

            // 5. Network Errors
            let mut if_table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
            if GetIfTable2(&mut if_table).is_ok() {
                let t = &*if_table;
                let table_ptr = t.Table.as_ptr();
                for i in 0..t.NumEntries as usize {
                    let row = &*table_ptr.add(i);
                    net_errs.0 += row.InErrors;
                    net_errs.1 += row.OutErrors;
                }
                let _ = FreeMibTable(if_table as *const _);
            }
        } 

        (l2, io, active_connections, net_errs)
    }
}

impl Drop for ProcessLock {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.handle); }
    }
}