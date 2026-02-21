use std::mem;
use std::ptr::null_mut;
use std::thread;
use std::time::Duration;
use windows::core::PCWSTR;
use windows::Win32::System::Performance::{
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData,
    PdhGetFormattedCounterValue, PdhOpenQueryW,
    PDH_FMT_COUNTERVALUE, PDH_FMT_LONG, PDH_FMT_DOUBLE,

};

type PdhHquery = isize;
type PdhHcounter = isize;

pub struct PdhSystemCollector {
    query: PdhHquery,
    runqueue: PdhHcounter,
    ctx_switch: PdhHcounter,
    interrupts: PdhHcounter,
}

impl PdhSystemCollector {
    pub fn new() -> windows::core::Result<Self> {
        unsafe {
            let mut query = PdhHquery::default();
            if PdhOpenQueryW(None, 0, &mut query) != 0 {
                return Err(windows::core::Error::from_win32());
            }

            let runqueue = add_counter(query, r"\System\Processor Queue Length")?;
            let ctx_switch = add_counter(query, r"\System\Context Switches/sec")?;
            let interrupts = add_counter(query, r"\Processor(_Total)\Interrupts/sec")?;

            // warmup (rate counters cần 2 sample)
            if PdhCollectQueryData(query) != 0 {
                return Err(windows::core::Error::from_win32());
            }
            thread::sleep(Duration::from_secs(1));
            if PdhCollectQueryData(query) != 0 {
                return Err(windows::core::Error::from_win32());
            }

            Ok(Self {
                query,
                runqueue,
                ctx_switch,
                interrupts,
            })
        }
    }

    pub fn collect(&self) -> (u32, f64, f64) {
        unsafe {
            let _ = PdhCollectQueryData(self.query);

            let rq = get_long(self.runqueue);
            let ctx = get_double(self.ctx_switch);
            let intr = get_double(self.interrupts);

            (rq as u32, ctx, intr)
        }
    }
}

unsafe fn add_counter(
    query: PdhHquery,
    path: &str,
) -> windows::core::Result<PdhHcounter> {
    use windows::core::PCWSTR;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(Some(0))
        .collect();

    let mut counter: PdhHcounter = 0;

    let status = PdhAddEnglishCounterW(
        query,
        PCWSTR(wide.as_ptr()),
        0,
        &mut counter,
    );

    if status != 0 {
        return Err(windows::core::Error::from_win32());
    }

    Ok(counter)
}

unsafe fn get_long(counter: PdhHcounter) -> i32 {
    let mut value = std::mem::zeroed::<PDH_FMT_COUNTERVALUE>();
    let mut typ = 0u32;

    let status = PdhGetFormattedCounterValue(
        counter,
        PDH_FMT_LONG,
        Some(&mut typ),
        &mut value,
    );

    if status == 0 {
        value.Anonymous.longValue
    } else {
        0
    }
}

unsafe fn get_double(counter: PdhHcounter) -> f64 {
    let mut value = std::mem::zeroed::<PDH_FMT_COUNTERVALUE>();
    let mut typ = 0u32;

    let status = PdhGetFormattedCounterValue(
        counter,
        PDH_FMT_DOUBLE,
        Some(&mut typ),
        &mut value,
    );

    if status == 0 {
        value.Anonymous.doubleValue
    } else {
        0.0
    }
}

impl Drop for PdhSystemCollector {
    fn drop(&mut self) {
        unsafe {
            let _ = PdhCloseQuery(self.query);
        }
    }
}