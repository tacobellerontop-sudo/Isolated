//! Marks the windows of a running sandbox so users can tell them apart from
//! normal ones: a colored frame around the active window and an
//! `[Isolated]` tag in front of window titles.
//!
//! Everything happens in the watcher, outside the sandbox: nothing is
//! injected into the app. One thread owns a click-through frame window and
//! follows the foreground window through WinEvent hooks; titles are set
//! with `WM_SETTEXT` and set again when the app changes them.

use super::util::Wide;
use isolated_core::marker::tagged_title;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{COLORREF, HANDLE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED, DWMWA_EXTENDED_FRAME_BOUNDS};
use windows::Win32::Graphics::Gdi::{
    CombineRgn, CreateRectRgn, CreateSolidBrush, DeleteObject, GetMonitorInfoW, MonitorFromWindow, SetWindowRgn,
    HGDIOBJ, MONITORINFO, MONITOR_DEFAULTTONEAREST, RGN_DIFF,
};
use windows::Win32::System::JobObjects::{
    JobObjectBasicProcessIdList, QueryInformationJobObject, JOBOBJECT_BASIC_PROCESS_ID_LIST,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Accessibility::{SetWinEventHook, UnhookWinEvent, HWINEVENTHOOK};
use windows::Win32::UI::HiDpi::GetDpiForWindow;
use windows::Win32::UI::WindowsAndMessaging::*;

/// What to mark.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Frame color, or `None` for no frame.
    pub frame: Option<[u8; 3]>,
    /// Title tag (such as `[Isolated] `), or `None` to leave titles alone.
    pub tag: Option<String>,
}

/// The running marker thread. Stop it before the job handle is closed.
pub struct Marker {
    thread: Option<JoinHandle<()>>,
    tid: u32,
}

const MSG_FOREGROUND: u32 = WM_APP + 1;
const MSG_MOVED: u32 = WM_APP + 2;
const MSG_RENAMED: u32 = WM_APP + 3;
const MSG_SHOWN: u32 = WM_APP + 4;
const MSG_GONE: u32 = WM_APP + 5;

const EVENT_SYSTEM_FOREGROUND: u32 = 0x0003;
const EVENT_SYSTEM_MINIMIZESTART: u32 = 0x0016;
const EVENT_SYSTEM_MINIMIZEEND: u32 = 0x0017;
const EVENT_OBJECT_DESTROY: u32 = 0x8001;
const EVENT_OBJECT_SHOW: u32 = 0x8002;
const EVENT_OBJECT_HIDE: u32 = 0x8003;
const EVENT_OBJECT_LOCATIONCHANGE: u32 = 0x800B;
const EVENT_OBJECT_NAMECHANGE: u32 = 0x800C;
const WINEVENT_OUTOFCONTEXT: u32 = 0;
const WINEVENT_SKIPOWNPROCESS: u32 = 2;

/// Diagnostics for the smoke test: appended to the file named by
/// `ISOLATED_MARKER_TRACE`, if set.
pub fn trace(msg: impl std::fmt::Display) {
    if let Some(path) = std::env::var_os("ISOLATED_MARKER_TRACE") {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{msg}");
        }
    }
}

impl Marker {
    /// Starts marking the windows of processes in `job`. Returns `None` when
    /// there is nothing to mark or the thread could not start.
    pub fn start(job: HANDLE, opts: Options) -> Option<Marker> {
        if opts.frame.is_none() && opts.tag.is_none() {
            return None;
        }
        let job_raw = job.0 as isize;
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("window-marker".into())
            .spawn(move || run(HANDLE(job_raw as *mut c_void), opts, tx))
            .ok()?;
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(tid) => Some(Marker {
                thread: Some(thread),
                tid,
            }),
            Err(_) => None,
        }
    }

    pub fn stop(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        if let Some(t) = self.thread.take() {
            unsafe {
                let _ = PostThreadMessageW(self.tid, WM_QUIT, WPARAM(0), LPARAM(0));
            }
            let _ = t.join();
        }
    }
}

impl Drop for Marker {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

struct State {
    job: HANDLE,
    pids: Vec<u32>,
    refreshed: Instant,
    frame: Option<Frame>,
    tag: Option<String>,
}

struct Frame {
    hwnd: HWND,
    /// The window it is drawn around, if shown.
    target: Option<HWND>,
    /// Screen rectangle it was last placed at.
    placed: RECT,
}

thread_local! {
    static TID: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

fn run(job: HANDLE, opts: Options, ready: mpsc::Sender<u32>) {
    unsafe {
        // Make sure the thread has a message queue before anyone posts.
        let mut msg: MSG = zeroed();
        let _ = PeekMessageW(&mut msg, None, 0, 0, PM_NOREMOVE);
        let tid = GetCurrentThreadId();
        TID.with(|t| t.set(tid));

        let frame = opts.frame.and_then(|c| {
            create_frame(c).map(|hwnd| Frame {
                hwnd,
                target: None,
                placed: RECT::default(),
            })
        });
        trace(format_args!(
            "marker thread {tid}: frame {:?}",
            frame.as_ref().map(|f| f.hwnd.0)
        ));
        let mut st = State {
            job,
            pids: Vec::new(),
            refreshed: Instant::now() - Duration::from_secs(10),
            frame,
            tag: opts.tag,
        };

        let flags = WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS;
        let hooks: Vec<HWINEVENTHOOK> = [
            (EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND),
            (EVENT_SYSTEM_MINIMIZESTART, EVENT_SYSTEM_MINIMIZEEND),
            (EVENT_OBJECT_DESTROY, EVENT_OBJECT_HIDE),
            (EVENT_OBJECT_LOCATIONCHANGE, EVENT_OBJECT_NAMECHANGE),
        ]
        .iter()
        .map(|&(a, b)| SetWinEventHook(a, b, None, Some(on_event), 0, 0, flags))
        .filter(|h| !h.is_invalid())
        .collect();
        let timer = SetTimer(None, 0, 1000, None);
        let _ = ready.send(tid);

        st.sweep();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            if msg.hwnd.is_invalid() || msg.hwnd.0.is_null() {
                let hwnd = HWND(msg.wParam.0 as *mut c_void);
                match msg.message {
                    WM_TIMER => st.sweep(),
                    MSG_FOREGROUND => st.update_frame(),
                    MSG_MOVED if st.frames(hwnd) || GetForegroundWindow() == hwnd => st.update_frame(),
                    MSG_RENAMED => st.tag_window(hwnd),
                    MSG_SHOWN => {
                        st.tag_window(hwnd);
                        if GetForegroundWindow() == hwnd {
                            st.update_frame();
                        }
                    }
                    MSG_GONE if st.frames(hwnd) => st.update_frame(),
                    _ => {}
                }
                continue;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        if timer != 0 {
            let _ = KillTimer(None, timer);
        }
        for h in hooks {
            let _ = UnhookWinEvent(h);
        }
        if let Some(f) = st.frame.take() {
            let _ = DestroyWindow(f.hwnd);
        }
    }
}

/// WinEvent callback: only posts to the loop, so no work runs re-entrantly
/// while a `WM_SETTEXT` is waiting.
unsafe extern "system" fn on_event(
    _hook: HWINEVENTHOOK,
    event: u32,
    hwnd: HWND,
    id_object: i32,
    id_child: i32,
    _thread: u32,
    _time: u32,
) {
    if hwnd.0.is_null() {
        return;
    }
    let msg = match event {
        EVENT_SYSTEM_FOREGROUND | EVENT_SYSTEM_MINIMIZESTART | EVENT_SYSTEM_MINIMIZEEND => MSG_FOREGROUND,
        _ if id_object != OBJID_WINDOW.0 || id_child != 0 => return,
        EVENT_OBJECT_LOCATIONCHANGE => MSG_MOVED,
        EVENT_OBJECT_NAMECHANGE => MSG_RENAMED,
        EVENT_OBJECT_SHOW => MSG_SHOWN,
        EVENT_OBJECT_HIDE | EVENT_OBJECT_DESTROY => MSG_GONE,
        _ => return,
    };
    let tid = TID.with(|t| t.get());
    let _ = PostThreadMessageW(tid, msg, WPARAM(hwnd.0 as usize), LPARAM(0));
}

impl State {
    fn refresh_pids(&mut self) {
        self.refreshed = Instant::now();
        let mut buf = vec![0usize; 2 + 2048];
        let ok = unsafe {
            QueryInformationJobObject(
                Some(self.job),
                JobObjectBasicProcessIdList,
                buf.as_mut_ptr() as *mut c_void,
                (buf.len() * size_of::<usize>()) as u32,
                None,
            )
            .is_ok()
        };
        self.pids.clear();
        if !ok {
            trace(format_args!(
                "job pid list failed: {:?}",
                windows::core::Error::from_thread()
            ));
        }
        if ok {
            let list = unsafe { &*(buf.as_ptr() as *const JOBOBJECT_BASIC_PROCESS_ID_LIST) };
            let n = (list.NumberOfProcessIdsInList as usize).min(2048);
            self.pids.extend(buf[2..2 + n].iter().map(|&p| p as u32));
        }
    }

    /// Whether the frame is drawn around `hwnd`.
    fn frames(&self, hwnd: HWND) -> bool {
        self.frame.as_ref().is_some_and(|f| f.target == Some(hwnd))
    }

    /// Whether a window belongs to a process in the sandbox.
    fn owns(&mut self, hwnd: HWND) -> bool {
        let mut pid = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
        if pid == 0 {
            return false;
        }
        if self.pids.contains(&pid) {
            return true;
        }
        // A process that just started: look again, but not on every event.
        if self.refreshed.elapsed() > Duration::from_millis(100) {
            self.refresh_pids();
            return self.pids.contains(&pid);
        }
        false
    }

    /// Periodic pass: tag every window and check the frame.
    fn sweep(&mut self) {
        self.refresh_pids();
        if self.tag.is_some() {
            let mut windows: Vec<HWND> = Vec::new();
            unsafe {
                let _ = EnumWindows(Some(collect), LPARAM(&mut windows as *mut Vec<HWND> as isize));
            }
            for w in windows {
                self.tag_window(w);
            }
        }
        self.update_frame();
    }

    fn tag_window(&mut self, hwnd: HWND) {
        let Some(tag) = self.tag.clone() else { return };
        if !is_app_window(hwnd) {
            return;
        }
        if !self.owns(hwnd) {
            if std::env::var_os("ISOLATED_MARKER_TRACE").is_some() {
                let mut pid = 0u32;
                unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
                let title = window_text(hwnd);
                if title.contains("Notepad") {
                    trace(format_args!("not ours: {title:?} pid {pid}, job pids {:?}", self.pids));
                }
            }
            return;
        }
        let title = window_text(hwnd);
        let Some(new) = tagged_title(&title, &tag) else {
            return;
        };
        let text = Wide::new(&new);
        let mut result = 0usize;
        let r = unsafe {
            // Never wait long on an app that is busy or hung.
            SendMessageTimeoutW(
                hwnd,
                WM_SETTEXT,
                WPARAM(0),
                LPARAM(text.0.as_ptr() as isize),
                SMTO_ABORTIFHUNG | SMTO_BLOCK,
                250,
                Some(&mut result),
            )
        };
        trace(format_args!(
            "tag {:?} {title:?} -> sent {} result {result} err {:?}",
            hwnd.0,
            r.0,
            windows::core::Error::from_thread()
        ));
    }

    fn update_frame(&mut self) {
        if self.frame.is_none() {
            return;
        }
        let fg = unsafe { GetForegroundWindow() };
        let rect = if !fg.0.is_null() && self.owns(fg) {
            frame_rect(fg)
        } else {
            None
        };
        let frame = self.frame.as_mut().unwrap();
        match rect {
            Some(r) => frame.show(fg, r),
            None => frame.hide(),
        }
    }
}

unsafe extern "system" fn collect(hwnd: HWND, lparam: LPARAM) -> windows::core::BOOL {
    let v = &mut *(lparam.0 as *mut Vec<HWND>);
    v.push(hwnd);
    true.into()
}

fn window_text(hwnd: HWND) -> String {
    unsafe {
        let len = GetWindowTextLengthW(hwnd).max(0) as usize;
        if len == 0 {
            return String::new();
        }
        let mut buf = vec![0u16; len + 1];
        let n = GetWindowTextW(hwnd, &mut buf).max(0) as usize;
        String::from_utf16_lossy(&buf[..n.min(len)])
    }
}

/// A visible top-level window that users see as an app window (not a
/// tooltip, menu, or hidden helper).
fn is_app_window(hwnd: HWND) -> bool {
    unsafe {
        if !IsWindowVisible(hwnd).as_bool() || GetAncestor(hwnd, GA_ROOT) != hwnd {
            return false;
        }
        let style = GetWindowLongW(hwnd, GWL_STYLE) as u32;
        let ex = GetWindowLongW(hwnd, GWL_EXSTYLE) as u32;
        if style & WS_CHILD.0 != 0 || ex & WS_EX_TOOLWINDOW.0 != 0 {
            return false;
        }
        let has_caption = style & WS_CAPTION.0 == WS_CAPTION.0;
        let owned = GetWindow(hwnd, GW_OWNER).map(|o| !o.0.is_null()).unwrap_or(false);
        has_caption || !owned
    }
}

fn cloaked(hwnd: HWND) -> bool {
    let mut v = 0u32;
    unsafe {
        DwmGetWindowAttribute(
            hwnd,
            DWMWA_CLOAKED,
            &mut v as *mut u32 as *mut c_void,
            size_of::<u32>() as u32,
        )
        .is_ok()
            && v != 0
    }
}

/// Where to draw the frame around `hwnd`, or `None` when it should not be
/// drawn: minimized, hidden, tiny, or full screen (games and videos).
fn frame_rect(hwnd: HWND) -> Option<RECT> {
    unsafe {
        if !IsWindowVisible(hwnd).as_bool() || IsIconic(hwnd).as_bool() || cloaked(hwnd) {
            return None;
        }
        let mut r = RECT::default();
        if DwmGetWindowAttribute(
            hwnd,
            DWMWA_EXTENDED_FRAME_BOUNDS,
            &mut r as *mut RECT as *mut c_void,
            size_of::<RECT>() as u32,
        )
        .is_err()
            && GetWindowRect(hwnd, &mut r).is_err()
        {
            return None;
        }
        if r.right - r.left < 60 || r.bottom - r.top < 40 {
            return None;
        }
        let mon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        let mut mi = MONITORINFO {
            cbSize: size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        if GetMonitorInfoW(mon, &mut mi).as_bool() {
            let m = mi.rcMonitor;
            if r.left <= m.left && r.top <= m.top && r.right >= m.right && r.bottom >= m.bottom {
                return None;
            }
        }
        Some(r)
    }
}

impl Frame {
    fn show(&mut self, target: HWND, r: RECT) {
        let w = r.right - r.left;
        let h = r.bottom - r.top;
        let resized = w != self.placed.right - self.placed.left || h != self.placed.bottom - self.placed.top;
        if self.target == Some(target) && !resized && r.left == self.placed.left && r.top == self.placed.top {
            return;
        }
        unsafe {
            if resized || self.target.is_none() {
                let dpi = GetDpiForWindow(target).max(96) as i32;
                let t = ((3 * dpi + 48) / 96).max(2);
                let outer = CreateRectRgn(0, 0, w, h);
                let inner = CreateRectRgn(t, t, w - t, h - t);
                CombineRgn(Some(outer), Some(outer), Some(inner), RGN_DIFF);
                let _ = DeleteObject(HGDIOBJ(inner.0));
                // The system owns the region from here on.
                SetWindowRgn(self.hwnd, Some(outer), false);
            }
            let _ = SetWindowPos(
                self.hwnd,
                Some(HWND_TOPMOST),
                r.left,
                r.top,
                w,
                h,
                SWP_NOACTIVATE | SWP_SHOWWINDOW | SWP_NOOWNERZORDER,
            );
        }
        self.target = Some(target);
        self.placed = r;
    }

    fn hide(&mut self) {
        if self.target.take().is_some() {
            unsafe {
                let _ = ShowWindow(self.hwnd, SW_HIDE);
            }
        }
    }
}

unsafe extern "system" fn frame_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        // Clicks go to the window underneath.
        WM_NCHITTEST => LRESULT(HTTRANSPARENT as isize),
        WM_MOUSEACTIVATE => LRESULT(MA_NOACTIVATE as isize),
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn create_frame(color: [u8; 3]) -> Option<HWND> {
    unsafe {
        let instance = GetModuleHandleW(None).ok()?;
        // One class per color: the class brush paints the frame.
        let class = Wide::new(format!("IsolatedFrame{:02X}{:02X}{:02X}", color[0], color[1], color[2]));
        let colorref = COLORREF(color[0] as u32 | (color[1] as u32) << 8 | (color[2] as u32) << 16);
        let wc = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(frame_proc),
            hInstance: instance.into(),
            hbrBackground: CreateSolidBrush(colorref),
            lpszClassName: class.pcwstr(),
            ..Default::default()
        };
        // Fails harmlessly when the class already exists.
        RegisterClassExW(&wc);
        let hwnd = CreateWindowExW(
            WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TOPMOST,
            class.pcwstr(),
            windows::core::w!("Isolated"),
            WS_POPUP,
            0,
            0,
            0,
            0,
            None,
            None,
            Some(instance.into()),
            None,
        )
        .map_err(|e| trace(format_args!("frame window: {e}")))
        .ok()?;
        let _ = SetLayeredWindowAttributes(hwnd, COLORREF(0), 255, LWA_ALPHA);
        Some(hwnd)
    }
}
