//! Win32 bindings fx needs that the standard library does not expose.
//!
//! Two capabilities live here. The console API replaces `isatty`, `TIOCGWINSZ`
//! and termios raw mode, which Windows has no equivalent of. Job objects replace
//! POSIX process groups, so cancelling a tool still tears down the whole child
//! process tree rather than leaking grandchildren.
//!
//! Every declaration is `windows`-only. Importing this module from a POSIX build
//! is a bug; guard the import site with `builtin.os.tag == .windows`.

const builtin = @import("builtin");
const std = @import("std");

pub const windows = std.os.windows;

const BOOL = windows.BOOL;
const DWORD = windows.DWORD;
const HANDLE = windows.HANDLE;
const SHORT = windows.SHORT;
const UINT = windows.UINT;
const WORD = windows.WORD;

comptime {
    if (builtin.os.tag != .windows) @compileError("windows_api is windows-only");
}

pub const SMALL_RECT = extern struct {
    Left: SHORT,
    Top: SHORT,
    Right: SHORT,
    Bottom: SHORT,
};

pub const CONSOLE_SCREEN_BUFFER_INFO = extern struct {
    dwSize: windows.COORD,
    dwCursorPosition: windows.COORD,
    wAttributes: WORD,
    srWindow: SMALL_RECT,
    dwMaximumWindowSize: windows.COORD,
};

/// Input console mode bits.
pub const input_mode = struct {
    pub const processed: DWORD = 0x0001;
    pub const line: DWORD = 0x0002;
    pub const echo: DWORD = 0x0004;
    pub const window: DWORD = 0x0008;
    pub const mouse: DWORD = 0x0010;
    pub const quick_edit: DWORD = 0x0040;
    pub const extended_flags: DWORD = 0x0080;
    pub const virtual_terminal: DWORD = 0x0200;
};

/// Output console mode bits.
pub const output_mode = struct {
    pub const processed: DWORD = 0x0001;
    pub const wrap_at_eol: DWORD = 0x0002;
    pub const virtual_terminal: DWORD = 0x0004;
    pub const disable_newline_auto_return: DWORD = 0x0008;
};

pub const utf8_code_page: UINT = 65001;

pub extern "kernel32" fn GetConsoleMode(hConsoleHandle: HANDLE, lpMode: *DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn SetConsoleMode(hConsoleHandle: HANDLE, dwMode: DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetConsoleScreenBufferInfo(
    hConsoleOutput: HANDLE,
    lpConsoleScreenBufferInfo: *CONSOLE_SCREEN_BUFFER_INFO,
) callconv(.winapi) BOOL;
pub extern "kernel32" fn SetConsoleOutputCP(wCodePageID: UINT) callconv(.winapi) BOOL;
pub extern "kernel32" fn SetConsoleCP(wCodePageID: UINT) callconv(.winapi) BOOL;

pub extern "kernel32" fn CreateJobObjectW(
    lpJobAttributes: ?*anyopaque,
    lpName: ?[*:0]const u16,
) callconv(.winapi) ?HANDLE;
pub extern "kernel32" fn AssignProcessToJobObject(
    hJob: HANDLE,
    hProcess: HANDLE,
) callconv(.winapi) BOOL;
pub extern "kernel32" fn TerminateJobObject(hJob: HANDLE, uExitCode: UINT) callconv(.winapi) BOOL;
pub extern "kernel32" fn SetInformationJobObject(
    hJob: HANDLE,
    JobObjectInformationClass: c_int,
    lpJobObjectInformation: *anyopaque,
    cbJobObjectInformationLength: DWORD,
) callconv(.winapi) BOOL;
pub extern "kernel32" fn OpenProcess(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwProcessId: DWORD,
) callconv(.winapi) ?HANDLE;

pub const job_object_extended_limit_information: c_int = 9;
pub const job_object_limit_kill_on_job_close: DWORD = 0x00002000;

pub const IO_COUNTERS = extern struct {
    ReadOperationCount: u64 = 0,
    WriteOperationCount: u64 = 0,
    OtherOperationCount: u64 = 0,
    ReadTransferCount: u64 = 0,
    WriteTransferCount: u64 = 0,
    OtherTransferCount: u64 = 0,
};

pub const JOBOBJECT_BASIC_LIMIT_INFORMATION = extern struct {
    PerProcessUserTimeLimit: i64 = 0,
    PerJobUserTimeLimit: i64 = 0,
    LimitFlags: DWORD = 0,
    MinimumWorkingSetSize: usize = 0,
    MaximumWorkingSetSize: usize = 0,
    ActiveProcessLimit: DWORD = 0,
    Affinity: usize = 0,
    PriorityClass: DWORD = 0,
    SchedulingClass: DWORD = 0,
};

pub const JOBOBJECT_EXTENDED_LIMIT_INFORMATION = extern struct {
    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION = .{},
    IoInfo: IO_COUNTERS = .{},
    ProcessMemoryLimit: usize = 0,
    JobMemoryLimit: usize = 0,
    PeakProcessMemoryUsed: usize = 0,
    PeakJobMemoryUsed: usize = 0,
};

pub const process_terminate: DWORD = 0x0001;
pub const process_set_quota: DWORD = 0x0100;

pub const wait_object_0: DWORD = 0x00000000;
pub const wait_timeout: DWORD = 0x00000102;
pub const wait_failed: DWORD = 0xFFFFFFFF;
pub const infinite: DWORD = 0xFFFFFFFF;

pub extern "kernel32" fn WaitForSingleObject(
    hHandle: HANDLE,
    dwMilliseconds: DWORD,
) callconv(.winapi) DWORD;

pub const key_event: WORD = 0x0001;

pub const KEY_EVENT_RECORD = extern struct {
    bKeyDown: BOOL,
    wRepeatCount: WORD,
    wVirtualKeyCode: WORD,
    wVirtualScanCode: WORD,
    uChar: extern union {
        UnicodeChar: u16,
        AsciiChar: u8,
    },
    dwControlKeyState: DWORD,
};

pub const MOUSE_EVENT_RECORD = extern struct {
    dwMousePosition: windows.COORD,
    dwButtonState: DWORD,
    dwControlKeyState: DWORD,
    dwEventFlags: DWORD,
};

pub const INPUT_RECORD = extern struct {
    EventType: WORD,
    Event: extern union {
        KeyEvent: KEY_EVENT_RECORD,
        MouseEvent: MOUSE_EVENT_RECORD,
    },
};

pub extern "kernel32" fn PeekConsoleInputW(
    hConsoleInput: HANDLE,
    lpBuffer: [*]INPUT_RECORD,
    nLength: DWORD,
    lpNumberOfEventsRead: *DWORD,
) callconv(.winapi) BOOL;
pub extern "kernel32" fn ReadConsoleInputW(
    hConsoleInput: HANDLE,
    lpBuffer: [*]INPUT_RECORD,
    nLength: DWORD,
    lpNumberOfEventsRead: *DWORD,
) callconv(.winapi) BOOL;

pub const InputWait = enum { readable, timed_out, failed };

/// Waits until `handle` has console input that a subsequent read will actually
/// return bytes for.
///
/// A console handle signals for every input record, including key-up, focus and
/// buffer-resize events that produce no bytes in virtual-terminal input mode.
/// Reporting those as readable would make the caller block inside its read, so
/// non-key records are consumed here and the wait restarts.
pub fn waitForInput(handle: HANDLE, timeout_ms: i32) InputWait {
    if (!isConsole(handle)) {
        // Pipes and files are readable as soon as the handle signals.
        return switch (WaitForSingleObject(handle, timeoutMillis(timeout_ms))) {
            wait_object_0 => .readable,
            wait_timeout => .timed_out,
            else => .failed,
        };
    }

    const remaining = timeout_ms;
    while (true) {
        switch (WaitForSingleObject(handle, timeoutMillis(remaining))) {
            wait_object_0 => {},
            wait_timeout => return .timed_out,
            else => return .failed,
        }

        var record: INPUT_RECORD = undefined;
        var count: DWORD = 0;
        if (!PeekConsoleInputW(handle, @ptrCast(&record), 1, &count).toBool()) return .failed;
        if (count == 0) return .timed_out;
        if (record.EventType == key_event and record.Event.KeyEvent.bKeyDown.toBool()) return .readable;

        var discarded: DWORD = 0;
        if (!ReadConsoleInputW(handle, @ptrCast(&record), 1, &discarded).toBool()) return .failed;
        if (remaining == 0) return .timed_out;
    }
}

fn timeoutMillis(timeout_ms: i32) DWORD {
    if (timeout_ms < 0) return infinite;
    return @intCast(timeout_ms);
}

/// True when `handle` is attached to a console. Windows has no `isatty`, so a
/// successful mode query stands in for one.
pub fn isConsole(handle: HANDLE) bool {
    var mode: DWORD = undefined;
    return GetConsoleMode(handle, &mode).toBool();
}

pub fn getMode(handle: HANDLE) ?DWORD {
    var mode: DWORD = undefined;
    if (!GetConsoleMode(handle, &mode).toBool()) return null;
    return mode;
}

pub fn setMode(handle: HANDLE, mode: DWORD) bool {
    return SetConsoleMode(handle, mode).toBool();
}

/// Turns on the ANSI escape sequence interpreter for `handle`. fx renders its
/// entire interface with ANSI, so without this the console prints raw escapes.
pub fn enableVirtualTerminalOutput(handle: HANDLE) bool {
    const mode = getMode(handle) orelse return false;
    const wanted = mode | output_mode.virtual_terminal | output_mode.processed;
    if (wanted == mode) return true;
    return setMode(handle, wanted);
}

/// Windows equivalent of termios raw mode: line buffering, echo and the
/// console's own Ctrl+C handling are turned off, and the console is asked to
/// deliver ANSI-encoded input the way a POSIX terminal would.
pub fn enableRawInput(handle: HANDLE) ?DWORD {
    const original = getMode(handle) orelse return null;
    var raw = original;
    raw &= ~(input_mode.line | input_mode.echo | input_mode.processed |
        input_mode.mouse | input_mode.window | input_mode.quick_edit);
    raw |= input_mode.virtual_terminal | input_mode.extended_flags;
    if (!setMode(handle, raw)) return null;
    return original;
}

/// Terminal size in rows and columns from the visible console window.
pub fn windowSize(handle: HANDLE) ?struct { rows: u16, cols: u16 } {
    var info: CONSOLE_SCREEN_BUFFER_INFO = undefined;
    if (!GetConsoleScreenBufferInfo(handle, &info).toBool()) return null;
    const cols = info.srWindow.Right - info.srWindow.Left + 1;
    const rows = info.srWindow.Bottom - info.srWindow.Top + 1;
    if (rows <= 0 or cols <= 0) return null;
    return .{ .rows = @intCast(rows), .cols = @intCast(cols) };
}

pub const OVERLAPPED = extern struct {
    Internal: usize = 0,
    InternalHigh: usize = 0,
    Offset: DWORD = 0,
    OffsetHigh: DWORD = 0,
    hEvent: ?HANDLE = null,
};

pub extern "kernel32" fn ReadFile(
    hFile: HANDLE,
    lpBuffer: [*]u8,
    nNumberOfBytesToRead: DWORD,
    lpNumberOfBytesRead: ?*DWORD,
    lpOverlapped: ?*OVERLAPPED,
) callconv(.winapi) BOOL;
pub extern "kernel32" fn WriteFile(
    hFile: HANDLE,
    lpBuffer: [*]const u8,
    nNumberOfBytesToWrite: DWORD,
    lpNumberOfBytesWritten: ?*DWORD,
    lpOverlapped: ?*OVERLAPPED,
) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetOverlappedResult(
    hFile: HANDLE,
    lpOverlapped: *OVERLAPPED,
    lpNumberOfBytesTransferred: *DWORD,
    bWait: BOOL,
) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetLastError() callconv(.winapi) DWORD;

pub const error_io_pending: DWORD = 997;
pub const error_handle_eof: DWORD = 38;
pub const error_broken_pipe: DWORD = 109;

pub const PositionalError = error{ PositionalReadFailed, PositionalWriteFailed };

/// Reads at an absolute offset without depending on how the handle was opened.
///
/// Zig 0.16 opens files asynchronously but describes them as synchronous, which
/// makes both standard library positional paths wrong: the synchronous one
/// reaches `unreachable` on `STATUS_PENDING`, and the asynchronous one waits for
/// an APC that never arrives outside its own event loop. Supplying an
/// `OVERLAPPED` and waiting on it explicitly is correct for either mode.
pub fn readAt(handle: HANDLE, buffer: []u8, offset: u64) PositionalError!usize {
    if (buffer.len == 0) return 0;
    var overlapped: OVERLAPPED = .{
        .Offset = @truncate(offset),
        .OffsetHigh = @truncate(offset >> 32),
    };
    var transferred: DWORD = 0;
    const wanted: DWORD = @intCast(@min(buffer.len, @as(usize, std.math.maxInt(DWORD))));
    if (ReadFile(handle, buffer.ptr, wanted, &transferred, &overlapped).toBool()) {
        return transferred;
    }
    return switch (GetLastError()) {
        error_io_pending => waitForOverlapped(handle, &overlapped, error.PositionalReadFailed),
        error_handle_eof, error_broken_pipe => 0,
        else => error.PositionalReadFailed,
    };
}

pub fn writeAt(handle: HANDLE, bytes: []const u8, offset: u64) PositionalError!usize {
    if (bytes.len == 0) return 0;
    var overlapped: OVERLAPPED = .{
        .Offset = @truncate(offset),
        .OffsetHigh = @truncate(offset >> 32),
    };
    var transferred: DWORD = 0;
    const wanted: DWORD = @intCast(@min(bytes.len, @as(usize, std.math.maxInt(DWORD))));
    if (WriteFile(handle, bytes.ptr, wanted, &transferred, &overlapped).toBool()) {
        return transferred;
    }
    return switch (GetLastError()) {
        error_io_pending => waitForOverlapped(handle, &overlapped, error.PositionalWriteFailed),
        else => error.PositionalWriteFailed,
    };
}

fn waitForOverlapped(
    handle: HANDLE,
    overlapped: *OVERLAPPED,
    failure: PositionalError,
) PositionalError!usize {
    var transferred: DWORD = 0;
    if (GetOverlappedResult(handle, overlapped, &transferred, .TRUE).toBool()) {
        return transferred;
    }
    return switch (GetLastError()) {
        error_handle_eof, error_broken_pipe => 0,
        else => failure,
    };
}

/// A job object that terminates every process assigned to it. This is the
/// Windows stand-in for `kill(-pgid)` on a POSIX process group.
pub const ProcessTree = struct {
    handle: HANDLE,

    pub fn create() ?ProcessTree {
        const job = CreateJobObjectW(null, null) orelse return null;
        var limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = .{};
        limits.BasicLimitInformation.LimitFlags = job_object_limit_kill_on_job_close;
        _ = SetInformationJobObject(
            job,
            job_object_extended_limit_information,
            &limits,
            @sizeOf(JOBOBJECT_EXTENDED_LIMIT_INFORMATION),
        );
        return .{ .handle = job };
    }

    /// Adopts an already-running process. Children it spawns afterwards join the
    /// job automatically, which is what makes tree termination work.
    pub fn adopt(self: ProcessTree, pid: DWORD) bool {
        const process = OpenProcess(
            process_terminate | process_set_quota,
            .FALSE,
            pid,
        ) orelse return false;
        defer windows.CloseHandle(process);
        return AssignProcessToJobObject(self.handle, process).toBool();
    }

    pub fn terminate(self: ProcessTree, exit_code: UINT) bool {
        return TerminateJobObject(self.handle, exit_code).toBool();
    }

    pub fn close(self: ProcessTree) void {
        windows.CloseHandle(self.handle);
    }
};

/// A length-prefixed byte range, the argument and result shape of every DPAPI
/// entry point.
pub const DATA_BLOB = extern struct {
    cbData: DWORD = 0,
    pbData: ?[*]u8 = null,

    fn borrow(bytes: []const u8) DATA_BLOB {
        return .{
            .cbData = @intCast(bytes.len),
            .pbData = @constCast(bytes.ptr),
        };
    }

    fn slice(self: DATA_BLOB) []u8 {
        const ptr = self.pbData orelse return &.{};
        return ptr[0..self.cbData];
    }
};

/// Never let DPAPI raise a window. fx is a command line program that also runs
/// unattended, so a prompt would hang the process instead of failing it.
pub const cryptprotect_ui_forbidden: DWORD = 0x1;

pub extern "crypt32" fn CryptProtectData(
    pDataIn: *DATA_BLOB,
    szDataDescr: ?[*:0]const u16,
    pOptionalEntropy: ?*DATA_BLOB,
    pvReserved: ?*anyopaque,
    pPromptStruct: ?*anyopaque,
    dwFlags: DWORD,
    pDataOut: *DATA_BLOB,
) callconv(.winapi) BOOL;

pub extern "crypt32" fn CryptUnprotectData(
    pDataIn: *DATA_BLOB,
    ppszDataDescr: ?*?[*:0]u16,
    pOptionalEntropy: ?*DATA_BLOB,
    pvReserved: ?*anyopaque,
    pPromptStruct: ?*anyopaque,
    dwFlags: DWORD,
    pDataOut: *DATA_BLOB,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn LocalFree(hMem: ?*anyopaque) callconv(.winapi) ?*anyopaque;

pub const DpapiError = error{ DpapiProtectFailed, DpapiUnprotectFailed, OutOfMemory };

/// Encrypts `plaintext` so only this Windows user account can read it back.
///
/// The data protection scope is the user rather than the machine, which is what
/// binds the result to the interactive login: another account on the same
/// computer cannot decrypt it even with the bytes in hand.
///
/// Caller owns the returned memory.
pub fn protect(
    alloc: std.mem.Allocator,
    plaintext: []const u8,
    entropy: []const u8,
) DpapiError![]u8 {
    var in = DATA_BLOB.borrow(plaintext);
    var salt = DATA_BLOB.borrow(entropy);
    var out: DATA_BLOB = .{};
    const ok = CryptProtectData(
        &in,
        null,
        if (entropy.len == 0) null else &salt,
        null,
        null,
        cryptprotect_ui_forbidden,
        &out,
    ).toBool();
    if (!ok) return error.DpapiProtectFailed;
    defer _ = LocalFree(@ptrCast(out.pbData));
    return alloc.dupe(u8, out.slice());
}

/// Reverses `protect`. Fails rather than returning partial data when the blob
/// belongs to another account, was produced with different entropy, or has been
/// modified, because DPAPI authenticates what it encrypts.
///
/// Caller owns the returned memory.
pub fn unprotect(
    alloc: std.mem.Allocator,
    ciphertext: []const u8,
    entropy: []const u8,
) DpapiError![]u8 {
    var in = DATA_BLOB.borrow(ciphertext);
    var salt = DATA_BLOB.borrow(entropy);
    var out: DATA_BLOB = .{};
    const ok = CryptUnprotectData(
        &in,
        null,
        if (entropy.len == 0) null else &salt,
        null,
        null,
        cryptprotect_ui_forbidden,
        &out,
    ).toBool();
    if (!ok) return error.DpapiUnprotectFailed;
    defer {
        const recovered = out.slice();
        std.crypto.secureZero(u8, recovered);
        _ = LocalFree(@ptrCast(out.pbData));
    }
    return alloc.dupe(u8, out.slice());
}

test "console helpers tolerate a non-console handle" {
    const nul = std.Io.Dir.openFileAbsolute(std.testing.io, "\\\\.\\NUL", .{}) catch
        return error.SkipZigTest;
    defer nul.close(std.testing.io);
    try std.testing.expect(!isConsole(nul.handle));
    try std.testing.expect(getMode(nul.handle) == null);
    try std.testing.expect(windowSize(nul.handle) == null);
    try std.testing.expect(enableRawInput(nul.handle) == null);
}

test "job object round-trips creation and termination" {
    var tree = ProcessTree.create() orelse return error.SkipZigTest;
    defer tree.close();
    try std.testing.expect(tree.terminate(0));
}
