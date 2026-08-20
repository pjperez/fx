//! Process-tree termination for Windows.
//!
//! POSIX fx puts every spawned tool into its own process group and cancels it
//! with `kill(-pgid)`, so a shell that spawned its own children is torn down
//! whole. Windows has no process groups; the equivalent guarantee comes from a
//! job object, which a process and everything it later spawns belong to.
//!
//! `std.process.Child` has no room to carry a job handle, so the association is
//! kept here, keyed by the child process handle the caller already holds. Entries
//! are bounded: when the table is full the child simply runs untracked and
//! degrades to a single-process kill, which is what it would have done anyway.

const builtin = @import("builtin");
const std = @import("std");
const io_mod = @import("io.zig");
const windows_api = @import("windows_api.zig");

const windows = std.os.windows;

comptime {
    if (builtin.os.tag != .windows) @compileError("windows_process_tree is windows-only");
}

const max_tracked = 64;

const Entry = struct {
    child: ?windows.HANDLE = null,
    job: windows_api.ProcessTree = undefined,
};

var mutex: std.Io.Mutex = .init;
var entries: [max_tracked]Entry = @splat(.{});

fn lock() void {
    mutex.lockUncancelable(io_mod.getIo());
}

fn unlock() void {
    mutex.unlock(io_mod.getIo());
}

/// Places `child` and every process it goes on to create into one job object.
///
/// Call immediately after spawning, before the child has had time to create
/// children of its own. Returns `false` when the child could not be tracked, in
/// which case `terminate` falls back to killing only that process.
pub fn track(child: windows.HANDLE) bool {
    const job = windows_api.ProcessTree.create() orelse return false;
    if (!windows_api.AssignProcessToJobObject(job.handle, child).toBool()) {
        job.close();
        return false;
    }

    lock();
    defer unlock();
    for (&entries) |*entry| {
        if (entry.child != null) continue;
        entry.* = .{ .child = child, .job = job };
        return true;
    }
    job.close();
    return false;
}

/// Terminates the whole tree rooted at `child`. Returns `false` when `child` was
/// never tracked, leaving the single-process kill to the caller.
pub fn terminate(child: windows.HANDLE, exit_code: u32) bool {
    lock();
    defer unlock();
    for (&entries) |*entry| {
        if (entry.child != child) continue;
        return entry.job.terminate(exit_code);
    }
    return false;
}

/// Releases the job handle for `child` once it has been reaped. Closing the job
/// also terminates any process still inside it, so a leaked entry cannot leave a
/// tool running after fx has moved on.
pub fn release(child: windows.HANDLE) void {
    lock();
    defer unlock();
    for (&entries) |*entry| {
        if (entry.child != child) continue;
        entry.job.close();
        entry.* = .{};
        return;
    }
}

/// True when `child` still has a live tree that has not been reaped.
pub fn isTracked(child: windows.HANDLE) bool {
    lock();
    defer unlock();
    for (&entries) |*entry| {
        if (entry.child == child) return true;
    }
    return false;
}

test "tracking a real child terminates its whole tree" {
    const io = std.testing.io;
    var child = std.process.spawn(io, .{
        .argv = &.{ "cmd.exe", "/C", "ping -n 30 127.0.0.1 > NUL" },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return error.SkipZigTest;
    const handle = child.id orelse return error.SkipZigTest;

    try std.testing.expect(track(handle));
    try std.testing.expect(isTracked(handle));
    try std.testing.expect(terminate(handle, 1));
    _ = child.wait(io) catch {};
    release(handle);
    try std.testing.expect(!isTracked(handle));
}

test "untracked children report no tree" {
    const fake: windows.HANDLE = @ptrFromInt(0x1234);
    try std.testing.expect(!isTracked(fake));
    try std.testing.expect(!terminate(fake, 1));
    release(fake);
}
