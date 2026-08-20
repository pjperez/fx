//! POSIX-style file permissions for every platform fx supports.
//!
//! fx states each private-state guarantee in POSIX mode bits: session directories
//! are `0o700`, session files are `0o600`. `std.Io.File.Permissions` models those
//! bits directly on POSIX, but on Windows it models file attributes and offers
//! neither `toMode` nor `fromMode`, because NTFS access is governed by ACLs.
//!
//! These helpers are the single place that difference is resolved. Every fx call
//! site states its intent through them, so the contract reads the same on all
//! platforms and simply becomes unenforceable on Windows rather than wrong.

const builtin = @import("builtin");
const std = @import("std");

/// Integer type holding POSIX mode bits. `std.posix.mode_t` is `u0` on Windows.
pub const Mode = if (builtin.os.tag == .windows) u32 else std.posix.mode_t;

/// True when the platform exposes POSIX mode bits fx can set and verify.
pub const enforced = builtin.os.tag != .windows;

/// Permissions carrying `mode`.
///
/// On Windows only the read-only attribute can be expressed, so a mode without
/// owner write becomes a read-only file and everything else an ordinary one.
pub fn fromMode(requested: Mode) std.Io.File.Permissions {
    if (comptime !enforced) {
        const writable = requested & 0o200 != 0;
        return fromAttributes(.{ .READONLY = !writable, .NORMAL = writable });
    }
    return .fromMode(requested);
}

/// `std.Io.File.Permissions.readOnly` and `setReadOnly` are unusable on Windows
/// in Zig 0.16: they name `windows.FILE_ATTRIBUTE_READONLY`, which no longer
/// exists. The attribute is read and written directly instead.
fn fromAttributes(attributes: std.os.windows.FILE.ATTRIBUTE) std.Io.File.Permissions {
    return @enumFromInt(@as(std.os.windows.ULONG, @bitCast(attributes)));
}

fn isReadOnlyAttribute(permissions: std.Io.File.Permissions) bool {
    return permissions.toAttributes().READONLY;
}

/// The POSIX mode bits of `permissions`, or `null` where they do not exist.
pub fn mode(permissions: std.Io.File.Permissions) ?Mode {
    if (comptime !enforced) return null;
    return permissions.toMode();
}

/// The POSIX mode bits of `permissions` for reporting, or `0` where they do not
/// exist. Use `mode` when the absence has to be distinguished.
pub fn modeOrZero(permissions: std.Io.File.Permissions) Mode {
    return mode(permissions) orelse 0;
}

/// True when `permissions` carries exactly `expected` in its permission bits.
/// Always true on Windows, where the mode cannot be observed.
pub fn hasMode(permissions: std.Io.File.Permissions, expected: Mode) bool {
    const actual = mode(permissions) orelse return true;
    return actual & 0o777 == expected;
}

/// True when no group or other class has any access.
/// Always true on Windows, where the mode cannot be observed.
pub fn isOwnerOnly(permissions: std.Io.File.Permissions) bool {
    const actual = mode(permissions) orelse return true;
    return actual & 0o077 == 0;
}

/// True when any class has write access.
pub fn isWritable(permissions: std.Io.File.Permissions) bool {
    if (comptime !enforced) return !isReadOnlyAttribute(permissions);
    return permissions.toMode() & 0o222 != 0;
}

/// True when both sides carry the same permissions.
pub fn eql(a: std.Io.File.Permissions, b: std.Io.File.Permissions) bool {
    return @intFromEnum(a) == @intFromEnum(b);
}

test "private modes round-trip where posix modes exist" {
    const private = fromMode(0o600);
    try std.testing.expect(hasMode(private, 0o600));
    try std.testing.expect(isOwnerOnly(private));
    try std.testing.expect(isWritable(private));
    if (enforced) try std.testing.expectEqual(@as(Mode, 0o600), mode(private).?);
}

test "read-only modes report as unwritable on every platform" {
    const read_only = fromMode(0o400);
    try std.testing.expect(!isWritable(read_only));
    try std.testing.expect(isOwnerOnly(read_only));
}

test "mode observation is absent without posix modes" {
    try std.testing.expectEqual(enforced, mode(fromMode(0o600)) != null);
    try std.testing.expectEqual(enforced, modeOrZero(fromMode(0o600)) != 0);
}
