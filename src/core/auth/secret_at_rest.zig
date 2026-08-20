//! Encryption of stored credentials on platforms that provide it without a
//! dependency.
//!
//! fx already chooses the credential store per platform: macOS keeps the API key
//! in the Keychain, every other platform keeps it in a profile file. This module
//! extends that principle to the bytes fx writes itself.
//!
//! On Windows the profile file is encrypted with DPAPI, whose key is derived from
//! the interactive login. This matters more there than elsewhere because the
//! `0o600` mode fx relies on cannot be enforced on Windows at all; see
//! `shared/file_permissions.zig`. A file whose access control is inherited from
//! the user profile is protected by the account, not by the file, so the content
//! is protected by the account instead.
//!
//! Linux stays plaintext deliberately. The equivalent service there is libsecret,
//! which needs D-Bus and a running keyring daemon. fx explicitly targets
//! containers and agent sandboxes where neither exists, and the kernel keyring
//! does not survive a reboot, so there is no dependency-free option that would
//! work everywhere fx runs. A conditional backend that silently disappears is
//! worse than a documented file.
//!
//! Callers see one contract on every platform: `seal` returns the bytes to write,
//! `open` returns the bytes to parse, and both return null when the input already
//! is the answer. On POSIX both are comptime-known to be null, so the call sites
//! compile to exactly what they were before this module existed.

const builtin = @import("builtin");
const std = @import("std");

const io_mod = @import("../shared/io.zig");
const secret = @import("secret.zig");
const windows_api = if (builtin.os.tag == .windows)
    @import("../shared/windows_api.zig")
else
    void;

const Allocator = std.mem.Allocator;

/// Whether stored credentials are encrypted by fx on this platform.
pub const encrypts = builtin.os.tag == .windows;

/// Names the protection for operators, matching how the credential backend is
/// already described to them.
pub const label = if (encrypts) "DPAPI (current Windows user)" else "file permissions";

/// Bound to fx so a blob lifted out of the profile cannot be decrypted by
/// pointing another program's DPAPI call at it. Entropy is not a secret; it
/// narrows what the ciphertext is usable for.
const entropy = "fx.credential.v1";

const envelope_version: i64 = 1;
const envelope_key = "dpapi";
const max_envelope_bytes: usize = 256 * 1024;

pub const SealError = error{ CredentialEncryptionFailed, OutOfMemory };
pub const OpenError = error{ CredentialDecryptionFailed, OutOfMemory };

/// Returns the bytes to write in place of `plaintext`, or null when `plaintext`
/// should be written unchanged.
///
/// Writes fail closed. There is no path that reports success after storing a
/// credential in the clear, because a silent downgrade would leave the operator
/// believing in protection that is not there.
///
/// Caller owns the returned memory.
pub fn seal(alloc: Allocator, plaintext: []const u8) SealError!?[]u8 {
    if (comptime !encrypts) return null;
    if (disabled()) return null;

    const ciphertext = windows_api.protect(alloc, plaintext, entropy) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.CredentialEncryptionFailed,
    };
    defer secret.zeroAndFree(alloc, ciphertext);

    return encodeEnvelope(alloc, ciphertext) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.CredentialEncryptionFailed,
    };
}

/// Returns the plaintext behind `bytes`, or null when `bytes` already is the
/// plaintext.
///
/// Accepting unencrypted input is the migration path: a profile written before
/// encryption existed still loads, and the next write seals it. Only a blob that
/// announces itself as encrypted and then fails to decrypt is an error, and that
/// error is reported rather than swallowed so the operator learns the credential
/// has to be re-established instead of seeing an unexplained logged-out state.
///
/// Caller owns the returned memory.
pub fn open(alloc: Allocator, bytes: []const u8) OpenError!?[]u8 {
    if (comptime !encrypts) return null;

    const ciphertext = (decodeEnvelope(alloc, bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.CredentialDecryptionFailed,
    }) orelse return null;
    defer secret.zeroAndFree(alloc, ciphertext);

    return windows_api.unprotect(alloc, ciphertext, entropy) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.CredentialDecryptionFailed,
    };
}

/// True when `bytes` claims to be encrypted, whether or not it can be decrypted.
pub fn isSealed(bytes: []const u8) bool {
    if (comptime !encrypts) return false;
    const trimmed = std.mem.trim(u8, bytes, " \t\r\n");
    if (trimmed.len == 0 or trimmed[0] != '{') return false;
    return std.mem.indexOf(u8, trimmed, "\"" ++ envelope_key ++ "\"") != null;
}

fn disabled() bool {
    const value = io_mod.getenv("FX_DISABLE_DPAPI") orelse return false;
    return std.mem.eql(u8, value, "1") or std.ascii.eqlIgnoreCase(value, "true");
}

/// The envelope stays valid JSON so a stored credential that is already JSON
/// keeps the same shape on disk and stays readable by anything that inspects it.
fn encodeEnvelope(alloc: Allocator, ciphertext: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const encoded = try alloc.alloc(u8, encoder.calcSize(ciphertext.len));
    defer alloc.free(encoded);
    _ = encoder.encode(encoded, ciphertext);

    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const writer = &out.writer;
    try writer.print("{{\"v\":{d},\"" ++ envelope_key ++ "\":", .{envelope_version});
    try std.json.Stringify.value(encoded, .{}, writer);
    try writer.writeAll("}\n");
    return out.toOwnedSlice();
}

/// Returns the ciphertext an envelope carries, or null when `bytes` is not an
/// envelope. Caller owns the returned memory.
fn decodeEnvelope(alloc: Allocator, bytes: []const u8) !?[]u8 {
    if (!isSealed(bytes)) return null;
    if (bytes.len > max_envelope_bytes) return error.InvalidEnvelope;

    var parsed = std.json.parseFromSlice(std.json.Value, alloc, bytes, .{}) catch
        return error.InvalidEnvelope;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidEnvelope;

    const version = parsed.value.object.get("v") orelse return error.InvalidEnvelope;
    if (version != .integer or version.integer != envelope_version) return error.InvalidEnvelope;
    const encoded = parsed.value.object.get(envelope_key) orelse return error.InvalidEnvelope;
    if (encoded != .string) return error.InvalidEnvelope;

    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(encoded.string) catch return error.InvalidEnvelope;
    const ciphertext = try alloc.alloc(u8, size);
    errdefer alloc.free(ciphertext);
    decoder.decode(ciphertext, encoded.string) catch return error.InvalidEnvelope;
    return ciphertext;
}

test "sealing is a no-op where fx does not encrypt credentials" {
    if (comptime encrypts) return error.SkipZigTest;
    try std.testing.expect((try seal(std.testing.allocator, "plain")) == null);
    try std.testing.expect((try open(std.testing.allocator, "plain")) == null);
    try std.testing.expect(!isSealed("{\"dpapi\":\"x\"}"));
}

test "sealed credentials round-trip and hide the plaintext" {
    if (comptime !encrypts) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const plaintext = "{\"version\":1,\"access_token\":\"vt-round-trip-token\"}";

    const sealed = (try seal(alloc, plaintext)) orelse return error.TestUnexpectedPlaintextWrite;
    defer alloc.free(sealed);

    try std.testing.expect(isSealed(sealed));
    try std.testing.expect(std.mem.indexOf(u8, sealed, "vt-round-trip-token") == null);
    try std.testing.expect(std.mem.indexOf(u8, sealed, "access_token") == null);

    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, sealed, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value.object.get("v").?.integer == envelope_version);

    const opened = (try open(alloc, sealed)) orelse return error.TestUnexpectedPlaintextRead;
    defer secret.zeroAndFree(alloc, opened);
    try std.testing.expectEqualStrings(plaintext, opened);
}

test "plaintext credentials stay readable so a profile can migrate" {
    if (comptime !encrypts) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    for ([_][]const u8{
        "{\"version\":1,\"access_token\":\"legacy\"}",
        "vt1-raw-api-key-value",
        "",
        "   \n",
        "{\"version\":1,\"note\":\"mentions dpapi in prose\"}",
    }) |legacy| {
        try std.testing.expect(!isSealed(legacy));
        try std.testing.expect((try open(alloc, legacy)) == null);
    }
}

test "a corrupt envelope reports failure instead of reading as plaintext" {
    if (comptime !encrypts) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    for ([_][]const u8{
        "{\"v\":1,\"dpapi\":\"bm90LWEtYmxvYg==\"}",
        "{\"v\":1,\"dpapi\":\"!!!not base64!!!\"}",
        "{\"v\":2,\"dpapi\":\"AAAA\"}",
        "{\"v\":1,\"dpapi\":7}",
        "{\"dpapi\":\"AAAA\"}",
        "{\"v\":1,\"dpapi\":\"AAAA\"",
    }) |broken| {
        try std.testing.expectError(error.CredentialDecryptionFailed, open(alloc, broken));
    }
}
