const impl = @cImport({
    @cInclude("pycabcrypt.h");
});
const std = @import("std");
const print = std.debug.print;

pub fn bcrypt_pbkdf(passphrase: []const u8, salt: []const u8, key: []u8, rounds: u32) !void {
    print("passphrase={s} saltlen={d} keylen={d} rounds={d}", .{ passphrase, salt.len, key.len, rounds });
    if (impl.bcrypt_pbkdf(passphrase.ptr, passphrase.len, salt.ptr, salt.len, key.ptr, key.len, rounds) != 0)
        return error.BCryptError;
}
