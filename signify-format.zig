const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const SHA512 = std.crypto.hash.sha2.Sha512;
const b64decoder = std.base64.standard.Decoder;
const b64encoder = std.base64.standard.Encoder;
const endian = @import("builtin").target.cpu.arch.endian();
const zero = std.crypto.utils.secureZero;
const bcrypt_pbkdf = @import("bcrypt_pbkdf.zig").bcrypt_pbkdf;

const comment_hdr = "untrusted comment: ";

pub const Signature = packed struct {
    /// This is always "Ed" for Ed25519.
    pkalg: [2]u8,
    /// A random 64-bit integer which is used to tell if the correct pubkey is used for verification.
    keynum: [8]u8,
    /// Ed25519 signature
    sig: [Ed25519.signature_length]u8,

    fn check(self: Signature) !void {
        if (!std.mem.eql(u8, &self.pkalg, "Ed"))
            return error.UnsupportedAlgorithm;
    }
};

pub const PubKey = packed struct {
    pkalg: [2]u8,
    keynum: [8]u8,
    pubkey: [Ed25519.public_length]u8,

    fn check(self: PubKey) !void {
        if (!std.mem.eql(u8, &self.pkalg, "Ed"))
            return error.UnsupportedAlgorithm;
    }
};

/// A possibly encrypted secret key.
pub const SecretKey = packed struct {
    pkalg: [2]u8,
    /// BK = bcrypt_pbkdf
    kdfalg: [2]u8,
    /// Number of bcrypt_pbkdf rounds, but if 0, skip bcrypt entirely (no passphrase)
    kdfrounds: u32,
    /// bcrypt salt
    salt: [16]u8,
    /// first eight bytes of the SHA-512 hash of the *decrypted* private key
    checksum: [8]u8,
    keynum: [8]u8,
    /// Ed25519 private key XORed with output of bcrypt_pbkdf (or nulls, if kdfrounds=0).
    seckey: [Ed25519.secret_length]u8,

    fn check(self: *SecretKey) !void {
        if (!std.mem.eql(u8, &self.pkalg, "Ed"))
            return error.UnsupportedAlgorithm;
        if (!std.mem.eql(u8, &self.kdfalg, "BK"))
            return error.UnsupportedAlgorithm;
        self.kdfrounds = std.mem.bigToNative(u32, self.kdfrounds);
    }

    pub fn is_encrypted(self: SecretKey) bool {
        return self.kdfrounds > 0;
    }

    pub fn decrypt(self: SecretKey, passphrase: []const u8) !DecryptedSecretKey {
        var xorkey: [Ed25519.secret_length]u8 = undefined;
        var enckey: [Ed25519.secret_length]u8 = self.seckey;
        if (!self.is_encrypted())
            return DecryptedSecretKey{ .keynum = self.keynum, .seckey = self.seckey };
        try bcrypt_pbkdf(passphrase, self.salt[0..], xorkey[0..], self.kdfrounds);
        for (xorkey) |keybyte, index|
            enckey[index] ^= keybyte;

        var key_digest: [SHA512.digest_length]u8 = undefined;
        SHA512.hash(&enckey, &key_digest, .{});
        if (!std.mem.eql(u8, key_digest[0..8], &self.checksum))
            return error.WrongPassphrase;

        return DecryptedSecretKey{ .keynum = self.keynum, .seckey = enckey };
    }
};

pub const DecryptedSecretKey = struct {
    keynum: [8]u8,
    seckey: [Ed25519.secret_length]u8,
};

pub const KeyPair = struct {
    pubkey: PubKey,
    seckey: SecretKey,
};

pub fn generate_keypair(passphrase: []const u8) !KeyPair {
    var keypair = try Ed25519.KeyPair.create(null); // null seed means random
    defer zerosingle(&keypair);
    const checksum = checksum: {
        var key_digest: [SHA512.digest_length]u8 = undefined;
        SHA512.hash(&keypair.secret_key, &key_digest, .{});
        break :checksum key_digest[0..8];
    };
    const kdfrounds: u32 = if (passphrase.len > 0) 42 else 0; // 42 rounds is used by signify
    const kdfsalt: [16]u8 = secure_random(16);
    const encrypted_key = if (kdfrounds > 0) key: {
        var xorkey: [Ed25519.secret_length]u8 = undefined;
        var enckey: [Ed25519.secret_length]u8 = keypair.secret_key;
        try bcrypt_pbkdf(passphrase, kdfsalt[0..], xorkey[0..], kdfrounds);
        for (xorkey) |keybyte, index|
            enckey[index] ^= keybyte;
        break :key enckey;
    } else key: {
        break :key keypair.secret_key;
    };
    const pubkey = PubKey{
        .pkalg = "Ed".*,
        .keynum = secure_random(8),
        .pubkey = keypair.public_key,
    };
    const seckey = SecretKey{
        .pkalg = "Ed".*,
        .kdfalg = "BK".*,
        .kdfrounds = std.mem.nativeToBig(u32, kdfrounds),
        .salt = kdfsalt,
        .checksum = checksum.*,
        .keynum = pubkey.keynum,
        .seckey = encrypted_key,
    };
    return KeyPair{ .pubkey = pubkey, .seckey = seckey };
}

pub fn sign_message(privatekey: DecryptedSecretKey, msg: []const u8) !Signature {
    const keypair = Ed25519.KeyPair.fromSecretKey(privatekey.seckey);
    const sig = try Ed25519.sign(msg, keypair, null);
    return Signature{ .pkalg = "Ed".*, .keynum = privatekey.keynum, .sig = sig };
}

pub fn verify_message(pubkey: PubKey, signature: Signature, msg: []const u8) !void {
    if (!std.mem.eql(u8, &pubkey.keynum, &signature.keynum)) {
        return error.WrongPublicKey;
    }
    return Ed25519.verify(signature.sig, msg, pubkey.pubkey);
}

/// read signify-base64 file at *path*. If *data_len* is specified,
/// the file is assumed to be in <header><payload> format and data_len
/// will receive the length of the header (in bytes).
pub fn read_base64_file(path: []const u8, data_len: ?*usize, allocator: std.mem.Allocator) ![]u8 {
    var contents_buf: [2048]u8 = undefined;
    const contents = try std.fs.cwd().readFile(path, &contents_buf);
    var iter = std.mem.split(u8, contents, "\n");
    var line = iter.next() orelse return error.InvalidFile;
    var length = line.len;
    if (std.mem.startsWith(u8, line, comment_hdr)) {
        line = iter.next() orelse return error.InvalidFile;
        length += line.len + 1; // +1 due to \n not being part of line
    }
    const empty_line = iter.next() orelse return error.InvalidFile;
    if (data_len != null) {
        length += 1;
        data_len.?.* = length;
    } else {
        // If no data follows the base64 portion, check that the file is terminated with \n.
        if (empty_line.len > 0) {
            return error.GarbageAtEndOfFile;
        }
        if (iter.next() != null) {
            return error.GarbageAtEndOfFile;
        }
    }
    const dec = try allocator.alloc(u8, try b64decoder.calcSizeForSlice(line));
    try b64decoder.decode(dec[0..dec.len], line);
    return dec;
}

pub fn write_base64_file(path: []const u8, comment: []const u8, data: []const u8, allocator: std.mem.Allocator) !void {
    var encode_buf = try allocator.alloc(u8, b64encoder.calcSize(data.len));
    defer allocator.free(encode_buf);
    const encoded = b64encoder.encode(encode_buf, data);

    const file = try std.fs.cwd().createFile(path, .{ .exclusive = true });
    defer file.close();
    try file.writeAll(comment_hdr);
    try file.writeAll(comment);
    try file.writeAll("\n");
    try file.writeAll(encoded);
    try file.writeAll("\n");
}

fn secure_random(comptime nbytes: u32) [nbytes]u8 {
    var ret: [nbytes]u8 = undefined;
    std.crypto.random.bytes(&ret);
    return ret;
}

fn from_bytes(comptime T: type, bytes: []const u8) !T {
    const size = @sizeOf(T);
    if (bytes.len != size)
        return error.InvalidLength;
    var self = @bitCast(T, bytes[0..size].*);
    try self.check();
    return self;
}

pub fn from_file(comptime T: type, path: []const u8, data_len: ?*usize, allocator: std.mem.Allocator) !T {
    const data = try read_base64_file(path, data_len, allocator);
    defer allocator.free(data);
    return from_bytes(T, data);
}

pub fn as_bytes(self: anytype) []const u8 {
    return @bitCast([@sizeOf(@TypeOf(self))]u8, self)[0..];
}

pub fn zerosingle(obj: anytype) void {
    zero(@TypeOf(obj.*), @as(*[1]@TypeOf(obj.*), obj));
}
