const std = @import("std");
const print = std.debug.print;
const Ed25519 = std.crypto.sign.Ed25519;
const SHA512 = std.crypto.hash.sha2.Sha512;
const b64decoder = std.base64.standard.Decoder;
const b64encoder = std.base64.standard.Encoder;
const endian = @import("builtin").target.cpu.arch.endian();

const bcrypt_pbkdf = @import("bcrypt_pbkdf.zig").bcrypt_pbkdf;

const comment_hdr = "untrusted comment: ";

const Signature = packed struct {
    /// This is always "Ed" for Ed25519.
    pkalg: [2]u8,
    /// A random 64-bit integer which is used to tell if the correct pubkey is used for verification.
    keynum: [8]u8,
    /// Ed25519 signature
    sig: [Ed25519.signature_length]u8,

    fn from_bytes(bytes: []const u8) !Signature {
        const size = @sizeOf(Signature);
        if (bytes.len != size)
            return error.InvalidLength;
        const self = @bitCast(Signature, bytes[0..size].*);
        if (!std.mem.eql(u8, &self.pkalg, "Ed"))
            return error.UnsupportedAlgorithm;
        return self;
    }

    fn from_file(path: []const u8, allocator: *std.mem.Allocator) !Signature {
        const data = try read_base64_file(path, allocator);
        defer allocator.free(data);
        return from_bytes(data);
    }

    fn as_bytes(self: Signature) []const u8 {
        return @bitCast([@sizeOf(Signature)]u8, self)[0..];
    }
};

const PubKey = packed struct {
    pkalg: [2]u8,
    keynum: [8]u8,
    pubkey: [Ed25519.public_length]u8,

    fn from_bytes(bytes: []const u8) !PubKey {
        const size = @sizeOf(PubKey);
        if (bytes.len != size)
            return error.InvalidLength;
        const self = @bitCast(PubKey, bytes[0..size].*);
        if (!std.mem.eql(u8, &self.pkalg, "Ed"))
            return error.UnsupportedAlgorithm;
        return self;
    }

    fn from_file(path: []const u8, allocator: *std.mem.Allocator) !PubKey {
        const data = try read_base64_file(path, allocator);
        defer allocator.free(data);
        return from_bytes(data);
    }
};

const PrivateKey = packed struct {
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

    fn from_bytes(bytes: []const u8) !PrivateKey {
        const size = @sizeOf(PrivateKey);
        if (bytes.len != size)
            return error.InvalidLength;
        var self = @bitCast(PrivateKey, bytes[0..size].*);
        if (!std.mem.eql(u8, &self.pkalg, "Ed"))
            return error.UnsupportedAlgorithm;
        if (!std.mem.eql(u8, &self.kdfalg, "BK"))
            return error.UnsupportedAlgorithm;
        self.kdfrounds = network_to_host(u32, self.kdfrounds);
        return self;
    }

    fn from_file(path: []const u8, allocator: *std.mem.Allocator) !PrivateKey {
        const data = try read_base64_file(path, allocator);
        defer allocator.free(data);
        return from_bytes(data);
    }

    fn decrypt(self: PrivateKey, passphrase: []const u8) !PrivateKey {
        var xorkey: [Ed25519.secret_length]u8 = undefined;
        var enckey: [Ed25519.secret_length]u8 = self.seckey;
        if (self.kdfrounds == 0)
            return self;
        try bcrypt_pbkdf(passphrase, self.salt[0..], xorkey[0..], self.kdfrounds);
        for (xorkey) |keybyte, index|
            enckey[index] ^= keybyte;

        var key_digest: [SHA512.digest_length]u8 = undefined;
        SHA512.hash(&enckey, &key_digest, .{});
        if (!std.mem.eql(u8, key_digest[0..8], &self.checksum))
            return error.WrongPassphrase;

        return PrivateKey{ .pkalg = self.pkalg, .kdfalg = self.kdfalg, .kdfrounds = self.kdfrounds, .salt = self.salt, .checksum = self.checksum, .keynum = self.keynum, .seckey = enckey };
    }
};

fn host_to_network(comptime T: type, value: T) T {
    return switch (endian) {
        .Big => value,
        .Little => @byteSwap(T, value),
    };
}

const network_to_host = host_to_network;

fn sign_file(seckeyfile: []const u8, msgfile: []const u8, sigfile: []const u8, allocator: *std.mem.Allocator) !void {
    const encseckey = try PrivateKey.from_file(seckeyfile, allocator);
    const msg = try read_file(msgfile, 65535, allocator);
    defer allocator.free(msg);
    const seckey = try encseckey.decrypt("");
    const signature = try sign_message(seckey, msg);
    try write_base64_file(sigfile, "no comment", signature.as_bytes(), allocator);
}

fn verify_file(pubkeyfile: []const u8, msgfile: []const u8, sigfile: []const u8, allocator: *std.mem.Allocator) !void {
    const pubkey = try PubKey.from_file(pubkeyfile, allocator);
    const sig = try Signature.from_file(sigfile, allocator);
    const msg = try read_file(msgfile, 65535, allocator);
    defer allocator.free(msg);
    return verify_message(pubkey, sig, msg);
}

fn verify_message(pubkey: PubKey, signature: Signature, msg: []const u8) !void {
    if (!std.mem.eql(u8, &pubkey.keynum, &signature.keynum)) {
        return error.WrongPublicKey;
    }
    return Ed25519.verify(signature.sig, msg, pubkey.pubkey);
}

fn sign_message(privatekey: PrivateKey, msg: []const u8) !Signature {
    const keypair = Ed25519.KeyPair.fromSecretKey(privatekey.seckey);
    const sig = try Ed25519.sign(msg, keypair, null);
    return Signature{ .pkalg = "Ed".*, .keynum = privatekey.keynum, .sig = sig };
}

fn read_file(path: []const u8, max_size: u32, allocator: *std.mem.Allocator) ![]u8 {
    return try std.fs.cwd().readFileAlloc(allocator, path, max_size);
}

fn read_base64_file(path: []const u8, allocator: *std.mem.Allocator) ![]u8 {
    const sig_contents = try read_file(path, 4096, allocator);
    defer allocator.free(sig_contents);
    var iter = std.mem.split(sig_contents, "\n");

    var line = iter.next().?;
    if (std.mem.startsWith(u8, line, comment_hdr)) {
        line = iter.next().?;
    }

    const empty_line = iter.next().?;
    if (empty_line.len > 0) {
        return error.GarbageAtEndOfFile;
    }
    if (iter.next() != null) {
        return error.GarbageAtEndOfFile;
    }

    const dec = try allocator.alloc(u8, try b64decoder.calcSizeForSlice(line));
    try b64decoder.decode(dec[0..dec.len], line);
    return dec;
}

fn write_base64_file(path: []const u8, comment: []const u8, data: []const u8, allocator: *std.mem.Allocator) !void {
    var encode_buf = try allocator.alloc(u8, b64encoder.calcSize(data.len));
    defer allocator.free(encode_buf);
    const encoded = b64encoder.encode(encode_buf, data);

    const file = try std.fs.cwd().createFile(
        path,
        .{ .truncate = true },
    );
    defer file.close();
    try file.writeAll(comment_hdr);
    try file.writeAll(comment);
    try file.writeAll("\n");
    try file.writeAll(encoded);
    try file.writeAll("\n");
}

pub fn main() !void {
    //const allocator = std.heap.page_allocator;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = &gpa.allocator;

    try sign_file("test/key.sec", "test/message.txt", "test/msg.sig", allocator);

    //    try verify_file("test/key.pub", "test/message.txt", "test/msg.sig", allocator);
    //    print("Signature Verified\n", .{});
}
