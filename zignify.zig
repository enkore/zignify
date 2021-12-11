const std = @import("std");
const print = std.debug.print;
const Ed25519 = std.crypto.sign.Ed25519;
const b64decoder = std.base64.standard.Decoder;

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

pub fn main() !void {
    //const allocator = std.heap.page_allocator;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = &gpa.allocator;

    try verify_file("test/key.pub", "test/message.txt", "test/msg.sig", allocator);
    print("Signature Verified\n", .{});
}
