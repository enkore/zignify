const std = @import("std");
const print = std.debug.print;
const Ed25519 = std.crypto.sign.Ed25519;
const SHA512 = std.crypto.hash.sha2.Sha512;
const b64decoder = std.base64.standard.Decoder;
const b64encoder = std.base64.standard.Encoder;
const endian = @import("builtin").target.cpu.arch.endian();
const getopt = @import("getopt.zig");
const zero = std.crypto.utils.secureZero;
const bcrypt_pbkdf = @import("bcrypt_pbkdf.zig").bcrypt_pbkdf;

const comment_hdr = "untrusted comment: ";

fn from_bytes(comptime T: type, bytes: []const u8) !T {
    const size = @sizeOf(T);
    if (bytes.len != size)
        return error.InvalidLength;
    var self = @bitCast(T, bytes[0..size].*);
    try self.check();
    return self;
}

fn from_file(comptime T: type, path: []const u8, allocator: *std.mem.Allocator) !T {
    const data = try read_base64_file(path, allocator);
    defer allocator.free(data);
    return from_bytes(T, data);
}

fn as_bytes(self: anytype) []const u8 {
    return @bitCast([@sizeOf(@TypeOf(self))]u8, self)[0..];
}

const Signature = packed struct {
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

const PubKey = packed struct {
    pkalg: [2]u8,
    keynum: [8]u8,
    pubkey: [Ed25519.public_length]u8,

    fn check(self: PubKey) !void {
        if (!std.mem.eql(u8, &self.pkalg, "Ed"))
            return error.UnsupportedAlgorithm;
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

    fn check(self: *PrivateKey) !void {
        if (!std.mem.eql(u8, &self.pkalg, "Ed"))
            return error.UnsupportedAlgorithm;
        if (!std.mem.eql(u8, &self.kdfalg, "BK"))
            return error.UnsupportedAlgorithm;
        self.kdfrounds = network_to_host(u32, self.kdfrounds);
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
    const encseckey = try from_file(PrivateKey, seckeyfile, allocator);
    const msg = try read_file(msgfile, 65535, allocator);
    defer allocator.free(msg);
    const seckey = try encseckey.decrypt("");
    const signature = try sign_message(seckey, msg);
    const keyname = std.fs.path.basename(seckeyfile);
    const comment = try std.mem.concat(allocator, u8, &[_][]const u8{ "verify with ", keyname[0 .. keyname.len - 3], "pub" });
    defer allocator.free(comment);
    try write_base64_file(sigfile, comment, as_bytes(signature), allocator);
}

fn verify_file(pubkeyfile: []const u8, msgfile: []const u8, sigfile: []const u8, allocator: *std.mem.Allocator) !void {
    const pubkey = try from_file(PubKey, pubkeyfile, allocator);
    const sig = try from_file(Signature, sigfile, allocator);
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

fn secure_random(comptime nbytes: u32) [nbytes]u8 {
    var ret: [nbytes]u8 = undefined;
    std.crypto.random.bytes(&ret);
    return ret;
}

fn generate_key(pubkeyfile: []const u8, seckeyfile: []const u8, passphrase: []const u8, allocator: *std.mem.Allocator) !void {
    const keypair = try Ed25519.KeyPair.create(null); // null seed means random
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
    const seckey = PrivateKey{
        .pkalg = "Ed".*,
        .kdfalg = "BK".*,
        .kdfrounds = host_to_network(u32, kdfrounds),
        .salt = kdfsalt,
        .checksum = checksum.*,
        .keynum = pubkey.keynum,
        .seckey = encrypted_key,
    };
    try write_base64_file(seckeyfile, "signify secret key", as_bytes(seckey), allocator);
    try write_base64_file(pubkeyfile, "signify public key", as_bytes(pubkey), allocator);
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

const Args = struct {
    const Operation = enum {
        Generate,
        Sign,
        Verify,
        VerifyList,
    };

    operation: ?Operation = null,
    embedded: bool = false,
    comment: ?[]const u8 = null,
    msgfile: ?[]const u8 = null,
    usepass: bool = true,
    pubkeyfile: ?[]const u8 = null,
    seckeyfile: ?[]const u8 = null,
    sigfile: ?[]const u8 = null,

    const Usage = error{Usage};

    fn usage() Usage!void {
        print(
            \\usage: {0s} -G [-c comment] -p pubkey -s seckey
            \\       {0s} -S [-e] [-x sigfile] -s seckey -m message
            \\       {0s} -V [-e] -p pubkey [-x sigfile] -m message
            \\       {0s} -C -p pubkey -x sigfile
            \\
        , .{std.fs.path.basename(std.mem.spanZ(std.os.argv[0]))});
        return error.Usage;
    }

    fn set_op(self: *Args, operation: Operation) Usage!void {
        if (self.operation != null)
            return usage();
        self.operation = operation;
    }

    fn parse_cmdline() Usage!Args {
        var opts = getopt.getopt("GSVChec:m:np:s:x:");
        var self = Args{};
        while (opts.next()) |maybe_opt| {
            if (maybe_opt) |opt| {
                switch (opt.opt) {
                    // Generate key pair
                    'G' => try self.set_op(.Generate),
                    // Sign message
                    'S' => try self.set_op(.Sign),
                    // Verify message
                    'V' => try self.set_op(.Verify),
                    // Verify signed checksum list, then verify checksum of each listed file
                    'C' => try self.set_op(.VerifyList),
                    // Flags
                    'h' => try usage(),
                    'e' => self.embedded = true,
                    'c' => self.comment = opt.arg.?,
                    'm' => self.msgfile = opt.arg.?,
                    'n' => self.usepass = false,
                    'p' => self.pubkeyfile = opt.arg.?,
                    's' => self.seckeyfile = opt.arg.?,
                    'x' => self.sigfile = opt.arg.?,
                    else => unreachable,
                }
            } else break;
        } else |err| {
            switch (err) {
                getopt.Error.InvalidOption => print("invalid option: -{c}\n", .{opts.optopt}),
                getopt.Error.MissingArgument => print("option requires an argument: -{c}\n", .{opts.optopt}),
            }
            return error.Usage;
        }
        if (self.operation == null)
            try usage();
        switch (self.operation.?) {
            .Generate => if (self.seckeyfile == null or self.pubkeyfile == null) try usage(),
            .Sign => if (self.seckeyfile == null or self.msgfile == null) try usage(),
            .Verify => if (self.pubkeyfile == null or self.msgfile == null) try usage(),
            .VerifyList => if (self.pubkeyfile == null or self.sigfile == null) try usage(),
        }
        if (self.seckeyfile) |secname| {
            if (!std.mem.endsWith(u8, secname, ".sec")) {
                print("key files need to be named keyname.pub and keyname.sec\n", .{});
                return error.Usage;
            }
            if (self.pubkeyfile) |pubname| {
                if (!std.mem.endsWith(u8, pubname, ".pub") or
                    !std.mem.eql(u8, secname[0 .. secname.len - 3], pubname[0 .. pubname.len - 3]))
                {
                    print("key files need to be named keyname.pub and keyname.sec\n", .{});
                    return error.Usage;
                }
            }
        }
        return self;
    }
};

const getpass = @import("getpass.zig").get_password;

pub fn main() !void {
    //const allocator = std.heap.page_allocator;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = &gpa.allocator;

    const args = Args.parse_cmdline() catch std.os.exit(1);
    // if (args.msgfile != null and args.sigfile == null) {
    //     args.sigfile = try std.mem.concat(allocator, u8, &[_][]const u8{ args.msgfile.?, ".sig" });
    //     defer allocator.free(args.sigfile.?);
    // } // scope ends here, so UAF ensues

    const default_sigfile = if (args.msgfile) |msgfile|
        try std.mem.concat(allocator, u8, &[_][]const u8{ msgfile, ".sig" })
    else
        null;
    defer if (default_sigfile) |df| allocator.free(df); // so unconditional defer, conditional free

    switch (args.operation.?) {
        .Generate => {
            var pwstor: [1024]u8 = undefined;
            defer zero(u8, &pwstor);
            const passphrase = if (args.usepass)
                try getpass("Passphrase for new key: ", &pwstor)
            else
                "";
            try generate_key(args.pubkeyfile.?, args.seckeyfile.?, passphrase, allocator);
        },
        .Sign => {
            try sign_file(args.seckeyfile.?, args.msgfile.?, args.sigfile orelse default_sigfile.?, allocator);
        },
        .Verify => {
            if (verify_file(args.pubkeyfile.?, args.msgfile.?, args.sigfile orelse default_sigfile.?, allocator)) {
                print("Signature verified\n", .{});
            } else |err| switch (err) {
                error.SignatureVerificationFailed => {
                    print("Signature verification failed\n", .{});
                    std.os.exit(1);
                },
                else => return err,
            }
        },
        .VerifyList => unreachable,
    }
}
