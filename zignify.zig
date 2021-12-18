const std = @import("std");
const print = std.debug.print;
const getopt = @import("getopt.zig");
const zero = std.crypto.utils.secureZero;
const impl = @import("signify-format.zig");

fn decrypt_secret_key(seckey: *const impl.PrivateKey) !impl.PrivateKey {
    if (seckey.kdfrounds == 0) {
        return seckey.*;
    } else {
        var pwstor: [1024]u8 = undefined;
        defer zero(u8, &pwstor);
        const passphrase = try getpass("Passphrase: ", &pwstor);
        return try seckey.decrypt(passphrase);
    }
}

fn generate_key(pubkeyfile: []const u8, seckeyfile: []const u8, passphrase: []const u8, allocator: *std.mem.Allocator) !void {
    const pair = try impl.generate_keypair(passphrase);
    try impl.write_base64_file(seckeyfile, "signify secret key", impl.as_bytes(pair.seckey), allocator);
    try impl.write_base64_file(pubkeyfile, "signify public key", impl.as_bytes(pair.pubkey), allocator);
}

fn sign_file(seckeyfile: []const u8, msgfile: []const u8, sigfile: []const u8, allocator: *std.mem.Allocator) !void {
    const encseckey = try impl.from_file(impl.PrivateKey, seckeyfile, allocator);
    const msg = try impl.read_file(msgfile, 65535, allocator);
    defer allocator.free(msg);
    var seckey = try decrypt_secret_key(&encseckey);
    defer impl.zerosingle(&seckey);
    const signature = try impl.sign_message(seckey, msg);
    const keyname = std.fs.path.basename(seckeyfile);
    const comment = try std.mem.concat(allocator, u8, &[_][]const u8{ "verify with ", keyname[0 .. keyname.len - 3], "pub" });
    defer allocator.free(comment);
    try impl.write_base64_file(sigfile, comment, impl.as_bytes(signature), allocator);
}

fn verify_file(pubkeyfile: []const u8, msgfile: []const u8, sigfile: []const u8, allocator: *std.mem.Allocator) !void {
    const pubkey = try impl.from_file(impl.PubKey, pubkeyfile, allocator);
    const sig = try impl.from_file(impl.Signature, sigfile, allocator);
    const msg = try impl.read_file(msgfile, 65535, allocator);
    defer allocator.free(msg);
    return impl.verify_message(pubkey, sig, msg);
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
