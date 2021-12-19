const std = @import("std");
const print = std.debug.print;
const getopt = @import("getopt.zig");
const zero = std.crypto.utils.secureZero;
const impl = @import("signify-format.zig");
const getpass = @import("getpass.zig");

const ExitError = error.ExitError;

pub fn main() !void {
    //const allocator = std.heap.page_allocator;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = &gpa.allocator;

    const args = Args.parse_cmdline() catch std.os.exit(1);
    args.run(allocator) catch |err| {
        switch (err) {
            getpass.PassphraseTooLong => print("The given passphrase is too long.\n", .{}),
            ExitError => {},
            else => return err,
        }
        std.os.exit(1);
    };
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

    fn run(args: *const Args, allocator: *std.mem.Allocator) !void {
        const default_sigfile = if (args.msgfile) |msgfile|
            try std.mem.concat(allocator, u8, &[_][]const u8{ msgfile, ".sig" })
        else
            null;
        defer if (default_sigfile) |df| allocator.free(df); // so unconditional defer, conditional free

        switch (args.operation.?) {
            .Generate => try generate_key(args.pubkeyfile.?, args.seckeyfile.?, args.usepass, allocator),
            .Sign => try sign_file(args.seckeyfile.?, args.msgfile.?, args.sigfile orelse default_sigfile.?, args.embedded, allocator),
            .Verify => {
                const result = if (args.embedded)
                    verify_embedded_file(args.pubkeyfile.?, args.msgfile.?, args.sigfile.?, allocator)
                else
                    verify_file(args.pubkeyfile.?, args.msgfile.?, args.sigfile orelse default_sigfile.?, allocator);
                if (result) {
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
};

fn generate_key(pubkeyfile: []const u8, seckeyfile: []const u8, encrypt: bool, allocator: *std.mem.Allocator) !void {
    var pwstor: [1024]u8 = undefined;
    defer zero(u8, &pwstor);
    const passphrase = if (encrypt)
        getpass.getpass("Passphrase for new key: ", &pwstor) catch |err| switch (err) {
            getpass.NoPassphraseGiven => {
                print("If you wish to not encrypt the key, use the -n switch.\n", .{});
                return ExitError;
            },
            else => return err,
        }
    else
        "";

    const pair = try impl.generate_keypair(passphrase);
    impl.write_base64_file(seckeyfile, "signify secret key", impl.as_bytes(pair.seckey), allocator) catch |err| return handle_file_error(seckeyfile, err);
    impl.write_base64_file(pubkeyfile, "signify public key", impl.as_bytes(pair.pubkey), allocator) catch |err| return handle_file_error(pubkeyfile, err);
}

fn sign_file(seckeyfile: []const u8, msgfile: []const u8, sigfile: []const u8, embedded: bool, allocator: *std.mem.Allocator) !void {
    const encseckey = impl.from_file(impl.SecretKey, seckeyfile, null, allocator) catch |err| return handle_file_error(seckeyfile, err);
    const msg = impl.read_file(msgfile, 65535, allocator) catch |err| return handle_file_error(msgfile, err);
    defer allocator.free(msg);
    var seckey = try decrypt_secret_key(&encseckey);
    defer impl.zerosingle(&seckey);
    const signature = try impl.sign_message(seckey, msg);
    const keyname = std.fs.path.basename(seckeyfile);
    const comment = try std.mem.concat(allocator, u8, &[_][]const u8{ "verify with ", keyname[0 .. keyname.len - 3], "pub" });
    defer allocator.free(comment);
    try impl.write_base64_file(sigfile, comment, impl.as_bytes(signature), allocator);
    if (embedded) {
        const file = std.fs.cwd().openFile(sigfile, .{ .write = true }) catch |err| return handle_file_error(msgfile, err);
        defer file.close();
        file.seekFromEnd(0) catch |err| return handle_file_error(sigfile, err);
        file.writeAll(msg) catch |err| return handle_file_error(sigfile, err);
    }
}

fn verify_file(pubkeyfile: []const u8, msgfile: []const u8, sigfile: []const u8, allocator: *std.mem.Allocator) !void {
    const pubkey = impl.from_file(impl.PubKey, pubkeyfile, null, allocator) catch |err| return handle_file_error(pubkeyfile, err);
    const sig = impl.from_file(impl.Signature, sigfile, null, allocator) catch |err| return handle_file_error(sigfile, err);
    const msg = impl.read_file(msgfile, 65535, allocator) catch |err| return handle_file_error(msgfile, err);
    defer allocator.free(msg);
    return impl.verify_message(pubkey, sig, msg) catch |err| return handle_file_error(msgfile, err);
}

fn verify_embedded_file(pubkeyfile: []const u8, msgfile: []const u8, sigfile: []const u8, allocator: *std.mem.Allocator) !void {
    const pubkey = impl.from_file(impl.PubKey, pubkeyfile, null, allocator) catch |err| return handle_file_error(pubkeyfile, err);
    var siglen: usize = undefined;
    const sig = impl.from_file(impl.Signature, sigfile, &siglen, allocator) catch |err| return handle_file_error(sigfile, err);
    const msg = read_file_offset(sigfile, siglen, allocator) catch |err| return handle_file_error(sigfile, err);
    defer allocator.free(msg);
    impl.verify_message(pubkey, sig, msg) catch |err| return handle_file_error(sigfile, err);
    // write verified contents to -m msgfile
    const file = std.fs.cwd().createFile(msgfile, .{ .truncate = true }) catch |err| return handle_file_error(msgfile, err);
    defer file.close();
    file.writeAll(msg) catch |err| return handle_file_error(sigfile, err);
}

fn read_file_offset(filename: []const u8, offset: usize, allocator: *std.mem.Allocator) ![]const u8 {
    const file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();
    try file.seekTo(offset);
    return try file.readToEndAlloc(allocator, 123456);
}

fn decrypt_secret_key(seckey: *const impl.SecretKey) !impl.DecryptedSecretKey {
    if (seckey.is_encrypted()) {
        var pwstor: [1024]u8 = undefined;
        defer zero(u8, &pwstor);
        const passphrase = try getpass.getpass("Passphrase: ", &pwstor);
        return try seckey.decrypt(passphrase);
    } else {
        return try seckey.decrypt("");
    }
}

fn handle_file_error(file: []const u8, err: anyerror) !void {
    const msg = switch (err) {
        error.UnsupportedAlgorithm => "Signature algorithm used is not supported by this tool",
        error.InvalidLength => "Invalid length of encoded data",
        error.GarbageAtEndOfFile => "Unexpected data at end of file",
        error.InvalidFile => "File has invalid format",
        error.WrongPassphrase => "Wrong passphrase or corrupted secret key",
        error.WrongPublicKey => "Signed with a different public key",

        // XXX: there is probably a better way to do this than re-do strerror() here, yeah?

        error.AccessDenied => "Access denied",
        error.BadPathName => "Bad path name",
        error.BrokenPipe => "Broken pipe",
        error.ConnectionResetByPeer => "Connection reset by peer",
        error.ConnectionTimedOut => "Connection timed out",
        error.DeviceBusy => "Device busy",
        error.FileLocksNotSupported => "File locks not supported",
        error.FileNotFound => "File not found",
        error.FileTooBig => "File too big",
        error.InputOutput => "I/O error",
        error.InvalidCharacter => "Invalid character",
        error.InvalidPadding => "Invalid padding",
        error.InvalidUtf8 => "Invalid UTF-8 path",
        error.IsDir => "Is a directory",
        error.NameTooLong => "Name too long",
        error.NoDevice => "No device",
        error.NoSpaceLeft => "No space left on device",
        error.NotDir => "Not a directory",
        error.NotOpenForReading => "Not opened for reading",
        error.OperationAborted => "Operation aborted",
        error.OutOfMemory => "Out of memory",
        error.PathAlreadyExists => "Path already exists",
        error.PipeBusy => "Pipe busy",
        error.ProcessFdQuotaExceeded => "Process fd quota exceeded",
        error.SharingViolation => "Sharing violation",
        error.SymLinkLoop => "Symlink loop",
        error.SystemFdQuotaExceeded => "System fd quota exceeded",
        error.SystemResources => "Kernel is out of memory",
        error.Unexpected => "Unexpected error?",
        error.Unseekable => "Unseekable file",
        error.WouldBlock => "Operation would block",
        else => return err,
    };
    print("{s}: {s}\n", .{ file, msg });
    return ExitError;
}
