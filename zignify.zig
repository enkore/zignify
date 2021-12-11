const std = @import("std");
const io = std.io;
const print = @import("std").debug.print;

const Ed25519 = std.crypto.sign.Ed25519;

const comment_hdr = "untrusted comment: ";

const b64decoder = std.base64.standard.Decoder;

const signature = packed struct {
// This is always "Ed" for Ed25519.
pkalg: [2]u8,
// A random 64-bit integer which is used to tell if the correct pubkey is used for verification.
keynum: [8]u8, sig: [Ed25519.signature_length]u8 };

fn read_base64_file(path: []const u8, allocator: *std.mem.Allocator) ![]u8 {
    const file = try std.fs.cwd().openFile(
        "test/msg.sig",
        .{ .read = true },
    );
    defer file.close();

    const sig_contents = try std.fs.cwd().readFileAlloc(allocator, "test/msg.sig", 4096);
    defer allocator.free(sig_contents);

    std.log.info("foo {s}", .{@TypeOf(sig_contents)});

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

    std.log.info("Found base64 line: {s} (len={d}, decoded={d})", .{ line, std.mem.len(line), b64decoder.calcSizeForSlice(line) });

    const dec = try allocator.alloc(u8, try b64decoder.calcSizeForSlice(line));
    //var dec: [@sizeOf(signature)]u8 = undefined;
    try b64decoder.decode(dec[0..dec.len], line);
    return dec;
}

pub fn main() !void {
    //const allocator = std.heap.page_allocator;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = &gpa.allocator;

    const dec = try read_base64_file("test/msg.sig", allocator);

    // const dec2: [74]u8 = dec[0..74];  // error: expected type '[74]u8', found '*[74]u8'
    // const dec2: [74]u8 = dec;  // error: expected type '[74]u8', found '[]u8'
    var dec2: [74]u8 = undefined;
    std.mem.copy(u8, dec2[0..], dec);
    const sig = @bitCast(signature, dec2);

    allocator.free(dec);

    std.log.info("pk: {s}", .{sig.pkalg});
}
