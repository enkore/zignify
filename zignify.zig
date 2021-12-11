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

pub fn main() !void {
    const file = try std.fs.cwd().openFile(
        "test/msg.sig",
        .{ .read = true },
    );
    defer file.close();

    const allocator = std.heap.page_allocator;
    const sig_contents = try std.fs.cwd().readFileAlloc(allocator, "test/msg.sig", 4096);

    std.log.info("foo {s}", .{@TypeOf(sig_contents)});

    var iter = std.mem.split(sig_contents, "\n");

    var line = iter.next().?;
    if (std.mem.startsWith(u8, line, comment_hdr)) {
        line = iter.next().?;
    }

    std.log.info("Found base64 line: {s} (len={d}, decoded={d})", .{ line, std.mem.len(line), b64decoder.calcSizeForSlice(line) });

    //const dec = try allocator.alloc(u8, try b64decoder.calcSizeForSlice(line));
    var dec: [@sizeOf(signature)]u8 = undefined;
    try b64decoder.decode(dec[0..dec.len], line);

    std.log.info("decoded: {s}", .{dec});

    const sig = @bitCast(signature, dec);

    std.log.info("pk: {s}", .{sig.pkalg});
    std.log.info("pk: {s}", .{sig.keynum});

    //    while (iter.next()) |line| {
    //      std.log.info("len={s}", .{line});
    //    if (std.mem.startsWith(u8, line, comment_hdr)) {
    //      std.log.info("This is a comment line.", .{});
    // }
    //}

    //var in_stream = file.reader();
    //var buf: [1024]u8 = undefined;
    //while (try in_stream.readUntilDelimiterOrEof(&buf, '\n')) |line| {
    //    std.log.info("len={s}", .{buf});
    //}
}
