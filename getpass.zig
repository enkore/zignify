const std = @import("std");
const os = std.os;
const io = std.io;

pub const PassphraseTooLong = error.PassphraseTooLong;
pub const NoPassphraseGiven = error.NoPassphraseGiven;

// *nix only
// OpenBSD has readpassphrase in libc.
// This is pretty much musl's getpass implementation.
pub fn getpass(prompt: []const u8, password: []u8) ![]u8 {
    errdefer std.crypto.utils.secureZero(u8, password);
    if (@hasDecl(os.system, "termios")) {
        if (os.open("/dev/tty", os.O.RDWR | os.O.NOCTTY, 0)) |fd| {
            defer os.close(fd);

            const orig = try os.tcgetattr(fd);
            var no_echo = orig;
            // local (terminal) flags: don't echo, don't generate signals, canonical mode
            // canonical mode basically means that the terminal does line editing and only
            // sends complete lines.
            no_echo.lflag &= ~(os.system.ECHO | os.system.ISIG);
            no_echo.lflag |= os.system.ICANON;
            // input flags: newline handling - not entirely sure what's needed here and what isn't.
            no_echo.iflag &= ~(os.system.INLCR | os.system.IGNCR);
            no_echo.iflag |= os.system.ICRNL;

            try os.tcsetattr(fd, os.TCSA.FLUSH, no_echo);
            defer os.tcsetattr(fd, os.TCSA.FLUSH, orig) catch {};
            //try os.tcdrain(fd); // block until the teletype port has caught up XXX: missing from std.os
            //try c.tcdrain(fd);

            _ = try os.write(fd, prompt);
            const read = try os.read(fd, password);
            _ = try os.write(fd, "\n");
            if (read == password.len)
                return PassphraseTooLong;
            if (read < 2)
                return NoPassphraseGiven;
            return password[0 .. read - 1];
        } else |_| {}
    }
    // no tty, print prompt to stderr and read passphrase from stdin
    const stderr = io.getStdErr();
    const stdin = io.getStdIn();
    try stderr.writeAll(prompt);
    if (stdin.reader().readUntilDelimiterOrEof(password, '\n')) |maybe_input| {
        const input = maybe_input orelse return NoPassphraseGiven;
        if (input.len == password.len)
            return PassphraseTooLong;
        if (input.len == 0)
            return NoPassphraseGiven;
        return input;
    } else |readerr| switch (readerr) {
        error.StreamTooLong => return PassphraseTooLong,
        else => return readerr,
    }
}
