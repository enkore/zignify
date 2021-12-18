const os = @import("std").os;
const io = @import("std").io;

const PassphraseTooLong = error.PassphraseTooLong;

// *nix only
// OpenBSD has readpassphrase in libc.
// This is pretty much musl's getpass implementation.
pub fn get_password(prompt: []const u8, password: []u8) ![]u8 {
    if (os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY, 0)) |fd| {
        defer os.close(fd);

        const orig = try os.tcgetattr(fd);
        var no_echo = orig;
        // local (terminal) flags: don't echo, don't generate signals, canonical mode
        // canonical mode basically means that the terminal does line editing and only
        // sends complete lines.
        no_echo.lflag &= ~@as(u32, os.ECHO | os.ISIG); // XXX: these constant should be explicitly typed as tcflag_t/u32, no?
        no_echo.lflag |= os.ICANON;
        // input flags: newline handling - not entirely sure what's needed here and what isn't.
        no_echo.iflag &= ~@as(u32, os.INLCR | os.IGNCR);
        no_echo.iflag |= os.ICRNL;

        try os.tcsetattr(fd, os.TCSA.FLUSH, no_echo);
        defer os.tcsetattr(fd, os.TCSA.FLUSH, orig) catch {};
        //try os.tcdrain(fd); // block until the teletype port has caught up XXX: missing from std.os
        //try c.tcdrain(fd);

        _ = try os.write(fd, prompt);
        const read = try os.read(fd, password);
        if (read == password.len or read < 1)
            return PassphraseTooLong;
        _ = try os.write(fd, "\n");
        return password[0 .. read - 1];
    } else |err| {
        // no tty, print prompt to stderr and read passphrase from stdin
        const stderr = io.getStdErr();
        const stdin = io.getStdIn();
        try stderr.writeAll(prompt);
        if (stdin.reader().readUntilDelimiterOrEof(password, '\n')) |maybe_input| {
            const input = maybe_input orelse return PassphraseTooLong;
            if (input.len == password.len)
                return PassphraseTooLong;
            return input;
        } else |readerr| switch (readerr) {
            error.StreamTooLong => return PassphraseTooLong,
            else => return err,
        }
    }
}