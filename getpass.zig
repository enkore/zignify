const os = @import("std").os;

// *nix only
// OpenBSD has readpassphrase in libc.
// This is pretty much musl's getpass implementation.
pub fn get_password(prompt: []const u8, password: []u8) ![]u8 {
    const fd = try os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY, 0);
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
    if (read == password.len)
        return error.PassphraseTooLong;
    _ = try os.write(fd, "\n");
    return password[0..read];
}
