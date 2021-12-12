const std = @import("std");

fn add_bcrypt_pbkdf_includes(exe: anytype) void {
    exe.linkLibC();
    exe.addIncludeDir("bcrypt_pbkdf");
    //exe.addCSourceFile(&[_][]const u8{ "bcrypt_pbkdf/sha2.c", "bcrypt_pbkdf/blf.c", "bcrypt_pbkdf/bcrypt_pbkdf.c" }, &[_][]const u8{ "-std=c99", "-O2" });
    exe.addCSourceFile("bcrypt_pbkdf/sha2.c", &[_][]const u8{ "-std=gnu99", "-O2" });
    exe.addCSourceFile("bcrypt_pbkdf/blf.c", &[_][]const u8{ "-std=gnu99", "-O2" });
    exe.addCSourceFile("bcrypt_pbkdf/bcrypt_pbkdf.c", &[_][]const u8{ "-std=gnu99", "-O2" });
}

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("zignify", "zignify.zig");
    add_bcrypt_pbkdf_includes(exe);
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    const test_step = b.step("test", "Runs the test suite");
    {
        const test_suite = b.addTest("bcrypt_pbkdf.zig");
        add_bcrypt_pbkdf_includes(test_suite);
        test_step.dependOn(&test_suite.step);
    }

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
