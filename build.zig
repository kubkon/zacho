const std = @import("std");
const builtin = @import("builtin");
const Builder = std.build.Builder;

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("zacho", "src/main.zig");
    exe.addPackagePath("clap", "zig-clap/clap.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);

    if (builtin.target.isDarwin()) {
        exe.addPackagePath("ZigKit", "ZigKit/src/main.zig");
        exe.linkFramework("CoreFoundation");
        exe.linkFramework("Security");
    }

    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run all tests");
    const tests = b.addTest("src/ZachO.zig");
    test_step.dependOn(&tests.step);
}
