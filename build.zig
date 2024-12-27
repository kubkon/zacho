const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "zacho",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = mode,
    });

    if (comptime builtin.target.isDarwin()) {
        const zig_kit = b.dependency("zigkit", .{
            .target = target,
            .optimize = mode,
        });
        exe.root_module.addImport("ZigKit", zig_kit.module("ZigKit"));

        if (b.sysroot) |sysroot| {
            exe.addSystemFrameworkPath(.{ .cwd_relative = b.pathJoin(&.{ sysroot, "/System/Library/Frameworks" }) });
        }
        exe.linkFramework("CoreFoundation");
        exe.linkFramework("Security");
    }

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
