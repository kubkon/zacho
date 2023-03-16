const std = @import("std");
const builtin = @import("builtin");
const Builder = std.build.Builder;

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "zacho",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = mode,
    });
    exe.addAnonymousModule("clap", .{
        .source_file = .{ .path = "zig-clap/clap.zig" },
    });

    if (comptime builtin.target.isDarwin()) {
        exe.addAnonymousModule("ZigKit", .{
            .source_file = .{ .path = "ZigKit/src/main.zig" },
        });
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
}
