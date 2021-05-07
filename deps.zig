const std = @import("std");
pub const pkgs = struct {
    pub const clap = std.build.Pkg{
        .name = "clap",
        .path = ".gyro/zig-clap-Hejsil-42433ca7b59c3256f786af5d1d282798b5b37f31/pkg/clap.zig",
    };

    pub fn addAllTo(artifact: *std.build.LibExeObjStep) void {
        @setEvalBranchQuota(1_000_000);
        inline for (std.meta.declarations(pkgs)) |decl| {
            if (decl.is_pub and decl.data == .Var) {
                artifact.addPackage(@field(pkgs, decl.name));
            }
        }
    }
};

pub const base_dirs = struct {
    pub const clap = ".gyro/zig-clap-Hejsil-42433ca7b59c3256f786af5d1d282798b5b37f31/pkg";
};
