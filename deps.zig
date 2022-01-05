const std = @import("std");
const Pkg = std.build.Pkg;
const FileSource = std.build.FileSource;

pub const pkgs = struct {
    pub const clap = Pkg{
        .name = "clap",
        .path = FileSource{
            .path = ".gyro/zig-clap-Hejsil-github.com-cf8a34d1/pkg/clap.zig",
        },
    };

    pub fn addAllTo(artifact: *std.build.LibExeObjStep) void {
        artifact.addPackage(pkgs.clap);
    }
};
