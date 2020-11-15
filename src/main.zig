const std = @import("std");
const clap = @import("clap");
const process = std.process;

const ZachO = @import("ZachO.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    const stderr = std.io.getStdErr().outStream();
    const stdout = std.io.getStdOut().outStream();

    const params = comptime [_]clap.Param(clap.Help){
        clap.parseParam("--help                 Display this help and exit.") catch unreachable,
        clap.parseParam("-h, --header           Print the Mach-O header.") catch unreachable,
        clap.parseParam("-l, --load-commands    Print load commands.") catch unreachable,
        clap.parseParam("<FILE>") catch unreachable,
    };

    var args = try clap.parse(clap.Help, &params, &gpa.allocator, null);
    defer args.deinit();

    if (args.flag("--help")) {
        return printUsageWithHelp(stderr, params[0..]);
    }

    const file = blk: {
        for (args.positionals()) |pos| {
            break :blk pos;
        }
        break :blk null;
    };
    if (file == null) {
        return stderr.print("missing positional argument <FILE>...\n", .{});
    }

    var zacho = ZachO.init(&gpa.allocator);
    defer zacho.deinit();

    try zacho.parseFile(file.?);

    if (args.flag("--header")) {
        try zacho.printHeader(stdout);
    } else if (args.flag("--load-commands")) {
        try zacho.printLoadCommands(stdout);
    }
}

fn printUsageWithHelp(stream: anytype, comptime params: []const clap.Param(clap.Help)) !void {
    try stream.print("zacho ", .{});
    try clap.usage(stream, params);
    try stream.print("\n", .{});
    try clap.help(stream, params);
}
