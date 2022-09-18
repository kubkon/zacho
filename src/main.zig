const std = @import("std");
const clap = @import("clap");
const process = std.process;

const ZachO = @import("ZachO.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    const stderr = std.io.getStdErr().writer();
    const stdout = std.io.getStdOut().writer();

    const params = comptime [_]clap.Param(clap.Help){
        clap.parseParam("--help                 Display this help and exit.") catch unreachable,
        clap.parseParam("-h, --header           Print the Mach-O header.") catch unreachable,
        clap.parseParam("-l, --load-commands    Print load commands.") catch unreachable,
        clap.parseParam("-d, --dyld-info        Print the contents of dyld rebase and bind opcodes.") catch unreachable,
        clap.parseParam("-c, --code-signature   Print the contents of code signature (if any).") catch unreachable,
        clap.parseParam("--verify-memory-layout Print virtual memory layout and verify there is no overlap.") catch unreachable,
        clap.parseParam("<FILE>") catch unreachable,
    };

    const parsers = comptime .{
        .FILE = clap.parsers.string,
    };

    var res = try clap.parse(clap.Help, &params, parsers, .{
        .allocator = gpa.allocator(),
        .diagnostic = null,
    });
    defer res.deinit();

    if (res.args.help) {
        return printUsageWithHelp(stderr, params[0..]);
    }

    if (res.positionals.len == 0) {
        return stderr.print("missing positional argument <FILE>...\n", .{});
    }

    const filename = res.positionals[0];
    const file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();

    var zacho = try ZachO.parse(gpa.allocator(), file);
    defer zacho.deinit();

    if (res.args.header) {
        try zacho.printHeader(stdout);
    }
    if (res.args.@"load-commands") {
        try zacho.printLoadCommands(stdout);
    }
    if (res.args.@"dyld-info") {
        try zacho.printDyldInfo(stdout);
    }
    if (res.args.@"code-signature") {
        try zacho.printCodeSignature(stdout);
    }
    if (res.args.@"verify-memory-layout") {
        try zacho.verifyMemoryLayout(stdout);
    }
}

fn printUsageWithHelp(stream: anytype, comptime params: []const clap.Param(clap.Help)) !void {
    try stream.print("zacho ", .{});
    try clap.usage(stream, clap.Help, params);
    try stream.print("\n", .{});
    try clap.help(stream, clap.Help, params, .{});
}
