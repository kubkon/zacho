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
        clap.parseParam("-c, --code-signature   Print the contents of code signature (if any).") catch unreachable,
        clap.parseParam("<FILE>") catch unreachable,
    };

    var args = try clap.parse(clap.Help, &params, .{
        .allocator = gpa.allocator(),
        .diagnostic = null,
    });
    defer args.deinit();

    if (args.flag("--help")) {
        return printUsageWithHelp(stderr, params[0..]);
    }

    if (args.positionals().len == 0) {
        return stderr.print("missing positional argument <FILE>...\n", .{});
    }

    const filename = args.positionals()[0];
    const file = try std.fs.cwd().openFile(filename, .{});
    var zacho = ZachO.init(gpa.allocator());
    defer {
        zacho.deinit();
        zacho.closeFiles();
    }

    try zacho.parse(file);

    if (args.flag("--header")) {
        try zacho.printHeader(stdout);
    } else if (args.flag("--load-commands")) {
        try zacho.printLoadCommands(stdout);
    } else if (args.flag("--code-signature")) {
        try zacho.printCodeSignature(stdout);
    }
}

fn printUsageWithHelp(stream: anytype, comptime params: []const clap.Param(clap.Help)) !void {
    try stream.print("zacho ", .{});
    try clap.usage(stream, params);
    try stream.print("\n", .{});
    try clap.help(stream, params);
}
