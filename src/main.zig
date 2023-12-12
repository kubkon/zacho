const std = @import("std");
const ZachO = @import("ZachO.zig");

var allocator = std.heap.GeneralPurposeAllocator(.{}){};
const gpa = allocator.allocator();

const usage =
    \\Usage: zacho [options] file
    \\
    \\General options:
    \\-c, --code-signature        Print the contents of code signature (if any)
    \\-d, --dyld-info             Print the contents of dyld rebase and bind opcodes
    \\-e, --exports-trie          Print export trie (if any)
    \\-h, --header                Print the Mach-O header
    \\-i, --indirect-symbol-table Print the indirect symbol table
    \\-l, --load-commands         Print load commands
    \\-s, --symbol-table          Print the symbol table
    \\-u, --unwind-info           Print the contents of (compact) unwind info section (if any)
    \\-v, --verbose               Print more detailed info for each flag
    \\--verify-memory-layout      Print virtual memory layout and verify there is no overlap
    \\--help                      Display this help and exit
    \\
;

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    ret: {
        const msg = std.fmt.allocPrint(gpa, format ++ "\n", args) catch break :ret;
        std.io.getStdErr().writeAll(msg) catch {};
    }
    std.process.exit(1);
}

const ArgsIterator = struct {
    args: []const []const u8,
    i: usize = 0,

    fn next(it: *@This()) ?[]const u8 {
        if (it.i >= it.args.len) {
            return null;
        }
        defer it.i += 1;
        return it.args[it.i];
    }

    fn nextOrFatal(it: *@This()) []const u8 {
        return it.next() orelse fatal("expected parameter after {s}", .{it.args[it.i - 1]});
    }
};

pub fn main() !void {
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const all_args = try std.process.argsAlloc(arena);
    const args = all_args[1..];

    if (args.len == 0) fatal(usage, .{});

    var filename: ?[]const u8 = null;
    var opts: Options = .{};

    var print_matrix: PrintMatrix = .{};

    var it = ArgsIterator{ .args = args };
    while (it.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "-")) blk: {
            var i: usize = 1;
            var tmp = PrintMatrix{};
            while (i < arg.len) : (i += 1) switch (arg[i]) {
                '-' => break :blk,
                'c' => tmp.code_signature = true,
                'd' => tmp.dyld_info = true,
                'e' => tmp.exports_trie = true,
                'h' => tmp.header = true,
                'i' => tmp.indirect_symbol_table = true,
                'l' => tmp.load_commands = true,
                's' => tmp.symbol_table = true,
                'u' => tmp.unwind_info = true,
                'v' => opts.verbose = true,
                else => break :blk,
            };
            print_matrix.add(tmp);
            continue;
        }

        if (std.mem.eql(u8, arg, "--help")) {
            fatal(usage, .{});
        } else if (std.mem.eql(u8, arg, "--code-signature")) {
            print_matrix.code_signature = true;
        } else if (std.mem.eql(u8, arg, "--dyld-info")) {
            print_matrix.dyld_info = true;
        } else if (std.mem.eql(u8, arg, "--exports-trie")) {
            print_matrix.exports_trie = true;
        } else if (std.mem.eql(u8, arg, "--header")) {
            print_matrix.header = true;
        } else if (std.mem.eql(u8, arg, "--load-commands")) {
            print_matrix.load_commands = true;
        } else if (std.mem.eql(u8, arg, "--symbol-table")) {
            print_matrix.symbol_table = true;
        } else if (std.mem.eql(u8, arg, "--indirect-symbol-table")) {
            print_matrix.indirect_symbol_table = true;
        } else if (std.mem.eql(u8, arg, "--unwind-info")) {
            print_matrix.unwind_info = true;
        } else if (std.mem.eql(u8, arg, "--verify-memory-layout")) {
            print_matrix.verify_memory_layout = true;
        } else if (std.mem.eql(u8, arg, "--verbose")) {
            opts.verbose = true;
        } else {
            if (filename != null) fatal("too many positional arguments specified", .{});
            filename = arg;
        }
    }

    const fname = filename orelse fatal("no input file specified", .{});

    if (print_matrix.isUnset()) fatal("no option specified", .{});

    const file = try std.fs.cwd().openFile(fname, .{});
    defer file.close();
    const data = try file.readToEndAlloc(arena, std.math.maxInt(u32));

    var zacho = try ZachO.parse(arena, data, opts.verbose);
    const stdout = std.io.getStdOut().writer();

    if (print_matrix.header) {
        try zacho.printHeader(stdout);
    }
    if (print_matrix.load_commands) {
        try zacho.printLoadCommands(stdout);
    }
    if (print_matrix.dyld_info) {
        try zacho.printDyldInfo(stdout);
    }
    if (print_matrix.exports_trie) {
        try zacho.printExportsTrie(stdout);
    }
    if (print_matrix.unwind_info) {
        try zacho.printUnwindInfo(stdout);
    }
    if (print_matrix.code_signature) {
        try zacho.printCodeSignature(stdout);
    }
    if (print_matrix.verify_memory_layout) {
        try zacho.verifyMemoryLayout(stdout);
    }
    if (print_matrix.symbol_table) {
        try zacho.printSymbolTable(stdout);
    }
    if (print_matrix.indirect_symbol_table) {
        try zacho.printIndirectSymbolTable(stdout);
    }
}

pub const Options = struct {
    verbose: bool = false,
};

const PrintMatrix = packed struct {
    header: bool = false,
    load_commands: bool = false,
    dyld_info: bool = false,
    exports_trie: bool = false,
    unwind_info: bool = false,
    code_signature: bool = false,
    verify_memory_layout: bool = false,
    symbol_table: bool = false,
    indirect_symbol_table: bool = false,

    const Int = blk: {
        const bits = @typeInfo(@This()).Struct.fields.len;
        break :blk @Type(.{
            .Int = .{
                .signedness = .unsigned,
                .bits = bits,
            },
        });
    };

    fn enableAll() @This() {
        return @as(@This(), @bitCast(~@as(Int, 0)));
    }

    fn isUnset(pm: @This()) bool {
        return @as(Int, @bitCast(pm)) == 0;
    }

    fn add(pm: *@This(), other: @This()) void {
        pm.* = @as(@This(), @bitCast(@as(Int, @bitCast(pm.*)) | @as(Int, @bitCast(other))));
    }
};
