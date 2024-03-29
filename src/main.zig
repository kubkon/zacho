const fat = @import("fat.zig");
const std = @import("std");

const Archive = @import("Archive.zig");
const Object = @import("Object.zig");

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
    \\-r, --relocations           Print relocation entries (if any)
    \\-s, --symbol-table          Print the symbol table
    \\-u, --unwind-info           Print the contents of (compact) unwind info section (if any)
    \\-v, --verbose               Print more detailed info for each flag
    \\--archive-index             Print archive index (if any)
    \\--string-table              Print the string table
    \\--data-in-code              Print data-in-code entries (if any)
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
                'r' => tmp.relocations = true,
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
        } else if (std.mem.eql(u8, arg, "--relocations")) {
            print_matrix.relocations = true;
        } else if (std.mem.eql(u8, arg, "--symbol-table")) {
            print_matrix.symbol_table = true;
        } else if (std.mem.eql(u8, arg, "--indirect-symbol-table")) {
            print_matrix.indirect_symbol_table = true;
        } else if (std.mem.eql(u8, arg, "--unwind-info")) {
            print_matrix.unwind_info = true;
        } else if (std.mem.eql(u8, arg, "--string-table")) {
            print_matrix.string_table = true;
        } else if (std.mem.eql(u8, arg, "--archive-index")) {
            print_matrix.archive_index = true;
        } else if (std.mem.eql(u8, arg, "--data-in-code")) {
            print_matrix.data_in_code = true;
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
    const file = try std.fs.cwd().openFile(fname, .{});
    defer file.close();
    const data = try file.readToEndAlloc(arena, std.math.maxInt(u32));

    const stdout = std.io.getStdOut().writer();
    if (print_matrix.isUnset()) fatal("no option specified", .{});

    if (try fat.isFatLibrary(fname)) {
        fatal("TODO: handle fat (universal) files: {s} is a fat file", .{fname});
    } else if (try Archive.isArchive(fname, null)) {
        var archive = Archive{ .gpa = gpa, .data = data, .path = try gpa.dupe(u8, fname), .verbose = opts.verbose };
        defer archive.deinit();
        try archive.parse();
        if (print_matrix.archive_index) {
            try archive.printSymbolTable(stdout);
        }
        print_matrix.archive_index = false;
        if (!print_matrix.isUnset()) for (archive.objects.values()) |object| {
            try stdout.print("File: {s}({s})\n", .{ archive.path, object.path });
            try printObject(object, print_matrix, stdout);
        };
    } else {
        var object = Object{ .gpa = gpa, .data = data, .path = try gpa.dupe(u8, fname), .verbose = opts.verbose };
        defer object.deinit();
        object.parse() catch |err| switch (err) {
            error.InvalidMagic => fatal("not a MachO file - invalid magic bytes", .{}),
            else => |e| return e,
        };
        try printObject(object, print_matrix, stdout);
    }
}

fn printObject(object: Object, print_matrix: PrintMatrix, stdout: anytype) !void {
    if (print_matrix.header) {
        try object.printHeader(stdout);
    }
    if (print_matrix.load_commands) {
        try object.printLoadCommands(stdout);
    }
    if (print_matrix.dyld_info) {
        try object.printDyldInfo(stdout);
    }
    if (print_matrix.exports_trie) {
        try object.printExportsTrie(stdout);
    }
    if (print_matrix.unwind_info) {
        try object.printUnwindInfo(stdout);
    }
    if (print_matrix.data_in_code) {
        try object.printDataInCode(stdout);
    }
    if (print_matrix.code_signature) {
        try object.printCodeSignature(stdout);
    }
    if (print_matrix.verify_memory_layout) {
        try object.verifyMemoryLayout(stdout);
    }
    if (print_matrix.relocations) {
        try object.printRelocations(stdout);
    }
    if (print_matrix.symbol_table) {
        try object.printSymbolTable(stdout);
    }
    if (print_matrix.string_table) {
        try object.printStringTable(stdout);
    }
    if (print_matrix.indirect_symbol_table) {
        try object.printIndirectSymbolTable(stdout);
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
    relocations: bool = false,
    symbol_table: bool = false,
    indirect_symbol_table: bool = false,
    data_in_code: bool = false,
    string_table: bool = false,
    archive_index: bool = false,

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
