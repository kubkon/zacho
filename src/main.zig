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
    \\--hex-dump=[name]           Dump section contents as bytes
    \\--string-dump=[name]        Dump section contents as strings
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
    var sect_name: ?[]const u8 = null;

    var it = ArgsIterator{ .args = args };
    var p = ArgsParser{ .it = &it };
    while (p.hasMore()) {
        if (std.mem.startsWith(u8, p.next_arg, "-")) blk: {
            var i: usize = 1;
            var tmp = PrintMatrix{};
            while (i < p.next_arg.len) : (i += 1) switch (p.next_arg[i]) {
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

        if (p.flag2("help")) {
            fatal(usage, .{});
        } else if (p.flag2("code-signature")) {
            print_matrix.code_signature = true;
        } else if (p.flag2("dyld-info")) {
            print_matrix.dyld_info = true;
        } else if (p.flag2("exports-trie")) {
            print_matrix.exports_trie = true;
        } else if (p.flag2("header")) {
            print_matrix.header = true;
        } else if (p.flag2("load-commands")) {
            print_matrix.load_commands = true;
        } else if (p.flag2("relocations")) {
            print_matrix.relocations = true;
        } else if (p.flag2("symbol-table")) {
            print_matrix.symbol_table = true;
        } else if (p.flag2("indirect-symbol-table")) {
            print_matrix.indirect_symbol_table = true;
        } else if (p.flag2("unwind-info")) {
            print_matrix.unwind_info = true;
        } else if (p.flag2("string-table")) {
            print_matrix.string_table = true;
        } else if (p.flag2("archive-index")) {
            print_matrix.archive_index = true;
        } else if (p.flag2("data-in-code")) {
            print_matrix.data_in_code = true;
        } else if (p.arg2("hex-dump")) |name| {
            print_matrix.dump_hex = true;
            sect_name = name;
        } else if (p.arg2("string-dump")) |name| {
            print_matrix.dump_string = true;
            sect_name = name;
        } else if (p.flag2("verify-memory-layout")) {
            print_matrix.verify_memory_layout = true;
        } else if (p.flag2("verbose")) {
            opts.verbose = true;
        } else {
            if (filename != null) fatal("too many positional arguments specified", .{});
            filename = p.next_arg;
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
            try printObject(object, print_matrix, sect_name, stdout);
        };
    } else {
        var object = Object{ .gpa = gpa, .data = data, .path = try gpa.dupe(u8, fname), .verbose = opts.verbose };
        defer object.deinit();
        object.parse() catch |err| switch (err) {
            error.InvalidMagic => fatal("not a MachO file - invalid magic bytes", .{}),
            else => |e| return e,
        };
        try printObject(object, print_matrix, sect_name, stdout);
    }
}

fn printObject(object: Object, print_matrix: PrintMatrix, sect_name: ?[]const u8, stdout: anytype) !void {
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
    if (print_matrix.dump_string or print_matrix.dump_hex) {
        const sect = getSectionByName(object, sect_name.?) catch |err| switch (err) {
            error.InvalidSectionName => fatal("invalid section name: '{s}'", .{sect_name.?}),
            error.SectionNotFound => fatal("section not found: '{s}'", .{sect_name.?}),
        };
        if (print_matrix.dump_string) {
            try object.dumpString(sect, stdout);
        }
        if (print_matrix.dump_hex) {
            try object.dumpHex(sect, stdout);
        }
    }
}

fn getSectionByName(object: Object, name: []const u8) !std.macho.section_64 {
    const index = std.mem.indexOfScalar(u8, name, ',') orelse return error.InvalidSectionName;
    if (index + 1 >= name.len) return error.InvalidSectionName;
    const seg_name = name[0..index];
    const sect_name = name[index + 1 ..];
    const sect = object.getSectionByName(seg_name, sect_name) orelse return error.SectionNotFound;
    return sect;
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
    dump_string: bool = false,
    dump_hex: bool = false,

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

    pub fn peek(it: *@This()) ?[]const u8 {
        const arg = it.next();
        defer if (it.i > 0) {
            it.i -= 1;
        };
        return arg;
    }
};

const ArgsParser = struct {
    next_arg: []const u8 = undefined,
    it: *ArgsIterator,

    pub fn hasMore(p: *ArgsParser) bool {
        p.next_arg = p.it.next() orelse return false;
        return true;
    }

    pub fn flag1(p: *ArgsParser, comptime pat: []const u8) bool {
        return p.flagPrefix(pat, "-");
    }

    pub fn flag2(p: *ArgsParser, comptime pat: []const u8) bool {
        return p.flagPrefix(pat, "--");
    }

    fn flagPrefix(p: *ArgsParser, comptime pat: []const u8, comptime prefix: []const u8) bool {
        if (std.mem.startsWith(u8, p.next_arg, prefix)) {
            const actual_arg = p.next_arg[prefix.len..];
            if (std.mem.eql(u8, actual_arg, pat)) {
                return true;
            }
        }
        return false;
    }

    pub fn arg1(p: *ArgsParser, comptime pat: []const u8) ?[]const u8 {
        return p.argPrefix(pat, "-");
    }

    pub fn arg2(p: *ArgsParser, comptime pat: []const u8) ?[]const u8 {
        return p.argPrefix(pat, "--");
    }

    fn argPrefix(p: *ArgsParser, comptime pat: []const u8, comptime prefix: []const u8) ?[]const u8 {
        if (std.mem.startsWith(u8, p.next_arg, prefix)) {
            const actual_arg = p.next_arg[prefix.len..];
            if (std.mem.eql(u8, actual_arg, pat)) {
                if (p.it.peek()) |next| {
                    if (std.mem.startsWith(u8, next, "-")) return null;
                }
                return p.it.nextOrFatal();
            }
            if (std.mem.startsWith(u8, actual_arg, pat)) {
                return actual_arg[pat.len..];
            }
        }
        return null;
    }
};
