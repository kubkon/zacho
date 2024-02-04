gpa: Allocator,
data: []const u8,
path: []const u8,

objects: std.AutoArrayHashMapUnmanaged(u64, Object) = .{},
symtab: Symtab = .{},

verbose: bool = false,

pub fn isArchive(path: []const u8, fat_arch: ?fat.Arch) !bool {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    if (fat_arch) |arch| {
        try file.seekTo(arch.offset);
    }
    const magic = file.reader().readBytesNoEof(ARMAG.len) catch return false;
    if (!mem.eql(u8, &magic, ARMAG)) return false;
    return true;
}

pub fn deinit(self: *Archive) void {
    for (self.objects.values()) |*object| {
        object.deinit();
    }
    self.objects.deinit(self.gpa);
    self.symtab.deinit(self.gpa);
    self.gpa.free(self.path);
}

pub fn parse(self: *Archive) !void {
    var stream = std.io.fixedBufferStream(self.data);
    const reader = stream.reader();
    _ = try reader.readBytesNoEof(ARMAG.len);

    while (true) {
        if (stream.pos >= self.data.len) break;
        if (!mem.isAligned(stream.pos, 2)) stream.pos += 1;

        const pos = stream.pos;
        const hdr = try reader.readStruct(ar_hdr);

        if (!mem.eql(u8, &hdr.ar_fmag, ARFMAG)) return error.InvalidHeaderDelimiter;

        var size = try hdr.size();
        if (try hdr.nameLength()) |len| size -= len;
        defer {
            _ = stream.seekBy(size) catch {};
        }

        const name = try hdr.getName(self.gpa, reader);
        if (mem.eql(u8, name, SYMDEF) or
            mem.eql(u8, name, SYMDEF64) or
            mem.eql(u8, name, SYMDEF_SORTED) or
            mem.eql(u8, name, SYMDEF64_SORTED))
        {
            const is_64 = mem.eql(u8, name, SYMDEF64) or mem.eql(u8, name, SYMDEF64_SORTED);
            if (is_64) self.symtab.format = .p64;
            try self.symtab.parse(self.gpa, self.data[stream.pos..][0..size]);
            continue;
        }

        const gop = try self.objects.getOrPut(self.gpa, pos);
        assert(!gop.found_existing);
        const object = gop.value_ptr;
        object.* = Object{
            .gpa = self.gpa,
            .path = name,
            .data = self.data[stream.pos..][0..size],
            .verbose = self.verbose,
        };
        try object.parse();
    }
}

pub fn printSymbolTable(self: Archive, writer: anytype) !void {
    if (self.symtab.entries.items.len == 0) {
        return writer.writeAll("no index found in archive\n");
    }

    const size_in_symtab: usize = self.symtab.entries.items.len * 2 * self.symtab.ptrWidth();
    try writer.print("Index of archive {s}: ({d} entries, 0x{x} bytes in the symbol table)\n", .{
        self.path,
        self.symtab.entries.items.len,
        size_in_symtab,
    });

    // Sort by file
    var by_file = std.AutoArrayHashMap(u64, std.ArrayList(usize)).init(self.gpa);
    defer {
        for (by_file.values()) |*list| {
            list.deinit();
        }
        by_file.deinit();
    }
    for (self.symtab.entries.items, 0..) |entry, i| {
        const gop = try by_file.getOrPut(entry.file);
        if (!gop.found_existing) {
            gop.value_ptr.* = std.ArrayList(usize).init(self.gpa);
        }
        try gop.value_ptr.append(i);
    }

    for (by_file.keys(), by_file.values()) |file, indexes| {
        const object = self.objects.get(file).?;
        try writer.print("Contents of binary {s}({s}) at offset 0x{x}\n", .{ self.path, object.path, file });
        for (indexes.items) |index| {
            try writer.print("      {s}\n", .{self.symtab.entries.items[index].getName(&self.symtab)});
        }
    }
}

const ar_hdr = extern struct {
    /// Member file name, sometimes / terminated.
    ar_name: [16]u8,

    /// File date, decimal seconds since Epoch.
    ar_date: [12]u8,

    /// User ID, in ASCII format.
    ar_uid: [6]u8,

    /// Group ID, in ASCII format.
    ar_gid: [6]u8,

    /// File mode, in ASCII octal.
    ar_mode: [8]u8,

    /// File size, in ASCII decimal.
    ar_size: [10]u8,

    /// Always contains ARFMAG.
    ar_fmag: [2]u8,

    fn date(self: ar_hdr) !u64 {
        const value = mem.trimRight(u8, &self.ar_date, &[_]u8{@as(u8, 0x20)});
        return std.fmt.parseInt(u64, value, 10);
    }

    fn size(self: ar_hdr) !u32 {
        const value = mem.trimRight(u8, &self.ar_size, &[_]u8{@as(u8, 0x20)});
        return std.fmt.parseInt(u32, value, 10);
    }

    fn name(self: *const ar_hdr) ?[]const u8 {
        const value = &self.ar_name;
        if (mem.startsWith(u8, value, "#1/")) return null;
        const sentinel = mem.indexOfScalar(u8, value, '/') orelse value.len;
        return value[0..sentinel];
    }

    fn nameLength(self: ar_hdr) !?u32 {
        const value = &self.ar_name;
        if (!mem.startsWith(u8, value, "#1/")) return null;
        const trimmed = mem.trimRight(u8, self.ar_name["#1/".len..], &[_]u8{0x20});
        return try std.fmt.parseInt(u32, trimmed, 10);
    }

    /// Caller owns the memory.
    fn getName(self: *const ar_hdr, gpa: Allocator, reader: anytype) ![]const u8 {
        if (self.name()) |n| return n;
        if (try self.nameLength()) |len| {
            const buf = try gpa.alloc(u8, len);
            defer gpa.free(buf);
            try reader.readNoEof(buf);
            const actual_len = mem.indexOfScalar(u8, buf, @as(u8, 0)) orelse len;
            return try gpa.dupe(u8, buf[0..actual_len]);
        }
        return error.MalformedArchive;
    }

    pub fn format(
        self: ar_hdr,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        try writer.print("ar_name: {s} ({x})\n", .{
            std.fmt.fmtSliceEscapeLower(&self.ar_name),
            std.fmt.fmtSliceHexLower(&self.ar_name),
        });
        try writer.print("ar_date: {s} ({x})\n", .{
            std.fmt.fmtSliceEscapeLower(&self.ar_date),
            std.fmt.fmtSliceHexLower(&self.ar_date),
        });
        try writer.print("ar_uid:  {s} ({x})\n", .{
            std.fmt.fmtSliceEscapeLower(&self.ar_uid),
            std.fmt.fmtSliceHexLower(&self.ar_uid),
        });
        try writer.print("ar_gid:  {s} ({x})\n", .{
            std.fmt.fmtSliceEscapeLower(&self.ar_gid),
            std.fmt.fmtSliceHexLower(&self.ar_gid),
        });
        try writer.print("ar_mode: {s} ({x})\n", .{
            std.fmt.fmtSliceEscapeLower(&self.ar_mode),
            std.fmt.fmtSliceHexLower(&self.ar_mode),
        });
        try writer.print("ar_size: {s} ({x})\n", .{
            std.fmt.fmtSliceEscapeLower(&self.ar_size),
            std.fmt.fmtSliceHexLower(&self.ar_size),
        });
        try writer.print("ar_fmag: {s} ({x})\n", .{
            std.fmt.fmtSliceEscapeLower(&self.ar_fmag),
            std.fmt.fmtSliceHexLower(&self.ar_fmag),
        });
    }
};

const Symtab = struct {
    entries: std.ArrayListUnmanaged(Entry) = .{},
    strtab: []const u8 = &[0]u8{},
    format: enum { p32, p64 } = .p32,

    fn deinit(ar: *Symtab, gpa: Allocator) void {
        ar.entries.deinit(gpa);
    }

    fn ptrWidth(ar: Symtab) usize {
        return switch (ar.format) {
            .p32 => @as(usize, 4),
            .p64 => 8,
        };
    }

    fn parse(ar: *Symtab, gpa: Allocator, data: []const u8) !void {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        const size = try ar.readInt(reader);
        const num = @divExact(size, ar.ptrWidth() * 2);
        try ar.entries.ensureTotalCapacityPrecise(gpa, num);

        for (0..num) |_| {
            const name = try ar.readInt(reader);
            const file = try ar.readInt(reader);
            ar.entries.appendAssumeCapacity(.{ .name = name, .file = file });
        }

        const strtab_off = size + ar.ptrWidth();
        const strtab_len = try ar.readInt(reader);
        ar.strtab = data[strtab_off + ar.ptrWidth() ..][0..strtab_len];
    }

    fn readInt(ar: Symtab, reader: anytype) !u64 {
        return switch (ar.format) {
            .p32 => @as(u64, @intCast(try reader.readInt(u32, .little))),
            .p64 => try reader.readInt(u64, .little),
        };
    }

    fn getString(ar: *const Symtab, off: u64) [:0]const u8 {
        assert(off < ar.strtab.len);
        return mem.sliceTo(@as([*:0]const u8, @ptrCast(ar.strtab.ptr + off)), 0);
    }

    const Entry = struct {
        /// Symbol name offset
        name: u64,
        /// Offset of the object file.
        file: u64,

        fn getName(entry: Entry, ctx: *const Symtab) [:0]const u8 {
            return ctx.getString(entry.name);
        }
    };
};

const ARMAG = "!<arch>\n";
const ARFMAG = "`\n";
const SYMDEF = "__.SYMDEF";
const SYMDEF64 = "__.SYMDEF_64";
const SYMDEF_SORTED = "__.SYMDEF SORTED";
const SYMDEF64_SORTED = "__.SYMDEF_64 SORTED";

const assert = std.debug.assert;
const fat = @import("fat.zig");
const mem = std.mem;
const std = @import("std");

const Allocator = mem.Allocator;
const Archive = @This();
const Object = @import("Object.zig");
