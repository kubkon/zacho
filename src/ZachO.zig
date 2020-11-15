const ZachO = @This();

const std = @import("std");
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const macho = std.macho;
const machoext = @import("machoext.zig");

const Allocator = std.mem.Allocator;

usingnamespace @import("ZachO/commands.zig");

alloc: *Allocator,

/// Mach-O header
header: ?macho.mach_header_64 = null,

/// Load commands
load_commands: std.ArrayListUnmanaged(LoadCommand) = .{},

/// Data
data: std.ArrayListUnmanaged(u8) = .{},

pub fn init(alloc: *Allocator) ZachO {
    return .{
        .alloc = alloc,
    };
}

pub fn parse(self: *ZachO, stream: *io.StreamSource) !void {
    self.header = try stream.reader().readStruct(macho.mach_header_64);

    const ncmds = self.header.?.ncmds;
    try self.load_commands.ensureCapacity(self.alloc, ncmds);

    var i: usize = 0;
    while (i < ncmds) : (i += 1) {
        const cmd = try LoadCommand.parse(self.alloc, stream);
        self.load_commands.appendAssumeCapacity(cmd);
    }

    // TODO parse memory mapped segments
    try stream.seekTo(0);
    const file_size = try stream.getEndPos();
    var data = try std.ArrayList(u8).initCapacity(self.alloc, file_size);
    try stream.reader().readAllArrayList(&data, file_size);
    self.data = data.toUnmanaged();
}

pub fn parseFile(self: *ZachO, pathname: []const u8) !void {
    const file = try fs.openFileAbsolute(pathname, .{});
    defer file.close();

    var stream = io.StreamSource{ .file = file };
    return self.parse(&stream);
}

pub fn deinit(self: *ZachO) void {
    for (self.load_commands.items) |*cmd| {
        cmd.deinit(self.alloc);
    }
    self.load_commands.deinit(self.alloc);
    self.data.deinit(self.alloc);
}

pub fn printHeader(self: ZachO, writer: anytype) !void {
    const header = &self.header.?;
    try writer.print("Header\n", .{});
    try writer.print("  Magic number: 0x{x}\n", .{header.magic});
    try writer.print("  CPU type: 0x{x}\n", .{header.cputype});
    try writer.print("  CPU sub-type: 0x{x}\n", .{header.cpusubtype});
    try writer.print("  File type: 0x{x}\n", .{header.filetype});
    try writer.print("  Number of load commands: {}\n", .{header.ncmds});
    try writer.print("  Size of load commands: {}\n", .{header.sizeofcmds});
    try writer.print("  Flags: 0x{x}\n", .{header.flags});
    try writer.print("  Reserved: 0x{x}\n", .{header.reserved});
}

pub fn printLoadCommands(self: ZachO, writer: anytype) !void {
    for (self.load_commands.items) |cmd| {
        try writer.print("{}\n", .{cmd});
    }
}

pub fn format(self: ZachO, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    try self.printHeader(writer);
    try writer.print("\n", .{});

    try self.printLoadCommands(writer);
    try writer.print("\n", .{});

    for (self.load_commands.items) |cmd| {
        switch (cmd) {
            .Segment => |seg| try self.formatData(seg, writer),
            .CodeSignature => |csig| try self.formatCodeSignatureData(csig, writer),
            else => {},
        }
    }
}

fn formatData(self: ZachO, segment_command: SegmentCommand, writer: anytype) !void {
    const seg = &segment_command.inner;
    const start_pos = seg.fileoff;
    const end_pos = seg.fileoff + seg.filesize;

    if (end_pos == start_pos) return;

    try writer.print("{}\n", .{seg.segname});
    try writer.print("file = {{ {}, {} }}\n", .{ start_pos, end_pos });
    try writer.print("address = {{ 0x{x:0<16}, 0x{x:0<16} }}\n\n", .{ seg.vmaddr, seg.vmaddr + seg.vmsize });

    for (segment_command.section_headers.items) |sect| {
        const file_start = sect.offset;
        const file_end = sect.offset + sect.size;
        const addr_start = sect.addr;
        const addr_end = sect.addr + sect.size;

        try writer.print("  {},{}\n", .{ sect.segname, sect.sectname });
        try writer.print("  file = {{ {}, {} }}\n", .{ file_start, file_end });
        try writer.print("  address = {{ 0x{x:0<16}, 0x{x:0<16} }}\n\n", .{ addr_start, addr_end });
        try formatBinaryBlob(self.data.items[file_start..file_end], "  ", writer);
        try writer.print("\n", .{});
    }
}

fn formatCodeSignatureData(self: ZachO, codesig_command: CodeSignatureCommand, writer: anytype) !void {
    const csig = &codesig_command.inner;
    const start_pos = csig.dataoff;
    const end_pos = csig.dataoff + csig.datasize;

    if (end_pos == start_pos) return;

    try writer.print("Code signature data:\n", .{});
    try writer.print("file = {{ {}, {} }}\n\n", .{ start_pos, end_pos });

    var data = self.data.items[start_pos..end_pos];
    const magic = mem.readIntBig(u32, data[0..4]);
    const length = mem.readIntBig(u32, data[4..8]);
    const count = mem.readIntBig(u32, data[8..12]);
    data = data[12..];

    try writer.print("{{\n", .{});
    try writer.print("    Magic = 0x{x}\n", .{magic});
    try writer.print("    Length = {}\n", .{length});
    try writer.print("    Count = {}\n", .{count});
    try writer.print("}}\n", .{});

    if (magic != machoext.CSMAGIC_EMBEDDED_SIGNATURE) {
        try writer.print("unknown signature type: 0x{x}\n", .{magic});
        try formatBinaryBlob(self.data.items[start_pos..end_pos], null, writer);
        return;
    }

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const tt = mem.readIntBig(u32, data[0..4]); // ignored for some reason?
        const offset = mem.readIntBig(u32, data[4..8]);

        try writer.print("{{\n", .{});

        const tt_fmt = switch (tt) {
            machoext.CSSLOT_CODEDIRECTORY => "CSSLOT_CODEDIRECTORY",
            machoext.CSSLOT_REQUIREMENTS => "CSSLOT_REQUIREMENTS",
            machoext.CSSLOT_ALTERNATE_CODEDIRECTORIES => "CSSLOT_ALTERNATE_CODEDIRECTORIES",
            machoext.CSSLOT_SIGNATURESLOT => "CSSLOT_SIGNATURESLOT",
            else => "Unknown",
        };
        try writer.print("    Type: {}(0x{x})\n", .{ tt_fmt, tt });
        try writer.print("    Offset: {}\n", .{offset});

        var inner = data[offset - 12 - i * 8 ..];
        const magic2 = mem.readIntBig(u32, inner[0..4]);
        const length2 = mem.readIntBig(u32, inner[4..8]);
        const magic2_fmt = switch (magic2) {
            machoext.CSMAGIC_REQUIREMENTS => "CSMAGIC_REQUIREMENTS",
            machoext.CSMAGIC_CODEDIRECTORY => "CSMAGIC_CODEDIRECTORY",
            machoext.CSMAGIC_BLOBWRAPPER => "CSMAGIC_BLOBWRAPPER",
            else => "Unknown",
        };

        try writer.print("    Magic: {}(0x{x})\n", .{ magic2_fmt, magic2 });
        try writer.print("    Length: {}\n", .{length2});

        switch (magic2) {
            machoext.CSMAGIC_CODEDIRECTORY => {
                const version = mem.readIntBig(u32, inner[8..12]);
                try writer.print("    Version: 0x{x}\n", .{version});
                try writer.print("    Flags: 0x{x}\n", .{mem.readIntBig(u32, inner[12..16])});
                try writer.print("    Hash offset: {}\n", .{mem.readIntBig(u32, inner[16..20])});
                try writer.print("    Ident offset: {}\n", .{mem.readIntBig(u32, inner[20..24])});
                try writer.print("    Number of special slots: {}\n", .{mem.readIntBig(u32, inner[24..28])});
                try writer.print("    Number of code slots: {}\n", .{mem.readIntBig(u32, inner[32..36])});
                try writer.print("    Code limit: {}\n", .{mem.readIntBig(u32, inner[40..44])});
                try writer.print("    Hash size: {}\n", .{mem.readIntBig(u8, inner[44..45])});
                try writer.print("    Hash type: {}\n", .{mem.readIntBig(u8, inner[45..46])});
                try writer.print("    Platform: {}\n", .{mem.readIntBig(u8, inner[46..47])});
                try writer.print("    Page size: {}\n", .{mem.readIntBig(u8, inner[47..48])});
                try writer.print("    Reserved: {}\n", .{mem.readIntBig(u32, inner[48..52])});

                const len = blk: {
                    switch (version) {
                        0x20400 => {
                            try writer.print("    Offset of executable segment: {}\n", .{mem.readIntBig(u64, inner[52..60])});
                            try writer.print("    Limit of executable segment: {}\n", .{mem.readIntBig(u64, inner[60..68])});
                            try writer.print("    Executable segment flags: 0x{x}\n", .{mem.readIntBig(u64, inner[68..76])});
                            inner = inner[76..];
                            break :blk length2 - 76;
                        },
                        0x20100 => {
                            try writer.print("    Offset of optional scatter vector: {}\n", .{mem.readIntBig(u32, inner[52..56])});
                            inner = inner[56..];
                            break :blk length2 - 56;
                        },
                        else => {
                            inner = inner[52..];
                            break :blk length2 - 52;
                        }
                    }
                };
                try writer.print("    Data still to parse:\n", .{});
                try formatBinaryBlob(inner[0..len], "        ", writer);
            },
            else => {
                try writer.print("    Data:\n", .{});
                try formatBinaryBlob(inner[8..length2], "        ", writer);
            },
        }

        try writer.print("}}\n", .{});

        data = data[8..];
    }
}

fn formatBinaryBlob(blob: []const u8, prefix: ?[]const u8, writer: anytype) !void {
    // Format as 16-by-16-by-8 with two left column in hex, and right in ascii:
    // xxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx  xxxxxxxx
    var i: usize = 0;
    const step = 16;
    const pp = prefix orelse "";
    while (i < blob.len) : (i += step) {
        if (blob[i..].len < step / 2) {
            try writer.print("{}{x:<033}  {}\n", .{ pp, blob[i..], blob[i..] });
            continue;
        }
        const rem = std.math.min(blob[i..].len, step);
        try writer.print("{}{x:<016} {x:<016}  {}\n", .{
            pp,
            blob[i .. i + rem / 2],
            blob[i + rem / 2 .. i + rem],
            blob[i .. i + rem],
        });
    }
}
