const ZachO = @This();

const std = @import("std");
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const macho = std.macho;

const Allocator = std.mem.Allocator;

usingnamespace @import("ZachO/commands.zig");

allocator: *Allocator,
file: ?fs.File = null,

/// Mach-O header
header: ?macho.mach_header_64 = null,

/// Load commands
load_commands: std.ArrayListUnmanaged(LoadCommand) = .{},

/// Data
data: std.ArrayListUnmanaged(u8) = .{},

/// Code signature load command
code_signature_cmd: ?u16 = null,

pub fn init(allocator: *Allocator) ZachO {
    return .{ .allocator = allocator };
}

pub fn deinit(self: *ZachO) void {
    for (self.load_commands.items) |*cmd| {
        cmd.deinit(self.allocator);
    }
    self.load_commands.deinit(self.allocator);
    self.data.deinit(self.allocator);
}

pub fn closeFiles(self: *ZachO) void {
    if (self.file) |file| {
        file.close();
    }
    self.file = null;
}

pub fn parse(self: *ZachO, file: fs.File) !void {
    self.file = file;
    var reader = file.reader();

    self.header = try reader.readStruct(macho.mach_header_64);

    const ncmds = self.header.?.ncmds;
    try self.load_commands.ensureCapacity(self.allocator, ncmds);

    var i: u16 = 0;
    while (i < ncmds) : (i += 1) {
        const cmd = try LoadCommand.parse(self.allocator, reader);
        switch (cmd.cmd()) {
            macho.LC_CODE_SIGNATURE => self.code_signature_cmd = i,
            else => {},
        }
        self.load_commands.appendAssumeCapacity(cmd);
    }

    // TODO parse memory mapped segments
    try reader.context.seekTo(0);
    const file_size = try reader.context.getEndPos();
    var data = try std.ArrayList(u8).initCapacity(self.allocator, file_size);
    try reader.readAllArrayList(&data, file_size);
    self.data = data.toUnmanaged();
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

pub fn printCodeSignature(self: ZachO, writer: anytype) !void {
    return if (self.code_signature_cmd) |code_sig|
        self.formatCodeSignatureData(self.load_commands.items[code_sig].LinkeditData, writer)
    else
        writer.print("LC_CODE_SIGNATURE load command not found\n", .{});
}

pub fn format(
    self: ZachO,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
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

    try writer.print("{s}\n", .{seg.segname});
    try writer.print("file = {{ {}, {} }}\n", .{ start_pos, end_pos });
    try writer.print("address = {{ 0x{x:0<16}, 0x{x:0<16} }}\n\n", .{
        seg.vmaddr,
        seg.vmaddr + seg.vmsize,
    });

    for (segment_command.section_headers.items) |sect| {
        const file_start = sect.offset;
        const file_end = sect.offset + sect.size;
        const addr_start = sect.addr;
        const addr_end = sect.addr + sect.size;

        try writer.print("  {s},{s}\n", .{ sect.segname, sect.sectname });
        try writer.print("  file = {{ {}, {} }}\n", .{ file_start, file_end });
        try writer.print("  address = {{ 0x{x:0<16}, 0x{x:0<16} }}\n\n", .{
            addr_start,
            addr_end,
        });
        try formatBinaryBlob(self.data.items[file_start..file_end], "  ", writer);
        try writer.print("\n", .{});
    }
}

fn formatCodeSignatureData(
    self: ZachO,
    csig: macho.linkedit_data_command,
    writer: anytype,
) !void {
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

    if (magic != macho.CSMAGIC_EMBEDDED_SIGNATURE) {
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
            macho.CSSLOT_CODEDIRECTORY => "CSSLOT_CODEDIRECTORY",
            macho.CSSLOT_REQUIREMENTS => "CSSLOT_REQUIREMENTS",
            macho.CSSLOT_ALTERNATE_CODEDIRECTORIES => "CSSLOT_ALTERNATE_CODEDIRECTORIES",
            macho.CSSLOT_SIGNATURESLOT => "CSSLOT_SIGNATURESLOT",
            else => "Unknown",
        };
        try writer.print("    Type: {s}(0x{x})\n", .{ tt_fmt, tt });
        try writer.print("    Offset: {}\n", .{offset});

        var inner = data[offset - 12 - i * 8 ..];
        const magic2 = mem.readIntBig(u32, inner[0..4]);
        const length2 = mem.readIntBig(u32, inner[4..8]);
        const magic2_fmt = switch (magic2) {
            macho.CSMAGIC_REQUIREMENTS => "CSMAGIC_REQUIREMENTS",
            macho.CSMAGIC_CODEDIRECTORY => "CSMAGIC_CODEDIRECTORY",
            macho.CSMAGIC_BLOBWRAPPER => "CSMAGIC_BLOBWRAPPER",
            else => "Unknown",
        };

        try writer.print("    Magic: {s}(0x{x})\n", .{ magic2_fmt, magic2 });
        try writer.print("    Length: {}\n", .{length2});

        switch (magic2) {
            macho.CSMAGIC_CODEDIRECTORY => {
                const version = mem.readIntBig(u32, inner[8..12]);
                try writer.print("    Version: 0x{x}\n", .{version});
                try writer.print("    Flags: 0x{x}\n", .{mem.readIntBig(u32, inner[12..16])});
                try writer.print("    Hash offset: {}\n", .{mem.readIntBig(u32, inner[16..20])});
                try writer.print("    Ident offset: {}\n", .{mem.readIntBig(u32, inner[20..24])});
                try writer.print("    Number of special slots: {}\n", .{mem.readIntBig(u32, inner[24..28])});
                try writer.print("    Number of code slots: {}\n", .{mem.readIntBig(u32, inner[28..32])});
                try writer.print("    Code limit: {}\n", .{mem.readIntBig(u32, inner[32..36])});
                try writer.print("    Hash size: {}\n", .{inner[36]});
                try writer.print("    Hash type: {}\n", .{inner[37]});
                try writer.print("    Platform: {}\n", .{inner[38]});
                try writer.print("    Page size: {}\n", .{inner[39]});
                try writer.print("    Reserved: {}\n", .{mem.readIntBig(u32, inner[40..44])});

                const len = blk: {
                    switch (version) {
                        0x20400 => {
                            try writer.print("    Scatter offset: {}\n", .{mem.readIntBig(u32, inner[44..48])});
                            try writer.print("    Team offset: {}\n", .{mem.readIntBig(u32, inner[48..52])});
                            try writer.print("    Reserved: {}\n", .{mem.readIntBig(u32, inner[52..56])});
                            try writer.print("    Code limit 64: {}\n", .{mem.readIntBig(u64, inner[56..64])});
                            try writer.print("    Offset of executable segment: {}\n", .{mem.readIntBig(u64, inner[64..72])});
                            try writer.print("    Limit of executable segment: {}\n", .{mem.readIntBig(u64, inner[72..80])});
                            try writer.print("    Executable segment flags: 0x{x}\n", .{mem.readIntBig(u64, inner[80..88])});
                            inner = inner[88..];
                            break :blk length2 - 88;
                        },
                        0x20100 => {
                            try writer.print("    Scatter offset: {}\n", .{mem.readIntBig(u32, inner[52..56])});
                            inner = inner[56..];
                            break :blk length2 - 56;
                        },
                        else => {
                            inner = inner[52..];
                            break :blk length2 - 52;
                        },
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
            try writer.print("{s}{x:<033}  {s}\n", .{
                pp,
                std.fmt.fmtSliceHexLower(blob[i..]),
                blob[i..],
            });
            continue;
        }
        const rem = std.math.min(blob[i..].len, step);
        try writer.print("{s}{x:<016} {x:<016}  {s}\n", .{
            pp,
            std.fmt.fmtSliceHexLower(blob[i .. i + rem / 2]),
            std.fmt.fmtSliceHexLower(blob[i + rem / 2 .. i + rem]),
            blob[i .. i + rem],
        });
    }
}

test "" {
    std.testing.refAllDecls(@This());
}
