const ZachO = @This();

const std = @import("std");
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const macho = std.macho;

const Allocator = std.mem.Allocator;

const commands = @import("ZachO/commands.zig");
const LoadCommand = commands.LoadCommand;
const SegmentCommand = commands.SegmentCommand;

allocator: Allocator,
file: ?fs.File = null,

/// Mach-O header
header: ?macho.mach_header_64 = null,

/// Load commands
load_commands: std.ArrayListUnmanaged(LoadCommand) = .{},

/// Data
data: std.ArrayListUnmanaged(u8) = .{},

/// Code signature load command
code_signature_cmd: ?u16 = null,

pub fn init(allocator: Allocator) ZachO {
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
    try self.load_commands.ensureTotalCapacity(self.allocator, ncmds);

    var i: u16 = 0;
    while (i < ncmds) : (i += 1) {
        const cmd = try LoadCommand.parse(self.allocator, reader);
        switch (cmd.cmd()) {
            macho.LC.CODE_SIGNATURE => self.code_signature_cmd = i,
            else => {},
        }
        self.load_commands.appendAssumeCapacity(cmd);
    }

    // TODO parse memory mapped segments
    try reader.context.seekTo(0);
    const file_size = try reader.context.getEndPos();
    var data = try std.ArrayList(u8).initCapacity(self.allocator, file_size);
    try reader.readAllArrayList(&data, file_size);
    self.data = data.moveToUnmanaged();
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
    _ = fmt;
    _ = options;

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
    var ptr = data;
    const magic = mem.readIntBig(u32, ptr[0..4]);
    const length = mem.readIntBig(u32, ptr[4..8]);
    const count = mem.readIntBig(u32, ptr[8..12]);
    ptr = ptr[12..];

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

    var blobs = std.ArrayList(macho.BlobIndex).init(self.allocator);
    defer blobs.deinit();
    try blobs.ensureTotalCapacityPrecise(count);

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const tt = mem.readIntBig(u32, ptr[0..4]);
        const offset = mem.readIntBig(u32, ptr[4..8]);
        const tt_fmt = switch (tt) {
            macho.CSSLOT_CODEDIRECTORY => "CSSLOT_CODEDIRECTORY",
            macho.CSSLOT_REQUIREMENTS => "CSSLOT_REQUIREMENTS",
            macho.CSSLOT_ALTERNATE_CODEDIRECTORIES => "CSSLOT_ALTERNATE_CODEDIRECTORIES",
            macho.CSSLOT_SIGNATURESLOT => "CSSLOT_SIGNATURESLOT",
            macho.CSSLOT_ENTITLEMENTS => "CSSLOT_ENTITLEMENTS",
            else => "UNKNOWN",
        };
        try writer.print("{{\n    Type: {s}(0x{x})\n    Offset: {}\n}}\n", .{ tt_fmt, tt, offset });
        blobs.appendAssumeCapacity(.{
            .@"type" = tt,
            .offset = offset,
        });
        ptr = ptr[8..];
    }

    for (blobs.items) |blob| {
        ptr = data[blob.offset..];
        const magic2 = mem.readIntBig(u32, ptr[0..4]);
        const length2 = mem.readIntBig(u32, ptr[4..8]);
        const magic2_fmt = switch (magic2) {
            macho.CSMAGIC_REQUIREMENTS => "CSMAGIC_REQUIREMENTS",
            macho.CSMAGIC_CODEDIRECTORY => "CSMAGIC_CODEDIRECTORY",
            macho.CSMAGIC_BLOBWRAPPER => "CSMAGIC_BLOBWRAPPER",
            macho.CSMAGIC_EMBEDDED_ENTITLEMENTS => "CSMAGIC_EMBEDDED_ENTITLEMENTS",
            macho.CSMAGIC_EMBEDDED_DER_ENTITLEMENTS => "CSMAGIC_EMBEDDED_DER_ENTITLEMENTS",
            else => "UNKNOWN",
        };

        try writer.print("{{\n", .{});
        try writer.print("    Magic: {s}(0x{x})\n", .{ magic2_fmt, magic2 });
        try writer.print("    Length: {}\n", .{length2});

        switch (magic2) {
            macho.CSMAGIC_CODEDIRECTORY => {
                const version = mem.readIntBig(u32, ptr[8..12]);
                const flags = mem.readIntBig(u32, ptr[12..16]);
                const hash_off = mem.readIntBig(u32, ptr[16..20]);
                const ident_off = mem.readIntBig(u32, ptr[20..24]);
                const n_special_slots = mem.readIntBig(u32, ptr[24..28]);
                const n_code_slots = mem.readIntBig(u32, ptr[28..32]);
                const code_limit = mem.readIntBig(u32, ptr[32..36]);
                const hash_size = ptr[36];
                const page_size = std.math.pow(u16, 2, ptr[39]);

                try writer.print("    Version: 0x{x}\n", .{version});
                try writer.print("    Flags: 0x{x}\n", .{flags});
                try writer.print("    Hash offset: {}\n", .{hash_off});
                try writer.print("    Ident offset: {}\n", .{ident_off});
                try writer.print("    Number of special slots: {}\n", .{n_special_slots});
                try writer.print("    Number of code slots: {}\n", .{n_code_slots});
                try writer.print("    Code limit: {}\n", .{code_limit});
                try writer.print("    Hash size: {}\n", .{hash_size});
                try writer.print("    Hash type: {}\n", .{ptr[37]});
                try writer.print("    Platform: {}\n", .{ptr[38]});
                try writer.print("    Page size: {}\n", .{ptr[39]});
                try writer.print("    Reserved: {}\n", .{mem.readIntBig(u32, ptr[40..44])});

                switch (version) {
                    0x20400 => {
                        try writer.print("    Scatter offset: {}\n", .{mem.readIntBig(u32, ptr[44..48])});
                        try writer.print("    Team offset: {}\n", .{mem.readIntBig(u32, ptr[48..52])});
                        try writer.print("    Reserved: {}\n", .{mem.readIntBig(u32, ptr[52..56])});
                        try writer.print("    Code limit 64: {}\n", .{mem.readIntBig(u64, ptr[56..64])});
                        try writer.print("    Offset of executable segment: {}\n", .{mem.readIntBig(u64, ptr[64..72])});
                        try writer.print("    Limit of executable segment: {}\n", .{mem.readIntBig(u64, ptr[72..80])});
                        try writer.print("    Executable segment flags: 0x{x}\n", .{mem.readIntBig(u64, ptr[80..88])});
                        ptr = ptr[88..];
                    },
                    0x20100 => {
                        try writer.print("    Scatter offset: {}\n", .{mem.readIntBig(u32, ptr[52..56])});
                        ptr = ptr[56..];
                    },
                    else => {
                        ptr = ptr[52..];
                    },
                }

                const ident = mem.sliceTo(@ptrCast([*:0]const u8, ptr), 0);
                try writer.print("\nIdent: {s}\n", .{ident});
                ptr = ptr[ident.len + 1 ..];

                var j: isize = n_special_slots;
                while (j > 0) : (j -= 1) {
                    const hash = ptr[0..hash_size];
                    try writer.print("\nSpecial slot {s}:\n", .{@intToEnum(CSSLOT, j)});
                    try formatBinaryBlob(hash, "        ", writer);
                    ptr = ptr[hash_size..];
                }

                var k: usize = 0;
                const base_addr: u64 = 0x100000000;
                while (k < n_code_slots) : (k += 1) {
                    const hash = ptr[0..hash_size];
                    try writer.print("\nCode slot (0x{x} - 0x{x}):\n", .{
                        base_addr + k * page_size,
                        base_addr + (k + 1) * page_size,
                    });
                    try formatBinaryBlob(hash, "        ", writer);
                    ptr = ptr[hash_size..];
                }
            },
            else => {
                try writer.print("    Data:\n", .{});
                try formatBinaryBlob(ptr[8..length2], "        ", writer);
            },
        }

        try writer.print("}}\n", .{});
    }
}

const CSSLOT = enum(u8) {
    CODEDIRECTORY = macho.CSSLOT_CODEDIRECTORY,
    INFOSLOT = macho.CSSLOT_INFOSLOT,
    REQUIREMENTS = macho.CSSLOT_REQUIREMENTS,
    RESOURCEDIR = macho.CSSLOT_RESOURCEDIR,
    APPLICATION = macho.CSSLOT_APPLICATION,
    ENTITLEMENTS = macho.CSSLOT_ENTITLEMENTS,
    UNKNOWN = 6,
    DER_ENTITLEMENTS = macho.CSSLOT_DER_ENTITLEMENTS,
};

fn formatBinaryBlob(blob: []const u8, prefix: ?[]const u8, writer: anytype) !void {
    // Format as 16-by-16-by-8 with two left column in hex, and right in ascii:
    // xxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx  xxxxxxxx
    var i: usize = 0;
    const step = 16;
    const pp = prefix orelse "";
    var tmp_buf: [step]u8 = undefined;
    while (i < blob.len) : (i += step) {
        const end = if (blob[i..].len >= step) step else blob[i..].len;
        const padding = step - blob[i .. i + end].len;
        if (padding > 0) {
            mem.set(u8, &tmp_buf, 0);
        }
        mem.copy(u8, &tmp_buf, blob[i .. i + end]);
        try writer.print("{s}{x:<016} {x:<016}  {s}\n", .{
            pp,
            std.fmt.fmtSliceHexLower(tmp_buf[0 .. step / 2]),
            std.fmt.fmtSliceHexLower(tmp_buf[step / 2 .. step]),
            std.fmt.fmtSliceEscapeLower(tmp_buf[0..step]),
        });
    }
}

test "" {
    std.testing.refAllDecls(@This());
}
