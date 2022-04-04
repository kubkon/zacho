const ZachO = @This();

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
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
        try formatBinaryBlob(self.data.items[start_pos..end_pos], .{}, writer);
        return;
    }

    var blobs = std.ArrayList(macho.BlobIndex).init(self.allocator);
    defer blobs.deinit();
    try blobs.ensureTotalCapacityPrecise(count);

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const tt = mem.readIntBig(u32, ptr[0..4]);
        const offset = mem.readIntBig(u32, ptr[4..8]);
        try writer.print("{{\n    Type: {s}(0x{x})\n    Offset: {}\n}}\n", .{ fmtCsSlotConst(tt), tt, offset });
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

        try writer.print("{{\n", .{});
        try writer.print("    Magic: {s}(0x{x})\n", .{ fmtCsMagic(magic2), magic2 });
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
                const team_off = mem.readIntBig(u32, ptr[48..52]);

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
                        try writer.print("    Team offset: {}\n", .{team_off});
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

                if (team_off > 0) {
                    assert(team_off - ident_off == ident.len + 1);
                    const team_ident = mem.sliceTo(@ptrCast([*:0]const u8, ptr), 0);
                    try writer.print("\nTeam ident: {s}\n", .{team_ident});
                    ptr = ptr[team_ident.len + 1 ..];
                }

                var j: isize = n_special_slots;
                while (j > 0) : (j -= 1) {
                    const hash = ptr[0..hash_size];
                    try writer.print("\nSpecial slot for {s}:\n", .{
                        fmtCsSlotConst(@intCast(u32, if (j == 6) macho.CSSLOT_SIGNATURESLOT else j)),
                    });
                    try formatBinaryBlob(hash, .{
                        .prefix = "        ",
                        .fmt_as_str = false,
                    }, writer);
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
                    try formatBinaryBlob(hash, .{
                        .prefix = "        ",
                        .fmt_as_str = false,
                    }, writer);
                    ptr = ptr[hash_size..];
                }
            },
            macho.CSMAGIC_REQUIREMENTS => {
                const req_data = ptr[8..length2];
                var stream = std.io.fixedBufferStream(req_data);
                var reader = stream.reader();

                try writer.print("    Parsed data:\n", .{});

                var req_count = try reader.readIntBig(u32);

                var req_blobs = std.ArrayList(macho.BlobIndex).init(self.allocator);
                defer req_blobs.deinit();
                try req_blobs.ensureTotalCapacityPrecise(req_count);

                var next_req: usize = 0;
                while (next_req < req_count) : (next_req += 1) {
                    const tt = try reader.readIntBig(u32);
                    const off = try reader.readIntBig(u32);
                    try writer.print("\n    {{\n      Type: {s}(0x{x})\n      Offset: {}\n    }}\n", .{
                        fmtCsSlotConst(tt),
                        tt,
                        off,
                    });
                    req_blobs.appendAssumeCapacity(.{
                        .@"type" = tt,
                        .offset = off,
                    });
                }

                for (req_blobs.items) |req_blob| {
                    try stream.seekTo(req_blob.offset - 8);
                    const req_blob_magic = try reader.readIntBig(u32);
                    const req_blob_len = try reader.readIntBig(u32);

                    try writer.writeAll("\n    {\n");
                    try writer.print("        Magic: {s}(0x{x})\n", .{
                        fmtCsMagic(req_blob_magic),
                        req_blob_magic,
                    });
                    try writer.print("        Length: {}\n", .{req_blob_len});

                    while (reader.context.pos < req_blob_len) {
                        const next = try reader.readIntBig(u32);
                        const op = @intToEnum(ExprOp, next);

                        try writer.print("  {}", .{op});

                        switch (op) {
                            .op_false,
                            .op_true,
                            .op_and,
                            .op_or,
                            .op_not,
                            .op_apple_anchor,
                            .op_anchor_hash,
                            .op_info_key_value,
                            .op_trusted_cert,
                            .op_trusted_certs,
                            .op_apple_generic_anchor,
                            .op_entitlement_field,
                            .op_cert_policy,
                            .op_named_anchor,
                            .op_named_code,
                            .op_notarized,
                            .op_cert_field_date,
                            .op_legacy_dev_id,
                            => {},
                            .op_ident => try fmtReqData(req_data, reader, writer),
                            .op_cert_generic => {
                                const slot = try reader.readIntBig(i32);
                                switch (slot) {
                                    LEAF_CERT => try writer.writeAll("\n    leaf"),
                                    ROOT_CERT => try writer.writeAll("\n    root"),
                                    else => try writer.print("\n    slot {d}", .{slot}),
                                }
                                try fmtCssmData(req_data, reader, writer);
                                try fmtReqMatch(req_data, reader, writer);
                            },
                            .op_cert_field => {
                                const slot = try reader.readIntBig(i32);
                                switch (slot) {
                                    LEAF_CERT => try writer.writeAll("\n    leaf"),
                                    ROOT_CERT => try writer.writeAll("\n    root"),
                                    else => try writer.print("\n    slot {d}", .{slot}),
                                }
                                try fmtReqData(req_data, reader, writer);
                                try fmtReqMatch(req_data, reader, writer);
                            },
                            .op_platform => {
                                const platform = try reader.readIntBig(i32);
                                try writer.print("\n    {x}", .{
                                    std.fmt.fmtSliceHexLower(mem.asBytes(&platform)),
                                });
                            },
                            else => {
                                if (next & EXPR_OP_GENERIC_FALSE != 0) {
                                    try writer.writeAll("\n    generic false");
                                } else if (next & EXPR_OP_GENERIC_SKIP != 0) {
                                    try writer.writeAll("\n    generic skip");
                                } else {
                                    try writer.writeAll("\n    unknown opcode");
                                }
                            },
                        }

                        try writer.writeByte('\n');
                    }
                    try writer.writeAll("\n    }");
                }

                try writer.print("\n    Raw data:\n", .{});
                try formatBinaryBlob(ptr[8..length2], .{
                    .prefix = "        ",
                    .fmt_as_str = true,
                    .escape_str = true,
                }, writer);
            },
            macho.CSMAGIC_BLOBWRAPPER => {
                const signature = ptr[8..length2];

                if (comptime builtin.target.isDarwin()) {
                    const cms = @import("cms.zig");

                    const cd: []const u8 = blk: {
                        const cd_blob = blobs.items[0];
                        const cd_header = data[cd_blob.offset..][0..8];
                        const cd_length = mem.readIntBig(u32, cd_header[4..8]);
                        break :blk data[cd_blob.offset..][0..cd_length];
                    };

                    const decoder = try cms.initCMSDecoderRef();
                    defer decoder.deinit();
                    try decoder.updateMessage(signature);
                    try decoder.setDetachedContent(cd);
                    try decoder.finalizeMessage();

                    const num_signers = try decoder.getNumSigners();
                    try writer.print("    Number of signers: {d}\n", .{num_signers});

                    const status = try decoder.getSignerStatus(0);
                    try writer.print("    Signer status: {}\n", .{status});

                    // if (try decoder.copyDetachedContent()) |content_ref| {
                    //     defer content_ref.deinit();
                    //     const as_bytes = content_ref.bytes();
                    //     std.log.warn("{x}", .{std.fmt.fmtSliceHexLower(as_bytes)});
                    // }

                    // var signer_index: usize = 0;
                    // while (signer_index < num_signers) : (signer_index += 1) {
                    //     try writer.print("\n    Signer #{d}\n", .{signer_index});
                    //     const email_addr = try decoder.signerEmailAddress(self.allocator, signer_index);
                    //     defer self.allocator.free(email_addr);
                    //     try writer.print("    Email address: {s}\n", .{email_addr});
                    // }
                }

                // try writer.print("    Raw data:\n", .{});
                // try formatBinaryBlob(signature, .{
                //     .prefix = "        ",
                //     .fmt_as_str = true,
                //     .escape_str = true,
                // }, writer);
            },
            else => {
                try writer.print("    Raw data:\n", .{});
                try formatBinaryBlob(ptr[8..length2], .{
                    .prefix = "        ",
                    .fmt_as_str = true,
                    .escape_str = true,
                }, writer);
            },
        }

        try writer.print("}}\n", .{});
    }
}

fn parseReqData(buf: []const u8, reader: anytype) ![]const u8 {
    const len = try reader.readIntBig(u32);
    const pos = try reader.context.getPos();
    const data = buf[@intCast(usize, pos)..][0..len];
    try reader.context.seekBy(@intCast(i64, mem.alignForward(len, @sizeOf(u32))));
    return data;
}

fn fmtReqData(buf: []const u8, reader: anytype, writer: anytype) !void {
    const data = try parseReqData(buf, reader);
    try writer.print("\n      {s}", .{data});
}

fn getOid(buf: []const u8, pos: *usize) usize {
    var q: usize = 0;
    while (true) {
        q = q * 128 + (buf[pos.*] & ~@as(usize, 0x80));
        if (pos.* >= buf.len) break;
        if (buf[pos.*] & 0x80 == 0) {
            pos.* += 1;
            break;
        }
        pos.* += 1;
    }
    return q;
}

fn fmtCssmData(buf: []const u8, reader: anytype, writer: anytype) !void {
    const data = try parseReqData(buf, reader);

    var pos: usize = 0;

    const oid1 = getOid(data, &pos);
    const q1 = @minimum(@divFloor(oid1, 40), 2);
    try writer.print("\n      {d}.{d}", .{ q1, oid1 - q1 * 40 });

    while (pos < data.len) {
        const oid2 = getOid(data, &pos);
        try writer.print(".{d}", .{oid2});
    }

    try writer.print("  ({x})", .{std.fmt.fmtSliceHexLower(data)});
}

fn fmtReqTimestamp(buf: []const u8, reader: anytype, writer: anytype) !void {
    _ = buf;
    const ts = try reader.readIntBig(i64);
    try writer.print("\n      {d}", .{ts});
}

fn fmtReqMatch(buf: []const u8, reader: anytype, writer: anytype) !void {
    const match = @intToEnum(MatchOperation, try reader.readIntBig(u32));
    try writer.print("\n    {}", .{match});
    switch (match) {
        .match_exists, .match_absent => {},
        .match_equal,
        .match_contains,
        .match_begins_with,
        .match_ends_with,
        .match_less_than,
        .match_greater_equal,
        .match_less_equal,
        .match_greater_than,
        => try fmtReqData(buf, reader, writer),
        .match_on,
        .match_before,
        .match_after,
        .match_on_or_before,
        .match_on_or_after,
        => try fmtReqTimestamp(buf, reader, writer),
        else => try writer.writeAll("\n      unknown opcode"),
    }
}

fn fmtCsSlotConst(raw: u32) []const u8 {
    if (macho.CSSLOT_ALTERNATE_CODEDIRECTORIES <= raw and raw < macho.CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT) {
        return "CSSLOT_ALTERNATE_CODEDIRECTORIES";
    }
    return switch (raw) {
        macho.CSSLOT_CODEDIRECTORY => "CSSLOT_CODEDIRECTORY",
        macho.CSSLOT_INFOSLOT => "CSSLOT_INFOSLOT",
        macho.CSSLOT_REQUIREMENTS => "CSSLOT_REQUIREMENTS",
        macho.CSSLOT_RESOURCEDIR => "CSSLOT_RESOURCEDIR",
        macho.CSSLOT_APPLICATION => "CSSLOT_APPLICATION",
        macho.CSSLOT_ENTITLEMENTS => "CSSLOT_ENTITLEMENTS",
        macho.CSSLOT_DER_ENTITLEMENTS => "CSSLOT_DER_ENTITLEMENTS",
        macho.CSSLOT_SIGNATURESLOT => "CSSLOT_SIGNATURESLOT",
        macho.CSSLOT_IDENTIFICATIONSLOT => "CSSLOT_IDENTIFICATIONSLOT",
        else => "UNKNOWN",
    };
}

fn fmtCsMagic(raw: u32) []const u8 {
    const magic = switch (raw) {
        macho.CSMAGIC_REQUIREMENT => "CSMAGIC_REQUIREMENT",
        macho.CSMAGIC_REQUIREMENTS => "CSMAGIC_REQUIREMENTS",
        macho.CSMAGIC_CODEDIRECTORY => "CSMAGIC_CODEDIRECTORY",
        macho.CSMAGIC_BLOBWRAPPER => "CSMAGIC_BLOBWRAPPER",
        macho.CSMAGIC_EMBEDDED_ENTITLEMENTS => "CSMAGIC_EMBEDDED_ENTITLEMENTS",
        macho.CSMAGIC_EMBEDDED_DER_ENTITLEMENTS => "CSMAGIC_EMBEDDED_DER_ENTITLEMENTS",
        else => "UNKNOWN",
    };
    return magic;
}

const FmtBinaryBlobOpts = struct {
    prefix: ?[]const u8 = null,
    fmt_as_str: bool = true,
    escape_str: bool = false,
};

fn formatBinaryBlob(blob: []const u8, opts: FmtBinaryBlobOpts, writer: anytype) !void {
    // Format as 16-by-16-by-8 with two left column in hex, and right in ascii:
    // xxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx  xxxxxxxx
    var i: usize = 0;
    const step = 16;
    const pp = opts.prefix orelse "";
    var tmp_buf: [step]u8 = undefined;
    while (i < blob.len) : (i += step) {
        const end = if (blob[i..].len >= step) step else blob[i..].len;
        const padding = step - blob[i .. i + end].len;
        if (padding > 0) {
            mem.set(u8, &tmp_buf, 0);
        }
        mem.copy(u8, &tmp_buf, blob[i .. i + end]);
        try writer.print("{s}{x:<016} {x:<016}", .{
            pp, std.fmt.fmtSliceHexLower(tmp_buf[0 .. step / 2]), std.fmt.fmtSliceHexLower(tmp_buf[step / 2 .. step]),
        });
        if (opts.fmt_as_str) {
            if (opts.escape_str) {
                try writer.print("  {s}", .{std.fmt.fmtSliceEscapeLower(tmp_buf[0..step])});
            } else {
                try writer.print("  {s}", .{tmp_buf[0..step]});
            }
        }
        try writer.writeByte('\n');
    }
}

test "" {
    std.testing.refAllDecls(@This());
}

const ExprOp = enum(u32) {
    op_false,
    op_true,
    op_ident,
    op_apple_anchor,
    op_anchor_hash,
    op_info_key_value,
    op_and,
    op_or,
    op_cd_hash,
    op_not,
    op_info_key_field,
    op_cert_field,
    op_trusted_cert,
    op_trusted_certs,
    op_cert_generic,
    op_apple_generic_anchor,
    op_entitlement_field,
    op_cert_policy,
    op_named_anchor,
    op_named_code,
    op_platform,
    op_notarized,
    op_cert_field_date,
    op_legacy_dev_id,
    _,
};

const MatchOperation = enum(u32) {
    match_exists,
    match_equal,
    match_contains,
    match_begins_with,
    match_ends_with,
    match_less_than,
    match_greater_than,
    match_less_equal,
    match_greater_equal,
    match_on,
    match_before,
    match_after,
    match_on_or_before,
    match_on_or_after,
    match_absent,
    _,
};

pub const EXPR_OP_FLAG_MASK: u32 = 0xff;
pub const EXPR_OP_GENERIC_FALSE: u32 = 0x80;
pub const EXPR_OP_GENERIC_SKIP: u32 = 0x40;

pub const LEAF_CERT = 0;
pub const ROOT_CERT = -1;
