const ZachO = @This();

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const macho = std.macho;

const Allocator = std.mem.Allocator;
const ZigKit = @import("ZigKit");
const CMSDecoder = ZigKit.Security.CMSDecoder;

gpa: Allocator,
header: macho.mach_header_64,
data: []align(@alignOf(u64)) const u8,

pub fn deinit(self: *ZachO) void {
    self.gpa.free(self.data);
}

pub fn parse(gpa: Allocator, file: fs.File) !ZachO {
    const file_size = try file.getEndPos();
    const data = try file.readToEndAllocOptions(gpa, file_size, file_size, @alignOf(u64), null);
    var self = ZachO{
        .gpa = gpa,
        .header = undefined,
        .data = data,
    };

    var stream = std.io.fixedBufferStream(self.data);
    const reader = stream.reader();
    const header = try reader.readStruct(macho.mach_header_64);

    if (header.magic != macho.MH_MAGIC_64) return error.InvalidMagic;

    self.header = header;

    return self;
}

pub fn printHeader(self: ZachO, writer: anytype) !void {
    const header = self.header;

    const cputype = switch (header.cputype) {
        macho.CPU_TYPE_ARM64 => "ARM64",
        macho.CPU_TYPE_X86_64 => "X86_64",
        else => "Unknown",
    };

    const cpusubtype = switch (header.cpusubtype) {
        macho.CPU_SUBTYPE_ARM_ALL => "ARM_ALL",
        macho.CPU_SUBTYPE_X86_64_ALL => "X86_64_ALL",
        else => "Unknown",
    };

    const filetype = switch (header.filetype) {
        macho.MH_OBJECT => "MH_OBJECT",
        macho.MH_EXECUTE => "MH_EXECUTE",
        macho.MH_FVMLIB => "MH_FVMLIB",
        macho.MH_CORE => "MH_CORE",
        macho.MH_PRELOAD => "MH_PRELOAD",
        macho.MH_DYLIB => "MH_DYLIB",
        macho.MH_DYLINKER => "MH_DYLINKER",
        macho.MH_BUNDLE => "MH_BUNDLE",
        macho.MH_DYLIB_STUB => "MH_DYLIB_STUB",
        macho.MH_DSYM => "MH_DSYM",
        macho.MH_KEXT_BUNDLE => "MH_KEXT_BUNDLE",
        else => "Unknown",
    };

    const fmt = "  {s: <25} {s: <15} ({x})\n";

    try writer.print("Header\n", .{});
    try writer.print(fmt, .{ "Magic number:", "", header.magic });
    try writer.print(fmt, .{ "CPU type:", cputype, header.cputype });
    try writer.print(fmt, .{ "CPU sub-type:", cpusubtype, header.cpusubtype });
    try writer.print(fmt, .{ "File type:", filetype, header.filetype });
    try writer.print(fmt, .{ "Number of load commands:", "", header.ncmds });
    try writer.print(fmt, .{ "Size of load commands:", "", header.sizeofcmds });
    try writer.print(fmt, .{ "Flags:", "", header.flags });

    if (header.flags > 0) {
        const flags_fmt = "      {s: <37} ({x})\n";

        if (header.flags & macho.MH_NOUNDEFS != 0) try writer.print(flags_fmt, .{
            "MH_NOUNDEFS",
            macho.MH_NOUNDEFS,
        });
        if (header.flags & macho.MH_INCRLINK != 0) try writer.print(flags_fmt, .{
            "MH_INCRLINK",
            macho.MH_INCRLINK,
        });
        if (header.flags & macho.MH_DYLDLINK != 0) try writer.print(flags_fmt, .{
            "MH_DYLDLINK",
            macho.MH_DYLDLINK,
        });
        if (header.flags & macho.MH_BINDATLOAD != 0) try writer.print(flags_fmt, .{
            "MH_BINDATLOAD",
            macho.MH_BINDATLOAD,
        });
        if (header.flags & macho.MH_PREBOUND != 0) try writer.print(flags_fmt, .{
            "MH_PREBOUND",
            macho.MH_PREBOUND,
        });
        if (header.flags & macho.MH_SPLIT_SEGS != 0) try writer.print(flags_fmt, .{
            "MH_SPLIT_SEGS",
            macho.MH_SPLIT_SEGS,
        });
        if (header.flags & macho.MH_LAZY_INIT != 0) try writer.print(flags_fmt, .{
            "MH_LAZY_INIT",
            macho.MH_LAZY_INIT,
        });
        if (header.flags & macho.MH_TWOLEVEL != 0) try writer.print(flags_fmt, .{
            "MH_TWOLEVEL",
            macho.MH_TWOLEVEL,
        });
        if (header.flags & macho.MH_FORCE_FLAT != 0) try writer.print(flags_fmt, .{
            "MH_FORCE_FLAT",
            macho.MH_FORCE_FLAT,
        });
        if (header.flags & macho.MH_NOMULTIDEFS != 0) try writer.print(flags_fmt, .{
            "MH_NOMULTIDEFS",
            macho.MH_NOMULTIDEFS,
        });
        if (header.flags & macho.MH_NOFIXPREBINDING != 0) try writer.print(flags_fmt, .{
            "MH_NOFIXPREBINDING",
            macho.MH_NOFIXPREBINDING,
        });
        if (header.flags & macho.MH_PREBINDABLE != 0) try writer.print(flags_fmt, .{
            "MH_PREBINDABLE",
            macho.MH_PREBINDABLE,
        });
        if (header.flags & macho.MH_ALLMODSBOUND != 0) try writer.print(flags_fmt, .{
            "MH_ALLMODSBOUND",
            macho.MH_ALLMODSBOUND,
        });
        if (header.flags & macho.MH_SUBSECTIONS_VIA_SYMBOLS != 0) try writer.print(flags_fmt, .{
            "MH_SUBSECTIONS_VIA_SYMBOLS",
            macho.MH_SUBSECTIONS_VIA_SYMBOLS,
        });
        if (header.flags & macho.MH_CANONICAL != 0) try writer.print(flags_fmt, .{
            "MH_CANONICAL",
            macho.MH_CANONICAL,
        });
        if (header.flags & macho.MH_WEAK_DEFINES != 0) try writer.print(flags_fmt, .{
            "MH_WEAK_DEFINES",
            macho.MH_WEAK_DEFINES,
        });
        if (header.flags & macho.MH_BINDS_TO_WEAK != 0) try writer.print(flags_fmt, .{
            "MH_BINDS_TO_WEAK",
            macho.MH_BINDS_TO_WEAK,
        });
        if (header.flags & macho.MH_ALLOW_STACK_EXECUTION != 0) try writer.print(flags_fmt, .{
            "MH_ALLOW_STACK_EXECUTION",
            macho.MH_ALLOW_STACK_EXECUTION,
        });
        if (header.flags & macho.MH_ROOT_SAFE != 0) try writer.print(flags_fmt, .{
            "MH_ROOT_SAFE",
            macho.MH_ROOT_SAFE,
        });
        if (header.flags & macho.MH_SETUID_SAFE != 0) try writer.print(flags_fmt, .{
            "MH_SETUID_SAFE",
            macho.MH_SETUID_SAFE,
        });
        if (header.flags & macho.MH_NO_REEXPORTED_DYLIBS != 0) try writer.print(flags_fmt, .{
            "MH_NO_REEXPORTED_DYLIBS",
            macho.MH_NO_REEXPORTED_DYLIBS,
        });
        if (header.flags & macho.MH_PIE != 0) try writer.print(flags_fmt, .{
            "MH_PIE",
            macho.MH_PIE,
        });
        if (header.flags & macho.MH_DEAD_STRIPPABLE_DYLIB != 0) try writer.print(flags_fmt, .{
            "MH_DEAD_STRIPPABLE_DYLIB",
            macho.MH_DEAD_STRIPPABLE_DYLIB,
        });
        if (header.flags & macho.MH_HAS_TLV_DESCRIPTORS != 0) try writer.print(flags_fmt, .{
            "MH_HAS_TLV_DESCRIPTORS",
            macho.MH_HAS_TLV_DESCRIPTORS,
        });
        if (header.flags & macho.MH_NO_HEAP_EXECUTION != 0) try writer.print(flags_fmt, .{
            "MH_NO_HEAP_EXECUTION",
            macho.MH_NO_HEAP_EXECUTION,
        });
        if (header.flags & macho.MH_APP_EXTENSION_SAFE != 0) try writer.print(flags_fmt, .{
            "MH_APP_EXTENSION_SAFE",
            macho.MH_APP_EXTENSION_SAFE,
        });
        if (header.flags & macho.MH_NLIST_OUTOFSYNC_WITH_DYLDINFO != 0) try writer.print(flags_fmt, .{
            "MH_NLIST_OUTOFSYNC_WITH_DYLDINFO",
            macho.MH_NLIST_OUTOFSYNC_WITH_DYLDINFO,
        });
    }

    try writer.print(fmt, .{ "Reserved:", "", header.reserved });
    try writer.writeByte('\n');
}

pub fn printLoadCommands(self: ZachO, writer: anytype) !void {
    const fmt = "  {s: <20} {s: <20} ({x})\n";

    var it = self.getLoadCommandsIterator();
    while (it.next()) |lc| {
        try writer.print("LOAD COMMAND {d}:\n", .{it.index - 1});
        try printGenericLC(fmt, lc, writer);

        switch (lc.cmd()) {
            .SEGMENT_64 => try printSegmentLC(fmt, lc, writer),
            .DYLD_INFO_ONLY => try printDyldInfoOnlyLC(fmt, lc, writer),
            else => {},
        }

        try writer.writeByte('\n');
    }
}

fn printGenericLC(comptime fmt: []const u8, lc: macho.LoadCommandIterator.LoadCommand, writer: anytype) !void {
    try writer.print(fmt, .{ "Command:", @tagName(lc.cmd()), @enumToInt(lc.cmd()) });
    try writer.print(fmt, .{ "Command size:", "", lc.cmdsize() });
}

fn printDyldInfoOnlyLC(comptime fmt: []const u8, lc: macho.LoadCommandIterator.LoadCommand, writer: anytype) !void {
    const cmd = lc.cast(macho.dyld_info_command).?;
    try writer.print(fmt, .{ "Rebase offset:", "", cmd.rebase_off });
    try writer.print(fmt, .{ "Rebase size:", "", cmd.rebase_size });
    try writer.print(fmt, .{ "Binding offset:", "", cmd.bind_off });
    try writer.print(fmt, .{ "Binding size:", "", cmd.bind_size });
    try writer.print(fmt, .{ "Weak binding offset:", "", cmd.weak_bind_off });
    try writer.print(fmt, .{ "Weak binding offset:", "", cmd.weak_bind_size });
    try writer.print(fmt, .{ "Lazy binding size:", "", cmd.lazy_bind_off });
    try writer.print(fmt, .{ "Lazy binding size:", "", cmd.lazy_bind_size });
    try writer.print(fmt, .{ "Export offset:", "", cmd.export_off });
    try writer.print(fmt, .{ "Export size:", "", cmd.export_size });
}

fn printSegmentLC(comptime fmt: []const u8, lc: macho.LoadCommandIterator.LoadCommand, writer: anytype) !void {
    const seg = lc.cast(macho.segment_command_64).?;
    try writer.print(fmt, .{ "Segment name:", seg.segName(), std.fmt.fmtSliceHexLower(&seg.segname) });
    try writer.print(fmt, .{ "VM address:", "", seg.vmaddr });
    try writer.print(fmt, .{ "VM size:", "", seg.vmsize });
    try writer.print(fmt, .{ "File offset:", "", seg.fileoff });
    try writer.print(fmt, .{ "File size:", "", seg.filesize });

    const prot_fmt = "      {s: <37} ({x})\n";
    try writer.print(fmt, .{ "Max VM protection:", "", seg.maxprot });
    try printProtectionFlags(prot_fmt, seg.maxprot, writer);

    try writer.print(fmt, .{ "Init VM protection:", "", seg.initprot });
    try printProtectionFlags(prot_fmt, seg.initprot, writer);

    try writer.print(fmt, .{ "Number of sections:", "", seg.nsects });
    try writer.print(fmt, .{ "Flags:", "", seg.flags });

    if (seg.nsects > 0) {
        const sect_fmt = "    {s: <20} {s: <18} ({x})\n";
        try writer.writeByte('\n');
        for (lc.getSections()) |sect| {
            try writer.print("  SECTION HEADER:\n", .{});
            try printSectionHeader(sect_fmt, sect, writer);
        }
    }
}

fn printProtectionFlags(comptime fmt: []const u8, flags: macho.vm_prot_t, writer: anytype) !void {
    if (flags == macho.PROT.NONE) try writer.print(fmt, .{ "VM_PROT_NONE", macho.PROT.NONE });
    if (flags & macho.PROT.READ != 0) try writer.print(fmt, .{ "VM_PROT_READ", macho.PROT.READ });
    if (flags & macho.PROT.WRITE != 0) try writer.print(fmt, .{ "VM_PROT_WRITE", macho.PROT.WRITE });
    if (flags & macho.PROT.EXEC != 0) try writer.print(fmt, .{ "VM_PROT_EXEC", macho.PROT.EXEC });
    if (flags & macho.PROT.COPY != 0) try writer.print(fmt, .{ "VM_PROT_COPY", macho.PROT.COPY });
}

fn printSectionHeader(comptime fmt: []const u8, sect: macho.section_64, writer: anytype) !void {
    try writer.print(fmt, .{ "Section name:", sect.sectName(), std.fmt.fmtSliceHexLower(&sect.sectname) });
    try writer.print(fmt, .{ "Segment name:", sect.segName(), std.fmt.fmtSliceHexLower(&sect.segname) });
    try writer.print(fmt, .{ "Address:", "", sect.addr });
    try writer.print(fmt, .{ "Size:", "", sect.size });
    try writer.print(fmt, .{ "Offset:", "", sect.offset });
    try writer.print(fmt, .{ "Alignment:", "", std.math.powi(u32, 2, sect.@"align") catch unreachable });
    try writer.print(fmt, .{ "Relocs offset:", "", sect.reloff });
    try writer.print(fmt, .{ "Number of relocs:", "", sect.nreloc });
    try writer.print(fmt, .{ "Flags:", "", sect.flags });

    const flag_fmt = "        {s: <35} ({x})\n";
    switch (sect.@"type"()) {
        macho.S_REGULAR => try writer.print(flag_fmt, .{
            "S_REGULAR",
            macho.S_REGULAR,
        }),
        macho.S_ZEROFILL => try writer.print(flag_fmt, .{
            "S_ZEROFILL",
            macho.S_ZEROFILL,
        }),
        macho.S_CSTRING_LITERALS => try writer.print(flag_fmt, .{
            "S_CSTRING_LITERALS",
            macho.S_CSTRING_LITERALS,
        }),
        macho.S_4BYTE_LITERALS => try writer.print(flag_fmt, .{
            "S_4BYTE_LITERALS",
            macho.S_4BYTE_LITERALS,
        }),
        macho.S_8BYTE_LITERALS => try writer.print(flag_fmt, .{
            "S_8BYTE_LITERALS",
            macho.S_8BYTE_LITERALS,
        }),
        macho.S_LITERAL_POINTERS => try writer.print(flag_fmt, .{
            "S_LITERAL_POINTERS",
            macho.S_LITERAL_POINTERS,
        }),
        macho.S_NON_LAZY_SYMBOL_POINTERS => try writer.print(flag_fmt, .{
            "S_NON_LAZY_SYMBOL_POINTERS",
            macho.S_NON_LAZY_SYMBOL_POINTERS,
        }),
        macho.S_LAZY_SYMBOL_POINTERS => try writer.print(flag_fmt, .{
            "S_LAZY_SYMBOL_POINTERS",
            macho.S_LAZY_SYMBOL_POINTERS,
        }),
        macho.S_SYMBOL_STUBS => try writer.print(flag_fmt, .{
            "S_SYMBOL_STUBS",
            macho.S_SYMBOL_STUBS,
        }),
        macho.S_MOD_INIT_FUNC_POINTERS => try writer.print(flag_fmt, .{
            "S_MOD_INIT_FUNC_POINTERS",
            macho.S_MOD_INIT_FUNC_POINTERS,
        }),
        macho.S_MOD_TERM_FUNC_POINTERS => try writer.print(flag_fmt, .{
            "S_MOD_TERM_FUNC_POINTERS",
            macho.S_MOD_TERM_FUNC_POINTERS,
        }),
        macho.S_COALESCED => try writer.print(flag_fmt, .{
            "S_COALESCED",
            macho.S_COALESCED,
        }),
        macho.S_GB_ZEROFILL => try writer.print(flag_fmt, .{
            "S_GB_ZEROFILL",
            macho.S_GB_ZEROFILL,
        }),
        macho.S_INTERPOSING => try writer.print(flag_fmt, .{
            "S_INTERPOSING",
            macho.S_INTERPOSING,
        }),
        macho.S_16BYTE_LITERALS => try writer.print(flag_fmt, .{
            "S_16BYTE_LITERALS",
            macho.S_16BYTE_LITERALS,
        }),
        macho.S_DTRACE_DOF => try writer.print(flag_fmt, .{
            "S_DTRACE_DOF",
            macho.S_DTRACE_DOF,
        }),
        macho.S_THREAD_LOCAL_REGULAR => try writer.print(flag_fmt, .{
            "S_THREAD_LOCAL_REGULAR",
            macho.S_THREAD_LOCAL_REGULAR,
        }),
        macho.S_THREAD_LOCAL_ZEROFILL => try writer.print(flag_fmt, .{
            "S_THREAD_LOCAL_ZEROFILl",
            macho.S_THREAD_LOCAL_ZEROFILL,
        }),
        macho.S_THREAD_LOCAL_VARIABLE_POINTERS => try writer.print(flag_fmt, .{
            "S_THREAD_LOCAL_VARIABLE_POINTERS",
            macho.S_THREAD_LOCAL_VARIABLE_POINTERS,
        }),
        macho.S_THREAD_LOCAL_INIT_FUNCTION_POINTERS => try writer.print(flag_fmt, .{
            "S_THREAD_LOCAL_INIT_FUNCTION_POINTERS",
            macho.S_THREAD_LOCAL_INIT_FUNCTION_POINTERS,
        }),
        macho.S_INIT_FUNC_OFFSETS => try writer.print(flag_fmt, .{
            "S_INIT_FUNC_OFFSETS",
            macho.S_INIT_FUNC_OFFSETS,
        }),
        else => {},
    }
    const attrs = sect.@"attrs"();
    if (attrs > 0) {
        if (attrs & macho.S_ATTR_DEBUG != 0) try writer.print(flag_fmt, .{
            "S_ATTR_DEBUG",
            macho.S_ATTR_DEBUG,
        });
        if (attrs & macho.S_ATTR_PURE_INSTRUCTIONS != 0) try writer.print(flag_fmt, .{
            "S_ATTR_PURE_INSTRUCTIONS",
            macho.S_ATTR_PURE_INSTRUCTIONS,
        });
        if (attrs & macho.S_ATTR_NO_TOC != 0) try writer.print(flag_fmt, .{
            "S_ATTR_NO_TOC",
            macho.S_ATTR_NO_TOC,
        });
        if (attrs & macho.S_ATTR_STRIP_STATIC_SYMS != 0) try writer.print(flag_fmt, .{
            "S_ATTR_STRIP_STATIC_SYMS",
            macho.S_ATTR_STRIP_STATIC_SYMS,
        });
        if (attrs & macho.S_ATTR_NO_DEAD_STRIP != 0) try writer.print(flag_fmt, .{
            "S_ATTR_NO_DEAD_STRIP",
            macho.S_ATTR_NO_DEAD_STRIP,
        });
        if (attrs & macho.S_ATTR_LIVE_SUPPORT != 0) try writer.print(flag_fmt, .{
            "S_ATTR_LIVE_SUPPORT",
            macho.S_ATTR_LIVE_SUPPORT,
        });
        if (attrs & macho.S_ATTR_SELF_MODIFYING_CODE != 0) try writer.print(flag_fmt, .{
            "S_ATTR_SELF_MODIFYING_CODE",
            macho.S_ATTR_SELF_MODIFYING_CODE,
        });
        if (attrs & macho.S_ATTR_SOME_INSTRUCTIONS != 0) try writer.print(flag_fmt, .{
            "S_ATTR_SOME_INSTRUCTIONS",
            macho.S_ATTR_SOME_INSTRUCTIONS,
        });
        if (attrs & macho.S_ATTR_EXT_RELOC != 0) try writer.print(flag_fmt, .{
            "S_ATTR_EXT_RELOC",
            macho.S_ATTR_EXT_RELOC,
        });
        if (attrs & macho.S_ATTR_LOC_RELOC != 0) try writer.print(flag_fmt, .{
            "S_ATTR_LOC_RELOC",
            macho.S_ATTR_LOC_RELOC,
        });
    }

    if (sect.@"type"() == macho.S_SYMBOL_STUBS) {
        try writer.print(fmt, .{ "Indirect sym index:", "", sect.reserved1 });
        try writer.print(fmt, .{ "Size of stubs:", "", sect.reserved2 });
    } else if (sect.@"type"() == macho.S_NON_LAZY_SYMBOL_POINTERS) {
        try writer.print(fmt, .{ "Indirect sym index:", "", sect.reserved1 });
        try writer.print(fmt, .{ "Reserved 2:", "", sect.reserved2 });
    } else if (sect.@"type"() == macho.S_LAZY_SYMBOL_POINTERS) {
        try writer.print(fmt, .{ "Indirect sym index:", "", sect.reserved1 });
        try writer.print(fmt, .{ "Reserved 2:", "", sect.reserved2 });
    } else {
        try writer.print(fmt, .{ "Reserved 1:", "", sect.reserved1 });
        try writer.print(fmt, .{ "Reserved 2:", "", sect.reserved2 });
    }
    try writer.print(fmt, .{ "Reserved 3:", "", sect.reserved3 });
}

pub fn printDyldInfo(self: ZachO, writer: anytype) !void {
    _ = self;
    _ = writer;
    // const cmd_id = self.dyld_info_only_cmd orelse {
    //     return writer.print("LC_DYLD_INFO_ONLY load command not found\n", .{});
    // };
    // const cmd = self.load_commands.items[cmd_id].DyldInfoOnly;

    // try formatBinaryBlob(self.data.items[cmd.rebase_off..][0..cmd.rebase_size], .{}, writer);
}

pub fn printCodeSignature(self: ZachO, writer: anytype) !void {
    _ = self;
    _ = writer;
    // return if (self.code_signature_cmd) |code_sig|
    //     self.formatCodeSignatureData(self.load_commands.items[code_sig].LinkeditData, writer)
    // else
    //     writer.print("LC_CODE_SIGNATURE load command not found\n", .{});
}

// pub fn format(
//     self: ZachO,
//     comptime fmt: []const u8,
//     options: std.fmt.FormatOptions,
//     writer: anytype,
// ) !void {
//     _ = fmt;
//     _ = options;

//     try self.printHeader(writer);
//     try writer.print("\n", .{});

//     try self.printLoadCommands(writer);
//     try writer.print("\n", .{});

//     for (self.load_commands.items) |cmd| {
//         switch (cmd) {
//             .Segment => |seg| try self.formatData(seg, writer),
//             .CodeSignature => |csig| try self.formatCodeSignatureData(csig, writer),
//             else => {},
//         }
//     }
// }

// fn formatData(self: ZachO, segment_command: SegmentCommand, writer: anytype) !void {
//     const seg = &segment_command.inner;
//     const start_pos = seg.fileoff;
//     const end_pos = seg.fileoff + seg.filesize;

//     if (end_pos == start_pos) return;

//     try writer.print("{s}\n", .{seg.segname});
//     try writer.print("file = {{ {}, {} }}\n", .{ start_pos, end_pos });
//     try writer.print("address = {{ 0x{x:0<16}, 0x{x:0<16} }}\n\n", .{
//         seg.vmaddr,
//         seg.vmaddr + seg.vmsize,
//     });

//     for (segment_command.section_headers.items) |sect| {
//         const file_start = sect.offset;
//         const file_end = sect.offset + sect.size;
//         const addr_start = sect.addr;
//         const addr_end = sect.addr + sect.size;

//         try writer.print("  {s},{s}\n", .{ sect.segname, sect.sectname });
//         try writer.print("  file = {{ {}, {} }}\n", .{ file_start, file_end });
//         try writer.print("  address = {{ 0x{x:0<16}, 0x{x:0<16} }}\n\n", .{
//             addr_start,
//             addr_end,
//         });
//         try formatBinaryBlob(self.data.items[file_start..file_end], "  ", writer);
//         try writer.print("\n", .{});
//     }
// }

// fn formatCodeSignatureData(
//     self: ZachO,
//     csig: macho.linkedit_data_command,
//     writer: anytype,
// ) !void {
//     const start_pos = csig.dataoff;
//     const end_pos = csig.dataoff + csig.datasize;

//     if (end_pos == start_pos) return;

//     try writer.print("Code signature data:\n", .{});
//     try writer.print("file = {{ {}, {} }}\n\n", .{ start_pos, end_pos });

//     var data = self.data.items[start_pos..end_pos];
//     var ptr = data;
//     const magic = mem.readIntBig(u32, ptr[0..4]);
//     const length = mem.readIntBig(u32, ptr[4..8]);
//     const count = mem.readIntBig(u32, ptr[8..12]);
//     ptr = ptr[12..];

//     try writer.print("{{\n", .{});
//     try writer.print("    Magic = 0x{x}\n", .{magic});
//     try writer.print("    Length = {}\n", .{length});
//     try writer.print("    Count = {}\n", .{count});
//     try writer.print("}}\n", .{});

//     if (magic != macho.CSMAGIC_EMBEDDED_SIGNATURE) {
//         try writer.print("unknown signature type: 0x{x}\n", .{magic});
//         try formatBinaryBlob(self.data.items[start_pos..end_pos], .{}, writer);
//         return;
//     }

//     var blobs = std.ArrayList(macho.BlobIndex).init(self.allocator);
//     defer blobs.deinit();
//     try blobs.ensureTotalCapacityPrecise(count);

//     var i: usize = 0;
//     while (i < count) : (i += 1) {
//         const tt = mem.readIntBig(u32, ptr[0..4]);
//         const offset = mem.readIntBig(u32, ptr[4..8]);
//         try writer.print("{{\n    Type: {s}(0x{x})\n    Offset: {}\n}}\n", .{ fmtCsSlotConst(tt), tt, offset });
//         blobs.appendAssumeCapacity(.{
//             .@"type" = tt,
//             .offset = offset,
//         });
//         ptr = ptr[8..];
//     }

//     for (blobs.items) |blob| {
//         ptr = data[blob.offset..];
//         const magic2 = mem.readIntBig(u32, ptr[0..4]);
//         const length2 = mem.readIntBig(u32, ptr[4..8]);

//         try writer.print("{{\n", .{});
//         try writer.print("    Magic: {s}(0x{x})\n", .{ fmtCsMagic(magic2), magic2 });
//         try writer.print("    Length: {}\n", .{length2});

//         switch (magic2) {
//             macho.CSMAGIC_CODEDIRECTORY => {
//                 const version = mem.readIntBig(u32, ptr[8..12]);
//                 const flags = mem.readIntBig(u32, ptr[12..16]);
//                 const hash_off = mem.readIntBig(u32, ptr[16..20]);
//                 const ident_off = mem.readIntBig(u32, ptr[20..24]);
//                 const n_special_slots = mem.readIntBig(u32, ptr[24..28]);
//                 const n_code_slots = mem.readIntBig(u32, ptr[28..32]);
//                 const code_limit = mem.readIntBig(u32, ptr[32..36]);
//                 const hash_size = ptr[36];
//                 const page_size = std.math.pow(u16, 2, ptr[39]);
//                 const team_off = mem.readIntBig(u32, ptr[48..52]);

//                 try writer.print("    Version: 0x{x}\n", .{version});
//                 try writer.print("    Flags: 0x{x}\n", .{flags});
//                 try writer.print("    Hash offset: {}\n", .{hash_off});
//                 try writer.print("    Ident offset: {}\n", .{ident_off});
//                 try writer.print("    Number of special slots: {}\n", .{n_special_slots});
//                 try writer.print("    Number of code slots: {}\n", .{n_code_slots});
//                 try writer.print("    Code limit: {}\n", .{code_limit});
//                 try writer.print("    Hash size: {}\n", .{hash_size});
//                 try writer.print("    Hash type: {}\n", .{ptr[37]});
//                 try writer.print("    Platform: {}\n", .{ptr[38]});
//                 try writer.print("    Page size: {}\n", .{ptr[39]});
//                 try writer.print("    Reserved: {}\n", .{mem.readIntBig(u32, ptr[40..44])});

//                 switch (version) {
//                     0x20400 => {
//                         try writer.print("    Scatter offset: {}\n", .{mem.readIntBig(u32, ptr[44..48])});
//                         try writer.print("    Team offset: {}\n", .{team_off});
//                         try writer.print("    Reserved: {}\n", .{mem.readIntBig(u32, ptr[52..56])});
//                         try writer.print("    Code limit 64: {}\n", .{mem.readIntBig(u64, ptr[56..64])});
//                         try writer.print("    Offset of executable segment: {}\n", .{mem.readIntBig(u64, ptr[64..72])});
//                         try writer.print("    Limit of executable segment: {}\n", .{mem.readIntBig(u64, ptr[72..80])});
//                         try writer.print("    Executable segment flags: 0x{x}\n", .{mem.readIntBig(u64, ptr[80..88])});
//                         ptr = ptr[88..];
//                     },
//                     0x20100 => {
//                         try writer.print("    Scatter offset: {}\n", .{mem.readIntBig(u32, ptr[52..56])});
//                         ptr = ptr[56..];
//                     },
//                     else => {
//                         ptr = ptr[52..];
//                     },
//                 }

//                 const ident = mem.sliceTo(@ptrCast([*:0]const u8, ptr), 0);
//                 try writer.print("\nIdent: {s}\n", .{ident});
//                 ptr = ptr[ident.len + 1 ..];

//                 if (team_off > 0) {
//                     assert(team_off - ident_off == ident.len + 1);
//                     const team_ident = mem.sliceTo(@ptrCast([*:0]const u8, ptr), 0);
//                     try writer.print("\nTeam ident: {s}\n", .{team_ident});
//                     ptr = ptr[team_ident.len + 1 ..];
//                 }

//                 var j: isize = n_special_slots;
//                 while (j > 0) : (j -= 1) {
//                     const hash = ptr[0..hash_size];
//                     try writer.print("\nSpecial slot for {s}:\n", .{
//                         fmtCsSlotConst(@intCast(u32, if (j == 6) macho.CSSLOT_SIGNATURESLOT else j)),
//                     });
//                     try formatBinaryBlob(hash, .{
//                         .prefix = "        ",
//                         .fmt_as_str = false,
//                     }, writer);
//                     ptr = ptr[hash_size..];
//                 }

//                 var k: usize = 0;
//                 const base_addr: u64 = 0x100000000;
//                 while (k < n_code_slots) : (k += 1) {
//                     const hash = ptr[0..hash_size];
//                     try writer.print("\nCode slot (0x{x} - 0x{x}):\n", .{
//                         base_addr + k * page_size,
//                         base_addr + (k + 1) * page_size,
//                     });
//                     try formatBinaryBlob(hash, .{
//                         .prefix = "        ",
//                         .fmt_as_str = false,
//                     }, writer);
//                     ptr = ptr[hash_size..];
//                 }
//             },
//             macho.CSMAGIC_REQUIREMENTS => {
//                 const req_data = ptr[8..length2];
//                 var stream = std.io.fixedBufferStream(req_data);
//                 var reader = stream.reader();

//                 try writer.print("    Parsed data:\n", .{});

//                 var req_count = try reader.readIntBig(u32);

//                 var req_blobs = std.ArrayList(macho.BlobIndex).init(self.allocator);
//                 defer req_blobs.deinit();
//                 try req_blobs.ensureTotalCapacityPrecise(req_count);

//                 var next_req: usize = 0;
//                 while (next_req < req_count) : (next_req += 1) {
//                     const tt = try reader.readIntBig(u32);
//                     const off = try reader.readIntBig(u32);
//                     try writer.print("\n    {{\n      Type: {s}(0x{x})\n      Offset: {}\n    }}\n", .{
//                         fmtCsSlotConst(tt),
//                         tt,
//                         off,
//                     });
//                     req_blobs.appendAssumeCapacity(.{
//                         .@"type" = tt,
//                         .offset = off,
//                     });
//                 }

//                 for (req_blobs.items) |req_blob| {
//                     try stream.seekTo(req_blob.offset - 8);
//                     const req_blob_magic = try reader.readIntBig(u32);
//                     const req_blob_len = try reader.readIntBig(u32);

//                     try writer.writeAll("\n    {\n");
//                     try writer.print("        Magic: {s}(0x{x})\n", .{
//                         fmtCsMagic(req_blob_magic),
//                         req_blob_magic,
//                     });
//                     try writer.print("        Length: {}\n", .{req_blob_len});

//                     while (reader.context.pos < req_blob_len) {
//                         const next = try reader.readIntBig(u32);
//                         const op = @intToEnum(ExprOp, next);

//                         try writer.print("  {}", .{op});

//                         switch (op) {
//                             .op_false,
//                             .op_true,
//                             .op_and,
//                             .op_or,
//                             .op_not,
//                             .op_apple_anchor,
//                             .op_anchor_hash,
//                             .op_info_key_value,
//                             .op_trusted_cert,
//                             .op_trusted_certs,
//                             .op_apple_generic_anchor,
//                             .op_entitlement_field,
//                             .op_cert_policy,
//                             .op_named_anchor,
//                             .op_named_code,
//                             .op_notarized,
//                             .op_cert_field_date,
//                             .op_legacy_dev_id,
//                             => {},
//                             .op_ident => try fmtReqData(req_data, reader, writer),
//                             .op_cert_generic => {
//                                 const slot = try reader.readIntBig(i32);
//                                 switch (slot) {
//                                     LEAF_CERT => try writer.writeAll("\n    leaf"),
//                                     ROOT_CERT => try writer.writeAll("\n    root"),
//                                     else => try writer.print("\n    slot {d}", .{slot}),
//                                 }
//                                 try fmtCssmData(req_data, reader, writer);
//                                 try fmtReqMatch(req_data, reader, writer);
//                             },
//                             .op_cert_field => {
//                                 const slot = try reader.readIntBig(i32);
//                                 switch (slot) {
//                                     LEAF_CERT => try writer.writeAll("\n    leaf"),
//                                     ROOT_CERT => try writer.writeAll("\n    root"),
//                                     else => try writer.print("\n    slot {d}", .{slot}),
//                                 }
//                                 try fmtReqData(req_data, reader, writer);
//                                 try fmtReqMatch(req_data, reader, writer);
//                             },
//                             .op_platform => {
//                                 const platform = try reader.readIntBig(i32);
//                                 try writer.print("\n    {x}", .{
//                                     std.fmt.fmtSliceHexLower(mem.asBytes(&platform)),
//                                 });
//                             },
//                             else => {
//                                 if (next & EXPR_OP_GENERIC_FALSE != 0) {
//                                     try writer.writeAll("\n    generic false");
//                                 } else if (next & EXPR_OP_GENERIC_SKIP != 0) {
//                                     try writer.writeAll("\n    generic skip");
//                                 } else {
//                                     try writer.writeAll("\n    unknown opcode");
//                                 }
//                             },
//                         }

//                         try writer.writeByte('\n');
//                     }
//                     try writer.writeAll("\n    }");
//                 }

//                 try writer.print("\n    Raw data:\n", .{});
//                 try formatBinaryBlob(ptr[8..length2], .{
//                     .prefix = "        ",
//                     .fmt_as_str = true,
//                     .escape_str = true,
//                 }, writer);
//             },
//             macho.CSMAGIC_BLOBWRAPPER => {
//                 const signature = ptr[8..length2];

//                 if (comptime builtin.target.isDarwin()) {
//                     const cd: []const u8 = blk: {
//                         const cd_blob = blobs.items[0];
//                         const cd_header = data[cd_blob.offset..][0..8];
//                         const cd_length = mem.readIntBig(u32, cd_header[4..8]);
//                         break :blk data[cd_blob.offset..][0..cd_length];
//                     };

//                     const decoder = try CMSDecoder.create();
//                     defer decoder.release();
//                     try decoder.updateMessage(signature);
//                     try decoder.setDetachedContent(cd);
//                     try decoder.finalizeMessage();

//                     const num_signers = try decoder.getNumSigners();
//                     try writer.print("    Number of signers: {d}\n", .{num_signers});

//                     const status = try decoder.getSignerStatus(0);
//                     try writer.print("    Signer status: {}\n", .{status});
//                 } else {
//                     try writer.print("\n\n    !! Validating signatures available only on macOS !! \n\n", .{});
//                     try writer.print("    Raw data:\n", .{});
//                     try formatBinaryBlob(signature, .{
//                         .prefix = "        ",
//                         .fmt_as_str = true,
//                         .escape_str = true,
//                     }, writer);
//                 }
//             },
//             else => {
//                 try writer.print("    Raw data:\n", .{});
//                 try formatBinaryBlob(ptr[8..length2], .{
//                     .prefix = "        ",
//                     .fmt_as_str = true,
//                     .escape_str = true,
//                 }, writer);
//             },
//         }

//         try writer.print("}}\n", .{});
//     }
// }

// fn parseReqData(buf: []const u8, reader: anytype) ![]const u8 {
//     const len = try reader.readIntBig(u32);
//     const pos = try reader.context.getPos();
//     const data = buf[@intCast(usize, pos)..][0..len];
//     try reader.context.seekBy(@intCast(i64, mem.alignForward(len, @sizeOf(u32))));
//     return data;
// }

// fn fmtReqData(buf: []const u8, reader: anytype, writer: anytype) !void {
//     const data = try parseReqData(buf, reader);
//     try writer.print("\n      {s}", .{data});
// }

// fn getOid(buf: []const u8, pos: *usize) usize {
//     var q: usize = 0;
//     while (true) {
//         q = q * 128 + (buf[pos.*] & ~@as(usize, 0x80));
//         if (pos.* >= buf.len) break;
//         if (buf[pos.*] & 0x80 == 0) {
//             pos.* += 1;
//             break;
//         }
//         pos.* += 1;
//     }
//     return q;
// }

// fn fmtCssmData(buf: []const u8, reader: anytype, writer: anytype) !void {
//     const data = try parseReqData(buf, reader);

//     var pos: usize = 0;

//     const oid1 = getOid(data, &pos);
//     const q1 = @minimum(@divFloor(oid1, 40), 2);
//     try writer.print("\n      {d}.{d}", .{ q1, oid1 - q1 * 40 });

//     while (pos < data.len) {
//         const oid2 = getOid(data, &pos);
//         try writer.print(".{d}", .{oid2});
//     }

//     try writer.print("  ({x})", .{std.fmt.fmtSliceHexLower(data)});
// }

// fn fmtReqTimestamp(buf: []const u8, reader: anytype, writer: anytype) !void {
//     _ = buf;
//     const ts = try reader.readIntBig(i64);
//     try writer.print("\n      {d}", .{ts});
// }

// fn fmtReqMatch(buf: []const u8, reader: anytype, writer: anytype) !void {
//     const match = @intToEnum(MatchOperation, try reader.readIntBig(u32));
//     try writer.print("\n    {}", .{match});
//     switch (match) {
//         .match_exists, .match_absent => {},
//         .match_equal,
//         .match_contains,
//         .match_begins_with,
//         .match_ends_with,
//         .match_less_than,
//         .match_greater_equal,
//         .match_less_equal,
//         .match_greater_than,
//         => try fmtReqData(buf, reader, writer),
//         .match_on,
//         .match_before,
//         .match_after,
//         .match_on_or_before,
//         .match_on_or_after,
//         => try fmtReqTimestamp(buf, reader, writer),
//         else => try writer.writeAll("\n      unknown opcode"),
//     }
// }

// fn fmtCsSlotConst(raw: u32) []const u8 {
//     if (macho.CSSLOT_ALTERNATE_CODEDIRECTORIES <= raw and raw < macho.CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT) {
//         return "CSSLOT_ALTERNATE_CODEDIRECTORIES";
//     }
//     return switch (raw) {
//         macho.CSSLOT_CODEDIRECTORY => "CSSLOT_CODEDIRECTORY",
//         macho.CSSLOT_INFOSLOT => "CSSLOT_INFOSLOT",
//         macho.CSSLOT_REQUIREMENTS => "CSSLOT_REQUIREMENTS",
//         macho.CSSLOT_RESOURCEDIR => "CSSLOT_RESOURCEDIR",
//         macho.CSSLOT_APPLICATION => "CSSLOT_APPLICATION",
//         macho.CSSLOT_ENTITLEMENTS => "CSSLOT_ENTITLEMENTS",
//         macho.CSSLOT_DER_ENTITLEMENTS => "CSSLOT_DER_ENTITLEMENTS",
//         macho.CSSLOT_SIGNATURESLOT => "CSSLOT_SIGNATURESLOT",
//         macho.CSSLOT_IDENTIFICATIONSLOT => "CSSLOT_IDENTIFICATIONSLOT",
//         else => "UNKNOWN",
//     };
// }

// fn fmtCsMagic(raw: u32) []const u8 {
//     const magic = switch (raw) {
//         macho.CSMAGIC_REQUIREMENT => "CSMAGIC_REQUIREMENT",
//         macho.CSMAGIC_REQUIREMENTS => "CSMAGIC_REQUIREMENTS",
//         macho.CSMAGIC_CODEDIRECTORY => "CSMAGIC_CODEDIRECTORY",
//         macho.CSMAGIC_BLOBWRAPPER => "CSMAGIC_BLOBWRAPPER",
//         macho.CSMAGIC_EMBEDDED_ENTITLEMENTS => "CSMAGIC_EMBEDDED_ENTITLEMENTS",
//         macho.CSMAGIC_EMBEDDED_DER_ENTITLEMENTS => "CSMAGIC_EMBEDDED_DER_ENTITLEMENTS",
//         else => "UNKNOWN",
//     };
//     return magic;
// }

// const FmtBinaryBlobOpts = struct {
//     prefix: ?[]const u8 = null,
//     fmt_as_str: bool = true,
//     escape_str: bool = false,
// };

// fn formatBinaryBlob(blob: []const u8, opts: FmtBinaryBlobOpts, writer: anytype) !void {
//     // Format as 16-by-16-by-8 with two left column in hex, and right in ascii:
//     // xxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx  xxxxxxxx
//     var i: usize = 0;
//     const step = 16;
//     const pp = opts.prefix orelse "";
//     var tmp_buf: [step]u8 = undefined;
//     while (i < blob.len) : (i += step) {
//         const end = if (blob[i..].len >= step) step else blob[i..].len;
//         const padding = step - blob[i .. i + end].len;
//         if (padding > 0) {
//             mem.set(u8, &tmp_buf, 0);
//         }
//         mem.copy(u8, &tmp_buf, blob[i .. i + end]);
//         try writer.print("{s}{x:<016} {x:<016}", .{
//             pp, std.fmt.fmtSliceHexLower(tmp_buf[0 .. step / 2]), std.fmt.fmtSliceHexLower(tmp_buf[step / 2 .. step]),
//         });
//         if (opts.fmt_as_str) {
//             if (opts.escape_str) {
//                 try writer.print("  {s}", .{std.fmt.fmtSliceEscapeLower(tmp_buf[0..step])});
//             } else {
//                 try writer.print("  {s}", .{tmp_buf[0..step]});
//             }
//         }
//         try writer.writeByte('\n');
//     }
// }

// test "" {
//     std.testing.refAllDecls(@This());
// }

// const ExprOp = enum(u32) {
//     op_false,
//     op_true,
//     op_ident,
//     op_apple_anchor,
//     op_anchor_hash,
//     op_info_key_value,
//     op_and,
//     op_or,
//     op_cd_hash,
//     op_not,
//     op_info_key_field,
//     op_cert_field,
//     op_trusted_cert,
//     op_trusted_certs,
//     op_cert_generic,
//     op_apple_generic_anchor,
//     op_entitlement_field,
//     op_cert_policy,
//     op_named_anchor,
//     op_named_code,
//     op_platform,
//     op_notarized,
//     op_cert_field_date,
//     op_legacy_dev_id,
//     _,
// };

// const MatchOperation = enum(u32) {
//     match_exists,
//     match_equal,
//     match_contains,
//     match_begins_with,
//     match_ends_with,
//     match_less_than,
//     match_greater_than,
//     match_less_equal,
//     match_greater_equal,
//     match_on,
//     match_before,
//     match_after,
//     match_on_or_before,
//     match_on_or_after,
//     match_absent,
//     _,
// };

// pub const EXPR_OP_FLAG_MASK: u32 = 0xff;
// pub const EXPR_OP_GENERIC_FALSE: u32 = 0x80;
// pub const EXPR_OP_GENERIC_SKIP: u32 = 0x40;

// pub const LEAF_CERT = 0;
// pub const ROOT_CERT = -1;

fn getLoadCommandsIterator(self: ZachO) macho.LoadCommandIterator {
    const data = self.data[@sizeOf(macho.mach_header_64)..][0..self.header.sizeofcmds];
    return .{
        .ncmds = self.header.ncmds,
        .buffer = data,
    };
}
