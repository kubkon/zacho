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

symtab_lc: ?macho.symtab_command = null,
symtab: []macho.nlist_64 = undefined,
source_symtab_lookup: []u32 = undefined,

dyld_info_only_lc: ?macho.dyld_info_command = null,

verbose: bool,

pub fn deinit(self: *ZachO) void {
    self.gpa.free(self.data);
    if (self.symtab_lc) |_| {
        self.gpa.free(self.symtab);
        self.gpa.free(self.source_symtab_lookup);
    }
}

pub fn parse(gpa: Allocator, file: fs.File, verbose: bool) !ZachO {
    const file_size = try file.getEndPos();
    const data = try file.readToEndAllocOptions(gpa, file_size, file_size, @alignOf(u64), null);
    var self = ZachO{
        .gpa = gpa,
        .header = undefined,
        .data = data,
        .verbose = verbose,
    };

    var stream = std.io.fixedBufferStream(self.data);
    const reader = stream.reader();
    const header = try reader.readStruct(macho.mach_header_64);

    if (header.magic != macho.MH_MAGIC_64) return error.InvalidMagic;

    self.header = header;

    var it = self.getLoadCommandsIterator();
    while (it.next()) |lc| switch (lc.cmd()) {
        .SYMTAB => {
            self.symtab_lc = lc.cast(macho.symtab_command).?;

            const symtab = self.getSymbols();
            self.symtab = try self.gpa.alloc(macho.nlist_64, symtab.len);
            self.source_symtab_lookup = try self.gpa.alloc(u32, symtab.len);

            var sorted_all_syms = try std.ArrayList(SymbolAtIndex).initCapacity(self.gpa, symtab.len);
            defer sorted_all_syms.deinit();

            for (symtab) |_, index| {
                sorted_all_syms.appendAssumeCapacity(.{ .index = @intCast(u32, index) });
            }

            const ctx = SymbolAtIndex.Context{
                .symtab = symtab,
                .strtab = self.data[self.symtab_lc.?.stroff..][0..self.symtab_lc.?.strsize],
            };

            std.sort.sort(SymbolAtIndex, sorted_all_syms.items, ctx, SymbolAtIndex.lessThan);

            for (sorted_all_syms.items) |sym_id, i| {
                const sym = sym_id.getSymbol(ctx);
                self.symtab[i] = sym;
                self.source_symtab_lookup[i] = sym_id.index;
            }
        },
        .DYLD_INFO_ONLY => self.dyld_info_only_lc = lc.cast(macho.dyld_info_command).?,
        else => {},
    };

    return self;
}

const SymbolAtIndex = struct {
    index: u32,

    const Context = struct {
        symtab: []align(1) const macho.nlist_64,
        strtab: []const u8,
    };

    fn getSymbol(self: SymbolAtIndex, ctx: Context) macho.nlist_64 {
        return ctx.symtab[self.index];
    }

    fn getSymbolName(self: SymbolAtIndex, ctx: Context) []const u8 {
        const off = self.getSymbol(ctx).n_strx;
        return mem.sliceTo(@ptrCast([*:0]const u8, ctx.strtab.ptr + off), 0);
    }

    /// Performs lexicographic-like check.
    /// * lhs and rhs defined
    ///   * if lhs == rhs
    ///     * if lhs.n_sect == rhs.n_sect
    ///       * ext < weak < local < temp
    ///     * lhs.n_sect < rhs.n_sect
    ///   * lhs < rhs
    /// * !rhs is undefined
    fn lessThan(ctx: Context, lhs_index: SymbolAtIndex, rhs_index: SymbolAtIndex) bool {
        const lhs = lhs_index.getSymbol(ctx);
        const rhs = rhs_index.getSymbol(ctx);
        if (lhs.sect() and rhs.sect()) {
            if (lhs.n_value == rhs.n_value) {
                if (lhs.n_sect == rhs.n_sect) {
                    if (lhs.ext() and rhs.ext()) {
                        if ((lhs.pext() or lhs.weakDef()) and (rhs.pext() or rhs.weakDef())) {
                            return false;
                        } else return rhs.pext() or rhs.weakDef();
                    } else {
                        const lhs_name = lhs_index.getSymbolName(ctx);
                        const lhs_temp = mem.startsWith(u8, lhs_name, "l") or mem.startsWith(u8, lhs_name, "L");
                        const rhs_name = rhs_index.getSymbolName(ctx);
                        const rhs_temp = mem.startsWith(u8, rhs_name, "l") or mem.startsWith(u8, rhs_name, "L");
                        if (lhs_temp and rhs_temp) {
                            return false;
                        } else return rhs_temp;
                    }
                } else return lhs.n_sect < rhs.n_sect;
            } else return lhs.n_value < rhs.n_value;
        } else if (lhs.undf() and rhs.undf()) {
            return false;
        } else return rhs.undf();
    }

    fn lessThanByNStrx(ctx: Context, lhs: SymbolAtIndex, rhs: SymbolAtIndex) bool {
        return lhs.getSymbol(ctx).n_strx < rhs.getSymbol(ctx).n_strx;
    }
};

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

    const fmt = struct {
        pub fn fmt(comptime specifier: []const u8) []const u8 {
            return "  {s: <25} {" ++ specifier ++ ": >15}\n";
        }
    };

    try writer.print("Header\n", .{});
    try writer.print(fmt.fmt("x"), .{ "Magic number:", header.magic });
    try writer.print(fmt.fmt("s"), .{ "CPU type:", cputype });
    try writer.print(fmt.fmt("s"), .{ "CPU sub-type:", cpusubtype });
    try writer.print(fmt.fmt("s"), .{ "File type:", filetype });
    try writer.print(fmt.fmt("x"), .{ "Number of load commands:", header.ncmds });
    try writer.print(fmt.fmt("x"), .{ "Size of load commands:", header.sizeofcmds });
    try writer.print(fmt.fmt("x"), .{ "Flags:", header.flags });

    if (header.flags > 0) {
        const flags_fmt = "      {s: <37}\n";

        if (header.flags & macho.MH_NOUNDEFS != 0) try writer.print(flags_fmt, .{"MH_NOUNDEFS"});
        if (header.flags & macho.MH_INCRLINK != 0) try writer.print(flags_fmt, .{"MH_INCRLINK"});
        if (header.flags & macho.MH_DYLDLINK != 0) try writer.print(flags_fmt, .{"MH_DYLDLINK"});
        if (header.flags & macho.MH_BINDATLOAD != 0) try writer.print(flags_fmt, .{"MH_BINDATLOAD"});
        if (header.flags & macho.MH_PREBOUND != 0) try writer.print(flags_fmt, .{"MH_PREBOUND"});
        if (header.flags & macho.MH_SPLIT_SEGS != 0) try writer.print(flags_fmt, .{"MH_SPLIT_SEGS"});
        if (header.flags & macho.MH_LAZY_INIT != 0) try writer.print(flags_fmt, .{"MH_LAZY_INIT"});
        if (header.flags & macho.MH_TWOLEVEL != 0) try writer.print(flags_fmt, .{"MH_TWOLEVEL"});
        if (header.flags & macho.MH_FORCE_FLAT != 0) try writer.print(flags_fmt, .{"MH_FORCE_FLAT"});
        if (header.flags & macho.MH_NOMULTIDEFS != 0) try writer.print(flags_fmt, .{"MH_NOMULTIDEFS"});
        if (header.flags & macho.MH_NOFIXPREBINDING != 0) try writer.print(flags_fmt, .{"MH_NOFIXPREBINDING"});
        if (header.flags & macho.MH_PREBINDABLE != 0) try writer.print(flags_fmt, .{"MH_PREBINDABLE"});
        if (header.flags & macho.MH_ALLMODSBOUND != 0) try writer.print(flags_fmt, .{"MH_ALLMODSBOUND"});
        if (header.flags & macho.MH_SUBSECTIONS_VIA_SYMBOLS != 0) try writer.print(flags_fmt, .{"MH_SUBSECTIONS_VIA_SYMBOLS"});
        if (header.flags & macho.MH_CANONICAL != 0) try writer.print(flags_fmt, .{"MH_CANONICAL"});
        if (header.flags & macho.MH_WEAK_DEFINES != 0) try writer.print(flags_fmt, .{"MH_WEAK_DEFINES"});
        if (header.flags & macho.MH_BINDS_TO_WEAK != 0) try writer.print(flags_fmt, .{"MH_BINDS_TO_WEAK"});
        if (header.flags & macho.MH_ALLOW_STACK_EXECUTION != 0) try writer.print(flags_fmt, .{"MH_ALLOW_STACK_EXECUTION"});
        if (header.flags & macho.MH_ROOT_SAFE != 0) try writer.print(flags_fmt, .{"MH_ROOT_SAFE"});
        if (header.flags & macho.MH_SETUID_SAFE != 0) try writer.print(flags_fmt, .{"MH_SETUID_SAFE"});
        if (header.flags & macho.MH_NO_REEXPORTED_DYLIBS != 0) try writer.print(flags_fmt, .{"MH_NO_REEXPORTED_DYLIBS"});
        if (header.flags & macho.MH_PIE != 0) try writer.print(flags_fmt, .{"MH_PIE"});
        if (header.flags & macho.MH_DEAD_STRIPPABLE_DYLIB != 0) try writer.print(flags_fmt, .{"MH_DEAD_STRIPPABLE_DYLIB"});
        if (header.flags & macho.MH_HAS_TLV_DESCRIPTORS != 0) try writer.print(flags_fmt, .{"MH_HAS_TLV_DESCRIPTORS"});
        if (header.flags & macho.MH_NO_HEAP_EXECUTION != 0) try writer.print(flags_fmt, .{"MH_NO_HEAP_EXECUTION"});
        if (header.flags & macho.MH_APP_EXTENSION_SAFE != 0) try writer.print(flags_fmt, .{"MH_APP_EXTENSION_SAFE"});
        if (header.flags & macho.MH_NLIST_OUTOFSYNC_WITH_DYLDINFO != 0) try writer.print(flags_fmt, .{"MH_NLIST_OUTOFSYNC_WITH_DYLDINFO"});
    }

    try writer.print(fmt.fmt("x"), .{ "Reserved:", header.reserved });
    try writer.writeByte('\n');
}

pub fn printLoadCommands(self: ZachO, writer: anytype) !void {
    const fmt = struct {
        pub fn fmt(comptime specifier: []const u8) []const u8 {
            return "  {s: <20} {" ++ specifier ++ ": >30}\n";
        }
    };

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

fn printGenericLC(f: anytype, lc: macho.LoadCommandIterator.LoadCommand, writer: anytype) !void {
    try writer.print(f.fmt("s"), .{ "Command:", @tagName(lc.cmd()) });
    try writer.print(f.fmt("x"), .{ "Command size:", lc.cmdsize() });
}

fn printDyldInfoOnlyLC(f: anytype, lc: macho.LoadCommandIterator.LoadCommand, writer: anytype) !void {
    const cmd = lc.cast(macho.dyld_info_command).?;
    try writer.print(f.fmt("x"), .{ "Rebase offset:", cmd.rebase_off });
    try writer.print(f.fmt("x"), .{ "Rebase size:", cmd.rebase_size });
    try writer.print(f.fmt("x"), .{ "Binding offset:", cmd.bind_off });
    try writer.print(f.fmt("x"), .{ "Binding size:", cmd.bind_size });
    try writer.print(f.fmt("x"), .{ "Weak binding offset:", cmd.weak_bind_off });
    try writer.print(f.fmt("x"), .{ "Weak binding offset:", cmd.weak_bind_size });
    try writer.print(f.fmt("x"), .{ "Lazy binding size:", cmd.lazy_bind_off });
    try writer.print(f.fmt("x"), .{ "Lazy binding size:", cmd.lazy_bind_size });
    try writer.print(f.fmt("x"), .{ "Export offset:", cmd.export_off });
    try writer.print(f.fmt("x"), .{ "Export size:", cmd.export_size });
}

fn printSegmentLC(f: anytype, lc: macho.LoadCommandIterator.LoadCommand, writer: anytype) !void {
    const seg = lc.cast(macho.segment_command_64).?;
    try writer.print(f.fmt("s"), .{ "Segment name:", seg.segName() });
    try writer.print(f.fmt("x"), .{ "VM address:", seg.vmaddr });
    try writer.print(f.fmt("x"), .{ "VM size:", seg.vmsize });
    try writer.print(f.fmt("x"), .{ "File offset:", seg.fileoff });
    try writer.print(f.fmt("x"), .{ "File size:", seg.filesize });

    const prot_fmt = "      {s: <37}\n";
    try writer.print(f.fmt("x"), .{ "Max VM protection:", seg.maxprot });
    try printProtectionFlags(prot_fmt, seg.maxprot, writer);

    try writer.print(f.fmt("x"), .{ "Init VM protection:", seg.initprot });
    try printProtectionFlags(prot_fmt, seg.initprot, writer);

    try writer.print(f.fmt("x"), .{ "Number of sections:", seg.nsects });
    try writer.print(f.fmt("x"), .{ "Flags:", seg.flags });

    if (seg.nsects > 0) {
        const sect_fmt = struct {
            pub fn fmt(comptime specifier: []const u8) []const u8 {
                return "    {s: <20} {" ++ specifier ++ ": >28}\n";
            }
        };
        try writer.writeByte('\n');
        for (lc.getSections()) |sect| {
            try writer.print("  SECTION HEADER:\n", .{});
            try printSectionHeader(sect_fmt, sect, writer);
        }
    }
}

fn printProtectionFlags(comptime f: []const u8, flags: macho.vm_prot_t, writer: anytype) !void {
    if (flags == macho.PROT.NONE) try writer.print(f, .{"VM_PROT_NONE"});
    if (flags & macho.PROT.READ != 0) try writer.print(f, .{"VM_PROT_READ"});
    if (flags & macho.PROT.WRITE != 0) try writer.print(f, .{"VM_PROT_WRITE"});
    if (flags & macho.PROT.EXEC != 0) try writer.print(f, .{"VM_PROT_EXEC"});
    if (flags & macho.PROT.COPY != 0) try writer.print(f, .{"VM_PROT_COPY"});
}

fn printSectionHeader(f: anytype, sect: macho.section_64, writer: anytype) !void {
    try writer.print(f.fmt("s"), .{ "Section name:", sect.sectName() });
    try writer.print(f.fmt("s"), .{ "Segment name:", sect.segName() });
    try writer.print(f.fmt("x"), .{ "Address:", sect.addr });
    try writer.print(f.fmt("x"), .{ "Size:", sect.size });
    try writer.print(f.fmt("x"), .{ "Offset:", sect.offset });
    try writer.print(f.fmt("x"), .{ "Alignment:", std.math.powi(u32, 2, sect.@"align") catch unreachable });
    try writer.print(f.fmt("x"), .{ "Relocs offset:", sect.reloff });
    try writer.print(f.fmt("x"), .{ "Number of relocs:", sect.nreloc });
    try writer.print(f.fmt("x"), .{ "Flags:", sect.flags });

    const flag_fmt = "        {s: <35}\n";
    switch (sect.type()) {
        macho.S_REGULAR => try writer.print(flag_fmt, .{"S_REGULAR"}),
        macho.S_ZEROFILL => try writer.print(flag_fmt, .{"S_ZEROFILL"}),
        macho.S_CSTRING_LITERALS => try writer.print(flag_fmt, .{"S_CSTRING_LITERALS"}),
        macho.S_4BYTE_LITERALS => try writer.print(flag_fmt, .{"S_4BYTE_LITERALS"}),
        macho.S_8BYTE_LITERALS => try writer.print(flag_fmt, .{"S_8BYTE_LITERALS"}),
        macho.S_LITERAL_POINTERS => try writer.print(flag_fmt, .{"S_LITERAL_POINTERS"}),
        macho.S_NON_LAZY_SYMBOL_POINTERS => try writer.print(flag_fmt, .{"S_NON_LAZY_SYMBOL_POINTERS"}),
        macho.S_LAZY_SYMBOL_POINTERS => try writer.print(flag_fmt, .{"S_LAZY_SYMBOL_POINTERS"}),
        macho.S_SYMBOL_STUBS => try writer.print(flag_fmt, .{"S_SYMBOL_STUBS"}),
        macho.S_MOD_INIT_FUNC_POINTERS => try writer.print(flag_fmt, .{"S_MOD_INIT_FUNC_POINTERS"}),
        macho.S_MOD_TERM_FUNC_POINTERS => try writer.print(flag_fmt, .{"S_MOD_TERM_FUNC_POINTERS"}),
        macho.S_COALESCED => try writer.print(flag_fmt, .{"S_COALESCED"}),
        macho.S_GB_ZEROFILL => try writer.print(flag_fmt, .{"S_GB_ZEROFILL"}),
        macho.S_INTERPOSING => try writer.print(flag_fmt, .{"S_INTERPOSING"}),
        macho.S_16BYTE_LITERALS => try writer.print(flag_fmt, .{"S_16BYTE_LITERALS"}),
        macho.S_DTRACE_DOF => try writer.print(flag_fmt, .{"S_DTRACE_DOF"}),
        macho.S_THREAD_LOCAL_REGULAR => try writer.print(flag_fmt, .{"S_THREAD_LOCAL_REGULAR"}),
        macho.S_THREAD_LOCAL_ZEROFILL => try writer.print(flag_fmt, .{"S_THREAD_LOCAL_ZEROFILl"}),
        macho.S_THREAD_LOCAL_VARIABLE_POINTERS => try writer.print(flag_fmt, .{"S_THREAD_LOCAL_VARIABLE_POINTERS"}),
        macho.S_THREAD_LOCAL_INIT_FUNCTION_POINTERS => try writer.print(flag_fmt, .{"S_THREAD_LOCAL_INIT_FUNCTION_POINTERS"}),
        macho.S_INIT_FUNC_OFFSETS => try writer.print(flag_fmt, .{"S_INIT_FUNC_OFFSETS"}),
        else => {},
    }
    const attrs = sect.attrs();
    if (attrs > 0) {
        if (attrs & macho.S_ATTR_DEBUG != 0) try writer.print(flag_fmt, .{"S_ATTR_DEBUG"});
        if (attrs & macho.S_ATTR_PURE_INSTRUCTIONS != 0) try writer.print(flag_fmt, .{"S_ATTR_PURE_INSTRUCTIONS"});
        if (attrs & macho.S_ATTR_NO_TOC != 0) try writer.print(flag_fmt, .{"S_ATTR_NO_TOC"});
        if (attrs & macho.S_ATTR_STRIP_STATIC_SYMS != 0) try writer.print(flag_fmt, .{"S_ATTR_STRIP_STATIC_SYMS"});
        if (attrs & macho.S_ATTR_NO_DEAD_STRIP != 0) try writer.print(flag_fmt, .{"S_ATTR_NO_DEAD_STRIP"});
        if (attrs & macho.S_ATTR_LIVE_SUPPORT != 0) try writer.print(flag_fmt, .{"S_ATTR_LIVE_SUPPORT"});
        if (attrs & macho.S_ATTR_SELF_MODIFYING_CODE != 0) try writer.print(flag_fmt, .{"S_ATTR_SELF_MODIFYING_CODE"});
        if (attrs & macho.S_ATTR_SOME_INSTRUCTIONS != 0) try writer.print(flag_fmt, .{"S_ATTR_SOME_INSTRUCTIONS"});
        if (attrs & macho.S_ATTR_EXT_RELOC != 0) try writer.print(flag_fmt, .{"S_ATTR_EXT_RELOC"});
        if (attrs & macho.S_ATTR_LOC_RELOC != 0) try writer.print(flag_fmt, .{"S_ATTR_LOC_RELOC"});
    }

    if (sect.type() == macho.S_SYMBOL_STUBS) {
        try writer.print(f.fmt("x"), .{ "Indirect sym index:", sect.reserved1 });
        try writer.print(f.fmt("x"), .{ "Size of stubs:", sect.reserved2 });
    } else if (sect.type() == macho.S_NON_LAZY_SYMBOL_POINTERS) {
        try writer.print(f.fmt("x"), .{ "Indirect sym index:", sect.reserved1 });
        try writer.print(f.fmt("x"), .{ "Reserved 2:", sect.reserved2 });
    } else if (sect.type() == macho.S_LAZY_SYMBOL_POINTERS) {
        try writer.print(f.fmt("x"), .{ "Indirect sym index:", sect.reserved1 });
        try writer.print(f.fmt("x"), .{ "Reserved 2:", sect.reserved2 });
    } else {
        try writer.print(f.fmt("x"), .{ "Reserved 1:", sect.reserved1 });
        try writer.print(f.fmt("x"), .{ "Reserved 2:", sect.reserved2 });
    }
    try writer.print(f.fmt("x"), .{ "Reserved 3:", sect.reserved3 });
}

pub fn printDyldInfo(self: ZachO, writer: anytype) !void {
    const lc = self.dyld_info_only_lc orelse {
        return writer.writeAll("LC_DYLD_INFO_ONLY load command not found\n");
    };

    try writer.writeAll("REBASE INFO:\n");
    const rebase_data = self.data[lc.rebase_off..][0..lc.rebase_size];
    try self.parseAndPrintRebaseInfo(rebase_data, writer);
}

fn parseAndPrintRebaseInfo(self: ZachO, data: []const u8, writer: anytype) !void {
    var stream = std.io.fixedBufferStream(data);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    var segments = std.ArrayList(macho.segment_command_64).init(self.gpa);
    defer segments.deinit();
    var it = self.getLoadCommandsIterator();
    while (it.next()) |lc| switch (lc.cmd()) {
        .SEGMENT_64 => try segments.append(lc.cast(macho.segment_command_64).?),
        else => {},
    };

    const fmt_value = "    {x: <8} {s: <50} {s: >20} ({x})\n";
    const fmt_ptr = "      {x: >8} => {x: <8}\n";

    var seg_id: ?u8 = null;
    var seg_offset: ?u64 = null;
    while (true) {
        const byte = reader.readByte() catch break;
        const opc = byte & macho.REBASE_OPCODE_MASK;
        const imm = byte & macho.REBASE_IMMEDIATE_MASK;
        switch (opc) {
            macho.REBASE_OPCODE_DONE => {
                try writer.print(fmt_value, .{ byte, "REBASE_OPCODE_DONE", "", imm });
                break;
            },
            macho.REBASE_OPCODE_SET_TYPE_IMM => {
                const tt = switch (imm) {
                    macho.REBASE_TYPE_POINTER => "REBASE_TYPE_POINTER",
                    macho.REBASE_TYPE_TEXT_ABSOLUTE32 => "REBASE_TYPE_TEXT_ABSOLUTE32",
                    macho.REBASE_TYPE_TEXT_PCREL32 => "REBASE_TYPE_TEXT_PCREL32",
                    else => "UNKNOWN",
                };
                try writer.print(fmt_value, .{ byte, "REBASE_OPCODE_SET_TYPE_IMM", tt, imm });
            },
            macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                seg_id = imm;
                const start = creader.bytes_read;
                seg_offset = try std.leb.readULEB128(u64, reader);
                const end = creader.bytes_read;

                try writer.print(fmt_value, .{ byte, "REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB", "segment", seg_id.? });
                try writer.print(fmt_value, .{ std.fmt.fmtSliceHexLower(data[start..end]), "", "offset", seg_offset.? });
            },
            macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES => {
                const ntimes = imm;

                try writer.print(fmt_value, .{ byte, "REBASE_OPCODE_DO_REBASE_IMM_TIMES", "count", ntimes });
                try writer.writeByte('\n');
                try writer.writeAll("    ACTIONS:\n");

                const seg = segments.items[seg_id.?];
                var addr = seg.vmaddr + seg_offset.?;
                var count: usize = 0;
                while (count < ntimes) : (count += 1) {
                    addr += count * @sizeOf(u64);
                    if (addr > seg.vmaddr + seg.vmsize) {
                        std.log.err("malformed rebase: address {x} outside of segment {s} ({d})!", .{
                            addr,
                            seg.segName(),
                            imm,
                        });
                        continue;
                    }
                    const ptr_offset = seg.fileoff + seg_offset.?;
                    const ptr = mem.readIntLittle(u64, self.data[ptr_offset..][0..@sizeOf(u64)]);
                    try writer.print(fmt_ptr, .{ addr, ptr });
                }
                try writer.writeByte('\n');
            },
            else => {},
        }
    }
}

const UnwindInfoRelocTarget = packed struct {
    tag: enum(u8) { symbol, section },
    index: u24,
};

fn getUnwindInfoRelocTarget(self: ZachO, rel: macho.relocation_info) UnwindInfoRelocTarget {
    if (rel.r_extern == 1) {
        return .{
            .tag = .symbol,
            .index = @intCast(u24, self.source_symtab_lookup[rel.r_symbolnum]),
        };
    }
    return .{
        .tag = .section,
        .index = rel.r_symbolnum,
    };
}

fn getUnwindInfoTargetNameAndAddend(self: ZachO, rel: macho.relocation_info, code: u64) struct {
    name: []const u8,
    addend: u64,
} {
    const target = self.getUnwindInfoRelocTarget(rel);
    switch (target.tag) {
        .symbol => {
            const sym = self.symtab[target.index];
            const sym_name = self.getString(sym.n_strx);
            return .{
                .name = sym_name,
                .addend = code,
            };
        },
        .section => {
            if (self.findSymbolByAddress(code)) |sym| {
                const sym_name = self.getString(sym.n_strx);
                return .{
                    .name = sym_name,
                    .addend = code - sym.n_value,
                };
            } else {
                const sect = self.getSectionByIndex(@intCast(u8, target.index));
                return .{
                    .name = sect.sectName(), // TODO alloc buffer to hold segname,sectname
                    .addend = code - sect.addr,
                };
            }
        },
    }
}

pub fn printUnwindInfo(self: ZachO, writer: anytype) !void {
    const is_obj = self.header.filetype == macho.MH_OBJECT;

    if (is_obj) {
        const sect = self.getSectionByName("__LD", "__compact_unwind") orelse {
            try writer.writeAll("No __LD,__compact_unwind section found.\n");
            return;
        };

        const data = self.data[sect.offset..][0..sect.size];
        if (data.len % @sizeOf(macho.compact_unwind_entry) != 0) {
            try writer.print("Size of __LD,__compact_unwind section not integral of compact unwind info entry: {d} % {d} != 0", .{
                data.len, @sizeOf(macho.compact_unwind_entry),
            });
            return error.MalformedCompactUnwindSection;
        }

        const num_entries = @divExact(data.len, @sizeOf(macho.compact_unwind_entry));
        const entries = @ptrCast([*]align(1) const macho.compact_unwind_entry, data)[0..num_entries];
        const relocs = @ptrCast([*]align(1) const macho.relocation_info, self.data.ptr + sect.reloff)[0..sect.nreloc];

        try writer.writeAll("Contents of __LD,__compact_unwind section:\n");

        for (entries) |entry, i| {
            const base_offset = i * @sizeOf(macho.compact_unwind_entry);
            const entry_relocs = filterRelocsByAddress(relocs, base_offset, @sizeOf(macho.compact_unwind_entry));
            const func = blk: {
                const rel = filterRelocsByAddress(entry_relocs, base_offset, 8);
                assert(rel.len == 1);
                break :blk self.getUnwindInfoTargetNameAndAddend(rel[0], entry.rangeStart);
            };
            const personality = blk: {
                const rel = filterRelocsByAddress(entry_relocs, base_offset + 16, 8);
                if (rel.len == 0) break :blk null;
                assert(rel.len == 1);
                break :blk self.getUnwindInfoTargetNameAndAddend(rel[0], entry.personalityFunction);
            };
            const lsda = blk: {
                const rel = filterRelocsByAddress(entry_relocs, base_offset + 24, 8);
                if (rel.len == 0) break :blk null;
                assert(rel.len == 1);
                break :blk self.getUnwindInfoTargetNameAndAddend(rel[0], entry.lsda);
            };
            const enc = try macho.UnwindEncodingArm64.fromU32(entry.compactUnwindEncoding);

            try writer.print("  Entry at offset 0x{x}:\n", .{i * @sizeOf(macho.compact_unwind_entry)});
            try writer.print("    {s: <22} 0x{x}", .{ "start:", entry.rangeStart });
            if (func.addend > 0) {
                try writer.print(" + {x}", .{func.addend});
            }
            try writer.print(" {s}\n", .{func.name});
            try writer.print("    {s: <22} 0x{x}\n", .{ "length:", entry.rangeLength });

            if (!self.verbose) {
                try writer.print("    {s: <22} 0x{x:0>8}\n", .{ "compact encoding:", enc.toU32() });
            }

            if (personality) |x| {
                try writer.print("    {s: <22} 0x{x}", .{ "personality function:", entry.personalityFunction });
                if (x.addend > 0) {
                    try writer.print(" + {x}", .{x.addend});
                }
                try writer.print(" {s}\n", .{x.name});
            }

            if (lsda) |x| {
                try writer.print("    {s: <22} 0x{x}", .{ "LSDA:", entry.lsda });
                if (x.addend > 0) {
                    try writer.print(" + {x}", .{x.addend});
                }
                try writer.print(" {s}\n", .{x.name});
            }

            if (self.verbose) {
                try writer.print("    {s: <22}\n", .{"compact encoding:"});
                try formatCompactUnwindEncodingArm64(enc, writer, .{
                    .prefix = 12,
                });
            }
        }
    } else {
        const sect = self.getSectionByName("__TEXT", "__unwind_info") orelse {
            try writer.writeAll("No __TEXT,__unwind_info section found.\n");
            return;
        };

        const data = self.data[sect.offset..][0..sect.size];
        const header = @ptrCast(*align(1) const macho.unwind_info_section_header, data.ptr).*;

        try writer.writeAll("Contents of __TEXT,__unwind_info section:\n");
        try writer.print("  {s: <25} {d}\n", .{ "Version:", header.version });
        try writer.print("  {s: <25} 0x{x}\n", .{
            "Common encodings offset:",
            header.commonEncodingsArraySectionOffset,
        });
        try writer.print("  {s: <25} {d}\n", .{
            "Common encodings count:",
            header.commonEncodingsArrayCount,
        });
        try writer.print("  {s: <25} 0x{x}\n", .{
            "Personalities offset:",
            header.personalityArraySectionOffset,
        });
        try writer.print("  {s: <25} {d}\n", .{
            "Personalities count:",
            header.personalityArrayCount,
        });
        try writer.print("  {s: <25} 0x{x}\n", .{
            "Indexes offset:",
            header.indexSectionOffset,
        });
        try writer.print("  {s: <25} {d}\n", .{
            "Indexes count:",
            header.indexCount,
        });

        const common_encodings = @ptrCast(
            [*]align(1) const macho.compact_unwind_encoding_t,
            data.ptr + header.commonEncodingsArraySectionOffset,
        )[0..header.commonEncodingsArrayCount];

        try writer.print("\n  Common encodings: (count = {d})\n", .{common_encodings.len});

        for (common_encodings) |raw, i| {
            if (self.verbose) {
                const enc = try macho.UnwindEncodingArm64.fromU32(raw);
                try writer.print("    encoding[{d}]\n", .{i});
                try formatCompactUnwindEncodingArm64(enc, writer, .{
                    .prefix = 6,
                });
            } else {
                try writer.print("    encoding[{d}]: 0x{x:0>8}\n", .{ i, raw });
            }
        }

        const personalities = @ptrCast(
            [*]align(1) const u32,
            data.ptr + header.personalityArraySectionOffset,
        )[0..header.personalityArrayCount];

        try writer.print("\n  Personality functions: (count = {d})\n", .{personalities.len});

        for (personalities) |personality, i| {
            if (self.verbose) {
                const seg = self.getSegmentByName("__TEXT").?;
                const addr = seg.vmaddr + personality;
                const target_sect = self.getSectionByAddress(addr).?;
                assert(target_sect.flags == macho.S_NON_LAZY_SYMBOL_POINTERS);
                const ptr = self.getGotPointerAtIndex(@divExact(addr - target_sect.addr, 8));
                const sym = self.findSymbolByAddress(ptr).?;
                const name = self.getString(sym.n_strx);
                try writer.print("    personality[{d}]: 0x{x} -> 0x{x} {s}\n", .{ i + 1, addr, ptr, name });
            } else {
                try writer.print("    personality[{d}]: 0x{x:0>8}\n", .{ i + 1, personality });
            }
        }

        const indexes = @ptrCast(
            [*]align(1) const macho.unwind_info_section_header_index_entry,
            data.ptr + header.indexSectionOffset,
        )[0..header.indexCount];

        try writer.print("\n  Top level indices: (count = {d})\n", .{indexes.len});
        for (indexes) |entry, i| {
            if (self.verbose) {
                const seg = self.getSegmentByName("__TEXT").?;
                const sym = self.findSymbolByAddress(seg.vmaddr + entry.functionOffset).?;
                const name = self.getString(sym.n_strx);

                try writer.print("    [{d}] {s}\n", .{ i, name });
                try writer.print("      {s: <20} 0x{x:0>16}\n", .{
                    "Function address:",
                    seg.vmaddr + entry.functionOffset,
                });
                try writer.print("      {s: <20} 0x{x:0>8}\n", .{
                    "Second level pages:",
                    entry.secondLevelPagesSectionOffset,
                });
                try writer.print("      {s: <20} 0x{x:0>8}\n", .{
                    "LSDA index array:",
                    entry.lsdaIndexArraySectionOffset,
                });
            } else {
                try writer.print("    [{d}]: function offset=0x{x:0>8}, 2nd level page offset=0x{x:0>8}, LSDA offset=0x{x:0>8}\n", .{
                    i,
                    entry.functionOffset,
                    entry.secondLevelPagesSectionOffset,
                    entry.lsdaIndexArraySectionOffset,
                });
            }
        }

        if (indexes.len == 0) return;

        const num_lsdas = @divExact(
            indexes[indexes.len - 1].lsdaIndexArraySectionOffset -
                indexes[0].lsdaIndexArraySectionOffset,
            @sizeOf(macho.unwind_info_section_header_lsda_index_entry),
        );
        const lsdas = @ptrCast(
            [*]align(1) const macho.unwind_info_section_header_lsda_index_entry,
            data.ptr + indexes[0].lsdaIndexArraySectionOffset,
        )[0..num_lsdas];

        try writer.writeAll("\n  LSDA descriptors:\n");
        for (lsdas) |lsda, i| {
            if (self.verbose) {
                const seg = self.getSegmentByName("__TEXT").?;
                const func_sym = self.findSymbolByAddress(seg.vmaddr + lsda.functionOffset).?;
                const func_name = self.getString(func_sym.n_strx);
                const lsda_sym = self.findSymbolByAddress(seg.vmaddr + lsda.lsdaOffset).?;
                const lsda_name = self.getString(lsda_sym.n_strx);

                try writer.print("    [{d}] {s}\n", .{ i, func_name });
                try writer.print("      {s: <20} 0x{x:0>16}\n", .{
                    "Function address:",
                    seg.vmaddr + lsda.functionOffset,
                });
                try writer.print("      {s: <20} 0x{x:0>16} {s}\n", .{
                    "LSDA address:",
                    seg.vmaddr + lsda.lsdaOffset,
                    lsda_name,
                });
            } else {
                try writer.print("    [{d}]: function offset=0x{x:0>8}, LSDA offset=0x{x:0>8}\n", .{
                    i,
                    lsda.functionOffset,
                    lsda.lsdaOffset,
                });
            }
        }

        try writer.writeAll("\n  Second level indices:\n");
        for (indexes) |entry, i| {
            const start_offset = entry.secondLevelPagesSectionOffset;
            if (start_offset == 0) break;

            if (self.verbose) {
                const seg = self.getSegmentByName("__TEXT").?;
                const func_sym = self.findSymbolByAddress(seg.vmaddr + entry.functionOffset).?;
                const func_name = self.getString(func_sym.n_strx);
                try writer.print("    Second level index[{d}]: {s}\n", .{ i, func_name });
                try writer.print("      Offset in section: 0x{x:0>8}\n", .{entry.secondLevelPagesSectionOffset});
                try writer.print("      Function address: 0x{x:0>16}\n", .{seg.vmaddr + entry.functionOffset});
            } else {
                try writer.print("    Second level index[{d}]: offset in section=0x{x:0>8}, base function offset=0x{x:0>8}\n", .{
                    i,
                    entry.secondLevelPagesSectionOffset,
                    entry.functionOffset,
                });
            }

            const kind = @intToEnum(
                macho.UNWIND_SECOND_LEVEL,
                @ptrCast(*align(1) const u32, data.ptr + start_offset).*,
            );

            switch (kind) {
                .REGULAR => {
                    const page_header = @ptrCast(
                        *align(1) const macho.unwind_info_regular_second_level_page_header,
                        data.ptr + start_offset,
                    ).*;

                    var pos = start_offset + page_header.entryPageOffset;
                    var count: usize = 0;
                    while (count < page_header.entryCount) : (count += 1) {
                        const inner = @ptrCast(
                            *align(1) const macho.unwind_info_regular_second_level_entry,
                            data.ptr + pos,
                        ).*;

                        if (self.verbose) blk: {
                            const seg = self.getSegmentByName("__TEXT").?;
                            const func_sym = self.findSymbolByAddress(seg.vmaddr + entry.functionOffset).?;
                            const func_name = self.getString(func_sym.n_strx);

                            try writer.print("      [{d}] {s}\n", .{
                                count,
                                func_name,
                            });
                            try writer.print("        Function address: 0x{x:0>16}\n", .{
                                seg.vmaddr + entry.functionOffset,
                            });
                            try writer.writeAll("        Encoding:\n");

                            const enc = macho.UnwindEncodingArm64.fromU32(inner.encoding) catch |err| switch (err) {
                                error.UnknownEncoding => if (inner.encoding == 0) {
                                    try writer.writeAll("          none\n");
                                    break :blk;
                                } else return err,
                            };
                            try formatCompactUnwindEncodingArm64(enc, writer, .{
                                .prefix = 10,
                            });
                        } else {
                            try writer.print("      [{d}]: function offset=0x{x:0>8}, encoding=0x{x:0>8}\n", .{
                                count,
                                inner.functionOffset,
                                inner.encoding,
                            });
                        }
                    }
                },
                .COMPRESSED => {
                    const page_header = @ptrCast(
                        *align(1) const macho.unwind_info_compressed_second_level_page_header,
                        data.ptr + start_offset,
                    ).*;

                    var page_encodings = std.ArrayList(macho.compact_unwind_encoding_t).init(self.gpa);
                    defer page_encodings.deinit();

                    if (page_header.encodingsCount > 0) {
                        try page_encodings.ensureTotalCapacityPrecise(page_header.encodingsCount);
                        try writer.print("      Page encodings: (count = {d})\n", .{
                            page_header.encodingsCount,
                        });

                        var pos = start_offset + page_header.encodingsPageOffset;
                        var count: usize = 0;
                        while (count < page_header.encodingsCount) : (count += 1) {
                            const raw = @ptrCast(*align(1) const macho.compact_unwind_encoding_t, data.ptr + pos).*;

                            if (self.verbose) blk: {
                                try writer.print("        encoding[{d}]\n", .{count + common_encodings.len});
                                const enc = macho.UnwindEncodingArm64.fromU32(raw) catch |err| switch (err) {
                                    error.UnknownEncoding => if (raw == 0) {
                                        try writer.writeAll("          none\n");
                                        break :blk;
                                    } else return err,
                                };
                                try formatCompactUnwindEncodingArm64(enc, writer, .{
                                    .prefix = 10,
                                });
                            } else {
                                try writer.print("        encoding[{d}]: 0x{x:0>8}\n", .{
                                    count + common_encodings.len,
                                    raw,
                                });
                            }

                            page_encodings.appendAssumeCapacity(raw);
                            pos += @sizeOf(macho.compact_unwind_encoding_t);
                        }
                    }

                    var pos = start_offset + page_header.entryPageOffset;
                    var count: usize = 0;
                    while (count < page_header.entryCount) : (count += 1) {
                        const inner = @ptrCast(*align(1) const u32, data.ptr + pos).*;
                        const func_offset = entry.functionOffset + (inner & 0xFFFFFF);
                        const id = inner >> 24;
                        const raw = if (id < common_encodings.len)
                            common_encodings[id]
                        else
                            page_encodings.items[id - common_encodings.len];

                        if (self.verbose) blk: {
                            const seg = self.getSegmentByName("__TEXT").?;
                            const func_sym = self.findSymbolByAddress(seg.vmaddr + func_offset).?;
                            const func_name = self.getString(func_sym.n_strx);

                            try writer.print("      [{d}] {s}\n", .{ count, func_name });
                            try writer.print("        Function address: 0x{x:0>16}\n", .{seg.vmaddr + func_offset});

                            const enc = macho.UnwindEncodingArm64.fromU32(raw) catch |err| switch (err) {
                                error.UnknownEncoding => if (raw == 0) {
                                    try writer.writeAll("          none\n");
                                    break :blk;
                                } else return err,
                            };
                            try writer.writeAll("        Encoding\n");
                            try formatCompactUnwindEncodingArm64(enc, writer, .{
                                .prefix = 10,
                            });
                        } else {
                            try writer.print("      [{d}]: function offset=0x{x:0>8}, encoding[{d}]=0x{x:0>8}\n", .{
                                count,
                                func_offset,
                                id,
                                raw,
                            });
                        }

                        pos += @sizeOf(u32);
                    }
                },
                else => return error.UnhandledSecondLevelKind,
            }
        }
    }
}

fn formatCompactUnwindEncodingArm64(enc: macho.UnwindEncodingArm64, writer: anytype, comptime opts: struct {
    prefix: usize = 0,
}) !void {
    const prefix: [opts.prefix]u8 = [_]u8{' '} ** opts.prefix;
    try writer.print(prefix ++ "{s: <12} {}\n", .{ "start:", enc.start() });
    try writer.print(prefix ++ "{s: <12} {}\n", .{ "LSDA:", enc.hasLsda() });
    try writer.print(prefix ++ "{s: <12} {d}\n", .{ "personality:", enc.personalityIndex() });
    try writer.print(prefix ++ "{s: <12} {s}\n", .{ "mode:", @tagName(enc.mode()) });

    switch (enc) {
        .frameless => |frameless| {
            try writer.print(prefix ++ "{s: <12} {d}\n", .{
                "stack size:",
                frameless.stack_size * 16,
            });
        },
        .frame => |frame| {
            inline for (@typeInfo(@TypeOf(frame.x_reg_pairs)).Struct.fields) |field| {
                try writer.print(prefix ++ "{s: <12} {}\n", .{
                    field.name,
                    @field(frame.x_reg_pairs, field.name) == 0b1,
                });
            }

            inline for (@typeInfo(@TypeOf(frame.d_reg_pairs)).Struct.fields) |field| {
                try writer.print(prefix ++ "{s: <12} {}\n", .{
                    field.name,
                    @field(frame.d_reg_pairs, field.name) == 0b1,
                });
            }
        },
        .dwarf => |dwarf| {
            try writer.print(prefix ++ "{s: <12} 0x{x:0>8}\n", .{
                "FDE offset:",
                dwarf.section_offset,
            });
        },
    }
}

pub fn printCodeSignature(self: ZachO, writer: anytype) !void {
    var it = self.getLoadCommandsIterator();
    while (it.next()) |lc| switch (lc.cmd()) {
        .CODE_SIGNATURE => return self.formatCodeSignatureData(lc.cast(macho.linkedit_data_command).?, writer),
        else => continue,
    };
    return writer.print("LC_CODE_SIGNATURE load command not found\n", .{});
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

    var data = self.data[start_pos..end_pos];
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
        try formatBinaryBlob(self.data[start_pos..end_pos], .{}, writer);
        return;
    }

    var blobs = std.ArrayList(macho.BlobIndex).init(self.gpa);
    defer blobs.deinit();
    try blobs.ensureTotalCapacityPrecise(count);

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const tt = mem.readIntBig(u32, ptr[0..4]);
        const offset = mem.readIntBig(u32, ptr[4..8]);
        try writer.print("{{\n    Type: {s}(0x{x})\n    Offset: {}\n}}\n", .{ fmtCsSlotConst(tt), tt, offset });
        blobs.appendAssumeCapacity(.{
            .type = tt,
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

                var req_blobs = std.ArrayList(macho.BlobIndex).init(self.gpa);
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
                        .type = tt,
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
                    const cd: []const u8 = blk: {
                        const cd_blob = blobs.items[0];
                        const cd_header = data[cd_blob.offset..][0..8];
                        const cd_length = mem.readIntBig(u32, cd_header[4..8]);
                        break :blk data[cd_blob.offset..][0..cd_length];
                    };

                    const decoder = try CMSDecoder.create();
                    defer decoder.release();
                    try decoder.updateMessage(signature);
                    try decoder.setDetachedContent(cd);
                    try decoder.finalizeMessage();

                    const num_signers = try decoder.getNumSigners();
                    try writer.print("    Number of signers: {d}\n", .{num_signers});

                    const status = try decoder.getSignerStatus(0);
                    try writer.print("    Signer status: {}\n", .{status});
                } else {
                    try writer.print("\n\n    !! Validating signatures available only on macOS !! \n\n", .{});
                    try writer.print("    Raw data:\n", .{});
                    try formatBinaryBlob(signature, .{
                        .prefix = "        ",
                        .fmt_as_str = true,
                        .escape_str = true,
                    }, writer);
                }
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
    const q1 = @min(@divFloor(oid1, 40), 2);
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

pub fn verifyMemoryLayout(self: ZachO, writer: anytype) !void {
    var segments = std.ArrayList(macho.segment_command_64).init(self.gpa);
    defer segments.deinit();

    var sections = std.AutoHashMap(u8, std.ArrayList(macho.section_64)).init(self.gpa);
    defer {
        var it = sections.valueIterator();
        while (it.next()) |value_ptr| {
            value_ptr.deinit();
        }
        sections.deinit();
    }

    var sorted_by_address = std.ArrayList(u8).init(self.gpa);
    defer sorted_by_address.deinit();

    var sorted_by_offset = std.ArrayList(u8).init(self.gpa);
    defer sorted_by_offset.deinit();

    var it = self.getLoadCommandsIterator();
    while (it.next()) |lc| switch (lc.cmd()) {
        .SEGMENT_64 => {
            const seg = lc.cast(macho.segment_command_64).?;
            const seg_id = @intCast(u8, segments.items.len);
            try segments.append(seg);

            const headers = lc.getSections();
            if (headers.len > 0) {
                const gop = try sections.getOrPut(seg_id);
                if (!gop.found_existing) {
                    gop.value_ptr.* = std.ArrayList(macho.section_64).init(self.gpa);
                }
                try gop.value_ptr.ensureUnusedCapacity(headers.len);
                gop.value_ptr.appendSliceAssumeCapacity(headers);
            }

            for (sorted_by_address.items) |other_id, i| {
                const other_seg = segments.items[other_id];
                if (seg.vmaddr < other_seg.vmaddr) {
                    try sorted_by_address.insert(i, seg_id);
                    break;
                }
            } else try sorted_by_address.append(seg_id);

            for (sorted_by_offset.items) |other_id, i| {
                const other_seg = segments.items[other_id];
                if (seg.fileoff < other_seg.fileoff) {
                    try sorted_by_offset.insert(i, seg_id);
                    break;
                }
            } else try sorted_by_offset.append(seg_id);
        },
        else => continue,
    };

    if (segments.items.len == 0) {
        try writer.writeAll("\nNo segments found.\n");
        return;
    }

    try writer.writeAll("\nMEMORY LAYOUT:\n");

    var i: u8 = 0;
    while (i < sorted_by_address.items.len) : (i += 1) {
        const seg_id = sorted_by_address.items[i];
        const seg = segments.items[seg_id];
        try writer.print("  {s: >20} ---------- {x}\n", .{ seg.segName(), seg.vmaddr });
        try writer.print("  {s: >20} |\n", .{""});

        if (sections.get(seg_id)) |headers| {
            try writer.writeByte('\n');
            for (headers.items) |header, header_id| {
                try writer.print("    {s: >20} -------- {x}\n", .{ header.sectName(), header.addr });
                try writer.print("    {s: >20} |\n", .{""});
                try writer.print("    {s: >20} -------- {x}\n", .{ "", header.addr + header.size });
                if (header_id < headers.items.len - 1) {
                    const next_header = headers.items[header_id + 1];
                    if (next_header.addr < header.addr + header.size) {
                        try writer.writeAll("      CURRENT SECTION OVERLAPS THE NEXT ONE\n");
                    }
                }
            }
            try writer.writeByte('\n');
        } else {
            try writer.print("  {s: >20} |\n", .{""});
        }

        try writer.print("  {s: >20} |\n", .{""});
        try writer.print("  {s: >20} ---------- {x}\n", .{ "", seg.vmaddr + seg.vmsize });
        if (i < sorted_by_address.items.len - 1) {
            const next_seg_id = sorted_by_address.items[i + 1];
            const next_seg = segments.items[next_seg_id];
            if (next_seg.vmaddr < seg.vmaddr + seg.vmsize) {
                try writer.writeAll("    CURRENT SEGMENT OVERLAPS THE NEXT ONE\n");
            }
        }
        try writer.writeByte('\n');
    }

    try writer.writeAll("\nIN-FILE LAYOUT:\n");

    i = 0;
    while (i < sorted_by_offset.items.len) : (i += 1) {
        const seg_id = sorted_by_offset.items[i];
        const seg = segments.items[seg_id];
        try writer.print("  {s: >20} ---------- {x}\n", .{ seg.segName(), seg.fileoff });
        try writer.print("  {s: >20} |\n", .{""});

        if (sections.get(seg_id)) |headers| {
            try writer.writeByte('\n');
            for (headers.items) |header, header_id| {
                try writer.print("    {s: >20} -------- {x}\n", .{ header.sectName(), header.offset });
                try writer.print("    {s: >20} |\n", .{""});
                try writer.print("    {s: >20} -------- {x}\n", .{ "", header.offset + header.size });
                if (header_id < headers.items.len - 1) {
                    const next_header = headers.items[header_id + 1];
                    if (next_header.offset < header.offset + header.size) {
                        try writer.writeAll("      CURRENT SECTION OVERLAPS THE NEXT ONE\n");
                    }
                }
            }
            try writer.writeByte('\n');
        } else {
            try writer.print("  {s: >20} |\n", .{""});
        }

        try writer.print("  {s: >20} |\n", .{""});
        try writer.print("  {s: >20} ---------- {x}\n", .{ "", seg.fileoff + seg.filesize });
        if (i < sorted_by_offset.items.len - 1) {
            const next_seg_id = sorted_by_offset.items[i + 1];
            const next_seg = segments.items[next_seg_id];
            if (next_seg.fileoff < seg.fileoff + seg.filesize) {
                try writer.writeAll("    CURRENT SEGMENT OVERLAPS THE NEXT ONE\n");
            }
        }
        try writer.writeByte('\n');
    }
}

pub fn printSymbolTable(self: ZachO, writer: anytype) !void {
    if (self.symtab_lc == null) {
        try writer.writeAll("\nNo symbol table found in the object file.\n");
        return;
    }

    try writer.writeAll("\nSymbol table:\n");

    for (self.getSymbols()) |sym| {
        if (sym.stab()) continue; // TODO

        const sym_name = self.getString(sym.n_strx);

        if (sym.sect()) {
            const sect = self.getSectionByIndex(sym.n_sect);
            try writer.print("  0x{x:0>16} ({s},{s})", .{
                sym.n_value,
                sect.segName(),
                sect.sectName(),
            });

            if (sym.n_desc & macho.REFERENCED_DYNAMICALLY != 0) {
                try writer.writeAll(" [referenced dynamically]");
            }

            if (sym.ext()) {
                try writer.writeAll(" external");
            } else {
                try writer.writeAll(" non-external");
            }

            try writer.print(" {s}\n", .{sym_name});
        } else if (sym.tentative()) {
            const alignment = (sym.n_desc >> 8) & 0x0F;
            try writer.print("  0x{x:0>16} (common) (alignment 2^{d})", .{ sym.n_value, alignment });

            if (sym.ext()) {
                try writer.writeAll(" external");
            } else {
                try writer.writeAll(" non-external");
            }

            try writer.print(" {s}\n", .{sym_name});
        } else {
            try writer.print("    {s: >16} (undefined)", .{" "});

            if (sym.ext()) {
                try writer.writeAll(" external");
            }

            try writer.print(" {s}", .{sym_name});

            const ord = @divTrunc(@bitCast(i16, sym.n_desc), macho.N_SYMBOL_RESOLVER);
            switch (ord) {
                macho.BIND_SPECIAL_DYLIB_FLAT_LOOKUP => {}, // TODO
                macho.BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE => {}, // TODO
                macho.BIND_SPECIAL_DYLIB_SELF => {}, // TODO
                else => {
                    const dylib = self.getDylibByIndex(@intCast(u16, ord));
                    const full_path = dylib.getDylibPathName();
                    const leaf_path = std.fs.path.basename(full_path);
                    var name = leaf_path;
                    while (true) {
                        const ext = std.fs.path.extension(name);
                        if (ext.len == 0) break;
                        name = name[0 .. name.len - ext.len];
                    }
                    try writer.print(" (from {s})", .{name});
                },
            }

            try writer.writeByte('\n');
        }
    }
}

fn getLoadCommandsIterator(self: ZachO) macho.LoadCommandIterator {
    const data = self.data[@sizeOf(macho.mach_header_64)..][0..self.header.sizeofcmds];
    return .{
        .ncmds = self.header.ncmds,
        .buffer = data,
    };
}

fn getSymbols(self: *const ZachO) []align(1) const macho.nlist_64 {
    const lc = self.symtab_lc orelse return &[0]macho.nlist_64{};
    const symtab = @ptrCast([*]align(1) const macho.nlist_64, self.data.ptr + lc.symoff)[0..lc.nsyms];
    return symtab;
}

fn getSymbol(self: *const ZachO, index: u32) macho.nlist_64 {
    const symtab = self.getSymbols().?;
    assert(index < symtab.len);
    return symtab[index];
}

fn findSymbolByAddress(self: *const ZachO, addr: u64) ?macho.nlist_64 {
    assert(self.symtab.len > 0);
    for (self.symtab) |sym, i| {
        if (sym.stab()) continue;
        if (sym.n_value > addr or sym.undf()) {
            return self.symtab[i - 1];
        }
    } else return null;
}

fn getString(self: *const ZachO, off: u32) []const u8 {
    const strtab = self.data[self.symtab_lc.?.stroff..][0..self.symtab_lc.?.strsize];
    assert(off < strtab.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, strtab.ptr + off), 0);
}

fn getSectionByName(self: ZachO, segname: []const u8, sectname: []const u8) ?macho.section_64 {
    var it = self.getLoadCommandsIterator();
    while (it.next()) |lc| switch (lc.cmd()) {
        .SEGMENT_64 => {
            const sections = lc.getSections();
            for (sections) |sect| {
                if (mem.eql(u8, segname, sect.segName()) and mem.eql(u8, sectname, sect.sectName()))
                    return sect;
            }
        },
        else => {},
    };
    return null;
}

fn getSectionByAddress(self: ZachO, addr: u64) ?macho.section_64 {
    var it = self.getLoadCommandsIterator();
    const lc = while (it.next()) |lc| switch (lc.cmd()) {
        .SEGMENT_64 => {
            const seg = lc.cast(macho.segment_command_64).?;
            if (seg.vmaddr <= addr and addr < seg.vmaddr + seg.vmsize) {
                break lc;
            }
        },
        else => continue,
    } else return null;
    const sect = for (lc.getSections()) |sect| {
        if (sect.addr <= addr and addr < sect.addr + sect.size) {
            break sect;
        }
    } else return null;
    return sect;
}

fn getSectionByIndex(self: ZachO, index: u8) macho.section_64 {
    var count: u8 = 1;
    var it = self.getLoadCommandsIterator();
    while (it.next()) |lc| switch (lc.cmd()) {
        .SEGMENT_64 => {
            const sects = lc.getSections();
            if (index > count + sects.len) {
                count += @intCast(u8, sects.len);
                continue;
            }

            for (sects) |sect| {
                if (index == count) return sect;
                count += 1;
            }
        },
        else => {},
    } else unreachable;
}

fn getGotPointerAtIndex(self: ZachO, index: usize) u64 {
    const sect = self.getSectionByName("__DATA_CONST", "__got").?;
    const data = self.data[sect.offset..][0..sect.size];
    const ptr = @ptrCast(*align(1) const u64, data[index * 8 ..]).*;

    const mask = 0xFFFF000000000000; // TODO I guessed the value of the mask, so verify!
    if (mask & ptr == 0) {
        // Old-style GOT with actual pointer values
        return ptr;
    }

    const actual_ptr = synthesiseGotPointerValue(data, index);
    const seg = self.getSegmentByName("__TEXT").?;
    return seg.vmaddr + actual_ptr;
}

fn synthesiseGotPointerValue(data: []const u8, index: usize) u64 {
    const enc_mask = 0xFFFF000000000000; // TODO I guessed the value of the mask, so verify!
    const value_mask = 0xFFFFFFFFFFFF;
    const ptr = @ptrCast(*align(1) const u64, data[index * 8 ..]).*;

    switch ((enc_mask & ptr) >> 48) {
        0x0010 => return value_mask & ptr, // Start offset value
        0x8010 => return (value_mask & ptr) + synthesiseGotPointerValue(data, index - 1),
        else => unreachable,
    }
}

fn getSegmentByName(self: ZachO, segname: []const u8) ?macho.segment_command_64 {
    var it = self.getLoadCommandsIterator();
    while (it.next()) |lc| switch (lc.cmd()) {
        .SEGMENT_64 => {
            const seg = lc.cast(macho.segment_command_64).?;
            if (mem.eql(u8, segname, seg.segName())) {
                return seg;
            }
        },
        else => continue,
    } else return null;
}

fn getSegmentByAddress(self: ZachO, addr: u64) ?macho.segment_command_64 {
    var it = self.getLoadCommandsIterator();
    while (it.next()) |lc| switch (lc.cmd()) {
        .SEGMENT_64 => {
            const seg = lc.cast(macho.segment_command_64).?;
            if (seg.vmaddr <= addr and addr < seg.vmaddr + seg.vmsize) {
                return seg;
            }
        },
        else => continue,
    } else return null;
}

fn sliceContentsByAddress(self: ZachO, addr: u64, size: u64) ?[]const u8 {
    var it = self.getLoadCommandsIterator();
    const lc = while (it.next()) |lc| switch (lc.cmd()) {
        .SEGMENT_64 => {
            const seg = lc.cast(macho.segment_command_64).?;
            if (seg.vmaddr <= addr and addr < seg.vmaddr + seg.vmsize) {
                break lc;
            }
        },
        else => continue,
    } else return null;
    const sect = for (lc.getSections()) |sect| {
        if (sect.addr <= addr and addr < sect.addr + sect.size) {
            break sect;
        }
    } else return null;
    const offset = addr - sect.addr + sect.offset;
    assert(offset + size < sect.offset + sect.size);
    return self.data[offset..][0..size];
}

fn getDylibByIndex(self: ZachO, index: u16) macho.LoadCommandIterator.LoadCommand {
    var count: u16 = 1;
    var it = self.getLoadCommandsIterator();
    while (it.next()) |lc| switch (lc.cmd()) {
        .LOAD_DYLIB => {
            if (count == index) return lc;
            count += 1;
        },
        else => {},
    } else unreachable;
}

fn filterRelocsByAddress(
    relocs: []align(1) const macho.relocation_info,
    address: u64,
    size: u64,
) []align(1) const macho.relocation_info {
    var i: usize = 0;
    const start = while (i < relocs.len) : (i += 1) {
        const rel = relocs[i];
        if (rel.r_address < address + size) break i;
    } else relocs.len;

    i = start;
    const end = while (i < relocs.len) : (i += 1) {
        const rel = relocs[i];
        if (rel.r_address < address) break i;
    } else relocs.len;

    return relocs[start..end];
}
