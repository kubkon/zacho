gpa: Allocator,
data: []const u8,
path: []const u8,

arch: Arch = undefined,
header: macho.mach_header_64 = undefined,
segments: std.ArrayListUnmanaged(macho.segment_command_64) = .{},

symtab: []align(1) const macho.nlist_64 = &[0]macho.nlist_64{},
sorted_symtab: std.ArrayListUnmanaged(SymbolAtIndex) = .{},
strtab: []const u8 = &[0]u8{},
symtab_lc: ?macho.symtab_command = null,
dysymtab_lc: ?macho.dysymtab_command = null,

dyld_info_only_lc: ?macho.dyld_info_command = null,
dyld_exports_trie_lc: ?macho.linkedit_data_command = null,
dyld_chained_fixups_lc: ?macho.linkedit_data_command = null,

data_in_code_lc: ?macho.linkedit_data_command = null,

verbose: bool = false,

pub fn deinit(self: *Object) void {
    self.gpa.free(self.path);
    self.segments.deinit(self.gpa);
    self.sorted_symtab.deinit(self.gpa);
}

pub fn parse(self: *Object) !void {
    var stream = std.io.fixedBufferStream(self.data);
    const reader = stream.reader();
    const header = try reader.readStruct(macho.mach_header_64);

    if (header.magic != macho.MH_MAGIC_64) return error.InvalidMagic;

    self.header = header;
    self.arch = switch (header.cputype) {
        macho.CPU_TYPE_ARM64 => .aarch64,
        macho.CPU_TYPE_X86_64 => .x86_64,
        else => .unknown,
    };

    var it = self.getLoadCommandsIterator();
    while (it.next()) |lc| switch (lc.cmd()) {
        .SEGMENT_64 => {
            const cmd = lc.cast(macho.segment_command_64).?;
            try self.segments.append(self.gpa, cmd);
        },
        .SYMTAB => self.symtab_lc = lc.cast(macho.symtab_command).?,
        .DYSYMTAB => self.dysymtab_lc = lc.cast(macho.dysymtab_command).?,
        .DYLD_INFO_ONLY => self.dyld_info_only_lc = lc.cast(macho.dyld_info_command).?,
        .DYLD_EXPORTS_TRIE => self.dyld_exports_trie_lc = lc.cast(macho.linkedit_data_command).?,
        .DYLD_CHAINED_FIXUPS => self.dyld_chained_fixups_lc = lc.cast(macho.linkedit_data_command).?,
        .DATA_IN_CODE => self.data_in_code_lc = lc.cast(macho.linkedit_data_command).?,
        else => {},
    };

    if (self.symtab_lc) |lc| {
        self.symtab = @as([*]align(1) const macho.nlist_64, @ptrCast(self.data.ptr + lc.symoff))[0..lc.nsyms];
        self.strtab = self.data[lc.stroff..][0..lc.strsize];

        // Filter defined symbols, sort by address and then by seniority
        try self.sorted_symtab.ensureTotalCapacityPrecise(self.gpa, self.symtab.len);
        for (self.symtab, 0..) |sym, idx| {
            if (sym.stab() or !sym.sect()) continue;
            self.sorted_symtab.appendAssumeCapacity(.{ .index = @intCast(idx), .size = 0 });
        }

        mem.sort(SymbolAtIndex, self.sorted_symtab.items, self, SymbolAtIndex.lessThan);

        // Remove duplicates
        var i: usize = 0;
        while (i < self.sorted_symtab.items.len) : (i += 1) {
            const start = i;
            const curr = self.sorted_symtab.items[start].getSymbol(self);

            while (i < self.sorted_symtab.items.len and
                self.sorted_symtab.items[i].getSymbol(self).n_sect == curr.n_sect and
                self.sorted_symtab.items[i].getSymbol(self).n_value == curr.n_value) : (i += 1)
            {}

            for (1..i - start) |_| {
                _ = self.sorted_symtab.orderedRemove(start + 1);
            }
            i = start;
        }

        // Estimate symbol sizes
        i = 0;
        while (i < self.sorted_symtab.items.len) : (i += 1) {
            const curr = self.sorted_symtab.items[i].getSymbol(self);
            const sect = self.getSectionByIndex(curr.n_sect);
            const end = if (i + 1 < self.sorted_symtab.items.len)
                self.sorted_symtab.items[i + 1].getSymbol(self).n_value
            else
                sect.addr + sect.size;
            const size = end - curr.n_value;
            self.sorted_symtab.items[i].size = size;
        }
    }
}

pub fn dumpString(self: Object, sect: macho.section_64, writer: anytype) !void {
    try writer.print("String dump of section '{s},{s}':\n", .{ sect.segName(), sect.sectName() });
    const data = self.data[sect.offset..][0..sect.size];
    var start: usize = 0;
    while (start < data.len) {
        try writer.print("  [{x: >6}]  ", .{start});
        var end = start;
        while (end < data.len - 1 and data[end] != 0) : (end += 1) {}
        if (data[end] != 0) {
            @panic("string not null terminated");
        }
        end += 1;
        const string = data[start..end];
        try writer.print("{s}\n", .{std.fmt.fmtSliceEscapeLower(string)});
        start = end;
    }
}

pub fn dumpHex(self: Object, sect: macho.section_64, writer: anytype) !void {
    try writer.print("Hex dump of section '{s},{s}':\n", .{ sect.segName(), sect.sectName() });
    const data = self.data[sect.offset..][0..sect.size];
    try fmtBlobHex(data, writer);
}

// Format as 4 hex columns and 1 ascii column.
// xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
fn fmtBlobHex(blob: []const u8, writer: anytype) !void {
    const step = 16;
    var hex_buf: [step]u8 = undefined;
    var str_buf: [step]u8 = undefined;
    var i: usize = 0;
    while (i < blob.len) : (i += step) {
        try writer.print("  0x{x:0>8} ", .{i});
        const end = if (blob[i..].len >= step) step else blob[i..].len;
        @memset(&hex_buf, 0);
        @memcpy(hex_buf[0..end], blob[i .. i + end]);
        var j: usize = 0;
        while (j < step) : (j += 4) {
            try writer.print("{x:<8} ", .{std.fmt.fmtSliceHexLower(hex_buf[j .. j + 4])});
        }
        _ = try std.fmt.bufPrint(&str_buf, "{s}", .{&hex_buf});
        std.mem.replaceScalar(u8, &str_buf, 0, '.');
        try writer.print("{s}\n", .{std.fmt.fmtSliceEscapeLower(&str_buf)});
    }
}

pub fn printHeader(self: Object, writer: anytype) !void {
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

pub fn printLoadCommands(self: Object, writer: anytype) !void {
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
            .UUID => try printUuidLC(fmt, lc, writer),
            .RPATH => try printRpathLC(fmt, lc, writer),
            .ID_DYLIB,
            .LOAD_DYLIB,
            .LOAD_WEAK_DYLIB,
            .LOAD_UPWARD_DYLIB,
            .REEXPORT_DYLIB,
            => try printDylibLC(fmt, lc, writer),
            .DATA_IN_CODE,
            .CODE_SIGNATURE,
            .FUNCTION_STARTS,
            .LINKER_OPTIMIZATION_HINT,
            .DYLIB_CODE_SIGN_DRS,
            .SEGMENT_SPLIT_INFO,
            .DYLD_CHAINED_FIXUPS,
            .DYLD_EXPORTS_TRIE,
            => try printLinkeditDataLC(fmt, lc, writer),
            .SYMTAB => try printSymtabLC(fmt, lc, writer),
            .DYSYMTAB => try printDysymtabLC(fmt, lc, writer),
            .BUILD_VERSION => try printBuildVersionLC(fmt, lc, writer),
            .VERSION_MIN_MACOSX,
            .VERSION_MIN_IPHONEOS,
            .VERSION_MIN_WATCHOS,
            .VERSION_MIN_TVOS,
            => try printVersionMinLC(fmt, lc, writer),
            .ID_DYLINKER,
            .LOAD_DYLINKER,
            .DYLD_ENVIRONMENT,
            => try printDylinkerLC(fmt, lc, writer),
            .MAIN => try printEntryPointLC(fmt, lc, writer),
            .SOURCE_VERSION => try printSourceVersionLC(fmt, lc, writer),
            else => {},
        }

        try writer.writeByte('\n');
    }
}

fn printGenericLC(f: anytype, lc: macho.LoadCommandIterator.LoadCommand, writer: anytype) !void {
    try writer.print(f.fmt("s"), .{ "Command:", @tagName(lc.cmd()) });
    try writer.print(f.fmt("x"), .{ "Command size:", lc.cmdsize() });
}

fn printSourceVersionLC(f: anytype, lc: macho.LoadCommandIterator.LoadCommand, writer: anytype) !void {
    const cmd = lc.cast(macho.source_version_command).?;
    try writer.print(f.fmt("d"), .{ "Version:", cmd.version });
}

fn printDylinkerLC(f: anytype, lc: macho.LoadCommandIterator.LoadCommand, writer: anytype) !void {
    const cmd = lc.cast(macho.dylinker_command).?;
    const data = lc.data[cmd.name..];
    const name = mem.sliceTo(data, 0);
    try writer.print(f.fmt("s"), .{ "Dynamic linker:", name });
}

fn printEntryPointLC(f: anytype, lc: macho.LoadCommandIterator.LoadCommand, writer: anytype) !void {
    const cmd = lc.cast(macho.entry_point_command).?;
    try writer.print(f.fmt("x"), .{ "Entry offset:", cmd.entryoff });
    try writer.print(f.fmt("d"), .{ "Initial stack size:", cmd.stacksize });
}

fn printSymtabLC(f: anytype, lc: macho.LoadCommandIterator.LoadCommand, writer: anytype) !void {
    const cmd = lc.cast(macho.symtab_command).?;
    try writer.print(f.fmt("x"), .{ "Symtab offset:", cmd.symoff });
    try writer.print(f.fmt("d"), .{ "Number of symbols:", cmd.nsyms });
    try writer.print(f.fmt("x"), .{ "Strtab offset:", cmd.stroff });
    try writer.print(f.fmt("d"), .{ "Strtab size:", cmd.strsize });
}

fn printDysymtabLC(f: anytype, lc: macho.LoadCommandIterator.LoadCommand, writer: anytype) !void {
    const cmd = lc.cast(macho.dysymtab_command).?;
    try writer.print(f.fmt("d"), .{ "Local syms index:", cmd.ilocalsym });
    try writer.print(f.fmt("d"), .{ "Number of locals:", cmd.nlocalsym });
    try writer.print(f.fmt("d"), .{ "Export syms index:", cmd.iextdefsym });
    try writer.print(f.fmt("d"), .{ "Number of exports:", cmd.nextdefsym });
    try writer.print(f.fmt("d"), .{ "Undef syms index:", cmd.iundefsym });
    try writer.print(f.fmt("d"), .{ "Number of undefs:", cmd.nundefsym });
    try writer.print(f.fmt("x"), .{ "ToC offset:", cmd.tocoff });
    try writer.print(f.fmt("d"), .{ "ToC entries:", cmd.ntoc });
    try writer.print(f.fmt("x"), .{ "Module tab offset:", cmd.modtaboff });
    try writer.print(f.fmt("d"), .{ "Module tab entries:", cmd.nmodtab });
    try writer.print(f.fmt("x"), .{ "Ref symtab offset:", cmd.extrefsymoff });
    try writer.print(f.fmt("d"), .{ "Ref symtab entries:", cmd.nextrefsyms });
    try writer.print(f.fmt("x"), .{ "Indsymtab offset:", cmd.indirectsymoff });
    try writer.print(f.fmt("d"), .{ "Indsymtab entries:", cmd.nindirectsyms });
    try writer.print(f.fmt("x"), .{ "Extrel offset:", cmd.extreloff });
    try writer.print(f.fmt("d"), .{ "Extrel entries:", cmd.nextrel });
    try writer.print(f.fmt("x"), .{ "Locrel offset:", cmd.locreloff });
    try writer.print(f.fmt("d"), .{ "Locrel entries:", cmd.nlocrel });
}

fn printBuildVersionLC(f: anytype, lc: macho.LoadCommandIterator.LoadCommand, writer: anytype) !void {
    const cmd = lc.cast(macho.build_version_command).?;
    try writer.print(f.fmt("s"), .{ "Platform:", @tagName(cmd.platform) });
    try writer.print(f.fmt("d"), .{ "Min OS version:", cmd.minos });
    try writer.print(f.fmt("d"), .{ "SDK version:", cmd.sdk });
    try writer.print(f.fmt("d"), .{ "Number of tools:", cmd.ntools });

    const tools = lc.getBuildVersionTools();
    for (tools) |tool| {
        switch (tool.tool) {
            .CLANG, .SWIFT, .LD, .LLD, .ZIG => try writer.print(f.fmt("s"), .{ "Tool:", @tagName(tool.tool) }),
            else => try writer.print(f.fmt("x"), .{ "Tool:", @intFromEnum(tool.tool) }),
        }
        try writer.print(f.fmt("d"), .{ "Version:", tool.version });
    }
}

fn printVersionMinLC(f: anytype, lc: macho.LoadCommandIterator.LoadCommand, writer: anytype) !void {
    const cmd = lc.cast(macho.version_min_command).?;
    try writer.print(f.fmt("d"), .{ "Version:", cmd.version });
    try writer.print(f.fmt("d"), .{ "SDK version:", cmd.sdk });
}

fn printRpathLC(f: anytype, lc: macho.LoadCommandIterator.LoadCommand, writer: anytype) !void {
    const rpath = lc.getRpathPathName();
    try writer.print(f.fmt("s"), .{ "Path:", rpath });
}

fn printUuidLC(f: anytype, lc: macho.LoadCommandIterator.LoadCommand, writer: anytype) !void {
    const cmd = lc.cast(macho.uuid_command).?;
    var buffer: [64]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(&buffer, &cmd.uuid);
    try writer.print(f.fmt("s"), .{ "UUID:", encoded });
}

fn printDylibLC(f: anytype, lc: macho.LoadCommandIterator.LoadCommand, writer: anytype) !void {
    const name = lc.getDylibPathName();
    const cmd = lc.cast(macho.dylib_command).?;
    try writer.print(f.fmt("s"), .{ "Name:", name });
    try writer.print(f.fmt("d"), .{ "Timestamp:", cmd.dylib.timestamp });
    try writer.print(f.fmt("d"), .{ "Current version:", cmd.dylib.current_version });
    try writer.print(f.fmt("d"), .{ "Compat version:", cmd.dylib.compatibility_version });
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

fn printLinkeditDataLC(f: anytype, lc: macho.LoadCommandIterator.LoadCommand, writer: anytype) !void {
    const cmd = lc.cast(macho.linkedit_data_command).?;
    try writer.print(f.fmt("x"), .{ "Data offset:", cmd.dataoff });
    try writer.print(f.fmt("x"), .{ "Data size:", cmd.datasize });
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

pub fn printDyldInfo(self: Object, writer: anytype) !void {
    const lc = self.dyld_info_only_lc orelse {
        return writer.writeAll("LC_DYLD_INFO_ONLY load command not found\n");
    };

    const rebase_data = self.data[lc.rebase_off..][0..lc.rebase_size];
    if (rebase_data.len > 0) {
        try writer.writeAll("REBASE INFO:\n");
        try self.printRebaseInfo(rebase_data, writer);
    }

    const bind_data = self.data[lc.bind_off..][0..lc.bind_size];
    if (bind_data.len > 0) {
        try writer.writeAll("\nBIND INFO:\n");
        try self.printBindInfo(bind_data, writer);
    }

    const weak_bind_data = self.data[lc.weak_bind_off..][0..lc.weak_bind_size];
    if (weak_bind_data.len > 0) {
        try writer.writeAll("\nWEAK BIND INFO:\n");
        try self.printBindInfo(weak_bind_data, writer);
    }

    const lazy_bind_data = self.data[lc.lazy_bind_off..][0..lc.lazy_bind_size];
    if (lazy_bind_data.len > 0) {
        try writer.writeAll("\nLAZY BIND INFO:\n");
        try self.printBindInfo(lazy_bind_data, writer);
    }
}

fn printRebaseInfo(self: Object, data: []const u8, writer: anytype) !void {
    var rebases = std.ArrayList(u64).init(self.gpa);
    defer rebases.deinit();
    try self.parseRebaseInfo(data, &rebases, writer);
    mem.sort(u64, rebases.items, {}, std.sort.asc(u64));
    for (rebases.items) |addr| {
        try writer.print("0x{x}\n", .{addr});
    }
}

fn parseRebaseInfo(self: Object, data: []const u8, rebases: *std.ArrayList(u64), writer: anytype) !void {
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

    var seg_id: ?u8 = null;
    var offset: u64 = 0;
    while (true) {
        const byte = reader.readByte() catch break;
        const opc = byte & macho.REBASE_OPCODE_MASK;
        const imm = byte & macho.REBASE_IMMEDIATE_MASK;
        switch (opc) {
            macho.REBASE_OPCODE_DONE => {
                if (self.verbose) {
                    try writer.print(fmt_value, .{ byte, "REBASE_OPCODE_DONE", "", imm });
                }
                break;
            },
            macho.REBASE_OPCODE_SET_TYPE_IMM => {
                if (self.verbose) {
                    const tt = switch (imm) {
                        macho.REBASE_TYPE_POINTER => "REBASE_TYPE_POINTER",
                        macho.REBASE_TYPE_TEXT_ABSOLUTE32 => "REBASE_TYPE_TEXT_ABSOLUTE32",
                        macho.REBASE_TYPE_TEXT_PCREL32 => "REBASE_TYPE_TEXT_PCREL32",
                        else => "UNKNOWN",
                    };
                    try writer.print(fmt_value, .{ byte, "REBASE_OPCODE_SET_TYPE_IMM", tt, imm });
                }
            },
            macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                seg_id = imm;
                const start = creader.bytes_read;
                offset = try std.leb.readULEB128(u64, reader);
                const end = creader.bytes_read;

                if (self.verbose) {
                    try writer.print(fmt_value, .{ byte, "REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB", "segment", seg_id.? });
                    if (end - start > 1) {
                        try writer.print("    {x:0<2}..{x:0<2}   {s: <50} {s: >20} ({x})\n", .{
                            data[start], data[end - 1], "", "offset", offset,
                        });
                    } else {
                        try writer.print("    {x:0<2} {s: <56} {s: >20} ({x})\n", .{ data[start], "", "offset", offset });
                    }
                }
            },
            macho.REBASE_OPCODE_ADD_ADDR_IMM_SCALED => {
                offset += imm * @sizeOf(u64);
                if (self.verbose) {
                    try writer.print(fmt_value, .{ byte, "REBASE_OPCODE_ADD_ADDR_IMM_SCALED", "scale", imm });
                }
            },
            macho.REBASE_OPCODE_ADD_ADDR_ULEB => {
                const addend = try std.leb.readULEB128(u64, reader);
                offset += addend;
                if (self.verbose) {
                    try writer.print(fmt_value, .{ byte, "REBASE_OPCODE_ADD_ADDR_ULEB", "addr", addend });
                }
            },
            macho.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB => {
                const addend = try std.leb.readULEB128(u64, reader);

                if (self.verbose) {
                    // TODO clean up formatting
                    try writer.print(fmt_value, .{ byte, "REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB", "addr", addend });
                }

                const seg = segments.items[seg_id.?];
                const addr = seg.vmaddr + offset;
                if (addr > seg.vmaddr + seg.vmsize) {
                    std.log.err("malformed rebase: address {x} outside of segment {s} ({d})!", .{
                        addr,
                        seg.segName(),
                        seg_id.?,
                    });
                    continue;
                }
                try rebases.append(addr);
                offset += addend + @sizeOf(u64);
            },
            macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES,
            macho.REBASE_OPCODE_DO_REBASE_ULEB_TIMES,
            macho.REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB,
            => {
                var ntimes: u64 = 1;
                var skip: u64 = 0;
                switch (opc) {
                    macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES => {
                        ntimes = imm;
                        if (self.verbose) {
                            try writer.print(fmt_value, .{
                                byte,
                                "REBASE_OPCODE_DO_REBASE_IMM_TIMES",
                                "count",
                                ntimes,
                            });
                        }
                    },
                    macho.REBASE_OPCODE_DO_REBASE_ULEB_TIMES => {
                        ntimes = try std.leb.readULEB128(u64, reader);
                        if (self.verbose) {
                            try writer.print(fmt_value, .{
                                byte,
                                "REBASE_OPCODE_DO_REBASE_ULEB_TIMES",
                                "count",
                                ntimes,
                            });
                        }
                    },
                    macho.REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
                        ntimes = try std.leb.readULEB128(u64, reader);
                        const start = creader.bytes_read;
                        skip = try std.leb.readULEB128(u64, reader);
                        if (self.verbose) {
                            try writer.print(fmt_value, .{
                                byte,
                                "REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB",
                                "count",
                                ntimes,
                            });
                            try writer.print("    {x:0<2} {s: <56} {s: >20} ({x})\n", .{
                                data[start],
                                "",
                                "skip",
                                skip,
                            });
                        }
                    },
                    else => unreachable,
                }
                const seg = segments.items[seg_id.?];
                const base_addr = seg.vmaddr;
                var count: usize = 0;
                while (count < ntimes) : (count += 1) {
                    const addr = base_addr + offset;
                    if (addr > seg.vmaddr + seg.vmsize) {
                        std.log.err("malformed rebase: address {x} outside of segment {s} ({d})!", .{
                            addr,
                            seg.segName(),
                            seg_id.?,
                        });
                        continue;
                    }
                    try rebases.append(addr);
                    offset += skip + @sizeOf(u64);
                }
            },
            else => {
                std.log.err("unknown opcode: {x}", .{opc});
                break;
            },
        }
    }
}

fn printBindInfo(self: Object, data: []const u8, writer: anytype) !void {
    var bindings = std.ArrayList(Binding).init(self.gpa);
    defer bindings.deinit();
    try self.parseBindInfo(data, &bindings, writer);
    mem.sort(Binding, bindings.items, {}, Binding.lessThan);
    for (bindings.items) |binding| {
        try writer.print("0x{x} [addend: {d}]", .{ binding.address, binding.addend });
        try writer.writeAll(" (");
        switch (binding.tag) {
            .self => try writer.writeAll("self"),
            .exe => try writer.writeAll("main executable"),
            .flat => try writer.writeAll("flat lookup"),
            .ord => {
                const dylib_name = self.getDylibNameByIndex(binding.ordinal);
                try writer.print("{s}", .{dylib_name});
            },
        }
        try writer.print(") {s}\n", .{binding.name});
    }
}

const Binding = struct {
    address: u64,
    addend: i64,
    name: []const u8,
    tag: Tag,
    ordinal: u16,

    fn lessThan(ctx: void, lhs: Binding, rhs: Binding) bool {
        _ = ctx;
        return lhs.address < rhs.address;
    }

    const Tag = enum {
        ord,
        self,
        exe,
        flat,
    };
};

fn parseBindInfo(self: Object, data: []const u8, bindings: *std.ArrayList(Binding), writer: anytype) !void {
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

    const fmt_value = "    {x:0<2}       {s: <50} {s: >20} ({x})\n";

    var seg_id: ?u8 = null;
    var tag: Binding.Tag = .self;
    var ordinal: u16 = 0;
    var offset: u64 = 0;
    var addend: i64 = 0;

    var name_buf = std.ArrayList(u8).init(self.gpa);
    defer name_buf.deinit();

    while (true) {
        const byte = reader.readByte() catch break;
        const opc = byte & macho.BIND_OPCODE_MASK;
        const imm = byte & macho.BIND_IMMEDIATE_MASK;
        switch (opc) {
            macho.BIND_OPCODE_DONE => {
                if (self.verbose) {
                    try writer.print(fmt_value, .{ byte, "BIND_OPCODE_DONE", "", imm });
                }
            },
            macho.BIND_OPCODE_SET_TYPE_IMM => {
                if (self.verbose) {
                    const tt = switch (imm) {
                        macho.BIND_TYPE_POINTER => "BIND_TYPE_POINTER",
                        macho.BIND_TYPE_TEXT_ABSOLUTE32 => "BIND_TYPE_TEXT_ABSOLUTE32",
                        macho.BIND_TYPE_TEXT_PCREL32 => "BIND_TYPE_TEXT_PCREL32",
                        else => "UNKNOWN",
                    };
                    try writer.print(fmt_value, .{ byte, "BIND_OPCODE_SET_TYPE_IMM", tt, imm });
                }
            },
            macho.BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => {
                tag = .ord;
                ordinal = imm;
                if (self.verbose) {
                    try writer.print(fmt_value, .{
                        byte,
                        "BIND_OPCODE_SET_DYLIB_ORDINAL_IMM",
                        "",
                        imm,
                    });

                    const dylib_name = self.getDylibNameByIndex(imm);
                    try writer.print("             '{s}'\n", .{dylib_name});
                }
            },
            macho.BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                if (self.verbose) {
                    try writer.print(fmt_value, .{
                        byte,
                        "BIND_OPCODE_SET_DYLIB_SPECIAL_IMM",
                        "",
                        imm,
                    });
                }
                switch (imm) {
                    0 => tag = .self,
                    0xf => tag = .exe,
                    0xe => tag = .flat,
                    else => unreachable,
                }
            },
            macho.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                seg_id = imm;
                const start = creader.bytes_read;
                offset = try std.leb.readULEB128(u64, reader);
                const end = creader.bytes_read;

                if (self.verbose) {
                    try writer.print(fmt_value, .{
                        byte,
                        "BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB",
                        "segment",
                        seg_id.?,
                    });
                    if (end - start > 1) {
                        try writer.print("    {x:0<2}..{x:0<2}   {s: <50} {s: >20} ({x})\n", .{
                            data[start], data[end - 1], "", "offset", offset,
                        });
                    } else {
                        try writer.print("    {x:0<2} {s: <56} {s: >20} ({x})\n", .{
                            data[start],
                            "",
                            "offset",
                            offset,
                        });
                    }
                }
            },
            macho.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                name_buf.clearRetainingCapacity();
                try reader.readUntilDelimiterArrayList(&name_buf, 0, std.math.maxInt(u32));
                try name_buf.append(0);
                if (self.verbose) {
                    const name = name_buf.items;
                    try writer.print(fmt_value, .{
                        byte,
                        "BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM",
                        "flags",
                        imm,
                    });
                    try writer.print("    {x:0<2}..{x:0<2}   {s: <50} {s: >20} ({d})\n", .{
                        name[0],
                        name[name.len - 1],
                        "",
                        "string",
                        name.len,
                    });
                    try writer.print("             '{s}'\n", .{name});
                }
            },
            macho.BIND_OPCODE_SET_ADDEND_SLEB => {
                addend = try std.leb.readILEB128(i64, reader);
                if (self.verbose) {
                    try writer.print(fmt_value, .{
                        byte,
                        "BIND_OPCODE_SET_ADDEND_SLEB",
                        "addend",
                        addend,
                    });
                }
            },
            macho.BIND_OPCODE_ADD_ADDR_ULEB => {
                const x = try std.leb.readULEB128(u64, reader);
                if (self.verbose) {
                    try writer.print(fmt_value, .{ byte, "BIND_OPCODE_ADD_ADDR_ULEB", "addr", x });
                }
                offset = @intCast(@as(i64, @intCast(offset)) + @as(i64, @bitCast(x)));
            },
            macho.BIND_OPCODE_DO_BIND,
            macho.BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB,
            macho.BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED,
            macho.BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB,
            => {
                var add_addr: u64 = 0;
                var count: u64 = 1;
                var skip: u64 = 0;

                switch (opc) {
                    macho.BIND_OPCODE_DO_BIND => {
                        if (self.verbose) {
                            try writer.print(fmt_value, .{ byte, "BIND_OPCODE_DO_BIND", "", imm });
                        }
                    },
                    macho.BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                        add_addr = try std.leb.readULEB128(u64, reader);
                        if (self.verbose) {
                            try writer.print(fmt_value, .{
                                byte,
                                "BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB",
                                "addr",
                                add_addr,
                            });
                        }
                    },
                    macho.BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                        add_addr = imm * @sizeOf(u64);
                        if (self.verbose) {
                            try writer.print(fmt_value, .{
                                byte,
                                "BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED",
                                "scale",
                                imm,
                            });
                        }
                    },
                    macho.BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                        count = try std.leb.readULEB128(u64, reader);
                        const start = creader.bytes_read;
                        skip = try std.leb.readULEB128(u64, reader);
                        if (self.verbose) {
                            try writer.print(fmt_value, .{
                                byte,
                                "BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB",
                                "count",
                                count,
                            });
                            try writer.print("    {x:0<2} {s: <56} {s: >20} ({x})\n", .{
                                data[start],
                                "",
                                "skip",
                                skip,
                            });
                        }
                    },
                    else => unreachable,
                }

                const seg = segments.items[seg_id.?];
                var i: u64 = 0;
                while (i < count) : (i += 1) {
                    const addr: u64 = @intCast(@as(i64, @intCast(seg.vmaddr + offset)));
                    if (addr > seg.vmaddr + seg.vmsize) {
                        std.log.err("malformed rebase: address {x} outside of segment {s} ({d})!", .{
                            addr,
                            seg.segName(),
                            seg_id.?,
                        });
                        continue;
                    }
                    try bindings.append(.{
                        .address = addr,
                        .addend = addend,
                        .tag = tag,
                        .ordinal = ordinal,
                        .name = try self.gpa.dupe(u8, name_buf.items),
                    });

                    offset += skip + @sizeOf(u64) + add_addr;
                }
            },
            else => {
                std.log.err("unknown opcode: {x}", .{opc});
                break;
            },
        }
    }
}

const dyld_chained_fixups_header = extern struct {
    fixups_version: u32,
    starts_offset: u32,
    imports_offset: u32,
    symbols_offset: u32,
    imports_count: u32,
    imports_format: dyld_chained_import_format,
    symbols_format: dyld_chained_symbol_format,
};

const dyld_chained_import_format = enum(u32) {
    import = 1,
    import_addend = 2,
    import_addend64 = 3,
    _,
};

const dyld_chained_symbol_format = enum(u32) {
    uncompressed = 0,
    zlib = 1,
};

const dyld_chained_starts_in_image = extern struct {
    seg_count: u32,
    seg_info_count: [1]u32,
};

const dyld_chained_starts_in_segment = extern struct {
    size: u32,
    page_size: u32,
    pointer_format: dyld_chained_ptr,
    segment_offset: u64,
    max_valid_pointer: u32,
    page_count: u16,
    page_start: [1]u16,
};

const dyld_chained_ptr_start = struct {
    const none: u16 = 0xffff;
    const multi: u16 = 0x8000;
    const last: u16 = 0x8000;
};

const dyld_chained_ptr = enum(u16) {
    arm64e = 1,
    @"64" = 2,
    @"32" = 3,
    @"32_cache" = 4,
    @"32_firmware" = 5,
    @"64_offset" = 6,
    arm64e_kernel = 7,
    @"64_kernel_cache" = 8,
    arm64e_userland = 9,
    arm64_firmware = 10,
    x86_64_kernel_cache = 11,
    arm64e_userland24 = 12,
};

const dyld_chained_import = packed struct(u32) {
    lib_ordinal: u8,
    weak_import: bool,
    name_offset: u23,
};

const dyld_chained_import_addend = extern struct {
    hdr: packed struct(u32) {
        lib_ordinal: u8,
        weak_import: bool,
        name_offset: u23,
    },
    addend: i32,
};

const dyld_chained_import_addend64 = extern struct {
    hdr: packed struct(u64) {
        lib_ordinal: u16,
        weak_import: bool,
        reserved: u15 = 0,
        name_offset: u32,
    },
    addend: u64,
};

const dyld_chained_ptr_64_bind = packed struct(u64) {
    ordinal: u24,
    addend: u8,
    reserved: u19 = 0,
    next: u12,
    bind: bool = true, // always set to true
};

const dyld_chained_ptr_64_rebase = packed struct(u64) {
    target: u36,
    high8: u8,
    reserved: u7 = 0,
    next: u12,
    bind: bool = false, // always set to false
};

pub fn printChainedFixups(self: Object, writer: anytype) !void {
    const lc = self.dyld_chained_fixups_lc orelse
        return writer.print("LC_DYLD_CHAINED_FIXUPS load command not found\n", .{});
    const data = self.data[lc.dataoff..][0..lc.datasize];
    const hdr = @as(*align(1) const dyld_chained_fixups_header, @ptrCast(data.ptr)).*;
    try writer.writeAll("CHAINED FIXUPS HEADER:\n");
    try writer.print("  fixups_version : {d}\n", .{hdr.fixups_version});
    try writer.print("  starts_offset  : 0x{x} ({d})\n", .{ hdr.starts_offset, hdr.starts_offset });
    try writer.print("  imports_offset : 0x{x} ({d})\n", .{ hdr.imports_offset, hdr.imports_offset });
    try writer.print("  symbols_offset : 0x{x} ({d})\n", .{ hdr.symbols_offset, hdr.symbols_offset });
    try writer.print("  imports_count  : {d}\n", .{hdr.imports_count});
    try writer.print("  imports_format : {d} ({s})\n", .{ @as(u32, @intFromEnum(hdr.imports_format)), @tagName(hdr.imports_format) });
    try writer.print("  symbols_format : {d} ({s})\n", .{ @as(u32, @intFromEnum(hdr.symbols_format)), @tagName(hdr.symbols_format) });

    try writer.print("{x}\n", .{std.fmt.fmtSliceHexLower(data)});
}

pub fn printExportsTrie(self: Object, writer: anytype) !void {
    const maybe_data = if (self.dyld_info_only_lc) |lc|
        self.data[lc.export_off..][0..lc.export_size]
    else if (self.dyld_exports_trie_lc) |lc|
        self.data[lc.dataoff..][0..lc.datasize]
    else
        null;
    const data = maybe_data orelse
        return writer.print("LC_DYLD_INFO_ONLY or LC_DYLD_EXPORTS_TRIE load command not found\n", .{});

    var arena = std.heap.ArenaAllocator.init(self.gpa);
    defer arena.deinit();

    var exports = std.ArrayList(Export).init(self.gpa);
    defer exports.deinit();

    var it = TrieIterator{ .data = data };
    try parseTrieNode(arena.allocator(), &it, "", &exports, self.verbose, writer);

    mem.sort(Export, exports.items, {}, Export.lessThan);

    const seg = self.getSegmentByName("__TEXT").?;

    if (self.verbose) try writer.writeByte('\n');
    try writer.writeAll("Exports:\n");
    for (exports.items) |exp| {
        switch (exp.tag) {
            .@"export" => {
                const info = exp.data.@"export";
                if (info.kind != .regular or info.weak) {
                    try writer.writeByte('[');
                }
                switch (info.kind) {
                    .regular => {},
                    .absolute => try writer.writeAll("ABS, "),
                    .tlv => try writer.writeAll("THREAD_LOCAL, "),
                }
                if (info.weak) try writer.writeAll("WEAK");
                if (info.kind != .regular or info.weak) {
                    try writer.writeAll("] ");
                }
                try writer.print("0x{x} ", .{seg.vmaddr + info.vmoffset});
            },
            else => {}, // TODO
        }

        try writer.print("{s}\n", .{exp.name});
    }
}

const TrieIterator = struct {
    data: []const u8,
    pos: usize = 0,

    fn getStream(it: *TrieIterator) std.io.FixedBufferStream([]const u8) {
        return std.io.fixedBufferStream(it.data[it.pos..]);
    }

    fn readULEB128(it: *TrieIterator) !u64 {
        var stream = it.getStream();
        var creader = std.io.countingReader(stream.reader());
        const reader = creader.reader();
        const value = try std.leb.readULEB128(u64, reader);
        it.pos += creader.bytes_read;
        return value;
    }

    fn readString(it: *TrieIterator) ![:0]const u8 {
        var stream = it.getStream();
        const reader = stream.reader();

        var count: usize = 0;
        while (true) : (count += 1) {
            const byte = try reader.readByte();
            if (byte == 0) break;
        }

        const str = @as([*:0]const u8, @ptrCast(it.data.ptr + it.pos))[0..count :0];
        it.pos += count + 1;
        return str;
    }

    fn readByte(it: *TrieIterator) !u8 {
        var stream = it.getStream();
        const value = try stream.reader().readByte();
        it.pos += 1;
        return value;
    }
};

const Export = struct {
    name: []const u8,
    tag: enum { @"export", reexport, stub_resolver },
    data: union {
        @"export": struct {
            kind: enum { regular, absolute, tlv },
            weak: bool = false,
            vmoffset: u64,
        },
        reexport: u64,
        stub_resolver: struct {
            stub_offset: u64,
            resolver_offset: u64,
        },
    },

    inline fn rankByTag(self: Export) u3 {
        return switch (self.tag) {
            .@"export" => 1,
            .reexport => 2,
            .stub_resolver => 3,
        };
    }

    fn lessThan(ctx: void, lhs: Export, rhs: Export) bool {
        _ = ctx;
        if (lhs.rankByTag() == rhs.rankByTag()) {
            return switch (lhs.tag) {
                .@"export" => lhs.data.@"export".vmoffset < rhs.data.@"export".vmoffset,
                .reexport => lhs.data.reexport < rhs.data.reexport,
                .stub_resolver => lhs.data.stub_resolver.stub_offset < rhs.data.stub_resolver.stub_offset,
            };
        }
        return lhs.rankByTag() < rhs.rankByTag();
    }
};

fn parseTrieNode(
    arena: Allocator,
    it: *TrieIterator,
    prefix: []const u8,
    exports: *std.ArrayList(Export),
    verbose: bool,
    writer: anytype,
) !void {
    const start = it.pos;
    const size = try it.readULEB128();
    if (verbose) try writer.print("0x{x:0>8}  size: {d}\n", .{ start, size });
    if (size > 0) {
        const flags = try it.readULEB128();
        if (verbose) try writer.print("{s: >12}flags: 0x{x}\n", .{ "", flags });
        switch (flags) {
            macho.EXPORT_SYMBOL_FLAGS_REEXPORT => {
                const ord = try it.readULEB128();
                const name = try arena.dupe(u8, try it.readString());
                if (verbose) {
                    try writer.print("{s: >12}ordinal: {d}\n", .{ "", ord });
                    try writer.print("{s: >12}install_name: {s}\n", .{ "", name });
                }
                try exports.append(.{
                    .name = if (name.len > 0) name else prefix,
                    .tag = .reexport,
                    .data = .{ .reexport = ord },
                });
            },
            macho.EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER => {
                const stub_offset = try it.readULEB128();
                const resolver_offset = try it.readULEB128();
                if (verbose) {
                    try writer.print("{s: >12}stub_offset: 0x{x}\n", .{ "", stub_offset });
                    try writer.print("{s: >12}resolver_offset: 0x{x}\n", .{ "", resolver_offset });
                }
                try exports.append(.{
                    .name = prefix,
                    .tag = .stub_resolver,
                    .data = .{ .stub_resolver = .{
                        .stub_offset = stub_offset,
                        .resolver_offset = resolver_offset,
                    } },
                });
            },
            else => {
                const vmoff = try it.readULEB128();
                if (verbose) try writer.print("{s: >12}vmoffset: 0x{x}\n", .{ "", vmoff });
                try exports.append(.{
                    .name = prefix,
                    .tag = .@"export",
                    .data = .{ .@"export" = .{
                        .kind = switch (flags & macho.EXPORT_SYMBOL_FLAGS_KIND_MASK) {
                            macho.EXPORT_SYMBOL_FLAGS_KIND_REGULAR => .regular,
                            macho.EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE => .absolute,
                            macho.EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL => .tlv,
                            else => unreachable,
                        },
                        .weak = flags & macho.EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION != 0,
                        .vmoffset = vmoff,
                    } },
                });
            },
        }
    }
    const nedges = try it.readByte();
    if (verbose) try writer.print("{s: >12}nedges: {d}\n", .{ "", nedges });

    var edges: [256]struct { off: u64, label: [:0]const u8 } = undefined;

    for (0..nedges) |i| {
        const label = try it.readString();
        const off = try it.readULEB128();
        if (verbose) try writer.print("{s: >12}label: {s}\n", .{ "", label });
        if (verbose) try writer.print("{s: >12}next: 0x{x}\n", .{ "", off });
        edges[i] = .{ .off = off, .label = label };
    }

    for (edges[0..nedges]) |edge| {
        const prefix_label = try std.fmt.allocPrint(arena, "{s}{s}", .{ prefix, edge.label });
        const curr = it.pos;
        it.pos = edge.off;
        if (verbose) try writer.writeByte('\n');
        try parseTrieNode(arena, it, prefix_label, exports, verbose, writer);
        it.pos = curr;
    }
}

const UnwindInfoTargetNameAndAddend = struct {
    tag: enum { symbol, section },
    name: u32,
    addend: u64,

    fn getName(self: UnwindInfoTargetNameAndAddend, object: *const Object) []const u8 {
        switch (self.tag) {
            .symbol => return object.getString(self.name),
            .section => return object.getSectionByIndex(@intCast(self.name)).sectName(),
        }
    }
};

fn getUnwindInfoTargetNameAndAddend(
    self: *const Object,
    rel: macho.relocation_info,
    code: u64,
) UnwindInfoTargetNameAndAddend {
    if (rel.r_extern == 1) {
        const sym = self.symtab[rel.r_symbolnum];
        return .{
            .tag = .symbol,
            .name = sym.n_strx,
            .addend = code,
        };
    }
    if (self.findSymbolByAddress(code)) |sym| {
        return .{
            .tag = .symbol,
            .name = sym.n_strx,
            .addend = code - sym.n_value,
        };
    } else {
        const sect = self.getSectionByIndex(@intCast(rel.r_symbolnum));
        return .{
            .tag = .section,
            .name = rel.r_symbolnum,
            .addend = code - sect.addr,
        };
    }
}

pub fn printUnwindInfo(self: *const Object, writer: anytype) !void {
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
        const entries = @as([*]align(1) const macho.compact_unwind_entry, @ptrCast(data))[0..num_entries];
        const relocs = relocs: {
            const relocs = @as([*]align(1) const macho.relocation_info, @ptrCast(self.data.ptr + sect.reloff))[0..sect.nreloc];
            const out = try self.gpa.alloc(macho.relocation_info, relocs.len);
            @memcpy(out, relocs);
            break :relocs out;
        };
        defer self.gpa.free(relocs);

        const sortFn = struct {
            fn sortFn(ctx: void, lhs: macho.relocation_info, rhs: macho.relocation_info) bool {
                _ = ctx;
                return lhs.r_address > rhs.r_address;
            }
        }.sortFn;
        mem.sort(macho.relocation_info, relocs, {}, sortFn);

        try writer.writeAll("Contents of __LD,__compact_unwind section:\n");

        for (entries, 0..) |entry, i| {
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

            try writer.print("  Entry at offset 0x{x}:\n", .{i * @sizeOf(macho.compact_unwind_entry)});
            try writer.print("    {s: <22} 0x{x}", .{ "start:", entry.rangeStart });
            if (func.addend > 0) {
                try writer.print(" + {x}", .{func.addend});
            }
            try writer.print(" {s}\n", .{func.getName(self)});
            try writer.print("    {s: <22} 0x{x}\n", .{ "length:", entry.rangeLength });

            if (!self.verbose) {
                try writer.print("    {s: <22} 0x{x:0>8}\n", .{ "compact encoding:", entry.compactUnwindEncoding });
            }

            if (personality) |x| {
                try writer.print("    {s: <22} 0x{x}", .{ "personality function:", entry.personalityFunction });
                if (x.addend > 0) {
                    try writer.print(" + {x}", .{x.addend});
                }
                try writer.print(" {s}\n", .{x.getName(self)});
            }

            if (lsda) |x| {
                try writer.print("    {s: <22} 0x{x}", .{ "LSDA:", entry.lsda });
                if (x.addend > 0) {
                    try writer.print(" + {x}", .{x.addend});
                }
                try writer.print(" {s}\n", .{x.getName(self)});
            }

            if (self.verbose) {
                try writer.print("    {s: <22}\n", .{"compact encoding:"});

                switch (self.arch) {
                    .aarch64 => {
                        const enc = try UnwindEncodingArm64.fromU32(entry.compactUnwindEncoding);
                        try formatCompactUnwindEncodingArm64(enc, writer, .{
                            .prefix = 12,
                        });
                    },
                    .x86_64 => {
                        const enc = try UnwindEncodingX86_64.fromU32(entry.compactUnwindEncoding);
                        try formatCompactUnwindEncodingX86_64(enc, writer, .{
                            .prefix = 12,
                        });
                    },
                    else => unreachable,
                }
            }
        }
    } else {
        const sect = self.getSectionByName("__TEXT", "__unwind_info") orelse {
            try writer.writeAll("No __TEXT,__unwind_info section found.\n");
            return;
        };

        const data = self.data[sect.offset..][0..sect.size];
        const header = @as(*align(1) const macho.unwind_info_section_header, @ptrCast(data.ptr)).*;

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

        const common_encodings = @as(
            [*]align(1) const macho.compact_unwind_encoding_t,
            @ptrCast(data.ptr + header.commonEncodingsArraySectionOffset),
        )[0..header.commonEncodingsArrayCount];

        try writer.print("\n  Common encodings: (count = {d})\n", .{common_encodings.len});

        for (common_encodings, 0..) |raw, i| {
            if (self.verbose) blk: {
                try writer.print("    encoding[{d}]\n", .{i});
                switch (self.arch) {
                    .aarch64 => {
                        const enc = UnwindEncodingArm64.fromU32(raw) catch |err| switch (err) {
                            error.UnknownEncoding => if (raw == 0) {
                                try writer.writeAll("          none\n");
                                break :blk;
                            } else return err,
                        };
                        try formatCompactUnwindEncodingArm64(enc, writer, .{
                            .prefix = 6,
                        });
                    },
                    .x86_64 => {
                        const enc = UnwindEncodingX86_64.fromU32(raw) catch |err| switch (err) {
                            error.UnknownEncoding => if (raw == 0) {
                                try writer.writeAll("          none\n");
                                break :blk;
                            } else return err,
                        };
                        try formatCompactUnwindEncodingX86_64(enc, writer, .{
                            .prefix = 6,
                        });
                    },
                    else => unreachable,
                }
            } else {
                try writer.print("    encoding[{d}]: 0x{x:0>8}\n", .{ i, raw });
            }
        }

        const personalities = @as(
            [*]align(1) const u32,
            @ptrCast(data.ptr + header.personalityArraySectionOffset),
        )[0..header.personalityArrayCount];

        try writer.print("\n  Personality functions: (count = {d})\n", .{personalities.len});

        for (personalities, 0..) |personality, i| {
            if (self.verbose) {
                const seg = self.getSegmentByName("__TEXT").?;
                const addr = seg.vmaddr + personality;
                const target_sect = self.getSectionByAddress(addr).?;
                assert(target_sect.flags == macho.S_NON_LAZY_SYMBOL_POINTERS);
                const ptr = self.getGotPointerAtIndex(@divExact(addr - target_sect.addr, 8));
                if (self.findSymbolByAddress(ptr)) |sym| {
                    const name = self.getString(sym.n_strx);
                    try writer.print("    personality[{d}]: 0x{x} -> 0x{x} {s}\n", .{ i + 1, addr, ptr, name });
                } else {
                    // TODO we need to parse DYSYMTAB and figure out which import we are referring to
                    try writer.print("    personality[{d}]: 0x{x} -> 0x{x} {s}\n", .{
                        i + 1,
                        addr,
                        ptr,
                        "(undefined)",
                    });
                }
            } else {
                try writer.print("    personality[{d}]: 0x{x:0>8}\n", .{ i + 1, personality });
            }
        }

        const indexes = @as(
            [*]align(1) const macho.unwind_info_section_header_index_entry,
            @ptrCast(data.ptr + header.indexSectionOffset),
        )[0..header.indexCount];

        try writer.print("\n  Top level indices: (count = {d})\n", .{indexes.len});
        for (indexes, 0..) |entry, i| {
            if (self.verbose) {
                const seg = self.getSegmentByName("__TEXT").?;
                const name = if (self.findSymbolByAddress(seg.vmaddr + entry.functionOffset)) |sym|
                    self.getString(sym.n_strx)
                else
                    "unknown";

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
        const lsdas = @as(
            [*]align(1) const macho.unwind_info_section_header_lsda_index_entry,
            @ptrCast(data.ptr + indexes[0].lsdaIndexArraySectionOffset),
        )[0..num_lsdas];

        try writer.writeAll("\n  LSDA descriptors:\n");
        for (lsdas, 0..) |lsda, i| {
            if (self.verbose) {
                const seg = self.getSegmentByName("__TEXT").?;
                const func_name = if (self.findSymbolByAddress(seg.vmaddr + lsda.functionOffset)) |sym|
                    self.getString(sym.n_strx)
                else
                    "unknown";
                const lsda_name = if (self.findSymbolByAddress(seg.vmaddr + lsda.lsdaOffset)) |sym|
                    self.getString(sym.n_strx)
                else
                    "unknown";

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
        for (indexes, 0..) |entry, i| {
            const start_offset = entry.secondLevelPagesSectionOffset;
            if (start_offset == 0) break;

            if (self.verbose) {
                const seg = self.getSegmentByName("__TEXT").?;
                const func_name = if (self.findSymbolByAddress(seg.vmaddr + entry.functionOffset)) |func_sym|
                    self.getString(func_sym.n_strx)
                else
                    "unknown";
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

            const kind = @as(
                macho.UNWIND_SECOND_LEVEL,
                @enumFromInt(@as(*align(1) const u32, @ptrCast(data.ptr + start_offset)).*),
            );

            switch (kind) {
                .REGULAR => {
                    const page_header = @as(
                        *align(1) const macho.unwind_info_regular_second_level_page_header,
                        @ptrCast(data.ptr + start_offset),
                    ).*;

                    var pos = start_offset + page_header.entryPageOffset;
                    var count: usize = 0;
                    while (count < page_header.entryCount) : (count += 1) {
                        const inner = @as(
                            *align(1) const macho.unwind_info_regular_second_level_entry,
                            @ptrCast(data.ptr + pos),
                        ).*;

                        if (self.verbose) blk: {
                            const seg = self.getSegmentByName("__TEXT").?;
                            const func_name = if (self.findSymbolByAddress(seg.vmaddr + inner.functionOffset)) |sym|
                                self.getString(sym.n_strx)
                            else
                                "unknown";

                            try writer.print("      [{d}] {s}\n", .{
                                count,
                                func_name,
                            });
                            try writer.print("        Function address: 0x{x:0>16}\n", .{
                                seg.vmaddr + inner.functionOffset,
                            });
                            try writer.writeAll("        Encoding:\n");

                            switch (self.arch) {
                                .aarch64 => {
                                    const enc = UnwindEncodingArm64.fromU32(inner.encoding) catch |err| switch (err) {
                                        error.UnknownEncoding => if (inner.encoding == 0) {
                                            try writer.writeAll("          none\n");
                                            break :blk;
                                        } else return err,
                                    };
                                    try formatCompactUnwindEncodingArm64(enc, writer, .{
                                        .prefix = 10,
                                    });
                                },
                                .x86_64 => {
                                    const enc = UnwindEncodingX86_64.fromU32(inner.encoding) catch |err| switch (err) {
                                        error.UnknownEncoding => if (inner.encoding == 0) {
                                            try writer.writeAll("          none\n");
                                            break :blk;
                                        } else return err,
                                    };
                                    try formatCompactUnwindEncodingX86_64(enc, writer, .{
                                        .prefix = 10,
                                    });
                                },
                                else => unreachable,
                            }
                        } else {
                            try writer.print("      [{d}]: function offset=0x{x:0>8}, encoding=0x{x:0>8}\n", .{
                                count,
                                inner.functionOffset,
                                inner.encoding,
                            });
                        }

                        pos += @sizeOf(macho.unwind_info_regular_second_level_entry);
                    }
                },
                .COMPRESSED => {
                    const page_header = @as(
                        *align(1) const macho.unwind_info_compressed_second_level_page_header,
                        @ptrCast(data.ptr + start_offset),
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
                            const raw = @as(*align(1) const macho.compact_unwind_encoding_t, @ptrCast(data.ptr + pos)).*;

                            if (self.verbose) blk: {
                                try writer.print("        encoding[{d}]\n", .{count + common_encodings.len});
                                switch (self.arch) {
                                    .aarch64 => {
                                        const enc = UnwindEncodingArm64.fromU32(raw) catch |err| switch (err) {
                                            error.UnknownEncoding => if (raw == 0) {
                                                try writer.writeAll("          none\n");
                                                break :blk;
                                            } else return err,
                                        };
                                        try formatCompactUnwindEncodingArm64(enc, writer, .{
                                            .prefix = 10,
                                        });
                                    },
                                    .x86_64 => {
                                        const enc = UnwindEncodingX86_64.fromU32(raw) catch |err| switch (err) {
                                            error.UnknownEncoding => if (raw == 0) {
                                                try writer.writeAll("          none\n");
                                                break :blk;
                                            } else return err,
                                        };
                                        try formatCompactUnwindEncodingX86_64(enc, writer, .{
                                            .prefix = 10,
                                        });
                                    },
                                    else => unreachable,
                                }
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
                        const inner = @as(*align(1) const u32, @ptrCast(data.ptr + pos)).*;
                        const func_offset = entry.functionOffset + (inner & 0xFFFFFF);
                        const id = inner >> 24;
                        const raw = if (id < common_encodings.len)
                            common_encodings[id]
                        else
                            page_encodings.items[id - common_encodings.len];

                        if (self.verbose) blk: {
                            const seg = self.getSegmentByName("__TEXT").?;
                            const func_name = if (self.findSymbolByAddress(seg.vmaddr + func_offset)) |func_sym|
                                self.getString(func_sym.n_strx)
                            else
                                "unknown";

                            try writer.print("      [{d}] {s}\n", .{ count, func_name });
                            try writer.print("        Function address: 0x{x:0>16}\n", .{seg.vmaddr + func_offset});
                            try writer.writeAll("        Encoding\n");

                            switch (self.arch) {
                                .aarch64 => {
                                    const enc = UnwindEncodingArm64.fromU32(raw) catch |err| switch (err) {
                                        error.UnknownEncoding => if (raw == 0) {
                                            try writer.writeAll("          none\n");
                                            break :blk;
                                        } else return err,
                                    };
                                    try formatCompactUnwindEncodingArm64(enc, writer, .{
                                        .prefix = 10,
                                    });
                                },

                                .x86_64 => {
                                    const enc = UnwindEncodingX86_64.fromU32(raw) catch |err| switch (err) {
                                        error.UnknownEncoding => if (raw == 0) {
                                            try writer.writeAll("          none\n");
                                            break :blk;
                                        } else return err,
                                    };
                                    try formatCompactUnwindEncodingX86_64(enc, writer, .{
                                        .prefix = 10,
                                    });
                                },
                                else => unreachable,
                            }
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

fn formatCompactUnwindEncodingArm64(enc: UnwindEncodingArm64, writer: anytype, comptime opts: struct {
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
            inline for (@typeInfo(@TypeOf(frame.x_reg_pairs)).@"struct".fields) |field| {
                try writer.print(prefix ++ "{s: <12} {}\n", .{
                    field.name,
                    @field(frame.x_reg_pairs, field.name) == 0b1,
                });
            }

            inline for (@typeInfo(@TypeOf(frame.d_reg_pairs)).@"struct".fields) |field| {
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

fn formatCompactUnwindEncodingX86_64(enc: UnwindEncodingX86_64, writer: anytype, comptime opts: struct {
    prefix: usize = 0,
}) !void {
    const prefix: [opts.prefix]u8 = [_]u8{' '} ** opts.prefix;
    try writer.print(prefix ++ "{s: <12} {}\n", .{ "start:", enc.start() });
    try writer.print(prefix ++ "{s: <12} {}\n", .{ "LSDA:", enc.hasLsda() });
    try writer.print(prefix ++ "{s: <12} {d}\n", .{ "personality:", enc.personalityIndex() });
    try writer.print(prefix ++ "{s: <12} {s}\n", .{ "mode:", @tagName(enc.mode()) });

    switch (enc) {
        .frameless => |frameless| {
            inline for (@typeInfo(@TypeOf(frameless)).@"struct".fields) |field| {
                try writer.print(prefix ++ "{s: <12} {x}\n", .{
                    field.name,
                    @field(frameless, field.name),
                });
            }
        },
        .frame => |frame| {
            inline for (@typeInfo(@TypeOf(frame)).@"struct".fields) |field| {
                try writer.print(prefix ++ "{s: <12} {x}\n", .{
                    field.name,
                    @field(frame, field.name),
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

pub fn printCodeSignature(self: Object, writer: anytype) !void {
    var it = self.getLoadCommandsIterator();
    while (it.next()) |lc| switch (lc.cmd()) {
        .CODE_SIGNATURE => return self.formatCodeSignatureData(lc.cast(macho.linkedit_data_command).?, writer),
        else => continue,
    };
    return writer.print("LC_CODE_SIGNATURE load command not found\n", .{});
}

fn formatCodeSignatureData(
    self: Object,
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
    const magic = mem.readInt(u32, ptr[0..4], .big);
    const length = mem.readInt(u32, ptr[4..8], .big);
    const count = mem.readInt(u32, ptr[8..12], .big);
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
        const tt = mem.readInt(u32, ptr[0..4], .big);
        const offset = mem.readInt(u32, ptr[4..8], .big);
        try writer.print("{{\n    Type: {s}(0x{x})\n    Offset: {}\n}}\n", .{ fmtCsSlotConst(tt), tt, offset });
        blobs.appendAssumeCapacity(.{
            .type = tt,
            .offset = offset,
        });
        ptr = ptr[8..];
    }

    for (blobs.items) |blob| {
        ptr = data[blob.offset..];
        const magic2 = mem.readInt(u32, ptr[0..4], .big);
        const length2 = mem.readInt(u32, ptr[4..8], .big);

        try writer.print("{{\n", .{});
        try writer.print("    Magic: {s}(0x{x})\n", .{ fmtCsMagic(magic2), magic2 });
        try writer.print("    Length: {}\n", .{length2});

        switch (magic2) {
            macho.CSMAGIC_CODEDIRECTORY => {
                const version = mem.readInt(u32, ptr[8..12], .big);
                const flags = mem.readInt(u32, ptr[12..16], .big);
                const hash_off = mem.readInt(u32, ptr[16..20], .big);
                const ident_off = mem.readInt(u32, ptr[20..24], .big);
                const n_special_slots = mem.readInt(u32, ptr[24..28], .big);
                const n_code_slots = mem.readInt(u32, ptr[28..32], .big);
                const code_limit = mem.readInt(u32, ptr[32..36], .big);
                const hash_size = ptr[36];
                const page_size = std.math.pow(u16, 2, ptr[39]);
                const team_off = mem.readInt(u32, ptr[48..52], .big);

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
                try writer.print("    Reserved: {}\n", .{mem.readInt(u32, ptr[40..44], .big)});

                switch (version) {
                    0x20400 => {
                        try writer.print("    Scatter offset: {}\n", .{mem.readInt(u32, ptr[44..48], .big)});
                        try writer.print("    Team offset: {}\n", .{team_off});
                        try writer.print("    Reserved: {}\n", .{mem.readInt(u32, ptr[52..56], .big)});
                        try writer.print("    Code limit 64: {}\n", .{mem.readInt(u64, ptr[56..64], .big)});
                        try writer.print("    Offset of executable segment: {}\n", .{mem.readInt(u64, ptr[64..72], .big)});
                        try writer.print("    Limit of executable segment: {}\n", .{mem.readInt(u64, ptr[72..80], .big)});
                        try writer.print("    Executable segment flags: 0x{x}\n", .{mem.readInt(u64, ptr[80..88], .big)});
                        ptr = ptr[88..];
                    },
                    0x20100 => {
                        try writer.print("    Scatter offset: {}\n", .{mem.readInt(u32, ptr[52..56], .big)});
                        ptr = ptr[56..];
                    },
                    else => {
                        ptr = ptr[52..];
                    },
                }

                const ident = mem.sliceTo(@as([*:0]const u8, @ptrCast(ptr)), 0);
                try writer.print("\nIdent: {s}\n", .{ident});
                ptr = ptr[ident.len + 1 ..];

                if (team_off > 0) {
                    assert(team_off - ident_off == ident.len + 1);
                    const team_ident = mem.sliceTo(@as([*:0]const u8, @ptrCast(ptr)), 0);
                    try writer.print("\nTeam ident: {s}\n", .{team_ident});
                    ptr = ptr[team_ident.len + 1 ..];
                }

                var j: isize = n_special_slots;
                while (j > 0) : (j -= 1) {
                    const hash = ptr[0..hash_size];
                    try writer.print("\nSpecial slot for {s}:\n", .{
                        fmtCsSlotConst(@as(u32, @intCast(if (j == 6) macho.CSSLOT_SIGNATURESLOT else j))),
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

                const req_count = try reader.readInt(u32, .big);

                var req_blobs = std.ArrayList(macho.BlobIndex).init(self.gpa);
                defer req_blobs.deinit();
                try req_blobs.ensureTotalCapacityPrecise(req_count);

                var next_req: usize = 0;
                while (next_req < req_count) : (next_req += 1) {
                    const tt = try reader.readInt(u32, .big);
                    const off = try reader.readInt(u32, .big);
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
                    const req_blob_magic = try reader.readInt(u32, .big);
                    const req_blob_len = try reader.readInt(u32, .big);

                    try writer.writeAll("\n    {\n");
                    try writer.print("        Magic: {s}(0x{x})\n", .{
                        fmtCsMagic(req_blob_magic),
                        req_blob_magic,
                    });
                    try writer.print("        Length: {}\n", .{req_blob_len});

                    while (reader.context.pos < req_blob_len) {
                        const next = try reader.readInt(u32, .big);
                        const op = @as(ExprOp, @enumFromInt(next));

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
                                const slot = try reader.readInt(i32, .big);
                                switch (slot) {
                                    LEAF_CERT => try writer.writeAll("\n    leaf"),
                                    ROOT_CERT => try writer.writeAll("\n    root"),
                                    else => try writer.print("\n    slot {d}", .{slot}),
                                }
                                try fmtCssmData(req_data, reader, writer);
                                try fmtReqMatch(req_data, reader, writer);
                            },
                            .op_cert_field => {
                                const slot = try reader.readInt(i32, .big);
                                switch (slot) {
                                    LEAF_CERT => try writer.writeAll("\n    leaf"),
                                    ROOT_CERT => try writer.writeAll("\n    root"),
                                    else => try writer.print("\n    slot {d}", .{slot}),
                                }
                                try fmtReqData(req_data, reader, writer);
                                try fmtReqMatch(req_data, reader, writer);
                            },
                            .op_platform => {
                                const platform = try reader.readInt(i32, .big);
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
                        const cd_length = mem.readInt(u32, cd_header[4..8], .big);
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
    const len = try reader.readInt(u32, .big);
    const pos = try reader.context.getPos();
    const data = buf[@as(usize, @intCast(pos))..][0..len];
    try reader.context.seekBy(@as(i64, @intCast(mem.alignForward(u32, len, @sizeOf(u32)))));
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
    try writer.print("\n      {d}.{d}", .{ q1, oid1 - @as(usize, q1) * 40 });

    while (pos < data.len) {
        const oid2 = getOid(data, &pos);
        try writer.print(".{d}", .{oid2});
    }

    try writer.print("  ({x})", .{std.fmt.fmtSliceHexLower(data)});
}

fn fmtReqTimestamp(buf: []const u8, reader: anytype, writer: anytype) !void {
    _ = buf;
    const ts = try reader.readInt(i64, .big);
    try writer.print("\n      {d}", .{ts});
}

fn fmtReqMatch(buf: []const u8, reader: anytype, writer: anytype) !void {
    const match = @as(MatchOperation, @enumFromInt(try reader.readInt(u32, .big)));
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
            @memset(tmp_buf[0..], 0);
        }
        @memcpy(&tmp_buf, blob[i .. i + end]);
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

pub fn verifyMemoryLayout(self: Object, writer: anytype) !void {
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
            const seg_id = @as(u8, @intCast(segments.items.len));
            try segments.append(seg);

            const headers = lc.getSections();
            if (headers.len > 0) {
                const gop = try sections.getOrPut(seg_id);
                if (!gop.found_existing) {
                    gop.value_ptr.* = std.ArrayList(macho.section_64).init(self.gpa);
                }
                try gop.value_ptr.ensureUnusedCapacity(headers.len);
                gop.value_ptr.appendUnalignedSliceAssumeCapacity(headers);
            }

            for (sorted_by_address.items, 0..) |other_id, i| {
                const other_seg = segments.items[other_id];
                if (seg.vmaddr < other_seg.vmaddr) {
                    try sorted_by_address.insert(i, seg_id);
                    break;
                }
            } else try sorted_by_address.append(seg_id);

            for (sorted_by_offset.items, 0..) |other_id, i| {
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
            for (headers.items, 0..) |header, header_id| {
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
            for (headers.items, 0..) |header, header_id| {
                if (header.isZerofill()) continue;
                try writer.print("    {s: >20} -------- {x}\n", .{ header.sectName(), header.offset });
                try writer.print("    {s: >20} |\n", .{""});
                try writer.print("    {s: >20} -------- {x}\n", .{ "", header.offset + header.size });
                if (header_id < headers.items.len - 1) {
                    const next_header = headers.items[header_id + 1];
                    if (next_header.offset < header.offset + header.size and !next_header.isZerofill()) {
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
            if (next_seg.fileoff < seg.fileoff + seg.filesize and next_seg.filesize > 0) {
                try writer.writeAll("    CURRENT SEGMENT OVERLAPS THE NEXT ONE\n");
            }
        }
        try writer.writeByte('\n');
    }
}

pub fn printRelocations(self: Object, writer: anytype) !void {
    var has_relocs = false;
    var it = self.getLoadCommandsIterator();
    while (it.next()) |lc| switch (lc.cmd()) {
        .SEGMENT_64 => {
            for (lc.getSections()) |sect| {
                const code = self.data[sect.offset..][0..sect.size];
                const relocs = relocs: {
                    const relocs = @as([*]align(1) const macho.relocation_info, @ptrCast(self.data.ptr + sect.reloff))[0..sect.nreloc];
                    const out = try self.gpa.alloc(macho.relocation_info, relocs.len);
                    @memcpy(out, relocs);
                    break :relocs out;
                };
                defer self.gpa.free(relocs);

                if (relocs.len == 0) continue;

                const sortFn = struct {
                    fn sortFn(ctx: void, lhs: macho.relocation_info, rhs: macho.relocation_info) bool {
                        _ = ctx;
                        return lhs.r_address > rhs.r_address;
                    }
                }.sortFn;
                mem.sort(macho.relocation_info, relocs, {}, sortFn);

                try writer.print("Relocation information ({s},{s}) {d} entries:\n", .{
                    sect.segName(),
                    sect.sectName(),
                    relocs.len,
                });
                try writer.writeAll("  address   pcrel length extern type     scattered symbolnum/value\n");
                for (relocs) |rel| {
                    try writer.print("  {x:0>8}", .{@as(u32, @intCast(rel.r_address))});
                    try writer.print("  {s: <5}", .{if (rel.r_pcrel == 0) "false" else "true"});
                    try writer.print(" {s: <6}", .{switch (rel.r_length) {
                        0 => "byte",
                        1 => "short",
                        2 => "long",
                        3 => "quad",
                    }});
                    try writer.print(" {s: <6}", .{if (rel.r_extern == 0) "false" else "true"});
                    try writer.print(" {s: <8}", .{fmtRelocType(rel.r_type, self.arch)});
                    try writer.print(" {s: <9}", .{"false"});

                    if (isArm64Addend(rel.r_type, self.arch)) {
                        try writer.print(" 0x{x}", .{rel.r_symbolnum});
                    } else {
                        if (rel.r_extern == 0) {
                            const target = self.getSectionByIndex(@intCast(rel.r_symbolnum));
                            try writer.print(" {d} ({s},{s})", .{ rel.r_symbolnum, target.segName(), target.sectName() });
                        } else {
                            const target = self.symtab[rel.r_symbolnum];
                            try writer.print(" {s}", .{self.getString(target.n_strx)});
                        }

                        if (hasAddendInCode(rel.r_type, self.arch)) {
                            const rel_offset = @as(usize, @intCast(rel.r_address));
                            var addend = switch (rel.r_length) {
                                0 => code[rel_offset],
                                1 => mem.readInt(i16, code[rel_offset..][0..2], .little),
                                2 => mem.readInt(i32, code[rel_offset..][0..4], .little),
                                3 => mem.readInt(i64, code[rel_offset..][0..8], .little),
                            };

                            if (rel.r_extern == 0) {
                                const target = self.getSectionByIndex(@intCast(rel.r_symbolnum));
                                if (rel.r_pcrel == 1) {
                                    addend = @as(i64, @intCast(sect.addr)) + rel.r_address + addend + 4;
                                }
                                if (addend < target.addr or addend > target.addr + target.size) {
                                    try writer.writeAll(" ADDEND OVERFLOWS TARGET SECTION");
                                } else {
                                    addend -= @intCast(target.addr);
                                }
                            }
                            try writer.print(" + 0x{x}", .{addend});
                        }
                    }

                    try writer.writeByte('\n');
                }
                has_relocs = true;
            }
        },
        else => {},
    };

    if (!has_relocs) {
        try writer.writeAll("No relocation entries found.\n");
    }
}

fn isArm64Addend(r_type: u8, arch: Arch) bool {
    return switch (arch) {
        .aarch64 => switch (@as(macho.reloc_type_arm64, @enumFromInt(r_type))) {
            .ARM64_RELOC_ADDEND => true,
            else => false,
        },
        else => false,
    };
}

fn hasAddendInCode(r_type: u8, arch: Arch) bool {
    return switch (arch) {
        .aarch64 => switch (@as(macho.reloc_type_arm64, @enumFromInt(r_type))) {
            .ARM64_RELOC_UNSIGNED => true,
            else => false,
        },
        .x86_64 => true,
        else => false,
    };
}

fn fmtRelocType(r_type: u8, arch: Arch) std.fmt.Formatter(formatRelocType) {
    return .{ .data = .{
        .r_type = r_type,
        .arch = arch,
    } };
}

const FmtRelocTypeCtx = struct {
    r_type: u8,
    arch: Arch,
};

fn formatRelocType(
    ctx: FmtRelocTypeCtx,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    const len = switch (ctx.arch) {
        .aarch64 => blk: {
            const r_type = switch (@as(macho.reloc_type_arm64, @enumFromInt(ctx.r_type))) {
                .ARM64_RELOC_UNSIGNED => "UNSIGND",
                .ARM64_RELOC_SUBTRACTOR => "SUB",
                .ARM64_RELOC_BRANCH26 => "BR26",
                .ARM64_RELOC_PAGE21 => "PAGE21",
                .ARM64_RELOC_PAGEOFF12 => "PAGOF12",
                .ARM64_RELOC_GOT_LOAD_PAGE21 => "GOTLDP",
                .ARM64_RELOC_GOT_LOAD_PAGEOFF12 => "GOTLDPOF",
                .ARM64_RELOC_POINTER_TO_GOT => "PTRGOT",
                .ARM64_RELOC_TLVP_LOAD_PAGE21 => "TLVLDP",
                .ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => "TLVLDPOF",
                .ARM64_RELOC_ADDEND => "ADDEND",
            };
            try writer.print("{s}", .{r_type});
            break :blk r_type.len;
        },
        .x86_64 => blk: {
            const r_type = switch (@as(macho.reloc_type_x86_64, @enumFromInt(ctx.r_type))) {
                .X86_64_RELOC_UNSIGNED => "UNSIGND",
                .X86_64_RELOC_SUBTRACTOR => "SUB",
                .X86_64_RELOC_SIGNED => "SIGNED",
                .X86_64_RELOC_SIGNED_1 => "SIGNED1",
                .X86_64_RELOC_SIGNED_2 => "SIGNED2",
                .X86_64_RELOC_SIGNED_4 => "SIGNED4",
                .X86_64_RELOC_BRANCH => "BR",
                .X86_64_RELOC_GOT_LOAD => "GOTLD",
                .X86_64_RELOC_GOT => "GOT",
                .X86_64_RELOC_TLV => "TLV",
            };
            try writer.print("{s}", .{r_type});
            break :blk r_type.len;
        },
        .unknown => unreachable,
    };
    if (options.width) |width| {
        if (width > len) {
            const padding = width - len;
            // TODO I have no idea what I'm doing here!
            var fill_buffer: [4]u8 = undefined;
            const fill = if (std.unicode.utf8Encode(options.fill, &fill_buffer)) |l|
                fill_buffer[0..l]
            else |_|
                @panic("impossible to apply fmt fill!");
            try writer.writeBytesNTimes(fill, padding);
        }
    }
}

pub fn printSymbolTable(self: Object, writer: anytype) !void {
    if (self.symtab_lc == null) {
        try writer.writeAll("\nNo symbol table found in the object file.\n");
        return;
    }

    try writer.writeAll("\nSymbol table:\n");

    for (self.symtab) |sym| {
        const sym_name = self.getString(sym.n_strx);

        if (sym.stab()) {
            const tt = switch (sym.n_type) {
                macho.N_SO => "SO",
                macho.N_OSO => "OSO",
                macho.N_BNSYM => "BNSYM",
                macho.N_ENSYM => "ENSYM",
                macho.N_FUN => "FUN",
                macho.N_GSYM => "GSYM",
                macho.N_STSYM => "STSYM",
                else => "TODO",
            };
            try writer.print("  0x{x:0>16}", .{sym.n_value});
            if (sym.n_sect > 0) {
                const sect = self.getSectionByIndex(sym.n_sect);
                try writer.print(" ({s},{s})", .{ sect.segName(), sect.sectName() });
            }
            try writer.print(" {s} (stab) {s}\n", .{ tt, sym_name });
        } else if (sym.sect()) {
            const sect = self.getSectionByIndex(sym.n_sect);
            try writer.print("  0x{x:0>16} ({s},{s})", .{
                sym.n_value,
                sect.segName(),
                sect.sectName(),
            });

            if (sym.n_desc & macho.REFERENCED_DYNAMICALLY != 0) try writer.writeAll(" [referenced dynamically]");
            if (sym.weakDef()) try writer.writeAll(" weak");
            if (sym.weakRef()) try writer.writeAll(" weak-ref");

            if (sym.ext()) {
                if (sym.pext()) try writer.writeAll(" private");
                try writer.writeAll(" external");
            } else {
                try writer.writeAll(" non-external");
                if (sym.pext()) try writer.writeAll(" (was private external)");
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

            if (sym.weakRef()) try writer.writeAll(" weak-ref");
            if (sym.ext()) try writer.writeAll(" external");

            try writer.print(" {s}", .{sym_name});

            const ord = @divFloor(@as(i16, @bitCast(sym.n_desc)), macho.N_SYMBOL_RESOLVER);
            switch (ord) {
                macho.BIND_SPECIAL_DYLIB_FLAT_LOOKUP => try writer.writeAll(" (from flat lookup)"),
                macho.BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE => try writer.writeAll(" (from main executable)"),
                macho.BIND_SPECIAL_DYLIB_SELF => try writer.writeAll(" (from self)"),
                else => {
                    const dylib = self.getDylibByIndex(@as(u16, @intCast(ord)));
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

pub fn printStringTable(self: Object, writer: anytype) !void {
    if (self.symtab_lc == null or self.symtab_lc.?.strsize == 0) {
        try writer.writeAll("\nNo string table found in the object file.\n");
        return;
    }
    try writer.writeAll("\nString table:\n");

    var strings = std.ArrayList(struct { pos: usize, str: []const u8 }).init(self.gpa);
    defer strings.deinit();

    var pos: usize = 0;
    while (pos < self.strtab.len) {
        const str = mem.sliceTo(@as([*:0]const u8, @ptrCast(self.strtab.ptr + pos)), 0);
        try strings.append(.{ .pos = pos, .str = str });
        pos += str.len + 1;
    }

    for (strings.items) |str| {
        try writer.print("{d}: {s}\n", .{ str.pos, str.str });
    }
}

pub fn printIndirectSymbolTable(self: Object, writer: anytype) !void {
    if (self.dysymtab_lc == null or self.dysymtab_lc.?.nindirectsyms == 0) {
        try writer.writeAll("\nNo indirect symbol table found in the object file.\n");
        return;
    }
    try writer.writeAll("\nIndirect symbol table:\n");

    var sects = std.ArrayList(macho.section_64).init(self.gpa);
    defer sects.deinit();
    try sects.ensureUnusedCapacity(3);

    if (self.getSectionByName("__TEXT", "__stubs")) |sect| sects.appendAssumeCapacity(sect);
    if (self.getSectionByName("__DATA_CONST", "__got")) |sect| sects.appendAssumeCapacity(sect);
    if (self.getSectionByName("__DATA", "__la_symbol_ptr")) |sect| sects.appendAssumeCapacity(sect);

    const sortFn = struct {
        fn sortFn(ctx: void, lhs: macho.section_64, rhs: macho.section_64) bool {
            _ = ctx;
            return lhs.reserved1 < rhs.reserved1;
        }
    }.sortFn;
    mem.sort(macho.section_64, sects.items, {}, sortFn);

    const lc = self.dysymtab_lc.?;
    const indsymtab = @as([*]align(1) const u32, @ptrCast(self.data.ptr + lc.indirectsymoff))[0..lc.nindirectsyms];

    var i: usize = 0;
    while (i < sects.items.len) : (i += 1) {
        const sect = sects.items[i];
        const start = sect.reserved1;
        const end = if (i + 1 >= sects.items.len) indsymtab.len else sects.items[i + 1].reserved1;
        const entry_size = blk: {
            if (mem.eql(u8, sect.sectName(), "__stubs")) break :blk sect.reserved2;
            break :blk @sizeOf(u64);
        };

        try writer.print("Indirect symbols for ({s},{s}) {d} entries\n", .{ sect.segName(), sect.sectName(), end - start });
        for (indsymtab[start..end], 0..) |index, j| {
            const sym = self.symtab[index];
            const addr = sect.addr + entry_size * j;
            try writer.print("0x{x} {d} {s}\n", .{ addr, index, self.getString(sym.n_strx) });
        }
    }
}

pub fn printDataInCode(self: Object, writer: anytype) !void {
    const lc = self.data_in_code_lc orelse {
        try writer.writeAll("\nNo data-in-code entries found in the object file.\n");
        return;
    };
    try writer.writeAll("\nData-in-code entries:\n");
    try writer.writeAll("  offset length  kind\n");

    const dice = dice: {
        const raw = self.data[lc.dataoff..][0..lc.datasize];
        const nentries = @divExact(lc.datasize, @sizeOf(macho.data_in_code_entry));
        break :dice @as([*]align(1) const macho.data_in_code_entry, @ptrCast(raw.ptr))[0..nentries];
    };

    for (dice) |entry| {
        const kind = switch (entry.kind) {
            else => "UNKNOWN",
            1 => "DATA",
            2 => "JUMP_TABLE8",
            3 => "JUMP_TABLE16",
            4 => "JUMP_TABLE32",
            5 => "ABS_JUMP_TABLE32",
        };
        try writer.print("{x:0>8} {d: >6}  {s}", .{ entry.offset, entry.length, kind });

        if (self.verbose) {
            const seg = if (self.header.filetype == macho.MH_EXECUTE)
                self.getSegmentByName("__TEXT").?
            else
                self.segments.items[0];
            const name = if (self.findSymbolByAddress(seg.vmaddr + entry.offset)) |sym|
                self.getString(sym.n_strx)
            else
                "INVALID TARGET OFFSET";
            try writer.print("  {s}", .{name});
        }

        try writer.writeByte('\n');
    }
}

fn getLoadCommandsIterator(self: Object) macho.LoadCommandIterator {
    const data = self.data[@sizeOf(macho.mach_header_64)..][0..self.header.sizeofcmds];
    return .{
        .ncmds = self.header.ncmds,
        .buffer = data,
    };
}

fn findSymbolByAddress(self: *const Object, addr: u64) ?macho.nlist_64 {
    for (self.sorted_symtab.items) |idx| {
        const sym = idx.getSymbol(self);
        if (sym.n_value <= addr and addr < sym.n_value + idx.size) return sym;
    }
    return null;
}

fn getString(self: *const Object, off: u32) []const u8 {
    assert(off < self.strtab.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(self.strtab.ptr + off)), 0);
}

pub fn getSectionByName(self: Object, segname: []const u8, sectname: []const u8) ?macho.section_64 {
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

fn getSectionByAddress(self: Object, addr: u64) ?macho.section_64 {
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

fn getSectionByIndex(self: Object, index: u8) macho.section_64 {
    var count: u8 = 1;
    var it = self.getLoadCommandsIterator();
    while (it.next()) |lc| switch (lc.cmd()) {
        .SEGMENT_64 => {
            const sects = lc.getSections();
            if (index > count + sects.len) {
                count += @as(u8, @intCast(sects.len));
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

fn getGotPointerAtIndex(self: Object, index: usize) u64 {
    const sect = self.getSectionByName("__DATA_CONST", "__got").?;
    const data = self.data[sect.offset..][0..sect.size];
    const ptr = @as(*align(1) const u64, @ptrCast(data[index * 8 ..])).*;

    const mask = 0xFFFF000000000000; // TODO I guessed the value of the mask, so verify!
    switch ((mask & ptr) >> 48) {
        0x0 => {
            // Old-style GOT with actual pointer values
            return ptr;
        },
        0x10 => {
            // indirect local
            const offset = 0xFFFFFFFFFFFF & ptr;
            const seg = self.getSegmentByName("__TEXT").?;
            return seg.vmaddr + offset;
        },
        else => {
            // TODO parse opcodes
            return 0x0;
        },
    }
}

fn getSegmentByName(self: Object, segname: []const u8) ?macho.segment_command_64 {
    for (self.segments.items) |seg| {
        if (mem.eql(u8, segname, seg.segName())) {
            return seg;
        }
    }
    return null;
}

fn getSegmentByAddress(self: Object, addr: u64) ?macho.segment_command_64 {
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

fn sliceContentsByAddress(self: Object, addr: u64, size: u64) ?[]const u8 {
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

fn getDylibByIndex(self: Object, index: u16) macho.LoadCommandIterator.LoadCommand {
    var count: u16 = 1;
    var it = self.getLoadCommandsIterator();
    while (it.next()) |lc| switch (lc.cmd()) {
        .LOAD_DYLIB,
        .LOAD_WEAK_DYLIB,
        .LOAD_UPWARD_DYLIB,
        .REEXPORT_DYLIB,
        => {
            if (count == index) return lc;
            count += 1;
        },
        else => {},
    } else unreachable;
}

fn getDylibNameByIndex(self: Object, index: u16) []const u8 {
    const dylib = self.getDylibByIndex(index);
    const full_path = dylib.getDylibPathName();
    const leaf_path = std.fs.path.basename(full_path);
    var name = leaf_path;
    while (true) {
        const ext = std.fs.path.extension(name);
        if (ext.len == 0) break;
        name = name[0 .. name.len - ext.len];
    }
    return name;
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

const UnwindEncodingArm64 = union(enum) {
    frame: Frame,
    frameless: Frameless,
    dwarf: Dwarf,

    const Frame = packed struct {
        x_reg_pairs: packed struct {
            x19_x20: u1,
            x21_x22: u1,
            x23_x24: u1,
            x25_x26: u1,
            x27_x28: u1,
        },
        d_reg_pairs: packed struct {
            d8_d9: u1,
            d10_d11: u1,
            d12_d13: u1,
            d14_d15: u1,
        },
        unused: u15,
        mode: Mode = .frame,
        personality_index: u2,
        has_lsda: u1,
        start: u1,
    };

    const Frameless = packed struct {
        unused: u12 = 0,
        stack_size: u12,
        mode: Mode = .frameless,
        personality_index: u2,
        has_lsda: u1,
        start: u1,
    };

    const Dwarf = packed struct {
        section_offset: u24,
        mode: Mode = .dwarf,
        personality_index: u2,
        has_lsda: u1,
        start: u1,
    };

    const Mode = enum(u4) {
        frameless = 0x2,
        dwarf = 0x3,
        frame = 0x4,
        _,
    };

    const mode_mask: u32 = 0x0F000000;

    fn fromU32(enc: u32) !UnwindEncodingArm64 {
        const m = (enc & mode_mask) >> 24;
        return switch (@as(Mode, @enumFromInt(m))) {
            .frame => .{ .frame = @as(Frame, @bitCast(enc)) },
            .frameless => .{ .frameless = @as(Frameless, @bitCast(enc)) },
            .dwarf => .{ .dwarf = @as(Dwarf, @bitCast(enc)) },
            else => return error.UnknownEncoding,
        };
    }

    fn toU32(enc: UnwindEncodingArm64) u32 {
        return switch (enc) {
            inline else => |x| @as(u32, @bitCast(x)),
        };
    }

    fn start(enc: UnwindEncodingArm64) bool {
        return switch (enc) {
            inline else => |x| x.start == 0b1,
        };
    }

    fn hasLsda(enc: UnwindEncodingArm64) bool {
        return switch (enc) {
            inline else => |x| x.has_lsda == 0b1,
        };
    }

    fn personalityIndex(enc: UnwindEncodingArm64) u2 {
        return switch (enc) {
            inline else => |x| x.personality_index,
        };
    }

    fn mode(enc: UnwindEncodingArm64) Mode {
        return switch (enc) {
            inline else => |x| x.mode,
        };
    }
};

pub const UnwindEncodingX86_64 = union(enum) {
    frame: Frame,
    frameless: Frameless,
    dwarf: Dwarf,

    pub const Frame = packed struct {
        frame_registers: u15,
        unused: u1 = 0,
        frame_offset: u8,
        mode: Mode = .ebp_frame,
        personality_index: u2,
        has_lsda: u1,
        start: u1,
    };

    pub const Frameless = packed struct {
        stack_reg_permutation: u10,
        stack_reg_count: u3,
        stack_adjust: u3,
        stack_size: u8,
        mode: Mode,
        personality_index: u2,
        has_lsda: u1,
        start: u1,
    };

    pub const Dwarf = packed struct {
        section_offset: u24,
        mode: Mode = .dwarf,
        personality_index: u2,
        has_lsda: u1,
        start: u1,
    };

    pub const Mode = enum(u4) {
        ebp_frame = 0x1,
        stack_immd = 0x2,
        stack_ind = 0x3,
        dwarf = 0x4,
        _,
    };

    pub const mode_mask: u32 = 0x0F000000;

    pub fn fromU32(enc: u32) !UnwindEncodingX86_64 {
        const m = (enc & mode_mask) >> 24;
        return switch (@as(Mode, @enumFromInt(m))) {
            .ebp_frame => .{ .frame = @as(Frame, @bitCast(enc)) },
            .stack_immd, .stack_ind => .{ .frameless = @as(Frameless, @bitCast(enc)) },
            .dwarf => .{ .dwarf = @as(Dwarf, @bitCast(enc)) },
            else => return error.UnknownEncoding,
        };
    }

    pub fn toU32(enc: UnwindEncodingX86_64) u32 {
        return switch (enc) {
            inline else => |x| @as(u32, @bitCast(x)),
        };
    }

    pub fn start(enc: UnwindEncodingX86_64) bool {
        return switch (enc) {
            inline else => |x| x.start == 0b1,
        };
    }

    pub fn hasLsda(enc: UnwindEncodingX86_64) bool {
        return switch (enc) {
            inline else => |x| x.has_lsda == 0b1,
        };
    }

    pub fn personalityIndex(enc: UnwindEncodingX86_64) u2 {
        return switch (enc) {
            inline else => |x| x.personality_index,
        };
    }

    pub fn mode(enc: UnwindEncodingX86_64) Mode {
        return switch (enc) {
            inline else => |x| x.mode,
        };
    }
};

const SymbolAtIndex = struct {
    index: u32,
    size: u64,

    const Context = *const Object;

    fn getSymbol(self: SymbolAtIndex, ctx: Context) macho.nlist_64 {
        return ctx.symtab[self.index];
    }

    fn getSymbolName(self: SymbolAtIndex, ctx: Context) []const u8 {
        const off = self.getSymbol(ctx).n_strx;
        return ctx.getString(off);
    }

    fn getSymbolSeniority(self: SymbolAtIndex, ctx: Context) u2 {
        const sym = self.getSymbol(ctx);
        if (sym.ext()) return 1;
        const sym_name = self.getSymbolName(ctx);
        if (mem.startsWith(u8, sym_name, "l") or mem.startsWith(u8, sym_name, "L")) return 3;
        return 2;
    }

    fn lessThan(ctx: Context, lhs_index: SymbolAtIndex, rhs_index: SymbolAtIndex) bool {
        const lhs = lhs_index.getSymbol(ctx);
        const rhs = rhs_index.getSymbol(ctx);
        if (lhs.n_value == rhs.n_value) {
            if (lhs.n_sect == rhs.n_sect) {
                const lhs_senior = lhs_index.getSymbolSeniority(ctx);
                const rhs_senior = rhs_index.getSymbolSeniority(ctx);
                if (lhs_senior == rhs_senior) {
                    return lessThanByNStrx(ctx, lhs_index, rhs_index);
                } else return lhs_senior < rhs_senior;
            } else return lhs.n_sect < rhs.n_sect;
        } else return lhs.n_value < rhs.n_value;
    }

    fn lessThanByNStrx(ctx: Context, lhs: SymbolAtIndex, rhs: SymbolAtIndex) bool {
        return lhs.getSymbol(ctx).n_strx < rhs.getSymbol(ctx).n_strx;
    }
};

const Arch = enum {
    aarch64,
    x86_64,
    unknown,
};

const Object = @This();

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
