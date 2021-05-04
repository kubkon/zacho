const std = @import("std");
const io = std.io;
const mem = std.mem;
const macho = std.macho;

const Allocator = mem.Allocator;
const FormatOptions = std.fmt.FormatOptions;
const StreamSource = io.StreamSource;

pub const LoadCommand = union(enum) {
    Segment: SegmentCommand,
    DyldInfoOnly: macho.dyld_info_command,
    Symtab: macho.symtab_command,
    Dysymtab: macho.dysymtab_command,
    Dylinker: DylinkerCommand,
    Dylib: DylibCommand,
    Main: macho.entry_point_command,
    VersionMin: macho.version_min_command,
    SourceVersion: macho.source_version_command,
    LinkeditData: macho.linkedit_data_command,
    Unknown: UnknownCommand,

    pub fn parse(alloc: *Allocator, stream: *StreamSource) !LoadCommand {
        const header = try stream.reader().readStruct(macho.load_command);
        try stream.seekBy(-@sizeOf(macho.load_command));

        return switch (header.cmd) {
            macho.LC_SEGMENT_64 => LoadCommand{
                .Segment = try SegmentCommand.parse(alloc, stream),
            },
            macho.LC_DYLD_INFO, macho.LC_DYLD_INFO_ONLY => LoadCommand{
                .DyldInfoOnly = try parseCommand(macho.dyld_info_command, stream),
            },
            macho.LC_SYMTAB => LoadCommand{
                .Symtab = try parseCommand(macho.symtab_command, stream),
            },
            macho.LC_DYSYMTAB => LoadCommand{
                .Dysymtab = try parseCommand(macho.dysymtab_command, stream),
            },
            macho.LC_ID_DYLINKER, macho.LC_LOAD_DYLINKER, macho.LC_DYLD_ENVIRONMENT => LoadCommand{
                .Dylinker = try DylinkerCommand.parse(alloc, stream),
            },
            macho.LC_ID_DYLIB, macho.LC_LOAD_WEAK_DYLIB, macho.LC_LOAD_DYLIB, macho.LC_REEXPORT_DYLIB => LoadCommand{
                .Dylib = try DylibCommand.parse(alloc, stream),
            },
            macho.LC_MAIN => LoadCommand{
                .Main = try parseCommand(macho.entry_point_command, stream),
            },
            macho.LC_VERSION_MIN_MACOSX, macho.LC_VERSION_MIN_IPHONEOS, macho.LC_VERSION_MIN_WATCHOS, macho.LC_VERSION_MIN_TVOS => LoadCommand{
                .VersionMin = try parseCommand(macho.version_min_command, stream),
            },
            macho.LC_SOURCE_VERSION => LoadCommand{
                .SourceVersion = try parseCommand(macho.source_version_command, stream),
            },
            macho.LC_FUNCTION_STARTS, macho.LC_DATA_IN_CODE, macho.LC_CODE_SIGNATURE => LoadCommand{
                .LinkeditData = try parseCommand(macho.linkedit_data_command, stream),
            },
            else => LoadCommand{
                .Unknown = try UnknownCommand.parse(alloc, stream),
            },
        };
    }

    pub fn cmd(self: LoadCommand) u32 {
        return switch (self) {
            .DyldInfoOnly => |x| x.cmd,
            .Symtab => |x| x.cmd,
            .Dysymtab => |x| x.cmd,
            .Main => |x| x.cmd,
            .VersionMin => |x| x.cmd,
            .SourceVersion => |x| x.cmd,
            .LinkeditData => |x| x.cmd,
            .Segment => |x| x.cmd(),
            .Dylinker => |x| x.cmd(),
            .Dylib => |x| x.cmd(),
            .Unknown => |x| x.cmd(),
        };
    }

    pub fn cmdsize(self: LoadCommand) u32 {
        return switch (self) {
            .DyldInfoOnly => |x| x.cmdsize,
            .Symtab => |x| x.cmdsize,
            .Dysymtab => |x| x.cmdsize,
            .Main => |x| x.cmdsize,
            .VersionMin => |x| x.cmdsize,
            .SourceVersion => |x| x.cmdsize,
            .LinkeditData => |x| x.cmdsize,
            .Segment => |x| x.cmdsize(),
            .Dylinker => |x| x.cmdsize(),
            .Dylib => |x| x.cmdsize(),
            .Unknown => |x| x.cmdsize(),
        };
    }

    pub fn format(self: LoadCommand, comptime fmt: []const u8, options: FormatOptions, writer: anytype) !void {
        return switch (self) {
            .Segment => |x| x.format(fmt, options, writer),
            .DyldInfoOnly => |x| formatDyldInfoCommand(x, fmt, options, writer),
            .Symtab => |x| formatSymtabCommand(x, fmt, options, writer),
            .Dysymtab => |x| formatDysymtabCommand(x, fmt, options, writer),
            .Dylinker => |x| x.format(fmt, options, writer),
            .Dylib => |x| x.format(fmt, options, writer),
            .Main => |x| formatMainCommand(x, fmt, options, writer),
            .VersionMin => |x| formatVersionMinCommand(x, fmt, options, writer),
            .SourceVersion => |x| formatSourceVersionCommand(x, fmt, options, writer),
            .LinkeditData => |x| formatLinkeditDataCommand(x, fmt, options, writer),
            .Unknown => |x| x.format(fmt, options, writer),
        };
    }

    pub fn deinit(self: *LoadCommand, alloc: *Allocator) void {
        return switch (self.*) {
            .Segment => |*x| x.deinit(alloc),
            .Dylinker => |*x| x.deinit(alloc),
            .Dylib => |*x| x.deinit(alloc),
            .Unknown => |*x| x.deinit(alloc),
            else => {},
        };
    }
};

pub const SegmentCommand = struct {
    inner: macho.segment_command_64,
    section_headers: std.ArrayListUnmanaged(macho.section_64) = .{},

    pub fn parse(alloc: *mem.Allocator, stream: *io.StreamSource) !SegmentCommand {
        const inner = try stream.reader().readStruct(macho.segment_command_64);
        var segment = SegmentCommand{
            .inner = inner,
        };

        try segment.section_headers.ensureCapacity(alloc, inner.nsects);

        var i: usize = 0;
        while (i < inner.nsects) : (i += 1) {
            const section_header = try stream.reader().readStruct(macho.section_64);
            segment.section_headers.appendAssumeCapacity(section_header);
        }

        return segment;
    }

    pub fn cmd(self: SegmentCommand) u32 {
        return self.inner.cmd;
    }

    pub fn cmdsize(self: SegmentCommand) u32 {
        return self.inner.cmdsize;
    }

    pub fn format(self: SegmentCommand, comptime fmt: []const u8, options: FormatOptions, writer: anytype) !void {
        try writer.print("Segment command\n", .{});
        try writer.print("  Command ID: LC_SEGMENT_64(0x{x})\n", .{self.inner.cmd});
        try writer.print("  Command size: {}\n", .{self.inner.cmdsize});
        try writer.print("  Segment name: {s}\n", .{self.inner.segname});
        try writer.print("  VM address: 0x{x:0>16}\n", .{self.inner.vmaddr});
        try writer.print("  VM size: {}\n", .{self.inner.vmsize});
        try writer.print("  File offset: 0x{x:0>8}\n", .{self.inner.fileoff});
        try writer.print("  File size: {}\n", .{self.inner.filesize});
        try writer.print("  Maximum VM protection: 0x{x}\n", .{self.inner.maxprot});
        try writer.print("  Initial VM protection: 0x{x}\n", .{self.inner.initprot});
        try writer.print("  Number of sections: {}\n", .{self.inner.nsects});
        try writer.print("  Flags: 0x{x}", .{self.inner.flags});

        if (self.section_headers.items.len > 0) {
            try writer.print("\n  Sections", .{});

            for (self.section_headers.items) |section| {
                try writer.print("\n", .{});
                try formatSectionHeader(section, fmt, options, writer);
            }
        }
    }

    pub fn deinit(self: *SegmentCommand, alloc: *Allocator) void {
        self.section_headers.deinit(alloc);
    }

    fn formatSectionHeader(section: macho.section_64, comptime fmt: []const u8, options: FormatOptions, writer: anytype) !void {
        try writer.print("     Section header\n", .{});
        try writer.print("       Section name: {s}\n", .{section.sectname});
        try writer.print("       Segment name: {s}\n", .{section.segname});
        try writer.print("       Address: 0x{x:0>16}\n", .{section.addr});
        try writer.print("       Size: {}\n", .{section.size});
        try writer.print("       Offset: 0x{x:0>8}\n", .{section.offset});
        try writer.print("       Alignment: {}\n", .{section.@"align"});
        try writer.print("       Relocations offset: 0x{x:0>8}\n", .{section.reloff});
        try writer.print("       Number of relocations: {}\n", .{section.nreloc});
        try writer.print("       Flags: 0x{x}\n", .{section.flags});
        try writer.print("       Reserved1: 0x{x}\n", .{section.reserved1});
        try writer.print("       Reserved2: {}\n", .{section.reserved2});
        try writer.print("       Reserved3: {}", .{section.reserved3});
    }
};

pub const DylinkerCommand = struct {
    inner: macho.dylinker_command,
    name: std.ArrayListUnmanaged(u8) = .{},

    pub fn parse(alloc: *mem.Allocator, stream: *io.StreamSource) !DylinkerCommand {
        const inner = try stream.reader().readStruct(macho.dylinker_command);
        var dylinker = DylinkerCommand{
            .inner = inner,
        };

        try stream.seekBy(-@sizeOf(macho.dylinker_command));
        try stream.seekBy(inner.name);
        var reader = stream.reader();
        const name_len = inner.cmdsize - inner.name;
        try dylinker.name.ensureCapacity(alloc, name_len);

        var i: usize = 0;
        while (i < name_len) : (i += 1) {
            dylinker.name.appendAssumeCapacity(try reader.readByte());
        }

        return dylinker;
    }

    pub fn cmd(self: DylinkerCommand) u32 {
        return self.inner.cmd;
    }

    pub fn cmdsize(self: DylinkerCommand) u32 {
        return self.inner.cmdsize;
    }

    pub fn format(self: DylinkerCommand, comptime fmt: []const u8, options: FormatOptions, writer: anytype) !void {
        try writer.print("Dylinker command\n", .{});
        const cmd_id = switch (self.inner.cmd) {
            macho.LC_ID_DYLINKER => "LC_ID_DYLINKER",
            macho.LC_LOAD_DYLINKER => "LC_LOAD_DYLINKER",
            macho.LC_DYLD_ENVIRONMENT => "LC_DYLD_ENVIRONMENT",
            else => unreachable,
        };
        try writer.print("  Command ID: {s}(0x{x})\n", .{ cmd_id, self.inner.cmd });
        try writer.print("  String offset: {}\n", .{self.inner.name});
        try writer.print("  Name: {s}", .{self.name.items});
    }

    pub fn deinit(self: *DylinkerCommand, alloc: *Allocator) void {
        self.name.deinit(alloc);
    }
};

pub const DylibCommand = struct {
    inner: macho.dylib_command,
    name: std.ArrayListUnmanaged(u8) = .{},

    pub fn parse(alloc: *mem.Allocator, stream: *io.StreamSource) !DylibCommand {
        const inner = try stream.reader().readStruct(macho.dylib_command);
        var dylib = DylibCommand{
            .inner = inner,
        };

        try stream.seekBy(-@sizeOf(macho.dylib_command));
        try stream.seekBy(inner.dylib.name);
        var reader = stream.reader();
        const name_len = inner.cmdsize - inner.dylib.name;
        try dylib.name.ensureCapacity(alloc, name_len);

        var i: usize = 0;
        while (i < name_len) : (i += 1) {
            dylib.name.appendAssumeCapacity(try reader.readByte());
        }

        return dylib;
    }

    pub fn cmd(self: DylibCommand) u32 {
        return self.inner.cmd;
    }

    pub fn cmdsize(self: DylibCommand) u32 {
        return self.inner.cmdsize;
    }

    pub fn format(self: DylibCommand, comptime fmt: []const u8, options: FormatOptions, writer: anytype) !void {
        try writer.print("Dylib command\n", .{});
        const cmd_id = switch (self.inner.cmd) {
            macho.LC_ID_DYLIB => "LC_ID_DYLIB",
            macho.LC_LOAD_WEAK_DYLIB => "LC_LOAD_WEAK_DYLIB",
            macho.LC_LOAD_DYLIB => "LC_LOAD_DYLIB",
            macho.LC_REEXPORT_DYLIB => "LC_REEXPORT_DYLIB",
            else => unreachable,
        };
        try writer.print("  Command ID: {s}(0x{x})\n", .{ cmd_id, self.inner.cmd });
        try writer.print("  String offset: {}\n", .{self.inner.dylib.name});
        try writer.print("  Timestamp: {}\n", .{self.inner.dylib.timestamp});
        try writer.print("  Current version: {}\n", .{self.inner.dylib.current_version});
        try writer.print("  Compatibility version: {}\n", .{self.inner.dylib.compatibility_version});
        try writer.print("  Name: {s}", .{self.name.items});
    }

    pub fn deinit(self: *DylibCommand, alloc: *Allocator) void {
        self.name.deinit(alloc);
    }
};

fn parseCommand(comptime Cmd: type, stream: *StreamSource) !Cmd {
    return try stream.reader().readStruct(Cmd);
}

fn formatDyldInfoCommand(
    cmd: macho.dyld_info_command,
    comptime fmt: []const u8,
    options: FormatOptions,
    writer: anytype,
) !void {
    try writer.print("Dyld info command\n", .{});
    const cmd_id = switch (cmd.cmd) {
        macho.LC_DYLD_INFO => "LC_DYLD_INFO",
        macho.LC_DYLD_INFO_ONLY => "LC_DYLD_INFO_ONLY",
        else => unreachable,
    };
    try writer.print("  Command ID: {s}(0x{x})\n", .{ cmd_id, cmd.cmd });
    try writer.print("  Command size: {}\n", .{cmd.cmdsize});
    try writer.print("  Rebase table offset: 0x{x:0>8}\n", .{cmd.rebase_off});
    try writer.print("  Rebase table size: {}\n", .{cmd.rebase_size});
    try writer.print("  Bind table offset: 0x{x:0>8}\n", .{cmd.bind_off});
    try writer.print("  Bind table size: {}\n", .{cmd.bind_size});
    try writer.print("  Weak bind table offset: 0x{x:0>8}\n", .{cmd.weak_bind_off});
    try writer.print("  Weak bind table size: {}\n", .{cmd.weak_bind_size});
    try writer.print("  Lazy bind table offset: 0x{x:0>8}\n", .{cmd.lazy_bind_off});
    try writer.print("  Lazy bind table size: {}\n", .{cmd.lazy_bind_size});
    try writer.print("  Export table offset: 0x{x:0>8}\n", .{cmd.export_off});
    try writer.print("  Export table size: {}", .{cmd.export_size});
}

fn formatSymtabCommand(
    cmd: macho.symtab_command,
    comptime fmt: []const u8,
    options: FormatOptions,
    writer: anytype,
) !void {
    try writer.print("Symtab command\n", .{});
    try writer.print("  Command ID: LC_SYMTAB(0x{x})\n", .{cmd.cmd});
    try writer.print("  Command size: {}\n", .{cmd.cmdsize});
    try writer.print("  Symbol table offset: 0x{x:0>8}\n", .{cmd.symoff});
    try writer.print("  Number of symbol table entries: {}\n", .{cmd.nsyms});
    try writer.print("  String table offset: 0x{x:0>8}\n", .{cmd.stroff});
    try writer.print("  String table size: {}", .{cmd.strsize});
}

fn formatDysymtabCommand(
    cmd: macho.dysymtab_command,
    comptime fmt: []const u8,
    options: FormatOptions,
    writer: anytype,
) !void {
    try writer.print("Dysymtab command\n", .{});
    try writer.print("  Command ID: LC_DYSYMTAB(0x{x})\n", .{cmd.cmd});
    try writer.print("  Command size: {}\n", .{cmd.cmdsize});
    try writer.print("  Index of local symbols: {}\n", .{cmd.ilocalsym});
    try writer.print("  Number of local symbols: {}\n", .{cmd.nlocalsym});
    try writer.print("  Index of externally defined symbols: {}\n", .{cmd.iextdefsym});
    try writer.print("  Number of externally defined symbols: {}\n", .{cmd.nextdefsym});
    try writer.print("  Index of undefined symbols: {}\n", .{cmd.iundefsym});
    try writer.print("  Number of undefined symbols: {}\n", .{cmd.nundefsym});
    try writer.print("  Table of contents offset: 0x{x:0>8}\n", .{cmd.tocoff});
    try writer.print("  Number of entries in table of contents: {}\n", .{cmd.ntoc});
    try writer.print("  Module table offset: 0x{x:0>8}\n", .{cmd.modtaboff});
    try writer.print("  Number of module table entries: {}\n", .{cmd.nmodtab});
    try writer.print("  Referenced symbol table offset: 0x{x:0>8}\n", .{cmd.extrefsymoff});
    try writer.print("  Number of referenced symbol table entries: {}\n", .{cmd.nextrefsyms});
    try writer.print("  Indirect symbol table offset: 0x{x:0>8}\n", .{cmd.indirectsymoff});
    try writer.print("  Number of indirect symbol table entries: {}\n", .{cmd.nindirectsyms});
    try writer.print("  External relocation table offset: 0x{x:0>8}\n", .{cmd.extreloff});
    try writer.print("  Number of external relocation table entries: {}\n", .{cmd.nextrel});
    try writer.print("  Local relocation table offset: 0x{x:0>8}\n", .{cmd.locreloff});
    try writer.print("  Number of local relocation table entries: {}", .{cmd.nlocrel});
}

fn formatMainCommand(
    cmd: macho.entry_point_command,
    comptime fmt: []const u8,
    options: FormatOptions,
    writer: anytype,
) !void {
    try writer.print("Main command\n", .{});
    try writer.print("  Command ID: LC_MAIN(0x{x})\n", .{cmd.cmd});
    try writer.print("  Command size: {}\n", .{cmd.cmdsize});
    try writer.print("  File (__TEXT) offset of main(): 0x{x:0>8}\n", .{cmd.entryoff});
    try writer.print("  Initial stack size: {}", .{cmd.stacksize});
}

fn formatVersionMinCommand(
    cmd: macho.version_min_command,
    comptime fmt: []const u8,
    options: FormatOptions,
    writer: anytype,
) !void {
    try writer.print("Version minimum command\n", .{});
    const cmd_id = switch (cmd.cmd) {
        macho.LC_VERSION_MIN_MACOSX => "LC_VERSION_MIN_MACOSX",
        macho.LC_VERSION_MIN_IPHONEOS => "LC_VERSION_MIN_IPHONEOS",
        macho.LC_VERSION_MIN_WATCHOS => "LC_VERSION_MIN_WATCHOS",
        macho.LC_VERSION_MIN_TVOS => "LC_VERSION_MIN_TVOS",
        else => unreachable,
    };
    try writer.print("  Command ID: {s}(0x{x})\n", .{ cmd_id, cmd.cmd });
    try writer.print("  Command size: {}\n", .{cmd.cmdsize});
    try writer.print("  Version: {}\n", .{cmd.version});
    try writer.print("  SDK version: {}", .{cmd.sdk});
}

fn formatSourceVersionCommand(
    cmd: macho.source_version_command,
    comptime fmt: []const u8,
    options: FormatOptions,
    writer: anytype,
) !void {
    try writer.print("Source version command\n", .{});
    try writer.print("  Command ID: LC_SOURCE_VERSION(0x{x})\n", .{cmd.cmd});
    try writer.print("  Command size: {}\n", .{cmd.cmdsize});
    try writer.print("  Version: {}", .{cmd.version});
}

fn formatLinkeditDataCommand(
    cmd: macho.linkedit_data_command,
    comptime fmt: []const u8,
    options: FormatOptions,
    writer: anytype,
) !void {
    try writer.print("Linkedit data command\n", .{});
    const cmd_id = switch (cmd.cmd) {
        macho.LC_CODE_SIGNATURE => "LC_CODE_SIGNATURE",
        macho.LC_FUNCTION_STARTS => "LC_FUNCTION_STARTS",
        macho.LC_DATA_IN_CODE => "LC_DATA_IN_CODE",
        else => unreachable,
    };
    try writer.print("  Command ID: {s}(0x{x})\n", .{ cmd_id, cmd.cmd });
    try writer.print("  Command size: {}\n", .{cmd.cmdsize});
    try writer.print("  Data offset: {}\n", .{cmd.dataoff});
    try writer.print("  Data size: {}", .{cmd.datasize});
}

pub const UnknownCommand = struct {
    inner: macho.load_command,
    contents: std.ArrayListUnmanaged(u8) = .{},

    pub fn parse(alloc: *Allocator, stream: *StreamSource) !UnknownCommand {
        const inner = try stream.reader().readStruct(macho.load_command);
        var contents = try alloc.alloc(u8, inner.cmdsize - @sizeOf(macho.load_command));
        _ = try stream.reader().readAll(contents[0..]);

        return UnknownCommand{
            .inner = inner,
            .contents = std.ArrayList(u8).fromOwnedSlice(alloc, contents).toUnmanaged(),
        };
    }

    pub fn cmd(self: UnknownCommand) u32 {
        return self.inner.cmd;
    }

    pub fn cmdsize(self: UnknownCommand) u32 {
        return self.inner.cmdsize;
    }

    pub fn format(self: UnknownCommand, comptime fmt: []const u8, options: FormatOptions, writer: anytype) !void {
        try writer.print("Unknown command\n", .{});
        try writer.print("  Command ID: ??(0x{x})\n", .{self.inner.cmd});
        try writer.print("  Command size: {}\n", .{self.inner.cmdsize});
        try writer.print("  Raw contents: 0x{x}", .{std.fmt.fmtSliceHexLower(self.contents.items[0..])});
    }

    pub fn deinit(self: *UnknownCommand, alloc: *Allocator) void {
        self.contents.deinit(alloc);
    }
};
