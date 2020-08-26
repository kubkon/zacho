const ZachO = @This();

const std = @import("std");
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const macho = std.macho;

const Allocator = std.mem.Allocator;

alloc: *Allocator,

/// Mach-O header
header: ?macho.mach_header_64 = null,

/// Load commands
load_commands: std.ArrayListUnmanaged(LoadCommand) = .{},

/// Data
data: std.ArrayListUnmanaged(u8) = .{},
file_data_offset: ?u64 = null,

const LoadCommand = union(enum) {
    Unknown: UnknownCommand,
    Segment: SegmentCommand,

    pub fn format(self: LoadCommand, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        switch (self) {
            .Unknown => |x| return writer.print("{}", .{x}),
            .Segment => |x| return writer.print("{}", .{x}),
        }
    }
};

const UnknownCommand = struct {
    cmd: u32,
    contents: std.ArrayListUnmanaged(u8) = .{},

    pub fn cmdsize(self: UnknownCommand) u32 {
        return @intCast(u32, @sizeOf(macho.load_command) + self.contents.items.len);
    }

    pub fn format(self: UnknownCommand, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("Load command {{\n", .{});
        try writer.print("  Command: {}(??)\n", .{self.cmd});
        try writer.print("  Command size: {}\n", .{self.cmdsize()});
        try writer.print("  Raw contents: 0x{x}\n", .{self.contents.items[0..]});
        try writer.print("}}\n", .{});
    }

    pub fn deinit(self: *UnknownCommand, alloc: *Allocator) void {
        self.contents.deinit(alloc);
    }
};

const SegmentCommand = struct {
    segname: [16]u8 = undefined,
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: macho.vm_prot_t,
    initprot: macho.vm_prot_t,
    flags: u32,
    sections: std.ArrayListUnmanaged(macho.section_64) = .{},

    pub fn cmdsize(self: SegmentCommand) u32 {
        return @intCast(u32, @sizeOf(macho.load_command) + @sizeOf(SegmentCommand) - @sizeOf(std.ArrayListUnmanaged(macho.section_64)) + self.sections.items.len * @sizeOf(macho.section_64));
    }

    pub fn format(self: SegmentCommand, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("Load command {{\n", .{});
        try writer.print("  Command: LC_SEGMENT_64\n", .{});
        try writer.print("  Command size: {}\n", .{self.cmdsize()});
        try writer.print("  Segment name: {}\n", .{self.segname});
        try writer.print("  VM address: 0x{x:0<16}\n", .{self.vmaddr});
        try writer.print("  VM size: {}\n", .{self.vmsize});
        try writer.print("  File offset: 0x{x:0<16}\n", .{self.fileoff});
        try writer.print("  File size: {}\n", .{self.filesize});
        try writer.print("  Maximum VM protection: 0x{x}\n", .{self.maxprot});
        try writer.print("  Initial VM protection: 0x{x}\n", .{self.initprot});
        try writer.print("  Number of sections: {}\n", .{self.sections.items.len});
        try writer.print("  Flags: 0x{x}\n", .{self.flags});
        try writer.print("  Sections: {{\n", .{});

        for (self.sections.items) |section| {
            try writer.print("    {{\n", .{});
            try writer.print("      Section name: {}\n", .{section.sectname});
            try writer.print("      Segment name: {}\n", .{section.segname});
            try writer.print("      Address: 0x{x:0<16}\n", .{section.addr});
            try writer.print("      Size: {}\n", .{section.size});
            try writer.print("      Offset: 0x{x:0<16}\n", .{section.offset});
            try writer.print("      Alignment: {}\n", .{section.@"align"});
            try writer.print("      Relocations offset: 0x{x:0<16}\n", .{section.reloff});
            try writer.print("      Number of relocations: {}\n", .{section.nreloc});
            try writer.print("      Flags: 0x{x}\n", .{section.flags});
            try writer.print("      Reserved1 : 0x{x}\n", .{section.reserved1});
            try writer.print("      Reserved2: {}\n", .{section.reserved2});
            try writer.print("      Reserved3: {}\n", .{section.reserved3});
            try writer.print("    }}\n", .{});
        }
        try writer.print("  }}\n", .{});
        try writer.print("}}\n", .{});
    }

    pub fn deinit(self: *SegmentCommand, alloc: *Allocator) void {
        self.sections.deinit(alloc);
    }

    fn formatSection(section: macho.section_64, writer: anytype) !void {}
};

pub fn init(alloc: *Allocator) ZachO {
    return .{
        .alloc = alloc,
    };
}

pub fn parse(self: *ZachO, stream: *io.StreamSource) !void {
    self.header = try stream.reader().readStruct(macho.mach_header_64);

    const ncmds = self.header.?.ncmds;
    var i: usize = 0;
    while (i < ncmds) : (i += 1) {
        try self.parseCommand(stream);
    }

    const pos = try stream.getPos();
    const end_pos = try stream.getEndPos();
    const remaining = end_pos - pos;

    self.file_data_offset = pos;

    var data = try std.ArrayList(u8).initCapacity(self.alloc, remaining);
    try stream.reader().readAllArrayList(&data, remaining);
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
        switch (cmd.*) {
            .Segment => |*x| x.deinit(self.alloc),
            .Unknown => |*x| x.deinit(self.alloc),
        }
    }
    self.load_commands.deinit(self.alloc);
    self.data.deinit(self.alloc);
}

pub fn format(self: ZachO, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    if (self.header) |header| {
        try formatHeader(header, writer);
    }
    try writer.print("\n", .{});

    for (self.load_commands.items) |cmd| {
        try writer.print("{}", .{cmd});
    }
    try writer.print("\n", .{});

    for (self.load_commands.items) |cmd| {
        switch (cmd) {
            .Segment => |seg| try self.formatData(seg, writer),
            else => {},
        }
    }
}

fn parseCommand(self: *ZachO, stream: *io.StreamSource) !void {
    const cmd_header = try stream.reader().readStruct(macho.load_command);
    try stream.seekBy(-@sizeOf(macho.load_command));

    switch (cmd_header.cmd) {
        macho.LC_SEGMENT_64 => {
            const raw_segment = try stream.reader().readStruct(macho.segment_command_64);
            var segment: SegmentCommand = .{
                .vmaddr = raw_segment.vmaddr,
                .vmsize = raw_segment.vmsize,
                .fileoff = raw_segment.fileoff,
                .filesize = raw_segment.filesize,
                .initprot = raw_segment.initprot,
                .maxprot = raw_segment.maxprot,
                .flags = raw_segment.flags,
            };
            mem.copy(u8, segment.segname[0..], raw_segment.segname[0..]);

            var i: usize = 0;
            while (i < raw_segment.nsects) : (i += 1) {
                const section = try stream.reader().readStruct(macho.section_64);
                try segment.sections.append(self.alloc, section);
            }

            try self.load_commands.append(self.alloc, .{
                .Segment = segment,
            });
        },
        else => {
            try stream.seekBy(@sizeOf(macho.load_command));

            var contents = try self.alloc.alloc(u8, cmd_header.cmdsize - @sizeOf(macho.load_command));
            _ = try stream.reader().readAll(contents[0..]);

            try self.load_commands.append(self.alloc, .{
                .Unknown = .{
                    .cmd = cmd_header.cmd,
                    .contents = std.ArrayList(u8).fromOwnedSlice(self.alloc, contents).toUnmanaged(),
                },
            });
        },
    }
}

fn formatHeader(header: macho.mach_header_64, writer: anytype) !void {
    try writer.print("Header {{\n", .{});
    try writer.print("  Magic number: 0x{x}\n", .{header.magic});
    try writer.print("  CPU type: 0x{x}\n", .{header.cputype});
    try writer.print("  CPU sub-type: 0x{x}\n", .{header.cpusubtype});
    try writer.print("  File type: 0x{x}\n", .{header.filetype});
    try writer.print("  Number of load commands: {}\n", .{header.ncmds});
    try writer.print("  Size of load commands: {}\n", .{header.sizeofcmds});
    try writer.print("  Flags: 0x{x}\n", .{header.flags});
    try writer.print("  Reserved: 0x{x}\n", .{header.reserved});
    try writer.print("}}\n", .{});
}

fn formatData(self: ZachO, seg: SegmentCommand, writer: anytype) !void {
    const start_pos = seg.fileoff;
    const end_pos = seg.fileoff + seg.filesize;

    if (end_pos == start_pos) return;

    try writer.print("{}\n", .{seg.segname});
    try writer.print("file = {{ {}, {} }}\n", .{ start_pos, end_pos });
    try writer.print("address = {{ 0x{x:0<16}, 0x{x:0<16} }}\n\n", .{ seg.vmaddr, seg.vmaddr + seg.vmsize });

    for (seg.sections.items) |sect| {
        const file_start = sect.offset;
        const file_end = sect.offset + sect.size;
        const addr_start = sect.addr;
        const addr_end = sect.addr + sect.size;

        try writer.print("  {},{}\n", .{ sect.segname, sect.sectname });
        try writer.print("  file = {{ {}, {} }}\n", .{ file_start, file_end });
        try writer.print("  address = {{ 0x{x:0<16}, 0x{x:0<16} }}\n\n", .{ addr_start, addr_end });
        try writer.print("  0x{x}\n\n", .{self.data.items[file_start - self.file_data_offset.? .. file_end - self.file_data_offset.?]});
    }
}
