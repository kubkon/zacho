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

const LoadCommand = struct {
    cmdsize: u32,
    inner: union(enum) {
        Unknown: struct {
            cmd: u32,
            contents: []u8,
        },
        Segment: struct {
            name: [16]u8,
            vm_address: u64,
            vm_size: u64,
            file_offset: u64,
            file_size: u64,
            init_prot: macho.vm_prot_t,
            max_prot: macho.vm_prot_t,
            flags: u32,
        },
    },
};

pub fn init(alloc: *Allocator) ZachO {
    return .{
        .alloc = alloc,
    };
}

pub fn parse(self: *ZachO, stream: *io.StreamSource) !void {
    var reader = stream.reader();
    try self.parseHeader(&reader);

    const ncmds = self.header.?.ncmds;
    var i: usize = 0;
    while (i < ncmds) : (i += 1) {
        try self.parseCommand(&reader);
    }
}

pub fn parseFile(self: *ZachO, pathname: []const u8) !void {
    const file = try fs.openFileAbsolute(pathname, .{});
    defer file.close();

    var stream = io.StreamSource{ .file = file };
    return self.parse(&stream);
}

pub fn deinit(self: *ZachO) void {
    for (self.load_commands.items) |*cmd| {
        switch (cmd.inner) {
            .Unknown => |*x| self.alloc.free(x.contents),
            else => {},
        }
    }
    self.load_commands.deinit(self.alloc);
}

pub fn format(self: ZachO, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    try writer.print("Mach-O file {{\n", .{});

    if (self.header) |header| {
        try formatHeader(header, writer);
    }

    for (self.load_commands.items) |cmd| {
        try formatCommand(cmd, writer);
    }

    try writer.print("}}", .{});
}

fn parseHeader(self: *ZachO, reader: *io.StreamSource.Reader) !void {
    var buf: [@sizeOf(macho.mach_header_64)]u8 = undefined;
    const nread = try reader.readAll(buf[0..]);

    if (nread < @sizeOf(macho.mach_header_64)) return error.MalformedMachOHeader;

    self.header = mem.bytesToValue(macho.mach_header_64, &buf);
}

fn parseCommand(self: *ZachO, reader: *io.StreamSource.Reader) !void {
    var buf: [@sizeOf(macho.load_command)]u8 = undefined;
    const nread = try reader.readAll(buf[0..]);

    if (nread < @sizeOf(macho.load_command)) return error.MalformedLoadCommand;

    const cmd_header = mem.bytesToValue(macho.load_command, &buf);
    switch (cmd_header.cmd) {
        // macho.LC_SEGMENT_64 => {},
        else => {
            var contents = try self.alloc.alloc(u8, cmd_header.cmdsize - @sizeOf(macho.load_command));
            _ = try reader.readAll(contents[0..]);

            try self.load_commands.append(self.alloc, .{
                .cmdsize = cmd_header.cmdsize,
                .inner = .{
                    .Unknown = .{
                        .cmd = cmd_header.cmd,
                        .contents = contents,
                    },
                },
            });
        },
    }
}

fn formatHeader(header: macho.mach_header_64, writer: anytype) !void {
    try writer.print("\tHeader {{\n", .{});
    try writer.print("\t\tMagic number: 0x{x}\n", .{header.magic});
    try writer.print("\t\tCPU type: 0x{x}\n", .{header.cputype});
    try writer.print("\t\tCPU sub-type: 0x{x}\n", .{header.cpusubtype});
    try writer.print("\t\tFile type: 0x{x}\n", .{header.filetype});
    try writer.print("\t\tNumber of load commands: {}\n", .{header.ncmds});
    try writer.print("\t\tSize of load commands: {}\n", .{header.sizeofcmds});
    try writer.print("\t\tFlags: 0x{x}\n", .{header.flags});
    try writer.print("\t\tReserved: 0x{x}\n", .{header.reserved});
    try writer.print("\t}}\n", .{});
}

fn formatCommand(command: LoadCommand, writer: anytype) !void {
    try writer.print("\tLoad command {{\n", .{});

    switch (command.inner) {
        .Unknown => |x| {
            try writer.print("\t\tCommand: {}(??)\n", .{x.cmd});
            try writer.print("\t\tCommand size: {}\n", .{command.cmdsize});
            try writer.print("\t\tRaw contents: 0x{x}", .{x.contents[0..]});
        },
        else => {},
    }

    try writer.print("\t}}\n", .{});
}
