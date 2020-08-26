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

pub fn init(alloc: *Allocator) ZachO {
    return .{
        .alloc = alloc,
    };
}

pub fn parse(self: *ZachO, stream: *io.StreamSource) !void {
    try self.parseHeader(stream);
}

pub fn parseFile(self: *ZachO, pathname: []const u8) !void {
    const file = try fs.openFileAbsolute(pathname, .{});
    defer file.close();

    var stream = io.StreamSource{ .file = file };
    return self.parse(&stream);
}

pub fn deinit(self: *ZachO) void {}

pub fn format(self: ZachO, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    try writer.print("Mach-O file {{\n", .{});

    if (self.header) |header| {
        try formatHeader(header, writer);
    }

    try writer.print("}}", .{});
}

fn parseHeader(self: *ZachO, stream: *io.StreamSource) !void {
    var buf: [@sizeOf(macho.mach_header_64)]u8 = undefined;
    const nread = try stream.read(buf[0..]);

    if (nread < @sizeOf(macho.mach_header_64)) return error.MalformedMachOHeader;

    self.header = mem.bytesToValue(macho.mach_header_64, &buf);
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
