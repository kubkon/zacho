const std = @import("std");
const io = std.io;
const mem = std.mem;
const macho = std.macho;
const machoext = @import("../machoext.zig");

const Allocator = mem.Allocator;
const StreamSource = io.StreamSource;

pub const LoadCommand = union(enum) {
    Segment: SegmentCommand,
    CodeSignature: CodeSignatureCommand,
    Unknown: UnknownCommand,

    pub fn parse(alloc: *Allocator, stream: *StreamSource) !LoadCommand {
        const header = try stream.reader().readStruct(macho.load_command);
        try stream.seekBy(-@sizeOf(macho.load_command));

        return switch (header.cmd) {
            macho.LC_SEGMENT_64 => LoadCommand{
                .Segment = try SegmentCommand.parse(alloc, stream),
            },
            machoext.LC_CODE_SIGNATURE => LoadCommand{
                .CodeSignature = try CodeSignatureCommand.parse(alloc, stream),
            },
            else => LoadCommand{
                .Unknown = try UnknownCommand.parse(alloc, stream),
            },
        };
    }

    pub fn cmd(self: LoadCommand) u32 {
        return switch (self) {
            .Segment => |x| x.cmd(),
            .CodeSignature => |x| x.cmd(),
            .Unknown => |x| x.cmd(),
        };
    }

    pub fn cmdsize(self: LoadCommand) u32 {
        return switch (self) {
            .Segment => |x| x.cmdsize(),
            .CodeSignature => |x| x.cmdsize(),
            .Unknown => |x| x.cmdsize(),
        };
    }

    pub fn format(self: LoadCommand, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        return switch (self) {
            .Segment => |x| x.format(fmt, options, writer),
            .CodeSignature => |x| x.format(fmt, options, writer),
            .Unknown => |x| x.format(fmt, options, writer),
        };
    }

    pub fn deinit(self: *LoadCommand, alloc: *Allocator) void {
        return switch (self.*) {
            .Segment => |*x| x.deinit(alloc),
            .CodeSignature => |*x| x.deinit(alloc),
            .Unknown => |*x| x.deinit(alloc),
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

    pub fn format(self: SegmentCommand, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("Segment command\n", .{});
        try writer.print("  Command ID: LC_SEGMENT_64(0x{x})\n", .{self.inner.cmd});
        try writer.print("  Command size: {}\n", .{self.inner.cmdsize});
        try writer.print("  Segment name: {}\n", .{self.inner.segname});
        try writer.print("  VM address: 0x{x:0<16}\n", .{self.inner.vmaddr});
        try writer.print("  VM size: {}\n", .{self.inner.vmsize});
        try writer.print("  File offset: 0x{x:0<16}\n", .{self.inner.fileoff});
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

    fn formatSectionHeader(section: macho.section_64, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("     Section header\n", .{});
        try writer.print("       Section name: {}\n", .{section.sectname});
        try writer.print("       Segment name: {}\n", .{section.segname});
        try writer.print("       Address: 0x{x:0<16}\n", .{section.addr});
        try writer.print("       Size: {}\n", .{section.size});
        try writer.print("       Offset: 0x{x:0<16}\n", .{section.offset});
        try writer.print("       Alignment: {}\n", .{section.@"align"});
        try writer.print("       Relocations offset: 0x{x:0<16}\n", .{section.reloff});
        try writer.print("       Number of relocations: {}\n", .{section.nreloc});
        try writer.print("       Flags: 0x{x}\n", .{section.flags});
        try writer.print("       Reserved1 : 0x{x}\n", .{section.reserved1});
        try writer.print("       Reserved2: {}\n", .{section.reserved2});
        try writer.print("       Reserved3: {}", .{section.reserved3});
    }
};

pub const CodeSignatureCommand = struct {
    inner: machoext.code_signature_command,

    pub fn parse(alloc: *Allocator, stream: *StreamSource) !CodeSignatureCommand {
        const inner = try stream.reader().readStruct(machoext.code_signature_command);
        return CodeSignatureCommand{
            .inner = inner,
        };
    }

    pub fn cmd(self: CodeSignatureCommand) u32 {
        return self.inner.cmd;
    }

    pub fn cmdsize(self: CodeSignatureCommand) u32 {
        return self.inner.cmdsize;
    }

    pub fn format(self: CodeSignatureCommand, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("Code signature\n", .{});
        try writer.print("  Command ID: LC_CODE_SIGNATURE(0x{x})\n", .{self.inner.cmd});
        try writer.print("  Command size: {}\n", .{self.inner.cmdsize});
        try writer.print("  Data offset: {}\n", .{self.inner.dataoff});
        try writer.print("  Data size: {}", .{self.inner.datasize});
    }

    pub fn deinit(self: *CodeSignatureCommand, alloc: *Allocator) void {}
};

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

    pub fn format(self: UnknownCommand, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("Unknown\n", .{});
        try writer.print("  Command ID: ??(0x{x})\n", .{self.inner.cmd});
        try writer.print("  Command size: {}\n", .{self.inner.cmdsize});
        try writer.print("  Raw contents: 0x{x}", .{self.contents.items[0..]});
    }

    pub fn deinit(self: *UnknownCommand, alloc: *Allocator) void {
        self.contents.deinit(alloc);
    }
};
