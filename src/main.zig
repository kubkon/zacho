const std = @import("std");
const process = std.process;
const ZachO = @import("ZachO.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    const args = try process.argsAlloc(&gpa.allocator);
    defer process.argsFree(&gpa.allocator, args);

    var zacho = ZachO.init(&gpa.allocator);
    defer zacho.deinit();

    try zacho.parseFile(args[1]);
    std.debug.print("{}\n", .{zacho});
}
