const std = @import("std");
const mem = std.mem;

const Allocator = mem.Allocator;

extern "c" fn CFRelease(*anyopaque) void;

pub const CMSDecoderRef = *opaque {
    pub fn deinit(self: CMSDecoderRef) void {
        CFRelease(self);
    }

    pub fn updateMessage(self: CMSDecoderRef, msg: []const u8) !void {
        const res = CMSDecoderUpdateMessage(self, msg.ptr, msg.len);
        if (res != 0) {
            return error.Failed;
        }
    }

    pub fn setDetachedContent(self: CMSDecoderRef, bytes: []const u8) !void {
        const dref = initCFDataRef(bytes);
        // TODO dealloc
        if (CMSDecoderSetDetachedContent(self, dref) != 0) {
            return error.Failed;
        }
    }

    pub fn finalizeMessage(self: CMSDecoderRef) !void {
        if (CMSDecoderFinalizeMessage(self) != 0) {
            return error.Failed;
        }
    }

    pub fn getNumSigners(self: CMSDecoderRef) !usize {
        var out: usize = undefined;
        if (CMSDecoderGetNumSigners(self, &out) != 0) {
            return error.Failed;
        }
        return out;
    }

    pub fn signerEmailAddress(self: CMSDecoderRef, allocator: Allocator, index: usize) ![]const u8 {
        var ref: ?CFStringRef = null;
        if (ref) |r| r.deinit();
        const res = CMSDecoderCopySignerEmailAddress(self, index, &ref);
        if (res != 0) {
            return error.Failed;
        }
        return ref.?.cstr(allocator);
    }

    pub fn copyDetachedContent(self: CMSDecoderRef) !?CFDataRef {
        var out: ?CFDataRef = null;
        const res = CMSDecoderCopyDetachedContent(self, &out);
        if (res != 0) {
            return error.Failed;
        }
        return out;
    }

    pub fn copyContent(self: CMSDecoderRef) !?CFDataRef {
        var out: ?CFDataRef = null;
        const res = CMSDecoderCopyContent(self, &out);
        if (res != 0) {
            return error.Failed;
        }
        return out;
    }

    pub fn getSignerStatus(self: CMSDecoderRef, index: usize) !CMSSignerStatus {
        const policy = SecPolicyCreateiPhoneProfileApplicationSigning();
        defer policy.deinit();
        var status: CMSSignerStatus = undefined;
        if (CMSDecoderCopySignerStatus(self, index, policy, false, &status, null, null) != 0) {
            return error.Failed;
        }
        return status;
    }

    extern "c" fn CMSDecoderSetDetachedContent(decoder: CMSDecoderRef, detached_content: CFDataRef) c_int;
    extern "c" fn CMSDecoderUpdateMessage(decoder: CMSDecoderRef, msg_bytes: *const anyopaque, msg_len: usize) c_int;
    extern "c" fn CMSDecoderFinalizeMessage(decoder: CMSDecoderRef) c_int;
    extern "c" fn CMSDecoderGetNumSigners(decoder: CMSDecoderRef, out: *usize) c_int;
    extern "c" fn CMSDecoderCopyDetachedContent(decoder: CMSDecoderRef, out: *?CFDataRef) c_int;
    extern "c" fn CMSDecoderCopyContent(decoder: CMSDecoderRef, out: *?CFDataRef) c_int;
    extern "c" fn CMSDecoderCopySignerEmailAddress(decoder: CMSDecoderRef, index: usize, out: *?CFStringRef) c_int;
    extern "c" fn CMSDecoderCopySignerStatus(
        decoder: CMSDecoderRef,
        index: usize,
        policy_or_array: *const anyopaque,
        eval_sec_trust: bool,
        out_status: *CMSSignerStatus,
        out_trust: ?*anyopaque,
        out_cert_verify_code: ?*c_int,
    ) c_int;
};

extern "c" fn SecPolicyCreateiPhoneApplicationSigning() SecPolicyRef;
extern "c" fn SecPolicyCreateiPhoneProfileApplicationSigning() SecPolicyRef;
extern "c" fn SecPolicyCreateMacOSProfileApplicationSigning() SecPolicyRef;

pub const SecPolicyRef = *opaque {
    pub fn deinit(self: SecPolicyRef) void {
        CFRelease(self);
    }
};

extern "c" fn CMSDecoderCreate(?*CMSDecoderRef) c_int;

pub fn initCMSDecoderRef() !CMSDecoderRef {
    var ref: CMSDecoderRef = undefined;
    const res = CMSDecoderCreate(&ref);
    if (res != 0) {
        return error.Failed;
    } else {
        return ref;
    }
}

pub const CFDataRef = *opaque {
    pub fn deinit(self: CFDataRef) void {
        CFRelease(self);
    }

    pub fn bytes(self: CFDataRef) []const u8 {
        const ptr = CFDataGetBytePtr(self);
        const len = @intCast(usize, CFDataGetLength(self));
        return @ptrCast([*]const u8, ptr)[0..len];
    }

    extern "c" fn CFDataGetBytePtr(CFDataRef) *const u8;
    extern "c" fn CFDataGetLength(CFDataRef) i32;
};

pub fn initCFDataRef(bytes: []const u8) CFDataRef {
    return CFDataCreate(null, bytes.ptr, bytes.len);
}

extern "c" fn CFDataCreate(allocator: ?*anyopaque, bytes: [*]const u8, length: usize) CFDataRef;

pub const CFStringRef = *opaque {
    pub fn deinit(self: CFStringRef) void {
        CFRelease(self);
    }

    /// Caller owns return memory.
    pub fn cstr(self: CFStringRef, allocator: Allocator) error{OutOfMemory}![]u8 {
        // if (CFStringGetCStringPtr(self, STRING_ENC_UTF8)) |ptr| {
        //     const c_str = mem.sliceTo(@ptrCast([*:0]const u8, ptr), 0);
        //     return allocator.dupe(u8, c_str);
        // }
        std.log.warn("length = {d}", .{CFStringGetLength(self)});

        const buf_size = 1024;
        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        try buf.resize(buf_size);

        while (!CFStringGetCString(self, buf.items.ptr, buf.items.len, STRING_ENC_UTF8)) {
            try buf.resize(buf.items.len + buf_size);
        }

        return buf.toOwnedSlice();
    }

    extern "c" fn CFStringGetLength(str: CFStringRef) usize;
    extern "c" fn CFStringGetCStringPtr(str: CFStringRef, encoding: u32) ?*const u8;
    extern "c" fn CFStringGetCString(str: CFStringRef, buffer: [*]u8, size: usize, encoding: u32) bool;
};

pub const CMSSignerStatus = enum(u32) {
    unsigned = 0,
    valid,
    needs_detached_content,
    invalid_signature,
    invalid_cert,
    invalid_index,
};

pub const CFRange = extern struct {
    length: usize,
    location: usize,
};

pub const STRING_ENC_UTF8: u32 = 0x8000100;
