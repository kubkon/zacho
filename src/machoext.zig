pub const LC_CODE_SIGNATURE: u32 = 0x1D;

pub const code_signature = extern struct {
    cmd: u32,
    cmdsize: u32,
    dataoff: u32,
    datasize: u32,
};

pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xFADE0CC0;

pub const SuperBlob = extern struct {
    magic: u32,
    length: u32,
    count: u32,
    index: ?*BlobIndex,
};

pub const BlobIndex = extern struct {
    @"type": u32,
    offset: u32,
};
