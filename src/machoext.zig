pub const LC_CODE_SIGNATURE: u32 = 0x1D;

pub const code_signature_command = extern struct {
    cmd: u32,
    cmdsize: u32,
    dataoff: u32,
    datasize: u32,
};

/// single Requirement blob 
pub const CSMAGIC_REQUIREMENT: u32 = 0xfade0c00;
/// Requirements vector (internal requirements)
pub const CSMAGIC_REQUIREMENTS: u32 = 0xfade0c01;
/// CodeDirectory blob
pub const CSMAGIC_CODEDIRECTORY: u32 = 0xfade0c02;
/// embedded form of signature data
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
/// XXX
pub const CSMAGIC_EMBEDDED_SIGNATURE_OLD: u32 = 0xfade0b02;
/// embedded entitlements
pub const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade7171;
/// multi-arch collection of embedded signatures
pub const CSMAGIC_DETACHED_SIGNATURE: u32 = 0xfade0cc1;
/// CMS Signature, among other things
pub const CSMAGIC_BLOBWRAPPER: u32 = 0xfade0b01;

pub const CS_SUPPORTSSCATTER: u32 = 0x20100;
pub const CS_SUPPORTSTEAMID: u32 = 0x20200;
pub const CS_SUPPORTSCODELIMIT64: u32 = 0x20300;
pub const CS_SUPPORTSEXECSEG: u32 = 0x20400;

/// slot index for CodeDirectory
pub const CSSLOT_CODEDIRECTORY: u32 = 0;
pub const CSSLOT_INFOSLOT: u32 = 1;
pub const CSSLOT_REQUIREMENTS: u32 = 2;
pub const CSSLOT_RESOURCEDIR: u32 = 3;
pub const CSSLOT_APPLICATION: u32 = 4;
pub const CSSLOT_ENTITLEMENTS: u32 = 5;

/// first alternate CodeDirectory, if any
pub const CSSLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;
/// max number of alternate CD slots */
pub const CSSLOT_ALTERNATE_CODEDIRECTORY_MAX: u32 = 5;
/// one past the last
pub const CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT: u32 = CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX;

/// CMS Signature
pub const CSSLOT_SIGNATURESLOT: u32 = 0x10000;
pub const CSSLOT_IDENTIFICATIONSLOT: u32 = 0x10001;
pub const CSSLOT_TICKETSLOT: u32 = 0x10002;

/// compat with amfi
pub const CSTYPE_INDEX_REQUIREMENTS: u32 = 0x00000002;
/// compat with amfi
pub const CSTYPE_INDEX_ENTITLEMENTS: u32 = 0x00000005;

pub const CS_HASHTYPE_SHA1: u32 = 1;
pub const CS_HASHTYPE_SHA256: u32 = 2;
pub const CS_HASHTYPE_SHA256_TRUNCATED: u32 = 3;
pub const CS_HASHTYPE_SHA384: u32 = 4;

pub const CS_SHA1_LEN: u32 = 20;
pub const CS_SHA256_LEN: u32 = 32;
pub const CS_SHA256_TRUNCATED_LEN: u32 = 20;

/// always - larger hashes are truncated
pub const CS_CDHASH_LEN: u32 = 20;
/// max size of the hash we'll support
pub const CS_HASH_MAX_SIZE: u32 = 48;

pub const SuperBlob = extern struct {
    magic: u32,
    length: u32,
    count: u32,
};

pub const BlobIndex = extern struct {
    @"type": u32,
    offset: u32,
};

pub const CodeDirectory = extern struct {
    magic: u32,
    length: u32,
    version: u32,
    flags: u32,
    hashOffset: u32,
    identOffset: u32,
    nSpecialSlots: u32,
    nCodeSlots: u32,
    codeLimit: u32,
    hashSize: u8,
    hashType: u8,
    platform: u8,
    pageSize: u8,
    spare2: u32,
    execSegBase: u64,
    execSegLimit: u64,
    execSegFlags: u64,
};
