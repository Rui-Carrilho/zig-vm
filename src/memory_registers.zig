pub const MemoryRegisters = enum (u16) {
    MR_KBSR = 0xFE00,  //keyboard status
    MR_KBDR = 0xFE02  //keyboard data
};