const OpCode = enum(u8) {
    BR = 0,   // branch
    ADD = 0b0001,      // add
    LD,       // load
    ST,       // store
    JSR,      // jump register
    AND = 0b0101,      // bitwise and
    LDR,      // load register
    STR,      // store register
    RTI,      // unused
    NOT,      // bitwise not
    LDI,      // load indirect
    STI,      // store indirect
    JMP,      // jump
    RES,      // reserved (unused)
    LEA,      // load effective address
    TRAP,     // execute trap
};