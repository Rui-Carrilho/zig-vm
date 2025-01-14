pub const Register = enum(usize) {
    R_R0 = 0,
    R_R1,
    R_R2,
    R_R3,
    R_R4,
    R_R5,
    R_R6,
    R_R7,
    R_PC, // program counter
    R_COND,
    R_COUNT,
};

pub var reg: [@intFromEnum(Register.R_COUNT)]u16 = undefined;
