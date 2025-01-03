const std = @import("std");
const registers = @import("registers.zig");
const opcodes = @import("opcodes.zig");
const flags = @import("flags.zig");

// No need to bother with headers in Zig
const MEMORY_MAX = 1 << 16;
var memory: [MEMORY_MAX]u16 = undefined;

//extremely easy to import bits of code in Zig,
//so we can compartmentize our codebase and make this part less crowded
const Register = registers.Register;
const reg = registers.reg;
const OP = opcodes.OpCode;
const FL = flags.Flags;

fn signExtend(x: u16, bit_count: u16) u16 {
    // Check if the highest bit in the bit_count range is set (sign bit)
    if (((x >> @intCast(bit_count - 1)) & 1) == 1) {
        // If sign bit is set, fill all higher bits with 1s
        return x | (@as(u16, 0xFFFF) << @intCast(bit_count));
    }
    return x;
}

fn updateFlags(r: u16) void {
    if (reg[r] == 0) {
        reg[Register.R_COND] = FL.FL_ZRO;
    } else if ((reg[r] >> 15) == 1) { // Check leftmost bit for negative
        reg[Register.R_COND] = FL.FL_NEG;
    } else {
        reg[Register.R_COND] = FL.FL_POS;
    }
}

pub fn main() !void {
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    if (args.len < 2) {
        std.debug.print("lc3 [image-file1] ...\n", .{});
        return;
    }

    for (args[1..]) |arg| {
        if (!read_image(arg)) {
            std.debug.print("failed to load image: {s}\n", .{arg});
            return;
        }
    }

    reg[Register.R_COND] = FL.FL_ZRO;

    const PC_START: u16 = 0x3000;
    reg[Register.R_PC] = PC_START;

    var running = true;
    while (running) {
        // FETCH
        const instr = mem_read(reg[Register.R_PC]);
        reg[Register.R_PC] += 1;
        const op = instr >> 12;

        switch (op) {
            OP.OP_ADD => {
                // Destination register (DR)
                const r0 = (instr >> 9) & 0x7;
                // First operand (SR1)
                const r1 = (instr >> 6) & 0x7;
                // Whether we are in immediate mode
                const imm_flag = (instr >> 5) & 0x1;

                if (imm_flag == 1) {
                    const imm5 = signExtend(instr & 0x1F, 5);
                    reg[r0] = reg[r1] + imm5;
                } else {
                    const r2 = instr & 0x7;
                    reg[r0] = reg[r1] + reg[r2];
                }

                updateFlags(r0);
            },
            OP.OP_AND => {
                // AND
            },
            OP.OP_NOT => {
                // NOT
            },
            OP.OP_BR => {
                // BR
            },
            OP.OP_JMP => {
                // JMP
            },
            OP.OP_JSR => {
                // JSR
            },
            OP.OP_LD => {
                // LD
            },
            OP.OP_LDI => {
                // LDI
                
            },
            OP.OP_LDR => {
                // LDR
            },
            OP.OP_LEA => {
                // LEA
            },
            OP.OP_ST => {
                // ST
            },
            OP.OP_STI => {
                // STI
            },
            OP.OP_STR => {
                // STR
            },
            OP.OP_TRAP => {
                // TRAP
            },
            else => {
                // BAD OPCODE
            },
        }
    }
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
