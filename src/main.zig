const std = @import("std");
const registers = @import("registers.zig");
const opcodes = @import("opcodes.zig");
const flags = @import("flags.zig");
const traps = @import("traps.zig");
const memoryRegisters = @import("memory_registers.zig");

// No need to bother with headers in Zig
const MEMORY_MAX = 1 << 16;
var memory: [MEMORY_MAX]u16 = undefined;

//extremely easy to import bits of code in Zig,
//so we can compartmentize our codebase and make this part less crowded
const Register = registers.Register;
const reg = registers.reg;
const OP = opcodes.OpCode;
const FL = flags.Flags;
const trap = traps.TrapCodes;
const MR = memoryRegisters.MemoryRegisters;

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

pub fn readImageFile(file: std.fs.File) !void {
    // Read the origin value
    var origin: u16 = undefined;
    const origin_bytes = try file.read(std.mem.asBytes(&origin));
    if (origin_bytes != @sizeOf(u16)) return error.InvalidRead;
    
    // Swap to correct endianness
    origin = swap16(origin);
    
    // Calculate maximum number of u16 values we can read
    const max_read = MEMORY_MAX - origin;
    
    // Read directly into memory slice starting at origin
    var dest_slice = memory[origin..];
    const items_read = try file.read(std.mem.sliceAsBytes(dest_slice));
    const words_read = items_read / @sizeOf(u16);
    
    // Swap endianness for each read word
    var i: usize = 0;
    while (i < words_read) : (i += 1) {
        dest_slice[i] = @byteSwap(dest_slice[i]);
    }
}

fn readImage(image_path: []const u8) !void {
    const file = try std.fs.cwd().openFile(image_path, .{});
    defer file.close();

    try readImageFile(file);
}

fn swap16(x: u16) u16 {
    return (x << 8) | (x >> 8);
}

fn memWrite(address: u16, val: u16) !void {
    memory[address] = val;
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
                const r0 = (instr >> 9) & 0x7;
                const r1 = (instr >> 6) & 0x7;
                const imm_flag = (instr >> 5) & 0x1;

                if (imm_flag == 1) {
                    const imm5 = signExtend(instr & 0x1F, 5);
                    reg[r0] = reg[r1] & imm5;
                } else {
                    const r2 = instr & 0x7;
                    reg[r0] = reg[r1] & reg[r2];
                }

                updateFlags(r0);
            },
            OP.OP_NOT => {
                // NOT
                const r0 = (instr >> 9) & 0x7;
                const r1 = (instr >> 6) & 0x7;

                reg[r0] = !reg[r1];
                updateFlags(r0);
            },
            OP.OP_BR => {
                const cond_flag = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1FF, 9);
                const cond = (cond_flag & reg[Register.R_COND]);
                if (cond) {
                    reg[Register.R_PC] += pc_offset;
                }
            },
            OP.OP_JMP => {
                const r1 = (instr >> 6) & 0x7;
                reg[Register.R_PC] = reg[r1];
            },
            OP.OP_JSR => {
                const long_flag = (instr >> 11) & 1;
                reg[Register.R_R7] = reg[Register.R_PC];
                if (long_flag) {
                    const pc_offset = signExtend(instr & 0x7FF, 11);
                    reg[Register.R_PC] += pc_offset;
                } else {
                    const r1 = (instr >> 6) & 0x7;
                    reg[Register.R_PC] = reg[r1];
                }
            },
            OP.OP_LD => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1FF, 9);
                reg[r0] = mem_read(reg[Register.R_PC] + pc_offset);
                updateFlags(r0);
            },
            OP.OP_LDI => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1FF, 9);
                const effective_addr = mem_read(reg[Register.R_PC] + pc_offset);
                reg[r0] = mem_read(effective_addr);
                updateFlags(r0);
            },
            OP.OP_LDR => {
                const r0 = (instr >> 9) & 0x7;
                const r1 = (instr >> 6) & 0x7;
                const offset = signExtend(instr & 0x3F, 6);
                reg[r0] = mem_read(reg[r1] + offset);
                updateFlags(r0);
            },
            OP.OP_LEA => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1FF, 9);
                reg[r0] = reg[Register.R_PC] + pc_offset;
                updateFlags(r0);
            },
            OP.OP_ST => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1FF, 9);
                mem_write(reg[Register.R_PC] + pc_offset, reg[r0]);
            },
            OP.OP_STI => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1FF, 9);
                const effective_addr = mem_read(reg[Register.R_PC] + pc_offset);
                mem_write(effective_addr, reg[r0]);
            },
            OP.OP_STR => {
                const r0 = (instr >> 9) & 0x7;
                const r1 = (instr >> 6) & 0x7;
                const offset = signExtend(instr & 0x3F, 6);
                mem_write(reg[r1] + offset, reg[r0]);
            },
            OP.OP_TRAP => {
                reg[Register.R_R7] = reg[Register.R_PC];
                const trap_vector = instr & 0xFF;
                switch (trap_vector) {
                    trap.GETC => {
                        reg[Register.R_R0] = try std.io.getStdIn().reader().readByte();
                        updateFlags(Register.R_R0);
                    },
                    trap.OUT => {
                        const output = @truncate(u8, reg[Register.R_R0]);
                        std.debug.print("{c}", .{output});
                        try std.io.getStdOut().writer().flush();
                    },
                    trap.PUTS => {
                        var c: [*]u16 = @ptrCast(memory + reg[Register.R_R0]);
                        while (c[0] != 0) : (c += 1) {
                            const char_value = @truncate(u8, c[0]);
                            std.debug.print("{c}", .{char_value});
                        }
                        try std.io.getStdOut().writer().flush();
                    },
                    trap.IN => {
                        std.debug.print("Type your character: ", .{});
                        const c = try std.io.getStdIn().reader().readByte();
                        std.debug.print("character: {c}", .{char});
                        try std.io.getStdOut().writer().flush();
                        reg[Register.R_R0] = char;
                        updateFlags(Register.R_R0);
                    },
                    trap.PUTSP => {
                        var c: [*]u16 = @ptrCast(memory + reg[Register.R_R0]);
                        while (c[0] != 0) : (c += 1) {
                            const first_part = @truncate(u8, c[0] & 0xFF);
                            std.debug.print("{c}", .{first_part});
                            const second_part = @truncate(u8, c >> 8);
                            if (second_part != 0) {
                                std.debug.print("{c}", .{second_part});
                            }
                        }
                        try std.io.getStdOut().writer().flush();
                    },
                    trap.HALT => {
                        std.debug.print("HALTING\n", .{});
                        try std.io.getStdOut().writer().flush();
                        running = false;
                    },
                    else => {
                        std.debug.print("unhandled trap vector\n", .{});
                    },
                }
            },
            else => {
                break;
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
