const std = @import("std");
const registers = @import("registers.zig");
const opcodes = @import("opcodes.zig");
const flags = @import("flags.zig");
const traps = @import("trap_codes.zig");
const memoryRegisters = @import("memory_registers.zig");

//Windows specific stuff declared here
const windows = std.os.windows;
const HANDLE = windows.HANDLE;
const DWORD = windows.DWORD;
const INVALID_HANDLE_VALUE = windows.INVALID_HANDLE_VALUE;
const kernel32 = windows.kernel32;

//courtesy of Claude, solving an error
const INPUT_RECORD = extern struct {
    EventType: windows.WORD,
    Event: extern union {
        KeyEvent: KEY_EVENT_RECORD,
        MouseEvent: MOUSE_EVENT_RECORD,
        WindowBufferSizeEvent: WINDOW_BUFFER_SIZE_RECORD,
        MenuEvent: MENU_EVENT_RECORD,
        FocusEvent: FOCUS_EVENT_RECORD,
    },
};

const KEY_EVENT_RECORD = extern struct {
    bKeyDown: windows.BOOL,
    wRepeatCount: windows.WORD,
    wVirtualKeyCode: windows.WORD,
    wVirtualScanCode: windows.WORD,
    UnicodeChar: windows.WCHAR,
    dwControlKeyState: DWORD,
};

// You'll need these structs if you plan to handle other event types
const MOUSE_EVENT_RECORD = extern struct {
    // Add fields as needed
};

const WINDOW_BUFFER_SIZE_RECORD = extern struct {
    // Add fields as needed
};

const MENU_EVENT_RECORD = extern struct {
    // Add fields as needed
};

const FOCUS_EVENT_RECORD = extern struct {
    // Add fields as needed
};

pub extern "kernel32" fn GetNumberOfConsoleInputEvents(
    hConsoleInput: windows.HANDLE,
    lpcNumberOfEvents: *windows.DWORD,
) callconv(windows.WINAPI) windows.BOOL;

pub extern "kernel32" fn PeekConsoleInputA(
    hConsoleInput: windows.HANDLE,
    lpBuffer: [*]INPUT_RECORD,
    nLength: windows.DWORD,
    lpNumberOfEventsRead: *windows.DWORD,
) callconv(windows.WINAPI) windows.BOOL;

// Import Windows API functions that aren't in the standard bindings
pub extern "kernel32" fn FlushConsoleInputBuffer(hConsoleInput: windows.HANDLE) callconv(windows.WINAPI) windows.BOOL;

const ENABLE_ECHO_INPUT = 0x0004;
const ENABLE_LINE_INPUT = 0x0002;

// No need to bother with headers in Zig
const MEMORY_MAX = 1 << 16;
var memory: [MEMORY_MAX]u16 = undefined;

var hStdin: ?HANDLE = INVALID_HANDLE_VALUE;
var fdwOldMode: DWORD = undefined;
var fdwMode: DWORD = undefined;

//extremely easy to import bits of code in Zig,
//so we can compartmentize our codebase and make this part less crowded
const Register = registers.Register;
const reg = registers.reg;
const OP = opcodes.OpCode;
const FL = flags.Flags;
const trap = traps.TrapCodes;
const MR = memoryRegisters.MemoryRegisters;

//for signal handling
const c = @cImport({
    @cInclude("signal.h");
});

//signal handler type
const SignalHandler = fn (c_int) callconv(.C) void;

//signal handler
export fn handleInterrupt(sig: c_int) callconv(.C) void {
    restoreInputBuffering() catch |err| {
        // Handle the error
        std.debug.print("Failed to restore input buffering: {}\n", .{err});
    };

    std.debug.print("\n", .{});

    std.process.exit(@intCast(sig));
}

// to set up signal handling
fn setupSignalHandler() void {
    _ = c.signal(c.SIGINT, handleInterrupt);
}

fn signExtend(x: u16, bit_count: u16) u16 {
    if (((x >> @intCast(bit_count - 1)) & 1) == 1) {
        // If sign bit is set, fill all higher bits with 1s
        return x | (@as(u16, 0xFFFF) << @intCast(bit_count));
    }
    return x;
}

fn updateFlags(r: u16) void {
    if (registers.reg[r] == 0) {
        registers.reg[@intFromEnum(Register.R_COND)] = @intFromEnum(FL.FL_ZRO);
    } else if ((registers.reg[r] >> 15) == 1) { // Check leftmost bit for negative
        registers.reg[@intFromEnum(Register.R_COND)] = @intFromEnum(FL.FL_NEG);
    } else {
        registers.reg[@intFromEnum(Register.R_COND)] = @intFromEnum(FL.FL_POS);
    }
}

pub fn readImageFile(file: std.fs.File) !void {
    // Read the origin value
    var origin: u16 = undefined;
    const origin_bytes = try file.read(std.mem.asBytes(&origin));
    if (origin_bytes != @sizeOf(u16)) return error.InvalidRead;

    // Swap to correct endianness
    origin = swap16(origin);

    //on second thought, maybe this is unnecessary in this implementation, since we don't really use fread
    // Calculate maximum number of u16 values we can read
    //const max_read = MEMORY_MAX - origin;

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
    //std.debug.print("successfully read file {}", .{file});
    defer file.close();
    try readImageFile(file);
}

fn swap16(x: u16) u16 {
    return (x << 8) | (x >> 8);
}

fn memWrite(address: u16, val: u16) !void {
    memory[address] = val;
}

fn memRead(address: u16) u16 {
    if (address == @intFromEnum(MR.MR_KBSR)) {
        if (checkKey()) {
            memory[@intFromEnum(MR.MR_KBSR)] = (1 << 15);
            // Read a single character from stdin
            if (std.io.getStdIn().reader().readByte()) |char| {
                memory[@intFromEnum(MR.MR_KBDR)] = char;
            } else |_| {
                // Handle error by clearing the keyboard status
                memory[@intFromEnum(MR.MR_KBSR)] = 0;
            }
        }
        return memory[@intFromEnum(MR.MR_KBSR)];
    }
    return memory[address];
}

pub fn disableInputBuffering() !void {
    // Get handle and ensure it's valid
    hStdin = kernel32.GetStdHandle(windows.STD_INPUT_HANDLE);
    if (hStdin) |handle| {
        // Save old mode
        if (kernel32.GetConsoleMode(handle, &fdwOldMode) == 0) {
            return error.GetConsoleModeFailed;
        }

        // Calculate new mode
        fdwMode = fdwOldMode;
        fdwMode ^= ENABLE_ECHO_INPUT; // no input echo
        fdwMode ^= ENABLE_LINE_INPUT; // return when one or more characters available

        // Set new mode
        if (kernel32.SetConsoleMode(handle, fdwMode) == 0) {
            return error.SetConsoleModeFailed;
        }

        // Clear buffer
        if (FlushConsoleInputBuffer(handle) == 0) {
            return error.FlushConsoleFailed;
        }
    } else {
        return error.GetStdHandleFailed;
    }
}

fn restoreInputBuffering() !void {
    if (hStdin) |handle| {
        if (kernel32.SetConsoleMode(handle, fdwOldMode) == 0) {
            return error.SetConsoleModeFailed;
        }
    } else {
        return error.InvalidHandle;
    }
}

fn checkKey() bool {
    const wait_result = kernel32.WaitForSingleObject(@ptrCast(hStdin), 1000);
    if (wait_result == windows.WAIT_OBJECT_0) {
        var numberOfEvents: DWORD = undefined;
        var numEventsRead: DWORD = undefined;
        var buffer: [1]INPUT_RECORD = undefined;

        _ = GetNumberOfConsoleInputEvents(@ptrCast(hStdin), &numberOfEvents);
        if (numberOfEvents > 0) {
            if (PeekConsoleInputA(@ptrCast(hStdin), &buffer, 1, &numEventsRead) != 0) {
                return buffer[0].Event.KeyEvent.bKeyDown != 0;
            }
        }
    }
    return false;
}

pub fn main() !void {
    setupSignalHandler();
    try disableInputBuffering();
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    if (args.len < 2) {
        std.debug.print("lc3 [image-file1] ...\n", .{});
        return;
    }

    for (args[1..]) |arg| {
        readImage(arg) catch |err| {
            std.debug.print("Failed to read image: {}\n", .{err});
            return;
        };
    }

    registers.reg[@intFromEnum(Register.R_COND)] = @intFromEnum(FL.FL_ZRO);

    const PC_START: u16 = 0x3000;
    registers.reg[@intFromEnum(Register.R_PC)] = PC_START;

    var running = true;
    while (running) {
        // FETCH
        const instr = memRead(registers.reg[@intFromEnum(Register.R_PC)]);
        //std.debug.print("registers.reg[@intFromEnum(Register.R_PC)]: {}\n", .{registers.reg[@intFromEnum(Register.R_PC)]});
        registers.reg[@intFromEnum(Register.R_PC)] += 1;
        const op = instr >> 12;

        switch (op) {
            @intFromEnum(OP.ADD) => {
                // Destination register (DR)
                const r0 = (instr >> 9) & 0x7;
                // First operand (SR1)
                const r1 = (instr >> 6) & 0x7;
                // Whether we are in immediate mode
                const imm_flag = (instr >> 5) & 0x1;

                if (imm_flag == 1) {
                    const imm5 = instr & 0x1F;
                    registers.reg[r0] = registers.reg[r1] + imm5;
                } else {
                    const r2 = instr & 0x7;
                    registers.reg[r0] = registers.reg[r1] + registers.reg[r2];
                }

                updateFlags(r0);
                break;
            },
            @intFromEnum(OP.AND) => {
                // AND
                const r0 = (instr >> 9) & 0x7;
                const r1 = (instr >> 6) & 0x7;
                const imm_flag = (instr >> 5) & 0x1;

                if (imm_flag == 1) {
                    const imm5 = signExtend(instr & 0x1F, 5);
                    registers.reg[r0] = registers.reg[r1] & imm5;
                } else {
                    const r2 = instr & 0x7;
                    registers.reg[r0] = registers.reg[r1] & registers.reg[r2];
                }

                updateFlags(r0);
                break;
            },
            @intFromEnum(OP.NOT) => {
                // NOT
                const r0 = (instr >> 9) & 0x7;
                const r1 = (instr >> 6) & 0x7;

                registers.reg[r0] = ~registers.reg[r1];
                updateFlags(r0);
                break;
            },
            @intFromEnum(OP.BR) => {
                const cond_flag = (instr >> 9) & 0x7;
                const pc_offset = instr & 0x1FF;
                const cond = (cond_flag & registers.reg[@intFromEnum(Register.R_COND)]);
                if (cond > 0) {
                    registers.reg[@intFromEnum(Register.R_PC)] += pc_offset;
                }
                break;
            },
            @intFromEnum(OP.JMP) => {
                const r1 = (instr >> 6) & 0x7;
                registers.reg[@intFromEnum(Register.R_PC)] = registers.reg[r1];
                break;
            },
            @intFromEnum(OP.JSR) => {
                const long_flag = (instr >> 11) & 1;
                registers.reg[@intFromEnum(Register.R_R7)] = registers.reg[@intFromEnum(Register.R_PC)];
                if (long_flag != 0) {
                    const pc_offset = signExtend(instr & 0x7FF, 11);
                    registers.reg[@intFromEnum(Register.R_PC)] += pc_offset;
                } else {
                    const r1 = (instr >> 6) & 0x7;
                    registers.reg[@intFromEnum(Register.R_PC)] = registers.reg[r1];
                }
                break;
            },
            @intFromEnum(OP.LD) => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1FF, 9);
                registers.reg[r0] = memRead(registers.reg[@intFromEnum(Register.R_PC)] + pc_offset);
                updateFlags(r0);
                break;
            },
            @intFromEnum(OP.LDI) => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1FF, 9);
                const effective_addr = memRead(registers.reg[@intFromEnum(Register.R_PC)] + pc_offset);
                registers.reg[r0] = memRead(effective_addr);
                updateFlags(r0);
                break;
            },
            @intFromEnum(OP.LDR) => {
                const r0 = (instr >> 9) & 0x7;
                const r1 = (instr >> 6) & 0x7;
                const offset = signExtend(instr & 0x3F, 6);
                registers.reg[r0] = memRead(registers.reg[r1] + offset);
                updateFlags(r0);
                break;
            },
            @intFromEnum(OP.LEA) => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1FF, 9);
                registers.reg[r0] = registers.reg[@intFromEnum(Register.R_PC)] + pc_offset;
                updateFlags(r0);
                break;
            },
            @intFromEnum(OP.ST) => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1FF, 9);
                try memWrite(registers.reg[@intFromEnum(Register.R_PC)] + pc_offset, registers.reg[r0]);
                break;
            },
            @intFromEnum(OP.STI) => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1FF, 9);
                const effective_addr = memRead(registers.reg[@intFromEnum(Register.R_PC)] + pc_offset);
                try memWrite(effective_addr, registers.reg[r0]);
                break;
            },
            @intFromEnum(OP.STR) => {
                const r0 = (instr >> 9) & 0x7;
                const r1 = (instr >> 6) & 0x7;
                const offset = (instr & 0x3F);
                std.debug.print("registers.reg[r1]: {},\noffset: {},\ninstr: {},\ninstr & 0x3F: {},\nregisters.reg[r0]: {}\n", .{ registers.reg[r1], offset, instr, instr & 0x3F, registers.reg[r0] });
                try memWrite(registers.reg[r1] + offset, registers.reg[r0]);
                break;
            },
            @intFromEnum(OP.TRAP) => {
                registers.reg[@intFromEnum(Register.R_R7)] = registers.reg[@intFromEnum(Register.R_PC)];
                const trap_vector = @as(trap, @enumFromInt(instr & 0xFF));
                switch (trap_vector) {
                    trap.GETC => {
                        registers.reg[@intFromEnum(Register.R_R0)] = try std.io.getStdIn().reader().readByte();
                        updateFlags(@intFromEnum(Register.R_R0));
                    },
                    trap.OUT => {
                        const output: u8 = @truncate(registers.reg[@intFromEnum(Register.R_R0)]);
                        std.debug.print("{c}", .{output});
                        try std.io.getStdOut().writer().writeAll("\n");
                    },
                    trap.PUTS => {
                        var addr: u16 = registers.reg[@intFromEnum(Register.R_R0)];
                        while (memory[addr] != 0) : (addr += 1) {
                            const char: u8 = @truncate(memory[addr]);
                            std.debug.print("{c}", .{char});
                        }
                        try std.io.getStdOut().writer().writeAll("\n");
                    },
                    trap.IN => {
                        std.debug.print("Type your character: ", .{});
                        const char = try std.io.getStdIn().reader().readByte();
                        std.debug.print("character: {c}", .{char});
                        try std.io.getStdOut().writer().writeAll("\n");
                        registers.reg[@intFromEnum(Register.R_R0)] = char;
                        updateFlags(@intFromEnum(Register.R_R0));
                    },
                    trap.PUTSP => {
                        var addr: u16 = registers.reg[@intFromEnum(Register.R_R0)];
                        while (memory[addr] != 0) : (addr += 1) {
                            const first_part: u8 = @truncate(memory[addr] & 0xFF);
                            std.debug.print("{c}", .{first_part});
                            const second_part: u8 = @truncate(memory[addr] >> 8);
                            if (second_part != 0) {
                                std.debug.print("{c}", .{second_part});
                            }
                        }
                        try std.io.getStdOut().writer().writeAll("\n");
                    },
                    trap.HALT => {
                        std.debug.print("HALTING\n", .{});
                        try std.io.getStdOut().writer().writeAll("\n");
                        running = false;
                    },
                }
                break;
            },
            else => {
                break;
            },
        }
    }
    try restoreInputBuffering();
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
