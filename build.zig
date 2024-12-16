const std = @import("std");

//const CFlags = &.{ "-fasm-blocks", "-masm=intel", "-fno-strict-aliasing" };

pub fn build(b: *std.Build) void {
    // Standard release options
    const optimize = b.standardOptimizeOption(.{
        // .preferred_optimize_mode = .ReleaseSmall,
    });

    // Create a lib artifact for Windows
    const lib = b.addSharedLibrary(.{
        .name = "excel_thread_demo",
        .root_source_file = b.path("src/main.zig"),
        .target = b.standardTargetOptions(.{
            .default_target = .{
                .cpu_arch = .x86_64,
                .os_tag = .windows,
                .abi = .gnu,
            },
        }),
        .optimize = optimize,
        .version = .{ .major = 0, .minor = 1, .patch = 0 },
    });

    lib.linkage = .dynamic;
    lib.linkSystemLibrary("kernel32");
    lib.linkSystemLibrary("user32");
    lib.linker_allow_shlib_undefined = true;
    lib.defineCMacro("EXPORT_EXCEL_FUNCTIONS", "1");

    // Add include paths
    lib.addIncludePath(b.path("src/dep/"));
    lib.linkLibC();

    // This puts the output file in zig-out/lib
    b.installArtifact(lib);
}
