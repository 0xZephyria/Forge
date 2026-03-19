// ============================================================================
// Forge Compiler -- Build Script (Zig 0.15.2)
// ============================================================================
//
// Targets:
//   zig build             -- build the forgec compiler binary
//   zig build test        -- run all unit tests across all source files
//   zig build check       -- semantic-only check on contracts/ directory
//   zig build run -- <args> -- build and run forgec with given arguments
//
// Options:
//   -Dtarget=<triple>     -- cross-compile target
//   -Doptimize=<mode>     -- Debug, ReleaseSafe, ReleaseFast, ReleaseSmall
//   -Dtest_filter=<str>   -- filter test names

const std = @import("std");

pub fn build(b: *std.Build) void {
    // ── Build options ────────────────────────────────────────────────────
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const test_filter_opt = b.option(
        []const u8,
        "test_filter",
        "Filter test names (substring match)",
    );

    // ── Root module for the forgec executable ─────────────────────────────
    const root_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Optimization-specific settings
    if (optimize == .ReleaseFast) {
        root_mod.single_threaded = true;
        root_mod.strip = true;
    }

    // ── Executable: forgec ────────────────────────────────────────────────
    const exe = b.addExecutable(.{
        .name = "forgec",
        .root_module = root_mod,
    });
    b.installArtifact(exe);

    // ── Run step ─────────────────────────────────────────────────────────
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the ZEPH compiler");
    run_step.dependOn(&run_cmd.step);

    // ── Test step ────────────────────────────────────────────────────────
    // Run tests in every source file that contains unit tests.
    const test_step = b.step("test", "Run all unit tests");

    const test_sources = [_][]const u8{
        "src/errors.zig",
        "src/ast.zig",
        "src/lexer.zig",
        "src/parser.zig",
        "src/types.zig",
        "src/checker.zig",
        "src/riscv.zig",
        "src/codegen.zig",
        "src/codegen_polkavm.zig",
        "src/main.zig",
    };

    // Build test filter array from the option
    const filters: []const []const u8 = if (test_filter_opt) |f|
        &.{f}
    else
        &.{};

    for (test_sources) |src| {
        const test_mod = b.createModule(.{
            .root_source_file = b.path(src),
            .target = target,
            .optimize = optimize,
        });

        const t = b.addTest(.{
            .root_module = test_mod,
            .filters = filters,
        });

        const run_t = b.addRunArtifact(t);
        test_step.dependOn(&run_t.step);
    }

    // ── Check step ───────────────────────────────────────────────────────
    // Runs forgec --check-only on all .foz files in contracts/ if present.
    const check_step = b.step("check", "Type-check .foz files in contracts/");

    if (std.fs.cwd().openDir("contracts", .{ .iterate = true })) |*dir| {
        var d = dir.*;
        defer d.close();
        var iter = d.iterate();
        while (iter.next() catch null) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".foz")) {
                const check_cmd = b.addRunArtifact(exe);
                check_cmd.addArg(b.fmt("contracts/{s}", .{entry.name}));
                check_cmd.addArg("--check-only");
                check_step.dependOn(&check_cmd.step);
            }
        }
    } else |_| {
        // contracts/ directory doesn't exist — check step is a no-op
    }
}
