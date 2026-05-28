// ============================================================================
// Forge Compiler -- Build Script (Zig 0.15)
// ============================================================================
//
// Targets:
//   zig build                  -- Build the forgec compiler binary
//   zig build test             -- Run all unit tests across all source files
//   zig build check            -- Perform semantic-only check on contracts
//   zig build run -- <args>    -- Build and run forgec with given arguments
//
// Options:
//   -Dtarget=<triple>          -- Cross-compile target
//   -Doptimize=<mode>          -- Debug, ReleaseSafe, ReleaseFast, ReleaseSmall
//   -Dtest_filter=<str>        -- Filter test names
//

const std = @import("std");

pub fn build(b: *std.Build) void {
    // ── Standard Build Options ───────────────────────────────────────────
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Option to filter test names during "zig build test"
    const test_filter_opt = b.option(
        []const u8,
        "test_filter",
        "Filter test names (substring match)",
    );

    // ── Zephyria VM Module ────────────────────────────────────────────────
    // Registers the core ZVM logic as a modular import so both the compiler
    // unit tests and other verification executables can load it.
    const zvm_vm = b.createModule(.{
        .root_source_file = b.path("vm/vm.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── Freestanding WebAssembly ZVM Module ──────────────────────────────
    // Configures ZVM module for target CPU wasm32 and OS freestanding.
    const zvm_wasm_mod = b.createModule(.{
        .root_source_file = b.path("vm/vm.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .wasm32,
            .os_tag = .freestanding,
        }),
        .optimize = .ReleaseSmall,
    });
    _ = zvm_wasm_mod;

    // ── Root Module for Forge Compiler ──────────────────────────────────
    // Registers the main CLI executable module and binds the ZVM as an import.
    const root_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    root_mod.addImport("zephyria_vm", zvm_vm);

    // Apply fast-path compilation options on ReleaseFast builds
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

    // ── Run Step ─────────────────────────────────────────────────────────
    // Allows building and executing the compiler in one go via 'zig build run -- <args>'
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the ZEPH compiler");
    run_step.dependOn(&run_cmd.step);

    // ── Unit Testing Step ────────────────────────────────────────────────
    // Executes unit tests within each component of the compiler.
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
        "src/codegen_evm.zig",
        "src/u256.zig",
        "src/main.zig",
        "src/wasm.zig",
        // Zephyria VM unit tests
        "vm/vm.zig",
    };

    // Construct the filter array if specified
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

        // Binds the ZVM module into the unit testing contexts
        test_mod.addImport("zephyria_vm", zvm_vm);

        const t = b.addTest(.{
            .root_module = test_mod,
            .filters = filters,
        });

        const run_t = b.addRunArtifact(t);
        // Force the sandboxed interpreter for VM execution inside tests
        run_t.setEnvironmentVariable("FORGE_NO_AOT", "1");
        test_step.dependOn(&run_t.step);
    }

    // ── Check Step ────────────────────────────────────────────────────────
    // Traverses the contracts directory and runs '--check-only' on all .foz files
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
