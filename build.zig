// ============================================================================
// Forge Compiler -- Build Script (Zig 0.15.2)
// ============================================================================
//
// Targets:
//   zig build             -- build the forgec compiler binary
//   zig build test        -- run all unit tests across all source files
//   zig build vmtest      -- compile + run every .foz contract through ForgeVM
//   zig build vmtest -- contracts/Foo.foz -- run one specific contract
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

    // ── Wasm: forge.wasm ──────────────────────────────────────────────────
    const wasm_mod = b.createModule(.{
        .root_source_file = b.path("src/wasm.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .wasm32,
            .os_tag = .freestanding,
        }),
        .optimize = .ReleaseSmall,
    });

    const wasm = b.addExecutable(.{
        .name = "forge",
        .root_module = wasm_mod,
    });
    wasm.entry = .disabled;
    wasm.rdynamic = true; // Export all public functions

    // Install the Wasm file to root `out/` directory to make it easy to find
    const install_wasm = b.addInstallArtifact(wasm, .{
        .dest_dir = .{ .override = .{ .custom = "../out" } },
    });
    b.getInstallStep().dependOn(&install_wasm.step);

    const wasm_step = b.step("wasm", "Build the WebAssembly compiler module");
    wasm_step.dependOn(&install_wasm.step);

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
        // "src/codegen_polkavm.zig",
        "src/codegen_evm.zig",
        "src/u256.zig",
        "src/main.zig",
        "src/wasm.zig",
        // Zephyria VM unit tests
        "zephyria/vm/vm.zig",
        "zephyria/vm/loader/zephbin_loader.zig",
        "zephyria/vm/core/decoder.zig",
        "zephyria/vm/core/executor.zig",
        "zephyria/vm/gas/meter.zig",
        "zephyria/vm/memory/sandbox.zig",
        "zephyria/vm/syscall/dispatch.zig",
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

    // ── VM Test step ──────────────────────────────────────────────────────
    // Compiles all .foz contracts and runs them through the Zephyria VM.
    // This is the end-to-end integration test suite (like `evm-test` for EVM).
    //
    // IMPORTANT: vm.zig uses bare relative @imports for all its sub-files.
    // In Zig 0.15, every source file must belong to exactly ONE module.
    // Therefore we register vm.zig as a single 'zephyria_vm' module and let
    // it resolve its children itself — we must NOT declare separate modules
    // for executor.zig, sandbox.zig etc. because vm.zig already owns them.
    const zvm_vm = b.createModule(.{
        .root_source_file = b.path("zephyria/vm/vm.zig"),
        .target = target,
        .optimize = optimize,
    });

    const vmtest_mod = b.createModule(.{
        .root_source_file = b.path("src/vmrun.zig"),
        .target = target,
        .optimize = optimize,
    });
    // zephyria_vm is the single entry point; zephbin_loader and syscall_dispatch
    // are accessed through vm_mod.zephbin_loader / vm_mod.syscall_dispatch re-exports.
    vmtest_mod.addImport("zephyria_vm", zvm_vm);


    const vmtest_exe = b.addExecutable(.{
        .name = "forge-vmtest",
        .root_module = vmtest_mod,
    });
    b.installArtifact(vmtest_exe);

    const vmtest_run = b.addRunArtifact(vmtest_exe);
    vmtest_run.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        vmtest_run.addArgs(args);
    }
    const vmtest_step = b.step(
        "vmtest",
        "Compile .foz contracts and run them through the Zephyria VM",
    );
    vmtest_step.dependOn(&vmtest_run.step);

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

