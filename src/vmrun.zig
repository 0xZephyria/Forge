// ============================================================================
// Forge VM Runner — CLI entry point for the standalone Zephyria VM test suite
// ============================================================================
//
// Usage:
//   zig build vmtest                        # tests all contracts/ directory
//   zig build vmtest -- contracts/Foo.foz   # tests a single contract
//
// Exit code:
//   0 = all contracts passed
//   1 = one or more contracts failed or errored
//
// SPEC REFERENCE: Part 5, Part 14

const std  = @import("std");
const vm_t = @import("vm_test.zig");

const PASS = "\x1b[32m✓ PASS\x1b[0m";
const FAIL = "\x1b[31m✗ FAIL\x1b[0m";
const WARN = "\x1b[33m⚠ WARN\x1b[0m";
const GAS_LIMIT: u64 = 10_000_000;

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // Collect .foz paths to test
    var paths = std.ArrayListUnmanaged([]const u8){};
    defer paths.deinit(allocator);

    if (args.len > 1) {
        // Explicit file list from CLI args
        for (args[1..]) |arg| {
            try paths.append(allocator, arg);
        }
    } else {
        // Auto-discover contracts/ directory
        var dir = std.fs.cwd().openDir("contracts", .{ .iterate = true }) catch {
            try stderr.print("No contracts/ directory found.\n", .{});
            std.process.exit(1);
        };
        defer dir.close();
        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".foz")) {
                const path = try std.fmt.allocPrint(allocator, "contracts/{s}", .{entry.name});
                try paths.append(allocator, path);
            }
        }
    }

    if (paths.items.len == 0) {
        try stdout.print("No .foz files found. Nothing to test.\n", .{});
        return;
    }

    try stdout.print("\n╔══════════════════════════════════════════════════════╗\n", .{});
    try stdout.print("║    Forge · Zephyria VM Contract Test Suite            ║\n", .{});
    try stdout.print("╚══════════════════════════════════════════════════════╝\n\n", .{});

    var total_contracts: usize = 0;
    var total_passed: usize    = 0;
    var total_failed: usize    = 0;

    for (paths.items) |path| {
        total_contracts += 1;
        const source = std.fs.cwd().readFileAlloc(allocator, path, 1 << 20) catch |err| {
            try stdout.print("{s}  {s}\n    Error reading file: {}\n\n", .{ FAIL, path, err });
            total_failed += 1;
            continue;
        };
        defer allocator.free(source);

        try stdout.print("  Testing: \x1b[1m{s}\x1b[0m\n", .{path});

        var result = vm_t.testContract(allocator, source, path, GAS_LIMIT) catch |err| {
            try stdout.print("    {s}  Compile/load error: {}\n\n", .{ FAIL, err });
            total_failed += 1;
            continue;
        };
        defer result.deinit();

        if (result.actions.len == 0) {
            try stdout.print("    {s}  No actions emitted (empty contract)\n\n", .{WARN});
            total_passed += 1;
            continue;
        }

        var contract_ok = true;
        for (result.actions) |ar| {
            const status_icon: []const u8 = switch (ar.status) {
                .halted    => PASS,
                .breakpoint => PASS,
                .reverted  => FAIL,
                .out_of_gas => FAIL,
                .running   => WARN,
                else       => FAIL,
            };
            const status_str: []const u8 = switch (ar.status) {
                .halted    => "halted",
                .breakpoint => "breakpoint",
                .reverted  => "reverted",
                .out_of_gas => "out_of_gas",
                .running   => "still_running",
                else       => "error",
            };
            try stdout.print(
                "    {s}  selector=0x{X:0>8}  gas={d}  events={d}  [{s}]\n",
                .{ status_icon, ar.selector, ar.gas_used, ar.events, status_str },
            );
            if (ar.status == .reverted and ar.revert_data.len > 0) {
                try stdout.print(
                    "         revert: {s}\n",
                    .{std.fmt.fmtSliceEscapeUpper(ar.revert_data)},
                );
            }
            if (ar.status != .halted and ar.status != .breakpoint) {
                contract_ok = false;
            }
        }

        if (contract_ok) {
            total_passed += 1;
            try stdout.print("    → Contract {s}\n\n", .{PASS});
        } else {
            total_failed += 1;
            try stdout.print("    → Contract {s}\n\n", .{FAIL});
        }
    }

    // ── Summary ──────────────────────────────────────────────────────────
    try stdout.print("══════════════════════════════════════════════════════\n", .{});
    try stdout.print(
        "  Contracts: {d}  Passed: \x1b[32m{d}\x1b[0m  Failed: \x1b[31m{d}\x1b[0m\n",
        .{ total_contracts, total_passed, total_failed },
    );
    try stdout.print("══════════════════════════════════════════════════════\n\n", .{});

    if (total_failed > 0) std.process.exit(1);
}
