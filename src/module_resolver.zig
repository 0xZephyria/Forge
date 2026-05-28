const std = @import("std");
const ast = @import("ast.zig");
const lexer = @import("lexer.zig");
const parser = @import("parser.zig");
const errors = @import("errors.zig");
const modules = @import("modules.zig");

const TopLevel = ast.TopLevel;
const Span = ast.Span;
const Lexer = lexer.Lexer;
const Parser = parser.Parser;
const DiagnosticList = errors.DiagnosticList;
const CompileError = errors.CompileError;

/// Result of resolving a single import.
pub const ResolvedImport = struct {
    /// The module namespace name (last path component, or alias).
    module_name: []const u8,
    /// Parsed top-level declarations from the imported file.
    top_levels: []const TopLevel,
    /// The file path that was resolved.
    file_path: []const u8,
    /// Source text of the imported file.
    source: []const u8,
};

/// Resolves `use path.to.module` to file contents and parsed ASTs.
/// Handles built-in stdlib modules, filesystem lookup, cycle detection,
/// and import caching.
pub const ModuleResolver = struct {
    allocator: std.mem.Allocator,
    diagnostics: *DiagnosticList,
    /// Directory of the main source file — used as base for relative imports.
    source_dir: []const u8,
    /// Cache of already-resolved imports: canonical path string → ResolvedImport.
    cache: std.StringHashMap(ResolvedImport),
    /// Set of imports currently being resolved (for cycle detection).
    resolving: std.StringHashMap(void),
    /// Allocator for arena-style allocations (kept until resolver is destroyed).
    temp_allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        diagnostics: *DiagnosticList,
        source_dir: []const u8,
    ) ModuleResolver {
        return .{
            .allocator = allocator,
            .diagnostics = diagnostics,
            .source_dir = source_dir,
            .cache = std.StringHashMap(ResolvedImport).init(allocator),
            .resolving = std.StringHashMap(void).init(allocator),
            .temp_allocator = allocator,
        };
    }

    pub fn deinit(self: *ModuleResolver) void {
        self.cache.deinit();
        self.resolving.deinit();
    }

/// Result of resolving all imports in a source file.
pub const ResolveAllResult = struct {
    /// All top-level declarations from the main file plus all imports.
    merged_top_levels: []const TopLevel,
    /// Map from module namespace name to ResolvedImport for file-based imports.
    file_modules: std.StringHashMap(ResolvedImport),
};

/// Walk all top-level declarations, resolve every `use_import`, and merge
/// imported files' top-level declarations into the result.
///
/// Built-in stdlib modules are NOT resolved here — they are handled by the
/// TypeResolver. Only file-based imports are resolved.
///
/// This function detects cyclic imports and namespace collisions.
pub fn resolveAll(self: *ModuleResolver, main_top_levels: []const TopLevel) anyerror!ResolveAllResult {
    var merged = std.ArrayListUnmanaged(TopLevel){};
    var file_modules = std.StringHashMap(ResolvedImport).init(self.allocator);

    // First, collect all non-import top-level declarations from the main file.
    for (main_top_levels) |tl| {
        if (tl != .use_import) {
            try merged.append(self.allocator, tl);
        }
    }

    // Now resolve each use_import in the main file.
    for (main_top_levels) |tl| {
        if (tl != .use_import) continue;
        const ui = tl.use_import;

        // Skip built-in stdlib modules (handled by type resolver).
        if (ui.path.len >= 1 and std.mem.eql(u8, ui.path[0], "std")) continue;

        const module_name = if (ui.alias) |a| a else ui.path[ui.path.len - 1];

        // Collision check: duplicate module name.
        if (file_modules.contains(module_name)) {
            const msg = try std.fmt.allocPrint(
                self.allocator,
                "import namespace collision: module '{s}' is already imported",
                .{module_name},
            );
            try self.diagnostics.add(.{
                .file = self.source_dir,
                .line = ui.span.line,
                .col = ui.span.col,
                .len = ui.span.len,
                .kind = CompileError.ImportCollision,
                .message = msg,
                .source_line = "",
            });
            continue;
        }

        const resolved = try self.resolve(ui.path) orelse continue;

        try file_modules.put(module_name, resolved);

        // Recursively resolve the imported file's own imports.
        // This returns its non-import declarations plus any nested imports.
        const sub_result = try self.resolveAll(resolved.top_levels);
        for (sub_result.merged_top_levels) |sub_tl| {
            try merged.append(self.allocator, sub_tl);
        }
        // Merge file_modules from sub-result (skip if already present).
        var iter = sub_result.file_modules.iterator();
        while (iter.next()) |entry| {
            if (!file_modules.contains(entry.key_ptr.*)) {
                try file_modules.put(entry.key_ptr.*, entry.value_ptr.*);
            }
        }
    }

    return ResolveAllResult{
        .merged_top_levels = try merged.toOwnedSlice(self.allocator),
        .file_modules = file_modules,
    };
}

/// Resolve a single `use` import path to its parsed top-level declarations.
/// Path is the dotted sequence, e.g. `["std", "math"]` or `["myprotocol", "interfaces"]`.
///
/// Returns null for unknown built-in modules (they are handled separately
/// in the type-checking phase). For file imports, returns the parsed result.
pub fn resolve(self: *ModuleResolver, path: []const []const u8) anyerror!?ResolvedImport {
        if (path.len == 0) return null;

        // Built-in stdlib modules are resolved directly by the type resolver.
        if (std.mem.eql(u8, path[0], "std")) {
            if (modules.resolveBuiltin(path) != null) {
                // Built-in: handled by type resolver, not by file resolution.
                return null;
            }
            // Unknown std.* module — treat as not found.
            const full_path = try std.mem.join(self.allocator, ".", path);
            const msg = try std.fmt.allocPrint(
                self.allocator,
                "unknown standard library module '{s}'",
                .{full_path},
            );
            try self.diagnostics.add(.{
                .file = self.source_dir,
                .line = 0,
                .col = 0,
                .len = 0,
                .kind = CompileError.ImportNotFound,
                .message = msg,
                .source_line = "",
            });
            return null;
        }

        // Convert dotted path to filesystem path.
        // E.g., ["myprotocol", "interfaces"] → "myprotocol/interfaces.foz"
        const module_name = if (path.len >= 2) path[path.len - 1] else path[0];

        // Build canonical key for cache/cycle detection.
        const canonical = try std.mem.join(self.allocator, ".", path);

        // Cycle detection.
        if (self.resolving.contains(canonical)) {
            const msg = try std.fmt.allocPrint(
                self.allocator,
                "cyclic import: '{s}' is already being resolved",
                .{canonical},
            );
            try self.diagnostics.add(.{
                .file = self.source_dir,
                .line = 0,
                .col = 0,
                .len = 0,
                .kind = CompileError.CyclicImport,
                .message = msg,
                .source_line = "",
            });
            return error.CyclicImport;
        }

        // Cache check.
        if (self.cache.get(canonical)) |cached| return cached;

        // Mark as resolving (cycle detection).
        try self.resolving.put(canonical, {});
        defer _ = self.resolving.remove(canonical);

        // Search for the file.
        const file_path = try self.findFile(path) orelse {
            const msg = try std.fmt.allocPrint(
                self.allocator,
                "import '{s}' not found (searched relative to '{s}')",
                .{ canonical, self.source_dir },
            );
            try self.diagnostics.add(.{
                .file = self.source_dir,
                .line = 0,
                .col = 0,
                .len = 0,
                .kind = CompileError.ImportNotFound,
                .message = msg,
                .source_line = "",
            });
            return null;
        };

        // Read the file.
        const source = std.fs.cwd().readFileAlloc(self.allocator, file_path, 1 << 20) catch |err| {
            const msg = try std.fmt.allocPrint(
                self.allocator,
                "cannot read import '{s}': {s}",
                .{ file_path, @errorName(err) },
            );
            try self.diagnostics.add(.{
                .file = self.source_dir,
                .line = 0,
                .col = 0,
                .len = 0,
                .kind = CompileError.ImportNotFound,
                .message = msg,
                .source_line = "",
            });
            return null;
        };

        // Lex and parse.
        var lex = Lexer.init(source, file_path);
        const tokens = lex.tokenize(self.allocator, self.diagnostics) catch |err| {
            return err;
        };
        var p = Parser.init(tokens, self.allocator, self.diagnostics, source, file_path);
        const top_levels = p.parse() catch |err| {
            return err;
        };

        const result = ResolvedImport{
            .module_name = module_name,
            .top_levels = top_levels,
            .file_path = file_path,
            .source = source,
        };

        // Cache the result.
        try self.cache.put(canonical, result);

        return result;
    }

    /// Find a file for the given import path.
    /// Searches relative to the source directory.
    fn findFile(self: *ModuleResolver, path: []const []const u8) !?[]const u8 {
        // Build the relative path from the dotted import.
        // E.g., ["myprotocol", "interfaces"] → "myprotocol/interfaces"
        const rel_dir = try std.mem.join(self.allocator, "/", path[0 .. path.len - 1]);
        const filename = path[path.len - 1];
        const full_base = if (rel_dir.len > 0)
            try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ rel_dir, filename })
        else
            try self.allocator.dupe(u8, filename);

        // Try extensions: .foz, .fozi
        const exts = [_][]const u8{ ".foz", ".fozi" };
        for (exts) |ext| {
            const try_path = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ full_base, ext });
            defer self.allocator.free(try_path);

            // Search relative to source directory.
            const abs_path = if (self.source_dir.len > 0)
                try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.source_dir, try_path })
            else
                try self.allocator.dupe(u8, try_path);

            if (fileExists(abs_path)) return abs_path;
            self.allocator.free(abs_path);
        }

        return null;
    }
};

fn fileExists(path: []const u8) bool {
    std.fs.accessAbsolute(path, .{}) catch return false;
    return true;
}

test "module_resolver detects empty path" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var res = ModuleResolver.init(allocator, &diags, "/tmp");
    defer res.deinit();
    try std.testing.expect((try res.resolve(&.{}) == null));
}

test "module_resolver resolveAll handles no imports" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var res = ModuleResolver.init(allocator, &diags, "/tmp");
    defer res.deinit();
    const result = try res.resolveAll(&.{});
    try std.testing.expect(result.merged_top_levels.len == 0);
    try std.testing.expect(result.file_modules.count() == 0);
}

test "module_resolver resolveAll skips stdlib imports" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var res = ModuleResolver.init(allocator, &diags, "/tmp");
    defer res.deinit();
    var path_storage: [2][]const u8 = .{ "std", "math" };
    const top_levels = [_]TopLevel{
        .{ .use_import = .{
            .path = path_storage[0..],
            .alias = null,
            .span = .{ .line = 1, .col = 1, .len = 14 },
        } },
    };
    const result = try res.resolveAll(&top_levels);
    // Stdlib imports are filtered out of merged_top_levels.
    try std.testing.expect(result.merged_top_levels.len == 0);
    try std.testing.expect(result.file_modules.count() == 0);
}
