# Compiler Passes Reference — checker.zig, types.zig

## Checker Architecture

```zig
pub const Checker = struct {
    arena:          std.heap.ArenaAllocator,
    diag:           *DiagEngine,
    allocator:      std.mem.Allocator,   // arena.allocator()
    scope_stack:    std.ArrayListUnmanaged(Scope) = .{},
    type_table:     std.StringHashMapUnmanaged(ResolvedType) = .{},
    // Contract context (set during checkContract, cleared after)
    cur_contract:   ?*const ContractDef     = null,
    cur_action:     ?*const ActionDecl      = null,
    // Access list accumulation
    access_builder: AccessListBuilder,
    // Linear type tracking
    linear_tracker: LinearTracker,
    // Module registry (from use imports)
    modules:        std.StringHashMapUnmanaged(Module) = .{},

    pub fn init(allocator: std.mem.Allocator, diag: *DiagEngine) !Checker {
        var arena = std.heap.ArenaAllocator.init(allocator);
        return Checker{
            .arena           = arena,
            .diag            = diag,
            .allocator       = arena.allocator(),
            .access_builder  = AccessListBuilder.init(arena.allocator()),
            .linear_tracker  = LinearTracker.init(arena.allocator()),
        };
    }

    pub fn deinit(self: *Checker) void { self.arena.deinit(); }
};

pub const Scope = struct {
    vars:    std.StringHashMapUnmanaged(VarInfo) = .{},
    parent:  ?*Scope = null,
    kind:    ScopeKind,          // .action / .view / .guard / .block / .pure

    pub const VarInfo = struct {
        typ:      ResolvedType,
        span:     Span,
        is_mut:   bool,
        is_linear: bool,         // capability types
        consumed: bool = false,  // linear tracking
    };
};
```

## Pass 1: Type Collection

```zig
fn pass1_collectTypes(self: *Checker, program: []TopLevel) !void {
    for (program) |tl| {
        switch (tl) {
            .contract_def   => |c| {
                // Register contract name as Program type
                try self.type_table.put(self.allocator, c.name, .program);
                // Register all structs/enums/records declared inside
                for (c.actions) |a| _ = a; // actions don't declare types
                // NOTE: nested struct/enum types from state_fields & events
                for (c.events) |e| try self.registerEventType(e);
                for (c.errors) |e| try self.registerErrorType(e);
            },
            .asset_def      => |a| try self.type_table.put(self.allocator, a.name, .{ .asset_acct = .{ .name = a.name } }),
            .interface_def  => |i| try self.registerInterface(i),
            .capability_def => |c| try self.type_table.put(self.allocator, c.name, .{ .capability = @constCast(&c) }),
            .use_import, .define_const, .global_inv => {},
        }
    }
    // Register built-in types
    const builtins = .{
        .{ "u8",void }, .{ "u16",void }, .{ "u32",void }, .{ "u64",void },
        .{ "u128",void }, .{ "u256",void }, .{ "uint",void },
        .{ "i8",void }, .{ "i16",void }, .{ "i32",void }, .{ "i64",void },
        .{ "bool",void }, .{ "Hash",void }, .{ "Commitment",void },
        .{ "Bytes",void }, .{ "Bytes32",void }, .{ "Signature",void },
        .{ "Timestamp",void }, .{ "Duration",void }, .{ "BlockNumber",void },
        .{ "Account",void }, .{ "Wallet",void }, .{ "Program",void },
        .{ "price9",void }, .{ "price18",void }, .{ "percent",void },
        .{ "String",void }, .{ "ShortStr",void }, .{ "Label",void },
    };
    inline for (builtins) |b| {
        if (!self.type_table.contains(b[0]))
            try self.type_table.put(self.allocator, b[0], @unionInit(ResolvedType, b[0], {}));
    }
}
```

## Pass 3: Contract Checking

```zig
fn checkContractDef(self: *Checker, c: ContractDef) !void {
    self.cur_contract = &c;
    defer self.cur_contract = null;

    // Check accounts: block
    for (c.accounts) |acct| try self.checkAccountDecl(acct);
    // Check authorities: block
    for (c.authorities) |auth| try self.checkAuthorityDecl(auth);
    // Check implements: interfaces exist
    for (c.implements) |iface| {
        if (!self.type_table.contains(iface))
            self.diag.err(E.UNDEFINED_SYMBOL, try std.fmt.allocPrint(
                self.allocator, "interface '{s}' not found", .{iface}), c.span);
    }
    // Check state fields
    for (c.state_fields) |f| try self.checkStateField(f);
    // Check setup
    if (c.setup) |s| try self.checkSetup(s);
    // Check guards
    for (c.guards) |g| try self.checkGuardDecl(g);
    // Check actions
    for (c.actions) |a| try self.checkAction(a);
    for (c.views)   |v| try self.checkView(v);
    for (c.pures)   |p| try self.checkPure(p);
    // Check events / errors are syntactically valid
    for (c.events) |e| try self.checkEventDecl(e);
    for (c.errors) |e| try self.checkErrorDecl(e);
    // Check upgrade block
    if (c.upgrade) |u| try self.checkUpgradeBlock(u);
    // Novel: conservation proofs
    for (c.conserves) |con| try self.checkConservation(con, c);
    // Novel: adversary blocks
    for (c.adversary) |adv| try self.checkAdversaryBlock(adv, c);
}
```

## Action Checking (Core Pass)

```zig
fn checkAction(self: *Checker, a: ActionDecl) !void {
    self.cur_action = &a;
    defer self.cur_action = null;
    self.access_builder.reset();
    self.linear_tracker.reset();

    try self.pushScope(.action);
    defer self.popScope();

    // Add params to scope
    for (a.params) |p| {
        const t = try self.resolveType(p.type_expr);
        try self.currentScope().vars.put(self.allocator, p.name, .{
            .typ = t, .span = p.span, .is_mut = false,
            .is_linear = isLinear(t),
        });
    }

    // Authority guard: verify authority name exists in contract
    if (a.authority_guard) |auth_guard| {
        try self.checkAuthorityGuard(auth_guard);
        // Record that this action requires authority check
        self.access_builder.requiresAuthority(auth_guard.name);
    }

    // Guards applied: verify guard names exist and param types match
    for (a.guards_applied) |guard_name| {
        try self.checkGuardReference(guard_name, a.span);
    }

    // Local accounts declared inside this action
    for (a.accounts_local) |acct| try self.checkAccountDecl(acct);

    // Check #[parallel] annotation
    const is_parallel = blk: {
        for (a.annotations) |ann| if (ann.kind == .parallel) break :blk true;
        break :blk false;
    };

    // Check #[reads] / #[writes] annotations (will verify against actual accesses)
    var explicit_reads:  ?[]FieldPath = null;
    var explicit_writes: ?[]FieldPath = null;
    for (a.annotations) |ann| {
        switch (ann.kind) {
            .reads  => |paths| explicit_reads  = paths,
            .writes => |paths| explicit_writes = paths,
            else    => {},
        }
    }

    // Check body statements
    for (a.body) |stmt| try self.checkStmt(stmt);

    // Verify return type if declared
    if (a.return_type) |rt| {
        const expected = try self.resolveType(rt);
        if (!self.access_builder.hasReturn()) {
            if (!isVoidCompatible(expected))
                self.diag.err(E.MISSING_RETURN, "action declares return type but has no 'give back'", a.span);
        }
    }

    // Verify access list annotations match actual accesses
    if (explicit_reads) |reads| try self.verifyReadAnnotations(reads);
    if (explicit_writes) |writes| try self.verifyWriteAnnotations(writes);

    // Parallel check: no global writes allowed
    if (is_parallel) try self.checkParallelConstraints(a.span);

    // Linear: all consumed capabilities must have been consumed exactly once
    try self.linear_tracker.verifyAllConsumed(self.diag, a.span);

    // Complexity class check
    if (a.complexity_class) |cc| try self.checkComplexityClass(cc, a.body, a.span);
}
```

## Access List Builder

```zig
pub const AccessListBuilder = struct {
    reads:  std.StringHashMapUnmanaged(void) = .{},
    writes: std.StringHashMapUnmanaged(void) = .{},
    allocator: std.mem.Allocator,
    has_return: bool = false,
    requires_auth: ?[]const u8 = null,

    pub fn init(alloc: std.mem.Allocator) AccessListBuilder {
        return .{ .allocator = alloc };
    }

    pub fn reset(self: *AccessListBuilder) void {
        self.reads.clearRetainingCapacity();
        self.writes.clearRetainingCapacity();
        self.has_return = false;
        self.requires_auth = null;
    }

    pub fn recordRead(self: *AccessListBuilder, path: []const u8) !void {
        try self.reads.put(self.allocator, path, {});
    }

    pub fn recordWrite(self: *AccessListBuilder, path: []const u8) !void {
        try self.reads.put(self.allocator, path, {});  // writes imply reads
        try self.writes.put(self.allocator, path, {});
    }

    pub fn requiresAuthority(self: *AccessListBuilder, name: []const u8) void {
        self.requires_auth = name;
    }

    pub fn hasReturn(self: *const AccessListBuilder) bool { return self.has_return; }

    pub fn isParallelSafe(self: *const AccessListBuilder) bool {
        // Parallel safe = no writes to non-caller-keyed paths
        // All write paths must contain "[caller]" somewhere
        var it = self.writes.iterator();
        while (it.next()) |entry| {
            if (!std.mem.containsAtLeast(u8, entry.key_ptr.*, 1, "[caller]")) return false;
        }
        return true;
    }

    pub fn toSignedList(self: *const AccessListBuilder, alloc: std.mem.Allocator) ![]u8 {
        // Serialize reads + writes into the ZephBin access list format
        var buf = std.ArrayList(u8).init(alloc);
        // Format: reads_count:u32 | read_path_lens_and_data | writes_count:u32 | ...
        _ = buf;
        return error.NotImplemented; // replace with real serializer
    }
};
```

## Linear Type Tracker (for Capability types)

```zig
pub const LinearTracker = struct {
    states: std.StringHashMapUnmanaged(LinearState) = .{},
    allocator: std.mem.Allocator,

    pub const LinearState = enum { unconsumed, consumed };

    pub fn init(alloc: std.mem.Allocator) LinearTracker {
        return .{ .allocator = alloc };
    }

    pub fn reset(self: *LinearTracker) void {
        self.states.clearRetainingCapacity();
    }

    pub fn introduce(self: *LinearTracker, name: []const u8) !void {
        try self.states.put(self.allocator, name, .unconsumed);
    }

    pub fn consume(self: *LinearTracker, name: []const u8, span: Span, diag: *DiagEngine) void {
        const entry = self.states.getPtr(name) orelse return;
        if (entry.* == .consumed) {
            diag.err(E.LINEAR_DROP,
                std.fmt.allocPrint(diag.allocator,
                    "capability '{s}' already consumed — cannot use again", .{name}
                ) catch return,
                span);
            return;
        }
        entry.* = .consumed;
    }

    pub fn verifyAllConsumed(self: *LinearTracker, diag: *DiagEngine, span: Span) !void {
        var it = self.states.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* == .unconsumed) {
                diag.warn("W0001",
                    std.fmt.allocPrint(diag.allocator,
                        "capability '{s}' was created but never consumed (linear type leak)", .{e.key_ptr.*}
                    ) catch return,
                    span);
            }
        }
    }
};
```

## Conservation Proof Checker (Novel — Pass 4)

```zig
fn checkConservation(self: *Checker, con: ConservationExpr, contract: ContractDef) !void {
    // Symbolic delta analysis:
    // For each action in the contract, compute the algebraic delta
    // on both sides of the conservation equation and verify they cancel.

    // con.lhs = aggregator(field_path)  e.g. sum(mine.balances)
    // con.rhs = expr                     e.g. mine.total_supply
    // con.op  = .eq | .gte | .lte

    for (contract.actions) |action| {
        var lhs_delta = SymbolicDelta.zero();
        var rhs_delta = SymbolicDelta.zero();

        for (action.body) |stmt| {
            switch (stmt) {
                .aug_assign => |aa| {
                    // Does lhs of aug_assign match lhs aggregated field?
                    if (matchesAggregatedField(aa.lhs, con.lhs_field)) {
                        const delta = computeExprDelta(aa.rhs, aa.op);
                        lhs_delta = lhs_delta.add(delta);
                    }
                    // Does it match rhs field?
                    if (matchesFieldPath(aa.lhs, con.rhs_path)) {
                        const delta = computeExprDelta(aa.rhs, aa.op);
                        rhs_delta = rhs_delta.add(delta);
                    }
                },
                .assign => |a| {
                    // Handle direct assignment (delta = new_value - old_value = unknown)
                    // Conservative: if we can't prove it's safe, emit error
                    if (matchesAggregatedField(a.lhs, con.lhs_field) or
                        matchesFieldPath(a.lhs, con.rhs_path)) {
                        self.diag.warn("W0002",
                            "conservation: direct assignment may break proof — use += or -=",
                            a.span);
                    }
                },
                else => {},
            }
        }

        // For .eq: lhs_delta must equal rhs_delta
        // For .gte: lhs_delta must >= rhs_delta (conservative: reject if unknown)
        if (!deltaSatisfies(lhs_delta, con.op, rhs_delta)) {
            self.diag.err(E.CONSERVATION_FAIL,
                try std.fmt.allocPrint(self.allocator,
                    "action '{s}' violates conservation: {s}",
                    .{ action.name, con.description }),
                action.span);
        }
    }
}
```

## Complexity Class Checker (Novel)

```zig
fn checkComplexityClass(self: *Checker, cc: ComplexityClass, body: []Stmt, span: Span) !void {
    const loop_depth = countMaxLoopDepth(body);
    const has_unbounded = hasUnboundedLoop(body);

    switch (cc) {
        .constant => {
            if (loop_depth > 0) {
                self.diag.err(E.COMPLEXITY_EXCEEDED,
                    "action declared O(1) but contains loops", span);
            }
        },
        .linear => |bound| {
            if (loop_depth > 1) {
                self.diag.err(E.COMPLEXITY_EXCEEDED,
                    "action declared O(n) but has nested loops (would be O(n²))", span);
            }
            if (has_unbounded) {
                self.diag.err(E.COMPLEXITY_EXCEEDED,
                    try std.fmt.allocPrint(self.allocator,
                        "O(n) action: all loops must have #[max_iterations {d}] annotation",
                        .{bound.max}),
                    span);
            }
        },
        .quadratic => |bound| {
            if (loop_depth > 2) {
                self.diag.err(E.COMPLEXITY_EXCEEDED, "declared O(n²) but has 3+ nested loops", span);
            }
            _ = bound;
        },
    }
}

fn countMaxLoopDepth(stmts: []Stmt) u32 {
    var max: u32 = 0;
    for (stmts) |stmt| {
        switch (stmt) {
            .each        => |e| max = @max(max, 1 + countMaxLoopDepth(e.body)),
            .repeat      => |r| max = @max(max, 1 + countMaxLoopDepth(r.body)),
            .while_loop  => |w| max = @max(max, 1 + countMaxLoopDepth(w.body)),
            .when        => |w| max = @max(max, countMaxLoopDepth(w.then_body)),
            .attempt     => |a| max = @max(max, countMaxLoopDepth(a.body)),
            else => {},
        }
    }
    return max;
}

fn hasUnboundedLoop(stmts: []Stmt) bool {
    for (stmts) |stmt| {
        switch (stmt) {
            .each   => |e| {
                // Check for #[max_iterations N] annotation on the loop
                if (!e.has_max_iterations_annotation) return true;
                if (hasUnboundedLoop(e.body)) return true;
            },
            .while_loop => return true,   // while is always unbounded without proof
            .repeat => |r| {
                // repeat N times: only unbounded if N is not a literal
                if (!r.count_is_literal) return true;
            },
            else => {},
        }
    }
    return false;
}
```
