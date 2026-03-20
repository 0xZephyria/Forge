const std = @import("std");

/// SPEC: Part 2.1 — `u256` is the default integer type for token math.
/// All arithmetic on token supplies uses u256 to prevent overflow.
pub const U256 = struct {
    /// Four 64-bit limbs in LITTLE-ENDIAN order.
    /// limbs[0] = least significant 64 bits.
    /// limbs[3] = most significant 64 bits.
    limbs: [4]u64,

    /// SPEC: Part 2.1 — The value zero represented as u256.
    pub const zero: U256 = .{ .limbs = .{ 0, 0, 0, 0 } };

    /// SPEC: Part 2.1 — The value one represented as u256.
    pub const one: U256 = .{ .limbs = .{ 1, 0, 0, 0 } };

    /// SPEC: Part 2.1 — The maximum value representable as u256 (2^256 - 1).
    pub const max: U256 = .{ .limbs = .{ std.math.maxInt(u64), std.math.maxInt(u64), std.math.maxInt(u64), std.math.maxInt(u64) } };

    /// SPEC: Part 2.1 — Parse a decimal string into a U256.
    pub fn parseDecimal(src: []const u8) !U256 {
        var result = U256.zero;
        for (src) |char| {
            if (char == '_') continue;
            if (char < '0' or char > '9') return error.InvalidCharacter;
            
            const digit: u64 = char - '0';
            
            const mul_res = result.mul10();
            if (mul_res.overflow) return error.Overflow;
            
            const digit_u256 = U256{ .limbs = .{ digit, 0, 0, 0 } };
            const add_res = mul_res.result.add(digit_u256);
            if (add_res.overflow) return error.Overflow;
            
            result = add_res.result;
        }
        return result;
    }

    /// SPEC: Part 2.1 — Parse a hexadecimal string into a U256.
    pub fn parseHex(src: []const u8) !U256 {
        var result = U256.zero;
        for (src) |char| {
            if (char == '_') continue;
            
            const digit: u64 = switch (char) {
                '0'...'9' => char - '0',
                'a'...'f' => char - 'a' + 10,
                'A'...'F' => char - 'A' + 10,
                else => return error.InvalidCharacter,
            };

            // Shift left by 4
            var new_limbs = [4]u64{ 0, 0, 0, 0 };
            var overflow_bits: u64 = 0;
            
            inline for (0..4) |i| {
                const limb = result.limbs[i];
                new_limbs[i] = (limb << 4) | overflow_bits;
                overflow_bits = limb >> 60; // top 4 bits
            }
            if (overflow_bits != 0) return error.Overflow;
            
            new_limbs[0] |= digit;
            result = .{ .limbs = new_limbs };
        }
        return result;
    }

    /// SPEC: Part 2.1 — Check if U256 fits within a 64-bit unsigned integer.
    pub fn fitsU64(self: U256) bool {
        return self.limbs[1] == 0 and self.limbs[2] == 0 and self.limbs[3] == 0;
    }

    /// SPEC: Part 2.1 — Check if U256 fits within a 32-bit unsigned integer.
    pub fn fitsU32(self: U256) bool {
        return self.fitsU64() and self.limbs[0] <= std.math.maxInt(u32);
    }

    /// SPEC: Part 2.1 — Convert U256 to u64. Caller must ensure it fits.
    pub fn toU64(self: U256) u64 {
        return self.limbs[0];
    }

    /// SPEC: Part 2.1 — Convert U256 to u32.
    pub fn toU32(self: U256) u32 {
        return @as(u32, @truncate(self.limbs[0]));
    }

    /// SPEC: Part 2.1 — 256-bit addition with overflow check.
    pub fn add(a: U256, b: U256) struct { result: U256, overflow: bool } {
        var res = U256.zero;
        var carry: u1 = 0;
        
        inline for (0..4) |i| {
            const add1 = @addWithOverflow(a.limbs[i], b.limbs[i]);
            const add2 = @addWithOverflow(add1[0], carry);
            res.limbs[i] = add2[0];
            carry = add1[1] | add2[1];
        }
        
        return .{ .result = res, .overflow = carry != 0 };
    }

    /// SPEC: Part 2.1 — Multiply U256 by 10 with overflow check.
    pub fn mul10(self: U256) struct { result: U256, overflow: bool } {
        // self * 10 = (self * 8) + (self * 2)
        // Shift left by 3 and 1, then add.
        var res8 = U256.zero;
        var overflow8: u64 = 0;
        inline for (0..4) |i| {
            res8.limbs[i] = (self.limbs[i] << 3) | overflow8;
            overflow8 = self.limbs[i] >> 61;
        }
        const has_overflow8 = overflow8 != 0;

        var res2 = U256.zero;
        var overflow2: u64 = 0;
        inline for (0..4) |i| {
            res2.limbs[i] = (self.limbs[i] << 1) | overflow2;
            overflow2 = self.limbs[i] >> 63;
        }
        const has_overflow2 = overflow2 != 0;

        const add_res = res8.add(res2);
        
        return .{
            .result = add_res.result,
            .overflow = has_overflow8 or has_overflow2 or add_res.overflow,
        };
    }

    /// SPEC: Part 2.1 — Check if two U256 values are equal.
    pub fn eql(a: U256, b: U256) bool {
        return a.limbs[0] == b.limbs[0] and
               a.limbs[1] == b.limbs[1] and
               a.limbs[2] == b.limbs[2] and
               a.limbs[3] == b.limbs[3];
    }

    /// SPEC: Part 2.1 — Check if U256 is zero.
    pub fn isZero(self: U256) bool {
        return self.fitsU64() and self.limbs[0] == 0;
    }

    /// SPEC: Part 2.1 — Extract limbs array.
    pub fn toLimbs(self: U256) [4]u64 {
        return self.limbs;
    }

    /// SPEC: Part 2.1 — Convert to 32 bytes little-endian.
    pub fn toBytes32Le(self: U256) [32]u8 {
        var buf: [32]u8 = undefined;
        std.mem.writeInt(u64, buf[0..8], self.limbs[0], .little);
        std.mem.writeInt(u64, buf[8..16], self.limbs[1], .little);
        std.mem.writeInt(u64, buf[16..24], self.limbs[2], .little);
        std.mem.writeInt(u64, buf[24..32], self.limbs[3], .little);
        return buf;
    }

    /// SPEC: Part 2.1 — Convert to 32 bytes big-endian.
    pub fn toBytes32Be(self: U256) [32]u8 {
        var buf: [32]u8 = undefined;
        std.mem.writeInt(u64, buf[0..8], self.limbs[3], .big);
        std.mem.writeInt(u64, buf[8..16], self.limbs[2], .big);
        std.mem.writeInt(u64, buf[16..24], self.limbs[1], .big);
        std.mem.writeInt(u64, buf[24..32], self.limbs[0], .big);
        return buf;
    }
};

test "U256 zero and one constants" {
    try std.testing.expect(U256.zero.isZero() == true);
    try std.testing.expect(U256.one.fitsU64() == true);
    try std.testing.expect(U256.one.toU64() == 1);
    try std.testing.expect(U256.max.isZero() == false);
}

test "parseDecimal basic values" {
    const val0 = try U256.parseDecimal("0");
    try std.testing.expect(val0.isZero());

    const val1 = try U256.parseDecimal("1");
    try std.testing.expect(val1.limbs[0] == 1);
    try std.testing.expect(val1.fitsU64() == true);

    const val255 = try U256.parseDecimal("255");
    try std.testing.expect(val255.limbs[0] == 255);

    const val_max_u64 = try U256.parseDecimal("18446744073709551615");
    try std.testing.expect(val_max_u64.limbs[0] == 0xFFFFFFFFFFFFFFFF);
    try std.testing.expect(val_max_u64.fitsU64() == true);

    const val_max_u64_plus_1 = try U256.parseDecimal("18446744073709551616");
    try std.testing.expect(val_max_u64_plus_1.limbs[0] == 0);
    try std.testing.expect(val_max_u64_plus_1.limbs[1] == 1);
    try std.testing.expect(val_max_u64_plus_1.fitsU64() == false);
}

test "parseDecimal underscore separators" {
    const v1 = try U256.parseDecimal("1_000_000");
    const v2 = try U256.parseDecimal("1000000");
    try std.testing.expect(v1.eql(v2));

    const v3 = try U256.parseDecimal("18_446_744_073_709_551_616");
    const v4 = try U256.parseDecimal("18446744073709551616");
    try std.testing.expect(v3.eql(v4));
}

test "parseDecimal overflow" {
    const err = U256.parseDecimal("999999999999999999999999999999999999999999999999999999999999999999999999999999");
    try std.testing.expectError(error.Overflow, err);
}

test "parseHex basic values" {
    const val0 = try U256.parseHex("0");
    try std.testing.expect(val0.isZero());

    const valFF = try U256.parseHex("FF");
    try std.testing.expect(valFF.limbs[0] == 255);

    const val_max_u64 = try U256.parseHex("FFFFFFFFFFFFFFFF");
    try std.testing.expect(val_max_u64.limbs[0] == 0xFFFFFFFFFFFFFFFF);

    const val_10000000000000000 = try U256.parseHex("10000000000000000");
    try std.testing.expect(val_10000000000000000.limbs[0] == 0);
    try std.testing.expect(val_10000000000000000.limbs[1] == 1);
}

test "parseDecimal invalid character" {
    try std.testing.expectError(error.InvalidCharacter, U256.parseDecimal("123abc"));
    try std.testing.expectError(error.InvalidCharacter, U256.parseDecimal("1.0"));
}

test "fitsU64 and fitsU32" {
    const v1 = U256{ .limbs = .{0xFFFFFFFF, 0, 0, 0} };
    try std.testing.expect(v1.fitsU32() == true);

    const v2 = U256{ .limbs = .{0x1_0000_0000, 0, 0, 0} };
    try std.testing.expect(v2.fitsU32() == false);

    const v3 = U256{ .limbs = .{0, 1, 0, 0} };
    try std.testing.expect(v3.fitsU64() == false);
}

test "add with carry" {
    const a = U256{ .limbs = .{0xFFFFFFFFFFFFFFFF, 0, 0, 0} };
    const res1 = a.add(U256.one);
    try std.testing.expect(res1.result.eql(U256{ .limbs = .{0, 1, 0, 0} }));
    try std.testing.expect(res1.overflow == false);

    const res2 = U256.max.add(U256.one);
    try std.testing.expect(res2.result.isZero());
    try std.testing.expect(res2.overflow == true);
}

test "toBytes32Le and toBytes32Be round-trip" {
    // For value 256 (0x100): Le[0]==0, Le[1]==1, Le[2..]==0
    const val256 = U256{ .limbs = .{ 256, 0, 0, 0 } };
    const le = val256.toBytes32Le();
    try std.testing.expect(le[0] == 0);
    try std.testing.expect(le[1] == 1);
    for (le[2..]) |b| {
        try std.testing.expect(b == 0);
    }

    // For same value: Be[31]==0, Be[30]==1, Be[0..29]==0
    const be = val256.toBytes32Be();
    try std.testing.expect(be[31] == 0);
    try std.testing.expect(be[30] == 1);
    for (be[0..30]) |b| {
        try std.testing.expect(b == 0);
    }
}
