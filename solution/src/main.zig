// flowkit: reads the case and every datagram off the flow archive and prints the case report.
//
// The archive is read page by page over the line protocol. Datagrams are kept once each (a
// re-sent copy is the same bytes with a later arrival), each router's clock error is read off
// the earliest copies as arrival minus header rounded to whole seconds, records are put on the
// true clock with the 32-bit uptime counter subtracted wrapping, grouped into connections by
// 5-tuple and the five minute port-reuse gap, and counted with the core's exact figures where
// it has them and the edge router's sampled figures times N where it does not. Lost records
// are the flow_sequence gaps within each boot.
const std = @import("std");

const REUSE_MS: i64 = 300_000;
const HDR: usize = 24;
const REC: usize = 48;

const Dgram = struct {
    exp: u8,
    rx: i64,
    data: []const u8,
};

const Rec = struct {
    key: u128,
    start: i64,
    end: i64,
    bytes: u64,
    n: u32,
};

const Agg = struct {
    bytes: u64 = 0,
    conns: u64 = 0,
    first: i64 = 0,
};

const Case = struct {
    net: u32,
    mask: u32,
    suspect: u32,
    from: i64,
    to: i64,
    names: [2][]const u8,
};

fn be16(b: []const u8) u16 {
    return std.mem.readInt(u16, b[0..2], .big);
}
fn be32(b: []const u8) u32 {
    return std.mem.readInt(u32, b[0..4], .big);
}

fn parseIp(s: []const u8) !u32 {
    var it = std.mem.splitScalar(u8, s, '.');
    var v: u32 = 0;
    var parts: usize = 0;
    while (it.next()) |p| {
        const o = try std.fmt.parseInt(u8, p, 10);
        v = (v << 8) | o;
        parts += 1;
    }
    if (parts != 4) return error.BadAddress;
    return v;
}

fn parseCase(alloc: std.mem.Allocator, line: []const u8) !Case {
    var c: Case = undefined;
    var have: u8 = 0;
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    const tag = it.next() orelse return error.Protocol;
    if (!std.mem.eql(u8, tag, "CASE")) return error.Protocol;
    while (it.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse return error.Protocol;
        const k = kv[0..eq];
        const v = kv[eq + 1 ..];
        if (std.mem.eql(u8, k, "inside")) {
            const slash = std.mem.indexOfScalar(u8, v, '/') orelse return error.Protocol;
            const bits = try std.fmt.parseInt(u6, v[slash + 1 ..], 10);
            c.mask = if (bits == 0) 0 else @as(u32, @truncate(~@as(u64, 0) << @intCast(32 - @as(u7, bits))));
            c.net = (try parseIp(v[0..slash])) & c.mask;
            have |= 1;
        } else if (std.mem.eql(u8, k, "suspect")) {
            c.suspect = try parseIp(v);
            have |= 2;
        } else if (std.mem.eql(u8, k, "from")) {
            c.from = try std.fmt.parseInt(i64, v, 10);
            have |= 4;
        } else if (std.mem.eql(u8, k, "to")) {
            c.to = try std.fmt.parseInt(i64, v, 10);
            have |= 8;
        } else if (std.mem.eql(u8, k, "exporters")) {
            const comma = std.mem.indexOfScalar(u8, v, ',') orelse return error.Protocol;
            c.names[0] = try alloc.dupe(u8, v[0..comma]);
            c.names[1] = try alloc.dupe(u8, v[comma + 1 ..]);
            have |= 16;
        }
    }
    if (have != 31) return error.Protocol;
    return c;
}

fn inside(c: *const Case, ip: u32) bool {
    return (ip & c.mask) == c.net;
}

fn recLess(_: void, a: Rec, b: Rec) bool {
    if (a.key != b.key) return a.key < b.key;
    if (a.start != b.start) return a.start < b.start;
    return a.end < b.end;
}

const Hdr = struct { count: u16, uptime: u32, clock: i64, seq: u32, n: u32 };

fn header(d: []const u8) Hdr {
    const sampling = be16(d[22..24]);
    return .{
        .count = be16(d[2..4]),
        .uptime = be32(d[4..8]),
        .clock = @as(i64, be32(d[8..12])) * 1000 + @as(i64, be32(d[12..16]) / 1_000_000),
        .seq = be32(d[16..20]),
        .n = if ((sampling >> 14) == 1) @as(u32, sampling & 0x3FFF) else 0,
    };
}

const Boot = struct { clock: i64, up: u32, seq: u32, count: u16 };

// The boot instant on the router's clock, modulo the 32-bit uptime counter.
fn bootAt(b: Boot) u32 {
    return @as(u32, @truncate(@as(u64, @bitCast(b.clock)))) -% b.up;
}

fn bootLess(_: void, a: Boot, b: Boot) bool {
    if (a.clock != b.clock) return a.clock < b.clock;
    return a.seq < b.seq;
}
fn seqLess(_: void, a: Boot, b: Boot) bool {
    return a.seq < b.seq;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();

    const host = try std.process.getEnvVarOwned(alloc, "ARCHIVE_HOST");
    const port_s = try std.process.getEnvVarOwned(alloc, "ARCHIVE_PORT");
    const port = try std.fmt.parseInt(u16, std.mem.trim(u8, port_s, " \r\n\t"), 10);

    const stream = try std.net.tcpConnectToHost(alloc, std.mem.trim(u8, host, " \r\n\t"), port);
    defer stream.close();
    var br = std.io.bufferedReader(stream.reader());
    const r = br.reader();
    const w = stream.writer();

    try w.writeAll("CASE\n");
    const case_line = try r.readUntilDelimiterAlloc(alloc, '\n', 1 << 16);
    const case = try parseCase(alloc, std.mem.trimRight(u8, case_line, "\r"));

    // ── every datagram, once ───────────────────────────────────────────────────────────────
    var dgrams = std.ArrayList(Dgram).init(alloc);
    var seen = std.StringHashMap(usize).init(alloc);
    var next: ?[]const u8 = null;
    while (true) {
        if (next) |t| try w.print("FETCH {s}\n", .{t}) else try w.writeAll("FETCH\n");
        const page = std.mem.trimRight(u8, try r.readUntilDelimiterAlloc(alloc, '\n', 1 << 16), "\r");
        var it = std.mem.tokenizeScalar(u8, page, ' ');
        const tag = it.next() orelse return error.Protocol;
        if (!std.mem.eql(u8, tag, "PAGE")) return error.Protocol;
        const n = try std.fmt.parseInt(usize, it.next() orelse return error.Protocol, 10);
        const nx = it.next() orelse return error.Protocol;
        for (0..n) |_| {
            const line = std.mem.trimRight(u8, try r.readUntilDelimiterAlloc(alloc, '\n', 4096), "\r");
            var jt = std.mem.tokenizeScalar(u8, line, ' ');
            const itag = jt.next() orelse return error.Protocol;
            if (!std.mem.eql(u8, itag, "ITEM")) return error.Protocol;
            const name = jt.next() orelse return error.Protocol;
            const rx = try std.fmt.parseInt(i64, jt.next() orelse return error.Protocol, 10);
            const len = try std.fmt.parseInt(usize, jt.next() orelse return error.Protocol, 10);
            const buf = try alloc.alloc(u8, len);
            try r.readNoEof(buf);
            var exp: u8 = 255;
            if (std.mem.eql(u8, name, case.names[0])) exp = 0;
            if (std.mem.eql(u8, name, case.names[1])) exp = 1;
            if (exp == 255) return error.UnknownExporter;
            if (len < HDR or be16(buf[0..2]) != 5) return error.BadDatagram;
            const h = header(buf);
            if (len != HDR + REC * @as(usize, h.count)) return error.BadDatagram;
            const gop = try seen.getOrPut(buf);
            if (gop.found_existing) {
                const i = gop.value_ptr.*;
                if (rx < dgrams.items[i].rx) dgrams.items[i].rx = rx;
                alloc.free(buf);
            } else {
                gop.value_ptr.* = dgrams.items.len;
                try dgrams.append(.{ .exp = exp, .rx = rx, .data = buf });
            }
        }
        if (std.mem.eql(u8, nx, "end")) break;
        next = try alloc.dupe(u8, nx);
    }
    try w.writeAll("QUIT\n");

    // ── each router's clock error: arrival minus header, whole seconds, the same everywhere ──
    var offset: [2]i64 = .{ 0, 0 };
    var lost: [2]i64 = .{ 0, 0 };
    for (0..2) |e| {
        var vals = std.ArrayList(i64).init(alloc);
        var boots = std.ArrayList(Boot).init(alloc);
        for (dgrams.items) |d| {
            if (d.exp != e) continue;
            const h = header(d.data);
            try vals.append(@divFloor(h.clock - d.rx + 500, 1000));
            try boots.append(.{ .clock = h.clock, .up = h.uptime, .seq = h.seq, .count = h.count });
        }
        if (vals.items.len == 0) continue;
        std.mem.sort(i64, vals.items, {}, std.sort.asc(i64));
        offset[e] = vals.items[vals.items.len / 2];

        // boots: ordered by the router's clock, a boot ends where the uptime stops running with it
        std.mem.sort(Boot, boots.items, {}, bootLess);
        var lo: usize = 0;
        var i: usize = 1;
        while (i <= boots.items.len) : (i += 1) {
            if (i == boots.items.len or @abs(@as(i32, @bitCast(bootAt(boots.items[i]) -% bootAt(boots.items[i - 1])))) > 1000) {
                const b = boots.items[lo..i];
                std.mem.sort(Boot, b, {}, seqLess);
                var j: usize = 1;
                while (j < b.len) : (j += 1) {
                    lost[e] += @as(i64, b[j].seq) - (@as(i64, b[j - 1].seq) + @as(i64, b[j - 1].count));
                }
                lo = i;
            }
        }
    }

    // ── records on the true clock ──────────────────────────────────────────────────────────
    var recs = std.ArrayList(Rec).init(alloc);
    for (dgrams.items) |d| {
        const h = header(d.data);
        const base = h.clock - offset[d.exp] * 1000;
        var i: usize = 0;
        while (i < h.count) : (i += 1) {
            const f = d.data[HDR + i * REC ..][0..REC];
            const first = be32(f[24..28]);
            const last = be32(f[28..32]);
            const key: u128 = (@as(u128, be32(f[0..4])) << 96) | (@as(u128, be32(f[4..8])) << 64) |
                (@as(u128, be16(f[32..34])) << 48) | (@as(u128, be16(f[34..36])) << 32) | @as(u128, f[38]);
            try recs.append(.{
                .key = key,
                .start = base - @as(i64, h.uptime -% first),
                .end = base - @as(i64, h.uptime -% last),
                .bytes = be32(f[20..24]),
                .n = h.n,
            });
        }
    }
    std.mem.sort(Rec, recs.items, {}, recLess);

    // ── connections, and the two tables ────────────────────────────────────────────────────
    var outbound = std.AutoHashMap(u32, Agg).init(alloc);
    var lateral = std.AutoHashMap(u32, Agg).init(alloc);
    var i: usize = 0;
    while (i < recs.items.len) {
        const key = recs.items[i].key;
        var start = recs.items[i].start;
        var end = recs.items[i].end;
        var exact: u64 = 0;
        var sampled: u64 = 0;
        var has_exact = false;
        var j = i;
        while (j < recs.items.len and recs.items[j].key == key) : (j += 1) {
            const rc = recs.items[j];
            if (j > i and rc.start - end >= REUSE_MS) break;
            if (rc.start < start) start = rc.start;
            if (rc.end > end) end = rc.end;
            if (rc.n == 0) {
                has_exact = true;
                exact += rc.bytes;
            } else {
                sampled += rc.bytes * rc.n;
            }
        }
        const bytes = if (has_exact) exact else sampled;
        const src: u32 = @truncate(key >> 96);
        const dst: u32 = @truncate(key >> 64);
        if (start >= case.from and start < case.to and inside(&case, src)) {
            if (!inside(&case, dst)) {
                const g = try outbound.getOrPut(src);
                if (!g.found_existing) g.value_ptr.* = .{};
                g.value_ptr.bytes += bytes;
                g.value_ptr.conns += 1;
            } else if (src == case.suspect and dst != case.suspect) {
                const g = try lateral.getOrPut(dst);
                if (!g.found_existing) g.value_ptr.* = .{ .first = start };
                if (start < g.value_ptr.first) g.value_ptr.first = start;
                g.value_ptr.bytes += bytes;
                g.value_ptr.conns += 1;
            }
        }
        i = j;
    }

    // ── the report ─────────────────────────────────────────────────────────────────────────
    var out_buf = std.io.bufferedWriter(std.io.getStdOut().writer());
    const o = out_buf.writer();
    try o.writeAll("{\"outbound\":[");
    var hosts = std.ArrayList(u32).init(alloc);
    var kit = outbound.keyIterator();
    while (kit.next()) |k| try hosts.append(k.*);
    std.mem.sort(u32, hosts.items, {}, std.sort.asc(u32));
    for (hosts.items, 0..) |h, n| {
        const a = outbound.get(h).?;
        if (n > 0) try o.writeAll(",");
        try o.print("{{\"host\":\"{d}.{d}.{d}.{d}\",\"bytes\":{d},\"connections\":{d}}}", .{ h >> 24, (h >> 16) & 255, (h >> 8) & 255, h & 255, a.bytes, a.conns });
    }
    try o.writeAll("],\"lateral\":[");
    const LatRow = struct { host: u32, agg: Agg };
    var rows = std.ArrayList(LatRow).init(alloc);
    var lit = lateral.iterator();
    while (lit.next()) |kv| try rows.append(.{ .host = kv.key_ptr.*, .agg = kv.value_ptr.* });
    std.mem.sort(LatRow, rows.items, {}, struct {
        fn lt(_: void, a: LatRow, b: LatRow) bool {
            if (a.agg.first != b.agg.first) return a.agg.first < b.agg.first;
            return a.host < b.host;
        }
    }.lt);
    for (rows.items, 0..) |row, n| {
        const h = row.host;
        if (n > 0) try o.writeAll(",");
        try o.print("{{\"host\":\"{d}.{d}.{d}.{d}\",\"first_ms\":{d},\"bytes\":{d},\"connections\":{d}}}", .{ h >> 24, (h >> 16) & 255, (h >> 8) & 255, h & 255, row.agg.first, row.agg.bytes, row.agg.conns });
    }
    try o.print("],\"lost\":{{\"{s}\":{d},\"{s}\":{d}}}}}\n", .{ case.names[0], lost[0], case.names[1], lost[1] });
    try out_buf.flush();
}
