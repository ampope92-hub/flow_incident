# The flow archive and the case report

## Reaching the archive

Two environment variables say where the archive is, and nothing else does: `ARCHIVE_HOST`
holds the host name or address it listens on and `ARCHIVE_PORT` the port. Both are set in the
container, and a different deployment sets them differently.

The archive speaks a line protocol over TCP. Every command is one line ending in a newline;
every answer starts with one line. Reads are all it does, several connections can be live
together, and a connection may make as many requests as it likes.

    CASE
    FETCH
    FETCH <token>
    QUIT

`CASE` answers one line:

    CASE inside=10.20.0.0/16 suspect=10.20.3.17 from=1746277200000 to=1746284400000 exporters=border,core

`inside` is the site's network, `suspect` the workstation the SOC flagged, `from` and `to` the
incident window as milliseconds since the Unix epoch, UTC, and `exporters` the names of the
two routers as the collector labelled them, the edge router first and the core second. The
collector's config allows only letters, digits, dot, dash and underscore in a label.

`FETCH` with no token answers the first page of datagrams, in the order the collector
received them; `FETCH <token>` answers the page after the one that handed out that token.
A page is

    PAGE <n> <next>
    ITEM <exporter> <received_ms> <length>
    <length bytes of datagram>
    ITEM ...

`n` items follow the PAGE line, each an ITEM line and then exactly `length` raw bytes with
nothing between them and the next ITEM line. `next` is the token for the following page, or
the word `end` on the last page. A token is opaque: the archive here writes one way and other
deployments write another, and the only thing to do with a token is to hand it back. The page
size is the archive's own setting and differs between deployments. `received_ms` is the
collector's clock when the datagram arrived, milliseconds since the epoch. An unknown
command gets `ERR` and a message back, and on `QUIT` the archive hangs up.

## What a datagram holds

Both routers export version 5 flow datagrams, the common layout, all fields big endian. The
header is 28 bytes:

    u16  version, always 5
    u16  count of records in this datagram, 1 to 30
    u32  uptime: milliseconds since the router booted, at the moment of export
    u32  unix_secs and
    u32  unix_nsecs: the router's own clock at the moment of export
    u32  flow_sequence: how many flow records the router had exported before this datagram,
         counted since it booted; no router exported 2^32 flows in the life of this archive
    u8   engine_type, u8 engine_id
    u16  sampling: the top two bits are the mode, the low fourteen the interval N. Mode 0
         means every packet was counted. Mode 1 means the router counted one packet in N.

Then `count` records of 48 bytes each:

    u32 srcaddr, u32 dstaddr, u32 nexthop
    u16 input, u16 output          interface indexes
    u32 dPkts, u32 dOctets         packets and bytes in this record
    u32 First, u32 Last            uptime at the first and the last packet of this record
    u16 srcport, u16 dstport
    u8  pad, u8 tcp_flags, u8 prot, u8 tos
    u16 src_as, u16 dst_as, u8 src_mask, u8 dst_mask, u16 pad

The three uptime fields are 32-bit millisecond counters and wrap after 49.7 days, and both
routers here have been up long enough for that to matter. A record's First and Last are on the
same counter as the header's uptime, so where the record falls in real time follows from the
header's clock and the distance between uptime and First.

A router keeps one cache entry per 5-tuple (source address, destination address, source port,
destination port, protocol) and direction; each direction of a connection is its own 5-tuple
and its own records. It closes a record and exports it after 60 seconds of traffic (active
timeout) or once 15 seconds pass without a packet (inactive timeout), and starts a fresh record
with the next packet of the same 5-tuple. A busy connection is therefore several records in a
row, and a quiet one can be several records with gaps between them. Exported records are sent
to the collector in datagrams within a second of being closed.

## The two routers

Every packet between the inside network and the internet crosses both routers, and traffic
between two inside hosts crosses only the core. Each router runs its own flow cache, so a
connection between inside and outside is in both routers' exports and a connection between
two inside hosts is in the core's only.

The edge router samples: it counts one packet in N, N as its header says, and the packets it
does not sample are not in its cache at all. A record from it holds the sampled packets only,
so its First is the first sampled packet, its counts are of the sampled packets, its inactive
timeout runs on the sampled packets, and a connection with too few packets to be sampled is
not in its export. The router's own volume screens show N times the sampled count, and the
case report treats a connection only the edge router saw the same way. The core counts every
packet of every connection it forwards, and where the core has a connection its count is the
count.

The edge router is on NTP and its clock is right. The core router has never been on NTP; its
clock was set by hand when it was installed and it keeps time well, so it is a whole number of
seconds away from true time and the same number of seconds through the whole archive. The
collector is on NTP, its clock is right, and a datagram reaches it a few tens of milliseconds
after the router sends it.

The core router was power cycled once during the archive. It forwarded nothing while it was
down, its cache was empty when it came back, and its uptime counter and flow sequence both
restarted from zero. The edge router stayed up.

No host on this network reuses a source port within five minutes of the last packet of the
connection that used it, so records of one 5-tuple less than five minutes apart belong to
the same connection and records five minutes or more apart belong to different connections.

## The collector

The collector keeps every datagram it received with the time it arrived. It did not receive
every datagram the routers sent: some were lost on the way, and the flow_sequence in the
headers is how far the loss shows. The collector also restarted once and, on coming back,
re-sent the last minutes of its spool into the archive, so a datagram from that stretch is in
the archive twice: the same bytes, with a later received_ms on the copy. A datagram is the
same datagram when its bytes are the same.

## The report

The tool prints one line to standard output and nothing else on it: a JSON object with three
members. Whitespace does not matter, and neither does the order of members in an object.

A connection is the records of one 5-tuple, from either router, that are less than five
minutes apart on the true clock, and it starts at the earliest First among them, on the true
clock. A connection is inside the window when its start is at or after `from` and before
`to`. Its bytes are the core's dOctets summed over its records when the core has any record of
it, and otherwise N times the edge router's dOctets summed over its records. Each direction is
its own connection, and the ones that matter are those whose source is the inside host.

`outbound` is an array with one object per inside host that has at least one connection to an
address outside `inside` starting inside the window, in ascending order of address: `host`
(dotted quad), `bytes` (the sum over those connections) and `connections` (how many).

`lateral` is an array with one object per inside host, other than the suspect, that the
suspect has a connection to starting inside the window, in ascending order of `first_ms` and
then of address: `host`, `first_ms` (the start of the earliest such connection, milliseconds
since the epoch on the true clock), `bytes` and `connections` as above. It is an empty array
when there are none.

`lost` is an object with one member per exporter, named as in the case line: the number of
flow records the collector never received from that router between the first and the last
datagram the archive holds from one boot of it, summed over its boots. A datagram carries
`count` records starting at `flow_sequence`, so the sequence of the next datagram the
collector has says how many records fell in between; records exported before the archive's
first datagram from a boot are not lost, they are before the archive.

All the figures in the report are plain JSON integers.

## How the tool is built and run

The tool is Zig, compiled with the Zig 0.14.1 that is on the box at
`/usr/local/lib/python3.13/site-packages/ziglang/zig`. The source lives under
`/app/flowkit/src` with `main.zig` as the root file; add more `.zig` files there as you like
and import them from it. The grader deletes everything under `src` that is not a `.zig` file
before it compiles, so a build file, a prebuilt object or anything in another language left
beside the sources is gone before the compiler runs, and it compiles with

    zig build-exe /app/flowkit/src/main.zig -O ReleaseSafe -femit-bin=<its own path>

with no other flag and no libc, then starts the result from `/app/flowkit` with the two
environment variables set. Only the submitted Zig sources are compiled, and the tool may
start no other program. The build is given 900 seconds and each graded run 600
seconds. `/app/flowkit/build.sh` runs the same compile and
`/app/flowkit/run.sh` builds and runs it against the archive here; the grader uses neither.
