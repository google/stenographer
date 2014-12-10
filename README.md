Stenographer
============

Overview
--------

Stenographer is a full-packet-capture utility for buffering packets to disk
for intrusion detection and incident response purposes.  It provides a
high-performance implementation of NIC-to-disk packet writing, handles
deleting those files as disk fills up, and provides methods for reading back
specific sets of packets quickly and easily.

It is designed to:

*   Write packets to disk, very quickly (~10Gbps on multi-core, multi-disk
    machines)
*   Store as much history as it can (managing disk usage, storing longer
    durations when traffic slows, then deleting the oldest packets when
    it hits disk limits)
*   Read a very small percentage (<1%) of packets from disk based on analyst
    needs

It is NOT designed for:

*   Complex packet processing (TCP stream reassembly, etc)
   *   It’s fast because it doesn’t do this.  Even with the very minimal,
       single-pass processing of packets we do, processing ~1Gbps for indexing
       alone can take >75% of a single core.
   *   Processing the data by reading it back from disk also doesn’t work:  see
       next bullet point.
*   Reading back large amounts of packets (> 1% of packets written)
   *   The key concept here is that disk reads compete with disk writes… you can
       write at 90% of disk speed, but that only gives you 10% of your disk’s
       time for reading.  Also, we’re writing highly sequential data, which
       disks are very good at doing quickly, and generally reading back sparse
       data with lots of seeks, which disks do slowly.

Architecture
------------

Stenographer is actually two separate processes:

1.  Stenographer:  long-running server which handles packet read requests, disk
    cleanup, and running/babysitting stenotype.
2.  Stenotype:  The actual packet-writing system; a multi-threaded NIC-to-disk
    writer.  Also writes out simple indexes for finding packets within files.
3.  Readback:  A simple command-line script that automates requesting packets
    from Stenographer and presenting them to analysts or other programs.

Stenotype writes packet files in a set of directories, based on the number of
writing threads it runs (one directory per thread).  Admins can then mount
different disks under these directories to spread load across a set of disks,
allowing faster writes than a single disk's throughput would allow.

Format
------

Stenotype writes files to disk in a non-standard format (they're straight dumps
of TPACKET_V3 memory regions), but users may request packets from Stenographer,
and the responses will be made available in PCAP format.  These can then be
passed to other systems like Wireshark or TCPDump for further analysis.

As well as writing out actual packet data, Stenotype also writes out indexes
which allow lookup of packets based on IP address, port (TCP and UDP), and
IP protocol.  When requesting packets from Stenographer, users may request
packets matching combinations of these features (packets between 1.2.3.4 and
4.3.2.1 on port 80), and only that subset of packets will be returned.

Performance
-----------

So far we're quite happy with Stenotype's performance.  When writing to
disk, we've tested up to 10Gbps with zero packet drops using 8
cores/disks.  Most of Stenotype's CPU usage is taken up with extracting index
information... with that turned off (just for testing, you'd probably never
actually want to do this), it can write out at full disk throughput
with roughly 6-8% of a single CPU.  With indexing turned on, a full 180MBps disk
write can be indexed with ~70% of a single CPU.

Querying
--------

### Query Language ###

A user requests packets from stenographer by specifying them with a very simple
query language.  The primitives in this language are:

    ip=1.1.1.1            # Single IP address (IPv4 OR IPv6)
    ip=1.1.1.0-1.1.2.200  # Arbitrary IP range
    port=80               # Single port number
    protocol=6            # Single IP protocol number
    last=4h               # Only packets from the last 4 hours.  Must end in
                          # 'h' for hours or 'm' for minutes.

You can do simple combinations of queries.  When combining queries, | does
a union and has highest precedence.  Whitespace does an intersection and has
lower precedence.  For example, to get all packets between IPs 1.1.1.1 and
2.2.2.2 in the last 45 minutes, you could use:

    # Packets must have both IP 1.1.1.1 (as src or dst) AND IP 2.2.2.2 (as
    # src or dst), and must have occurred within the last 45 minutes.
    ip=1.1.1.1 ip=2.2.2.2 last=45m

To get packets between 1.1.1.1 and either 2.2.2.2 or 3.3.3.3, use:

    # Packets must have IP 1.1.1.1 (as src or dst) either IP 2.2.2.2 OR 3.3.3.3
    # (as either src or dst).
    ip=1.1.1.1 ip=2.2.2.2|ip=3.3.3.3

To get all packets on ports 80, 8080, or 443 sent or received by 1.1.1.1, you can use:

    ip=1.1.1.1 port=80|port=8080|port=443

To get a specific tuple, you can use:

    ip=1.1.1.1 ip=2.2.2.2 port=80 port=65555 proto=6

### Readback CLI ###

The *readback* command line script automates pulling packets from Stenographer
and presenting them in a usable format to analysts.  It requests raw packets
from stenographer, then runs them through *tcpdump* to provide a more
full-featured formatting/filtering experience.  The first argument to *readback*
is a stenographer query (see 'Query Language' above).  All other arguments are
passed to *tcpdump*.  For example:

    # Request all packets from IP 1.2.3.4 port 6543, then do extra filtering by
    # TCP flag, which typical stenographer does not support.
    $ readback 'ip=1.2.3.4 port=6543' 'tcp[tcpflags] & tcp-push != 0'

    # Request packets on port 8765, disabling IP resolution (-n) and showing
    # link-level headers (-e) when printing them out.
    $ readback 'port=8765' -n -e

    # Request packets for any IPs in the range 1.1.1.1-1.1.1.6, writing them
    # out to a local PCAP file so they can be opened in Wireshark.
    $ readback 'ip=1.1.1.1-1.1.1.6' -w /tmp/output_for_wireshark.pcap

### Advanced Usage:  Writing Fast Queries ###

By understanding how stenographer stores/reads files and the volumes of network
traffic that typically occur, you can optimize your queries to get data back
faster and be an all-around nicer client.

Stenographer keeps two sets of files:  indexes which stores IP/port/protocol ->
position mappings, and blockfiles which store the actual packets.  When you
issue a query, stenographer first looks up the positions of the packets in the
index, then only reads the necessary packets out of the blockfiles.  These
packets are then passed through TCPDump, which can do additional filtering.

Consider the query 'ip=1.2.3.4 port=80’.  Stenographer will read in all
positions for ip=1.2.3.4 and all positions for port=80 from the indexes, then do
a set intersection to only pull out the packets that match both queries.  Then
it will read from the blockfiles.  But consider that probably over 50% of all
packets on the zombies have port=80… this means that when you use port=80,
you’re going to block a LONG time, as all positions for all port 80 packets are
read from all indexes.  Then, you’re going to throw away most of those positions
because a very small number ALSO have ip=1.2.3.4.

So how to optimize this?  If over 2% of all packets match a given filter, it’s
probably best to do that filtering in the tcpdump phase.  For example, these two
queries are guaranteed to return the same packets:

*   $ readback 'ip=1.2.3.4 port=80’ -n

    Will take a LONG time, because it has to find all port=80 packet positions
    in index files, using lots of disk reads, CPU, and RAM to
    read/hold/process them all, then throw them all away when filtering
    against ip=1.2.3.4.

*   $ readback 'ip=1.2.3.4’ -n port 80

    Only has to find ip=1.2.3.4 packets in index files (probably far less than
    1% of packets), then ships that small percentage to TCPDump where they’re
    filtered further using minimal CPU/RAM.

Given this, we recommend against using any of the following filters with
stenographer if you have typical traffic human-generated traffic patterns:

*   port=80
*   port=443
*   protocol=6  (TCP)
*   protocol=17  (UDP)

Of course, you can still use port=X for more esoteric ports, especially
ephemeral ports when you’re trying to follow a single stream, and for highly
esoteric protocols (especially because they won’t have port information for
further filtering).
