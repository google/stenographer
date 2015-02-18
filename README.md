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

For further reading, check out DESIGN.md for a discussion of stenographer's
design, or INSTALL.md for how to install stenographer on a machine.


Querying
--------

### Query Language ###

A user requests packets from stenographer by specifying them with a very simple
query language.  This language is a simple subset of BPF, and includes the
primitives:

    host 8.8.8.8          # Single IP address (hostnames not allowed)
    net 1.0.0.0/8         # Network with CIDR
    net 1.0.0.0 mask 255.255.255.0  # Network with mask
    port 80               # Port number (UDP or TCP)
    ip proto 6            # IP protocol number 6
    icmp                  # equivalent to 'ip proto 1'
    tcp                   # equivalent to 'ip proto 6'
    udp                   # equivalent to 'ip proto 17'

    # Stenographer-specific time additions:
    before 2012-11-03T11:05:00      # Packets before a specific time (UTC)
    after 2012-11-03T11:05:00-0700  # Packets after a specific time (with TZ)
    before 45m ago        # Packets before a relative time
    before 3h ago         # Packets after a relative time

Primitives can be combined with and/&& and with or/||, which have equal
precendence and evaluate left-to-right.  Parens can also be used to group.

    (udp and port 514) or (tcp and port 8080)

### Stenoread CLI ###

The *stenoread* command line script automates pulling packets from Stenographer
and presenting them in a usable format to analysts.  It requests raw packets
from stenographer, then runs them through *tcpdump* to provide a more
full-featured formatting/filtering experience.  The first argument to *stenoread*
is a stenographer query (see 'Query Language' above).  All other arguments are
passed to *tcpdump*.  For example:

    # Request all packets from IP 1.2.3.4 port 6543, then do extra filtering by
    # TCP flag, which typical stenographer does not support.
    $ stenoread 'host 1.2.3.4 and port 6543' 'tcp[tcpflags] & tcp-push != 0'

    # Request packets on port 8765, disabling IP resolution (-n) and showing
    # link-level headers (-e) when printing them out.
    $ stenoread 'port 8765' -n -e

    # Request packets for any IPs in the range 1.1.1.0-1.1.1.255, writing them
    # out to a local PCAP file so they can be opened in Wireshark.
    $ stenoread 'net 1.1.1.0/24' -w /tmp/output_for_wireshark.pcap

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

*   $ stenoread 'host 1.2.3.4 and port 80’ -n

    Will take a LONG time, because it has to find all port=80 packet positions
    in index files, using lots of disk reads, CPU, and RAM to
    read/hold/process them all, then throw them all away when filtering
    against host 1.2.3.4.

*   $ stenoread 'host 1.2.3.4’ -n port 80

    Only has to find ip=1.2.3.4 packets in index files (probably far less than
    1% of packets), then ships that small percentage to TCPDump where they’re
    filtered further using minimal CPU/RAM.

Given this, we recommend against using any of the following filters with
stenographer if you have typical traffic human-generated traffic patterns:

*   port 80
*   port 443
*   protocol 6  (tcp)
*   protocol 17  (udp)

Of course, you can still use 'port X' for more esoteric ports, especially
ephemeral ports when you’re trying to follow a single stream, and for highly
esoteric protocols (especially because they won’t have port information for
further filtering).


Obligatory Fine Print
---------------------

This is not an official Google product (experimental or otherwise), it is just
code that happens to be owned by Google.

This code is not intended (or used) to watch Google's users.  Its purpose
is to increase security on our networks by augmenting our internal monitoring
capabilities.
