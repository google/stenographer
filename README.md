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

For further reading, check out **[DESIGN.md](DESIGN.md)** for a discussion of stenographer's
design, or read **[INSTALL.md](INSTALL.md)** for how to install stenographer on a machine.


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
    before 2012-11-03T11:05:00Z      # Packets before a specific time (UTC)
    after 2012-11-03T11:05:00-07:00  # Packets after a specific time (with TZ)
    before 45m ago        # Packets before a relative time
    after 3h ago         # Packets after a relative time

**NOTE**: Relative times must be measured in integer values of hours or minutes
as demonstrated above.

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
    

Downloading
-----------

To download the source code, install Go locally, then run:

    $ go get github.com/google/stenographer
    
Go will handle downloading and installing all Go libraries that `stenographer`
depends on.  To build `stenotype`, go into the `stenotype` directory and run `make`.
You may need to install the following Ubuntu packages (or their equivalents on
other Linux distros):

*   libaio-dev
*   libleveldb-dev
*   libsnappy-dev
*   g++
*   libcap2-bin
*   libseccomp-dev


Obligatory Fine Print
---------------------

This is not an official Google product (experimental or otherwise), it is just
code that happens to be owned by Google.

This code is not intended (or used) to watch Google's users.  Its purpose
is to increase security on our networks by augmenting our internal monitoring
capabilities.
