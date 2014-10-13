Stenographer
============

Overview
--------

Stenographer is a full-packet-capture utility for buffering full packet data on
disk for a period of time.  It will write all network traffic it sees out to
files on disk, deleting those files only when disk space decreases below a
threshold.  While packets reside on disk, they are accessible by querying
stenographer, which returns them in the industry-standard PCAP format.

Stenographer is meant to perform well on high-bandwidth networks, and given
enough CPUs and enough spinning platters it's proven its ability to write out at
least 10Gbps.  Even in situations where it may not be able to write out data
fast enough, Stenographer degrades nicely and still writes all it can without
falling over.

Stenographer is built to provide short-term packet history.  It will happily
write packets to disk, then return to you a small subset that you might care
about.  It is not designed, though, to store all packets for large-scale batch
processing or offload to external systems.

Architecture
------------

Stenographer is actually two separate processes:

1.  Stenographer:  long-running server which handles packet read requests, disk
    cleanup.
2.  Stenotype:  The actual packet-writing system; a multi-threaded NIC-to-disk
    writer.  Also writes out simple indexes for finding packets within files.

We're working on their interactions at the moment, but the long-term goal is
that Stenographer handles starting/running stenotype without much work on the
administrator's side.

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
information... with that turned off, it can write out at full disk throughput
with roughly 6-8% of a single CPU.  With indexing turned on, a full 180MBps disk
write can be indexed with ~70% of a single CPU.
