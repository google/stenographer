Installing Stenographer
=======================

If you'd prefer to read a shell script, you can take a look at install.sh :)
Also, we do plan to eventually create a real debian package config, and once
that's done we'll provide deb packages for easier installation.

This documentation provides our current method for installing stenographer on a
machine, including the justifications for why we think that method is currently
best-practice (or why it's not ;)


User/Group Setup
----------------

We set up a single system group `stenographer`, and a system user `stenographer`
with the former as its primary group.

### Group `stenographer` ###

The `stenographer` group is used to control access to locally stored packet
data.  Users are added to this group to allow them to query stenographer (via
the `stenoread` command).

### User `stenographer` ###

The `stenographer` user is used to run the `stenographer` and `stenotype`
binaries.  We use the `stenographer` user to protect the system from
`stenographer` and `stenotype`... this user has no special privileges except the
ability to read/write packet data and run the (setcap'd) stenotype binary.  So
if either is compromised, the system as a whole won't be.  See the **Defense In
Depth** section of DESIGN.md for more details.


Configuration Files
-------------------

There are a number of files in the `configs/` subdirectory, which may help in
installation.

   * `steno.conf`:  Discussed in more detail in the **Configuration File**
     section.  A configuration file must exist at `/etc/stenographer/config`
   * `upstart.conf`:  Upstart configuration file, can be copied into
     `/etc/init/stenographer.conf` to allow upstart to manage Stenographer
   * `limits.conf`:  If you don't use upstart, you may need to move this to
     `/etc/security/limits.d/stenographer.conf` in order to allow Stenographer
     to create files at the size it needs, and to open the number of files it
     needs to


Needed Directories
------------------

There are a few directories Stenographer needs in order to run correctly:

   * `/etc/stenographer root:root/0755`:  Stores configuration file
   * `/etc/stenographer/certs stenographer:stenographer/0750`:  Stores
     certificates used to verify clients are allowed to access packet data.
     `stenographer` writes certificates for client and server to this directory,
     and read clients `stenoread/stenocurl` read these certs and use them to
     make requests.
   * Packet directories:  These are chosen by the installer.  See
     **Configuration File** section for more details.


Configuration File
------------------

The `/etc/stenographer/config` file tells Stenographer what packets to read,
where to write them, how to serve them, etc.  It also tells the clients where
the Stenographer server is running and how to query it.

Here's an example config (note:  it's JSON):

    {
      "Threads": [
          { "PacketsDirectory": "/disk1/stenopkt", "IndexDirectory": "/disk3/stenoidx/disk1"}
        , { "PacketsDirectory": "/disk2/stenopkt", "IndexDirectory": "/disk3/stenoidx/disk2", "DiskFreePercentage": 25}
      ]
      , "StenotypePath": "/usr/local/bin/stenotype"
      , "Interface": "em1"
      , "Port": 1234
      , "Flags": []
      , "CertPath": "/etc/stenographer/certs"
    }

Let's look at each part of this in detail:

   * `StenotypePath`:  Where `stenographer` can find the `stenotype` binary,
     which it runs as a subprocess
   * `Interface`:  Network interface to read packets from
   * `Port`:  Port `stenographer` will bind to in order to serve `stenoread`
     requests.
   * `CertPath`:  Where `stenographer` will write certificates for client
     verification, and where the clients will read certificates when issuing
     queries.

### Threads ###

The `Threads` section is one of the most important.  It tells `stenotype`, the
packet capturing subprocess, a number of things:  how many threads to read
packets with, where to store those packets, and how to clean them up.

For each packet reading thread you'd like to run (IE: for each core you'd like
to use), you must specify:

   * `PacketsDirectory`:  Where to write packet files.  We recommend mounting
     a separate disk for each thread... we've found that at least for spinning
     disks, a single core can easily fill a disk's entire write throughput with
     room to spare.
   * `IndexDirectory`:  Where to write index files.  We've had good luck with
     using a single separate disk to write all index files, writing each
     thread's index to a separate subdirectory.  This directory gets FAR fewer
     writes, and they're FAR smaller.  We've found that even with up to 8
     threads, the all 8 index directories take up less than 20% of the space of
     a single thread's packets.
   * `DiskFreePercentage`:  The amount of space to keep free in the *packets*
     directory.  `stenographer` will delete files in this thread's packets
     directory when free disk space decreases below this percentage.  Note that
     we don't currently do any automated cleanup of the index directory.
     When a packet file is cleaned up, its index file is cleaned up, and because
     index files take so little space, we haven't ever needed to clean them up
     directly.  Note that `DiskFreePercentage` is optional... it defaults to
     10%.
   * `MaxDirectoryFiles`:  The maximum number of packet/index files to create
     before cleaning old ones up.  Defaults to 30K files, to avoid issues with
     ext3's 32K file-per-directory maximums.  For ext4 you should be able to go
     higher without issue.  Note that since we create at least one file every
     minute, this defaults to a maximum limit of 8 1/3 days before we drop old
     packets.

### Flags ###

The `Flags` section allows you to specify flags to pass to the `stenotype`
binary.  Here are some flags which may prove particularly useful:

   * `-v`:  Add verbosity to logging.  Logs by default are written to syslog,
     and are relatively quiet.  Adding one `-v` will have stenotype write
     per-thread capture statistics every minute or 100MB of packets, whichever
     comes first.  Adding more `-v` flags will provide you with reams of
     debugging information.
   * `--blocks=NUM`:  The number of 1MB packet blocks used by AF_PACKET to store
     packets in memory, *per thread*.  This flag basically allows you to control
     how much RAM the `stenotype` binary uses:  `blocks * threads * 1MB`.  More
     blocks will allow a thread to handle traffic spikes:  if you have 2048
     blocks (the default), then a thread can hold 2GB of traffic in memory while
     waiting for it to hit disk.  If you have slow links and you want to
     decrease memory usage, you can probably decrease this a LOT. :)
   * `--fanout_type=NUM`:  This sets the AF_PACKET fanout type to the passed-in
     value.  See AF_PACKET documentation for details on options here.  The
     default should probably be fine.
   * `--filter=HEX`:  Allows users to specify a BPF filter for packet capture...
     only packets which match this filter will be written by `stenotype`.  This
     is NOT a human-readable BPF filter... it's a hex-encoded compiled filter.
     Use the supplied `compile_bpf.sh` script to generate this encoding from a
     human-readable filter.
   * `--seccomp=none|trace|kill`:  We use seccomp to sandbox stenotype, but
     we've found that this can be fragile as we switch between different machine
     configurations.  Some VMs appear to freeze while trying to set up seccomp
     sandboxes:  for those environments, you can pass `--seccomp=none` in (note
     that this will turn off some sandboxing).  If you're trying to debug
     a `stenotype` failure you think is caused by overzealous sandboxing, you
     can pass in `--seccomp=trace`, then run stenotype with `strace` to figure
     out why things are misbehaving.
   * `--preallocate_file_mb=NUM`:  Certain file systems handle writes faster if
     the file has already been allocated to its eventual size.  If you set this
     flag to `4096`, then stenotype will preallocate each new packet file to
     this size while opening it.  The file will be truncated to its actual size
     when closed.  This should not be necessary unless you're really trying to
     eak out some extra speed on a file system that supports extents.

There's a number of other flags that `stenotype` supports, but most of them are
for debugging purposes.
