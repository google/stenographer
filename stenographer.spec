%global commit0 89a9b664ba8ef2953abbc8bcf5908211e762d5ec
%global shortcommit0 %(c=%{commit0}; echo ${c:0:7})

# https://bugzilla.redhat.com/show_bug.cgi?id=995136#c12
%global _dwz_low_mem_die_limit 0


Name:           stenographer
Version:        0.0
Release:        1.git%{shortcommit0}%{?dist}
Summary:        A high-speed packet capture solution that provides indexed access

License:       	Apache License, 2.0 
URL:            https://github.com/google/stenographer
Source0:        https://github.com/google/%{name}/archive/%{commit0}.tar.gz


BuildRequires:  libaio-devel, leveldb-devel, snappy-devel, gcc-c++, make
BuildRequires:  libpcap-devel, libseccomp-devel, git
BuildRequires:  golang

Requires:       libaio, leveldb, snappy, libpcap, libseccomp
Requires: 	tcpdump, curl, rpmlib(FileCaps)
Requires(pre):  shadow-utils

%description
Stenographer is a full-packet-capture utility for buffering packets to disk for 
intrusion detection and incident response purposes. It provides a high-
performance implementation of NIC-to-disk packet writing, handles deleting those
files as disk fills up, and provides methods for reading back specific sets of 
packets quickly and easily.

%prep
%setup -q -n %{name}-%{commit0}

%build
# Build stenographer

export GOPATH=$(pwd):%{gopath}

#Get go deps
go get golang.org/x/text/encoding
#go get golang.org/x/text/encoding/unicode
go get golang.org/x/text/transform

# I don't understand go enough to figure out how to do this cleanly
# It complains that it can't install the project subdirs into GOPATH
# But `go build` works below regardless
set +e
go get ./...
set -e

# *** ERROR: No build ID note found in /.../BUILDROOT/etcd-2.0.0-1.rc1.fc22.x86_64/usr/bin/etcd
go build -o %{name} -a -ldflags "-B 0x$(head -c20 /dev/urandom|od -An -tx1|tr -d ' \n')" -v -x "$@"; 

# Build stenotype
(cd stenotype; make %{?_smp_mflags} )

%install
rm -rf %{buildroot}

# Install binaries & scripts
install -d %{buildroot}%{_bindir}
install -p -m 755 %{name} %{buildroot}%{_bindir}
install -p -m 755 stenotype/stenotype %{buildroot}%{_bindir}
install -p -m 755 stenoread %{buildroot}%{_bindir}
install -p -m 755 stenocurl %{buildroot}%{_bindir}

# Install configuration and service files
install -d %{buildroot}%{_sysconfdir}/%{name}/certs
install -p -m 644 configs/steno.conf   %{buildroot}%{_sysconfdir}/%{name}/config

install -d %{buildroot}%{_sysconfdir}/security/limits.d
install -p -m 644 configs/limits.conf  %{buildroot}%{_sysconfdir}/security/limits.d/stenographer.conf

install -d %{buildroot}%{_prefix}/lib/systemd/system
install -p -m 644 configs/systemd.conf %{buildroot}%{_prefix}/lib/systemd/system/stenographer.service

%files
%doc README.md DESIGN.md LICENSE

%attr(0500, stenographer, root) %{_bindir}/stenographer
%attr(0500, stenographer, root) %caps(cap_net_admin,cap_net_raw,cap_ipc_lock=ep) %{_bindir}/stenotype
%{_bindir}/stenoread
%{_bindir}/stenocurl

%{_sysconfdir}/stenographer
%attr(0750, stenographer, stenographer) %{_sysconfdir}/stenographer/certs
%config(noreplace) %{_sysconfdir}/stenographer/*

%{_sysconfdir}/security/limits.d/stenographer.conf
%{_prefix}/lib/systemd/system/stenographer.service

%pre
getent group stenographer  || groupadd -r stenographer
getent passwd stenographer || useradd -r -g stenographer -d / -s /sbin/nologin \
  -c "Stenographer service account" stenographer
exit 0

%post
echo << EOF
===============================================================================

Configure data and index directories in '/etc/stenographer/config' and set them
to be owned by the 'stenographer' user and group before starting the service

===============================================================================
EOF

exit 0

%changelog
