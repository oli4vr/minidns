Name: minidns
Version: 1.0.0
Release: 1%{?dist}
Summary: Minimal DNS server
License: MIT
%define debug_package %{nil}
Source0: minidns
%description
A minimal DNS server.
%prep
%setup -c -T
%install
mkdir -p %{buildroot}/usr/bin
install -m 0755 %{_sourcedir}/minidns %{buildroot}/usr/bin/minidns
mkdir -p %{buildroot}/etc/systemd/system
install -m 0644 %{_sourcedir}/minidns.service %{buildroot}/etc/systemd/system/minidns.service
mkdir -p %{buildroot}/etc
install -m 0644 %{_sourcedir}/minidns.env.sample %{buildroot}/etc/minidns.env
%files
/usr/bin/minidns
/etc/systemd/system/minidns.service
/etc/minidns.env
%post
/usr/bin/systemctl daemon-reload || :
/usr/bin/systemctl enable minidns.service || :
%changelog
* Thu Jan 01 2020 Builder <builder@example.com> - 1.0.0-1
- Initial package