%global __os_install_post %{nil}
%global _build_id_links none
Name: satsuma-core-dnf-guard
Version: 2.1.6
Release: 1%{?dist}
Summary: Mandatory Satsuma package verification gates for DNF5
License: LicenseRef-Proprietary
Source0: satsuma-core-%{version}.tar.gz
BuildRequires: gcc-c++
BuildRequires: pkgconfig(libdnf5)
Requires: libdnf5%{?_isa} >= 5.4.6.0
Requires: dnf5
Requires: satsuma-core = %{version}-%{release}

%description
Pins repository sources and signing keys before loading metadata, checks the
resolved download plan, and independently verifies downloaded RPMs before the
native DNF transaction. Refuses automatic repository key imports.

%prep
%setup -q -n satsuma-core-%{version}

%build
%{__cxx} %{build_cxxflags} %{build_ldflags} -std=c++20 -fPIC -fvisibility=hidden -shared -Wl,-z,relro,-z,now \
 $(pkg-config --cflags libdnf5) dnf_guard/satsuma_guard.cpp \
 -o satsuma_package_guard.so $(pkg-config --libs libdnf5)

%install
install -D -m 0755 satsuma_package_guard.so %{buildroot}%{_libdir}/libdnf5/plugins/satsuma_package_guard.so
install -D -m 0644 dnf_guard/satsuma_package_guard.conf %{buildroot}%{_sysconfdir}/dnf/libdnf5-plugins/satsuma_package_guard.conf

%files
%{_libdir}/libdnf5/plugins/satsuma_package_guard.so
%config(noreplace) %{_sysconfdir}/dnf/libdnf5-plugins/satsuma_package_guard.conf
