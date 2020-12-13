# SPDX-License-Identifier: BSD-3-Clause
#
# % {_libdir} typically points to /usr/lib64 but dracut is installed
# in /usr/lib on RHEL and SLES. So define dracutlibdir as is done
# in dracut.spec (commit ee6ce31 of dracut.git)
#
#
%define	dracutlibdir %{_prefix}/lib/dracut
%define	dracutmoddst %{dracutlibdir}/modules.d/98svm

Name:          svm-password-agent
Version:       0.0.1
Release:       0%{?dist}
Summary:       Password agent for IBM Secure VMs
URL:           https://github.com/open-power

# NOTE: svm-rootfs-askpass script installed by this rpm is licenced under GPLv3
# or later, and the rest of the files are licenced under  BSD-3-Clause
License:       GPL-3.0-or-later and BSD-3-Clause

Source0:       svm-password-agent.tgz
BuildRequires: gcc
BuildRequires: make
BuildArch:     ppc64le
Requires:      dracut
	
%description
	
Password agent that procures the password from the ESM-operand. Compatible
with the systemd password agent standards.

# Don't try to create a debug info for the esmb-get-file
%global debug_package %{nil}
 
%prep
%setup -q
	
%build
make
	
%install

%{make_install} PREFIX=$RPM_BUILD_ROOT/usr	\
		BINDIR=%{_bindir}		\
		INCLUDEDIR=%{_includedir}	\
		DRACUT_MOD_DST=%{dracutmoddst}

%files
%dir %{dracutmoddst}
%{_bindir}/svm-rootfs-askpass
%{_bindir}/esmb-get-file
%{dracutmoddst}/module-setup.sh
%{dracutmoddst}/svm-rootfs-hook.sh

%changelog
