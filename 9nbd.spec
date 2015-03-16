Name:
Version:
Release:
Source0:

Summary: 9P Network Block Device
Packager: Jim Garlick <garlick@llnl.gov>
License: GPL
Group: System Environment/Base
Requires: kmod-%{name} = %{version}-%{release}
BuildRequires: redhat-rpm-config
BuildRequires: module-init-tools
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
9P File System

#  kmod package will be named kmod-{kmod_name}
%define kmod_name 9nbd

%define debug_package %{nil}

# Work around for total inflexibility of kernel_module_package -f argument.
#  we have to ensure kmod-9nbd.list is available now since macros
#  are expanded on RPM parsing:
%(/bin/echo -e "\
%defattr(644,root,root,755)\n\
/lib/modules/%2-%1\n\
/etc/depmod.d/kmod-9nbd.conf" >%{_sourcedir}/kmod-9nbd.list)

# Generate section for kmod-9nbd subpackage:
%kernel_module_package -f %{_sourcedir}/kmod-%{name}.list

%define kdir %{_usrsrc}/kernels/%{kverrel}

%prep
if ! [ -d "%{kdir}"  ]; then
	echo "Kernel build directory isn't set properly, cannot continue"
	exit 1
fi
%setup

%build
make -C "%{_usrsrc}/kernels/%{kverrel}" M=$PWD
echo "override 9p * weak-updates/%{kmod_name}"    > kmod-%{kmod_name}.conf
echo "override 9pnet * weak-updates/%{kmod_name}" >>kmod-%{kmod_name}.conf

%install
mkdir -p -m 755 $RPM_BUILD_ROOT
%{__install} -d %{buildroot}%{_sysconfdir}/depmod.d/
%{__install} kmod-%{kmod_name}.conf %{buildroot}%{_sysconfdir}/depmod.d/
export INSTALL_MOD_PATH=%{buildroot}
export INSTALL_MOD_DIR=extra/%{kmod_name}
make -C "%{_usrsrc}/kernels/%{kverrel}" modules_install M=$PWD
%{__rm} -f %{buildroot}/lib/modules/%{kverrel}/modules.*
