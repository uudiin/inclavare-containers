%define centos_base_release 1
%define _debugsource_template %{nil}
%define debug_package %{nil}

%global _missing_build_ids_terminate_build 0
%global PROJECT inclavare-containers

%global ENCLAVE_TLS_ROOTDIR /opt/enclave-tls
%global ENCLAVE_TLS_BINDIR /usr/share/enclave-tls/samples

Name: enclave-tls
Version: 0.6.1
Release: %{centos_base_release}%{?dist}
Summary: enclave-tls is a protocol to establish secure and trusted channel by integrating enclave attestation with transport layer security.

Group: Development/Tools
License: Apache License 2.0
URL: https://github.com/alibaba/%{PROJECT}
Source0: https://github.com/alibaba/%{PROJECT}/archive/v%{version}.tar.gz
Source10: enclave_tls.filelist

BuildRequires: git
BuildRequires: make
BuildRequires: autoconf
BuildRequires: libtool
BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: libsgx-dcap-quote-verify-devel
BuildRequires: libsgx-dcap-ql-devel
BuildRequires: libsgx-uae-service
ExclusiveArch: x86_64

%description
enclave-tls is a protocol to establish secure and trusted channel by integrating enclave attestation with transport layer security.

%prep
%setup -q -n %{PROJECT}-%{version}

%build
# If the SGX SDK is not prepared well in build environment, stop the build
if [ -z "$SGX_SDK" ]; then
        echo 'Error: Please install SGX SDK firstly'
        exit 1
fi

if [ "$SGX_SDK" != "/opt/intel/sgxsdk" ]; then
        echo 'Error: The SGX_SDK environment variable value is not correct'
        exit 1
fi

pushd %{name}
make SGX=1
popd

%install
pushd %{name}
Enclave_Tls_Root=%{?buildroot}%{ENCLAVE_TLS_ROOTDIR} Enclave_Tls_Bindir=%{?buildroot}%{ENCLAVE_TLS_BINDIR} make install
popd

%postun
rm -rf %{ENCLAVE_TLS_ROOTDIR} $(dirname %{ENCLAVE_TLS_BINDIR})

%files -f %{SOURCE10}

%changelog
* Thu Apr 22 2021 Shirong Hao <shirong@linux.alibaba.com> - 0.6.1
- Package init.
