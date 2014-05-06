%define		baserelease		1
%define		cif_feed_dir		/opt/cif/etc

Name:           perl-CIF-Smrt-Plugin-Contrib
Version:        1.0.0
Release:        %{baserelease}%{?dist}
Summary:        Collection of extra CIF plugins
Group:          Development/Libraries
License:        LGPL
Source0:        CIF-Smrt-Plugin-Contrib-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  perl(ExtUtils::MakeMaker)
BuildRequires:	perl(Test::More)
Requires:	cif >= 1.0.0
Requires:	perl(LWP::UserAgent)
Requires:	perl(Iodef::Pb::Simple) >= 0.18
Requires:	perl(Net::Google::SafeBrowsing2)
Requires:	perl(Net::Google::SafeBrowsing2::Sqlite)
Requires:	perl(REST::Client)
Requires:	perl(URI::Escape)
Requires:	perl(XML::Smart)
Requires:  	perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))

%{?filter_setup:
%filter_from_requires /perl(CIF)/d
%filter_from_requires /perl(CIF::.*)/d
%filter_setup
}
%{?perl_default_filter}

%description
Collection of extra CIF plugins
* Google Safe Browsing
* D-Shield API lookup
* NSRL lookup


%prep
%setup -q -n CIF-Smrt-Plugin-Contrib-%{version}


%build
%{__perl} Makefile.PL INSTALLDIRS=vendor
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make pure_install PERL_INSTALL_ROOT=$RPM_BUILD_ROOT
find $RPM_BUILD_ROOT -type f -name .packlist -exec rm -f {} ';'
find $RPM_BUILD_ROOT -depth -type d -exec rmdir {} 2>/dev/null ';'
%{_fixperms} $RPM_BUILD_ROOT/*

%{__mkdir} -p $RPM_BUILD_ROOT%{cif_feed_dir}
%{__install} -m 644 etc/* $RPM_BUILD_ROOT%{cif_feed_dir}


%check
make test


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc README
# For noarch packages: vendorlib
%{perl_vendorlib}/*
%{_mandir}/man3/*.3*

%config(noreplace) %attr(664,cif,cif) %{cif_feed_dir}/*


%changelog
* Thu Jun 13 2013 Aaron K. Reffett <akreffett@cert.org> - 1.0.0-1
- Tagged release 1.0.0

