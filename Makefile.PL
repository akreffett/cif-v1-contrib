use ExtUtils::MakeMaker;

WriteMakefile(
    NAME            => 'CIF::Smrt::Plugin::Contrib',
    VERSION_FROM    => 'lib/CIF/Smrt/Plugin/Contrib.pm',
    BUILD_REQUIRES  => {
        'Test::More'            =>  0,
    },
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker'   =>  0,
        'version'               =>  0,
    },
    PREREQ_PM => {
        'CIF'                   =>  0,
        'CIF::Smrt'             =>  0,
        'Iodef::Pb::Simple'     =>  0.18,
        'LWP::UserAgent'        =>  0,
        'Net::Google::SafeBrowsing2::Lookup'    =>  0,
        'REST::Client'          =>  0,
        'URI::Escape'           =>  0,
        'XML::Smart'            =>  0,
        'version'               =>  0,
    },
    LICENSE => 'lgpl',
);

