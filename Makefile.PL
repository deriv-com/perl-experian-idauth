use 5.006;
use strict;
use warnings FATAL => 'all';
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Experian::IDAuth',
    AUTHOR           => q{binary.com <perl@binary.com>},
    VERSION_FROM     => 'lib/Experian/IDAuth.pm',
    ABSTRACT_FROM    => 'lib/Experian/IDAuth.pm',
    LICENSE          => 'Artistic_2_0',
    PL_FILES         => {},
    MIN_PERL_VERSION => 5.006,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
        'Test::Most' => 0,
        'Test::MockModule' => 0,
    },
    PREREQ_PM => {
        'Locale::Country' => 0,
        'Path::Tiny'      => 0,
        'WWW::Mechanize'  => 0,
        'XML::Simple'     => 0,
        'XML::Twig'       => 0,
        'SOAP::Lite'      => 0,
        'IO::Socket'      => 0,
      },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Experian-IDAuth-*' },
    (eval { ExtUtils::MakeMaker->VERSION(6.46) } ? (META_MERGE => {
        'meta-spec' => { version => 2 },
            resources => {
                repository => {
                    type => 'git',
                    url  => 'https://github.com/binary-com/perl-experian-idauth.git',
                    web  => 'https://github.com/binary-com/perl-experian-idauth',
                },
            }})
     : ()
    ),
);
