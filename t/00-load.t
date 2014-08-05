#!perl -T
use 5.006;
use strict;
use warnings FATAL => 'all';
use Test::More;

use lib 'lib';

plan tests => 1;

BEGIN {
    use_ok( 'Experian::IDAuth' ) || print "Bail out!\n";
}

diag( "Testing Experian::IDAuth $Experian::IDAuth::VERSION, Perl $], $^X" );
