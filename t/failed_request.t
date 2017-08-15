#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use Test::Exception;
use lib 'lib';
use_ok('Experian::IDAuth');

# clean up
system "rm -rf /tmp/proveid/";

my $prove_id = Experian::IDAuth->new(
    client_id     => '45',
    search_option => 'ProveID_KYC',
    username      => 'my_user',
    password      => 'my_pass',
    residence     => 'gb',
    postcode      => '666',
    date_of_birth => '1977-04-10',
    first_name    => 'John',
    last_name     => 'Galt',
    phone         => '34878123',
    email         => 'john.galt@gmail.com',
    premise       => 'premise',
);

throws_ok(
    sub {
        $prove_id->get_result;
    },
    qr/ErrorCode/,
    "Expected die because of invalid credentials"
);

done_testing;

