package Experian::IDAuth;
use strict;
use warnings;

our $VERSION = '2.0.0';

use Locale::Country;
use Path::Tiny;
use WWW::Mechanize;
use XML::Simple;
use XML::Twig;
use SOAP::Lite;
use IO::Socket::SSL 'SSL_VERIFY_NONE';

sub new {
    my ( $class, %args ) = @_;
    my $obj = bless {}, $class;
    $obj->set( $obj->defaults, %args );
    return $obj;
}

sub defaults {
    my $self = shift;
    return (
        username    => 'experian_user',
        password    => '?',
        members_url => 'https://proveid.experian.com',
        api_uri     => 'http://corpwsdl.oneninetwo',
        api_proxy   => 'https://xml.proveid.experian.com/IDSearch.cfc',
        folder      => '/tmp/proveid',

        # if you're using a logger,
        #logger     => Log::Log4per::get_logger,
    );
}

sub set {
    my ( $self, %args ) = @_;
    $self->{$_} = $args{$_} for keys %args;
    return $self;
}

sub logi {
    my ( $self, $msg ) = @_;

    if ( $self->{logger} ) {
        return $self->{logger}->info($msg);
    }

    return;
}

sub get_result {
    my $self = shift;
    $self->_do_192_authentication || return;
    for ( $self->{search_option} ) {
        /ProveID_KYC/ && return $self->_get_result_proveid;
        /CheckID/     && return $self->_get_result_checkid;
        die "invalid search_option $_";
    }
    return;
}

sub save_pdf_result {

    my $self = shift;

    # Parse and convert the result to hash
    my $result = $self->_xml_as_hash || die 'no xml result in place';

    # 192 reference which we should pass to 192 to download the result
    my $our_ref = $result->{OurReference} || do {
        $self->logi("No 'OurReference'; invalid save-pdf request");
        return;
    };

    my $url  = $self->{members_url};
    my $mech = WWW::Mechanize->new();
    $mech->ssl_opts(
        verify_hostname => 0,
        SSL_verify_mode => SSL_VERIFY_NONE
    );

    eval {

        # Get the login page
        $mech->get("$url/signin/");

        # Login to the members environments
        $mech->submit_form(
            with_fields => {
                login    => $self->{username},
                password => $self->{password},
            }
        );

        # Download pdf result on given reference number
        $mech->get("$url/archive/index.cfm?event=archive.pdf&id=$our_ref");
        1;
    } || do {
        my $err = $@;
        $self->logi("errors downloading pdf: $err");
        return;
    };

    # Save the result to our pdf path
    my $folder_pdf = "$self->{folder}/pdf";

    # make directory if necessary
    if ( not -d $folder_pdf ) {
        Path::Tiny::path($folder_pdf)->mkpath;
    }
    my $file_pdf = $self->_pdf_report_filename;
    $mech->save_content($file_pdf);

    # Check if the downloaded file is a pdf.
    my $file_type = qx(file $file_pdf);
    if ( $file_type !~ /PDF/ ) {
        $self->logi("discarding downloaded file $file_pdf, not a pdf!");
        unlink $file_pdf;
        return;
    }

    return 1;
}

sub has_downloaded_pdf {
    my $self     = shift;
    my $file_pdf = $self->_pdf_report_filename;
    -e ($file_pdf) || return;
    my $file_type = qx(file $file_pdf);
    return $file_type =~ /PDF/;
}

sub has_done_request {
    my $self = shift;
    return -f $self->_xml_report_filename;
}

sub get_192_xml_report {
    my $self = shift;
    return Path::Tiny::path( $self->_xml_report_filename )->slurp;
}

sub valid_country {
    my $self    = shift;
    my $country = shift;
    for (

        # To make CheckID work well for non-UK countries we need to pass
        # in drivers license, Passport MRZ, national ID number
        #qw( ad at au be ca ch cz dk es fi fr gb gg hu ie im it je lu nl no pt se sk us )
        qw ( gb im )
      )
    {
        return 1 if $country eq $_;
    }
    return;
}

sub _build_request {
    my $self = shift;

    $self->{request_as_xml} =
        '<Search>'
      . ( $self->_build_authentication_tag )
      . ( $self->_build_country_code_tag || return )
      . ( $self->_build_person_tag       || return )
      . ( $self->_build_addresses_tag )
      . ( $self->_build_telephones_tag )
      . ( $self->_build_search_reference_tag || return )
      . ( $self->_build_search_option_tag )
      . '</Search>';

    return 1;
}

# Send the given SOAP request to 192.com
sub _send_request {
    my $self = shift;

    my $request = $self->{request_as_xml} || die 'needs request';

    # Hide password
    ( my $request1 = $request ) =~
      s/\<Password\>.+\<\/Password\>/\<Password\>XXXXXXX<\/Password\>/;

    # Log request
    $self->logi( "REQUEST: " . $self->{client_id} . " : $request1" );

    # Create soap object
    my $soap =
      SOAP::Lite->readable(1)->uri( $self->{api_uri} )
      ->proxy( $self->{api_proxy} );

    $soap->transport->ssl_opts(
        verify_hostname => 0,
        SSL_verify_mode => SSL_VERIFY_NONE
    );
    $soap->transport->timeout(60);

    # Do it
    my $som = $soap->search($request);
    if ( $som->fault ) {
        $self->logi( "ERRTEXT: " . $som->fault->faultstring );
        return;
    }

    my $result = $som->result;
    $self->logi("RESULTS: $result");
    $self->{result_as_xml} = $result;

    return 1;
}

sub _build_authentication_tag {
    my $self = shift;
    return
"<Authentication><Username>$self->{username}</Username><Password>$self->{password}</Password></Authentication>";
}

sub _build_country_code_tag {
    my $self              = shift;
    my $two_digit_country = $self->{residence};
    my $three_digit_country =
      uc Locale::Country::country_code2code( $two_digit_country,
        LOCALE_CODE_ALPHA_2, LOCALE_CODE_ALPHA_3 );

    if ( not $three_digit_country ) {
        $self->logi( "Client "
              . $self->{client_id}
              . " could not get country from residence [$two_digit_country]" );
        return;
    }

    return "<CountryCode>$three_digit_country</CountryCode>";
}

sub _build_person_tag {
    my $self = shift;

    my $dob = $self->{date_of_birth} || do {
        $self->logi( "No date of birth for " . $self->{client_id} );
        return;
    };

    if ( $dob =~ /^(\d\d\d\d)/ ) {
        my $birth_year = $1;

        # Check client not older than 100 or less than 18 years old
        my ( undef, undef, undef, undef, undef, $curyear ) = gmtime(time);
        $curyear += 1900;
        my $maxyear = $curyear - 17;
        my $minyear = $curyear - 100;

        if ( $birth_year > $maxyear or $birth_year < $minyear ) {
            return;
        }
    }
    else {
        $self->logi( "Invalid date of birth [$dob] for " . $self->{client_id} );
        return;
    }

    return
        '<Person>'
      . '<Name><Forename>'
      . $self->{first_name}
      . '</Forename>'
      . '<Surname>'
      . $self->{last_name}
      . '</Surname></Name>'
      . "<DateOfBirth>$dob</DateOfBirth>"
      . '</Person>';

}

sub _build_addresses_tag {
    my $self = shift;

    my $postcode     = $self->{postcode};
    my $premise      = $self->{premise} || die 'needs premise';
    my $country_code = $self->_build_country_code_tag;

    return qq(<Addresses><Address Current="1"><Premise>$premise</Premise>)
      . qq(<Postcode>$postcode</Postcode>$country_code</Address></Addresses>);
}

sub _build_telephones_tag {
    my $self = shift;

    my $telephone_type = 'U';
    my $number;
    if ( $self->{phone} =~ /^([\+\d\s]+)/ ) {
        $number = $1;
    }

    return
        '<Telephones>'
      . qq(<Telephone Type="$telephone_type">)
      . "<Number>$number</Number>"
      . "</Telephone>"
      . '</Telephones>';
}

sub _build_search_reference_tag {
    my $self     = shift;
    my $shortopt = ( $self->{search_option} eq 'ProveID_KYC' ) ? 'PK' : 'C';
    my $time     = time();
    return
        "<YourReference>${shortopt}_"
      . $self->{client_id}
      . "_$time</YourReference>";
}

sub _build_search_option_tag {
    my $self = shift;
    return
"<SearchOptions><ProductCode>$self->{search_option}</ProductCode></SearchOptions>";
}

sub _xml_as_hash {
    my $self = shift;
    my $xml = $self->{result_as_xml} || return;
    return XML::Simple::XMLin(
        $xml,
        KeyAttr    => { DocumentID => 'type' },
        ForceArray => ['DocumentID'],
        ContentKey => '-content',
    );
}

sub _get_result_proveid {
    my $self = shift;

    my $report = $self->{result_as_xml} || die 'needs xml report';

    my $twig = eval { XML::Twig->parse($report) } || do {
        my $err = $@;
        $self->logi("could not parse xml report: $err");
        return;
    };

    my ($report_summary_twig) = $twig->get_xpath(
        '/Search/Result/Summary/ReportSummary/DatablocksSummary');

    return unless $report_summary_twig;

    my %report_summary;
    for my $dblock ( $report_summary_twig->get_xpath('DatablockSummary') ) {
        my $name  = $dblock->findvalue('Name');
        my $value = $dblock->findvalue('Decision');
        $report_summary{$name} = $value;
    }
    my ($kyc_summary) = $twig->get_xpath('/Search/Result/Summary/KYCSummary');
    my ($credit_reference) =
      $twig->get_xpath('/Search/Result/CreditReference/CreditReferenceSummary');

    return unless $credit_reference and $kyc_summary;

    my $decision = { matches => []};

    # check if client has died or fraud
    my $cr_deceased = $credit_reference->findvalue('DeceasedMatch') || 0;
    $report_summary{Deceased} ||= 0;
    my $confidence_level = 0;
    if ( $report_summary{Deceased} ) {

        # We only taking Deceased flag in ReportSummary into account
        # if ConfidenceLevel 7 or above
        my ($deceased_record) =
          $twig->get_xpath('/Search/Result/Deceased/DeceasedRecord');
        $confidence_level = $deceased_record->findvalue('ConfidenceLevel') || 0;
    }
    if ( ( $report_summary{Deceased} == 1 and $confidence_level > 6 )
        or $cr_deceased == 1 )
    {
        $decision->{deceased} = 1;
    }

    $report_summary{Fraud} ||= 0;
    if ( $report_summary{Fraud} == 1 ) {
        $decision->{fraud} = 1;
    }

    # check if client is age verified
    my $kyc_dob = $kyc_summary->findvalue('DateOfBirth/Count') || 0;
    my $cr_total = $credit_reference->findvalue('TotalNumberOfVerifications')
      || 0;
    if ( $kyc_dob or $cr_total ) {
        $decision->{age_verified} = 1;
    }

    # check if client is in any suspicious list
    # we don't care about: NoOfCCJ, COAMatch
    my @matches =
      map  { $_->[0] }
      grep { $_->[1] > 0 }
      map  { [ $_, $credit_reference->findvalue($_) || 0 ] }
      qw(BOEMatch PEPMatch OFACMatch CIFASMatch);

    if (@matches) {
        my @hard_fails = grep { my $f = $_; 
                                grep { "${f}Match" eq $_ } @matches } 
                         qw(BOE PEP OFAC CIFAS);
        $decision->{$_} = 1 for @hard_fails;
        $decision->{deny} = 1 if @hard_fails;

        $decision->{matches} = \@matches;
    }

    # if client is in Directors list, we should not fully authenticate him
    if ( $report_summary{Directors} ) {
        $decision->{matches} = [ @{$decision->{matches}, 'Directors' ];
    }

    # check if client can be fully authenticated
    my @kyc_two =
      grep { $_ >= 2 }
      map { $kyc_summary->findvalue("$_/Count") || 0 }
      qw(FullNameAndAddress SurnameAndAddress Address DateOfBirth);
    if ( @kyc_two or $cr_total >= 2 ) {
        $decision->{fully_authenticated} = 1;
    }

    return $decision;
}

sub _get_result_checkid {

    my $self   = shift;
    my $passed = 0;

    # Convert xml to hashref
    my $result = $self->_xml_as_hash || do {
        $self->logi('no xml result');
        return;
    };

    if (
        (
            (
                    $result->{'Result'}->{'ElectoralRoll'}->{'Type'} eq 'Result'
                and $result->{'Result'}->{'ElectoralRoll'}->{'Summary'}
                ->{'Decision'} == 1
            )
            or (    $result->{'Result'}->{'Directors'}->{'Type'} eq 'Result'
                and
                $result->{'Result'}->{'Directors'}->{'Summary'}->{'Decision'} ==
                1 )
            or (    $result->{'Result'}->{'Telephony'}->{'Type'} eq 'Result'
                and
                $result->{'Result'}->{'Telephony'}->{'Summary'}->{'Decision'} ==
                1 )
        )
      )
    {

        # Check Directors DecisionReasons
        if ( $result->{'Result'}->{'Directors'}->{'Type'} eq 'Result' ) {
          DIRECTORS_DECISION_REASONS:
            foreach my $decision_reason (
                @{
                    $result->{'Result'}->{'Directors'}->{'Summary'}
                      ->{'DecisionReasons'}->{'DecisionReason'}
                }
              )
            {
                if ( $decision_reason->{'Element'} eq
                    'Director/Person/DateOfBirth'
                    and $decision_reason->{'Decision'} == 1 )
                {
                    $passed = 1;
                    last DIRECTORS_DECISION_REASONS;
                }
            }

            if ( not $passed ) {
              ELECTORALROLL_DECISION_REASONS:
                foreach my $decision_reason (
                    @{
                        $result->{'Result'}->{'ElectoralRoll'}->{'Summary'}
                          ->{'DecisionReasons'}->{'DecisionReason'}
                    }
                  )
                {
                    if ( $decision_reason->{'Element'} eq
                        'ElectoralRollRecord/Person/DateOfBirth'
                        and $decision_reason->{'Decision'} == 1 )
                    {
                        $passed = 1;
                        last ELECTORALROLL_DECISION_REASONS;
                    }
                }
            }
        }
    }

    return $passed;
}

sub _do_192_authentication {
    my $self = shift;

    my $search_option = $self->{search_option};

    my $force_recheck = $self->{force_recheck} || 0;

    $self->logi( "Attempt 192 authentication for "
          . $self->{client_id}
          . " via $search_option" );

    my $residence = $self->{residence};

    # check for 192 supported countries
    unless ( $self->valid_country( $self->{residence} ) ) {
        $self->logi( "Invalid residence: "
              . $self->{client_id}
              . ", Residence $residence" );
        return;
    }

    if ( !$force_recheck && $self->has_done_request ) {
        $self->{result_as_xml} = $self->get_192_xml_report;
        return 1;
    }

    # No previous result so prepare a request
    $self->_build_request
      || die( "Cannot build xml_request for ["
          . $self->{client_id}
          . "/$search_option]" );

    # Remove old pdf in case this client has done the 192 pdf request before
    my $file_pdf = $self->_pdf_report_filename;
    unlink $file_pdf if -e $file_pdf;

    eval { $self->_send_request } || do {
        my $err = $@ || '?';
        $self->logi("could not send pdf request: $err");
        return;
    };

    # Save xml result
    my $folder_xml = "$self->{folder}/xml";
    if ( not -d $folder_xml ) {
        Path::Tiny::path($folder_xml)->mkpath;
    }
    my $file_xml = $self->_xml_report_filename;
    Path::Tiny::path($file_xml)->spew( $self->{result_as_xml} );

    if ( not -e $file_xml ) {
        $self->logi(
            "Couldn't save 192.com xml result for " . $self->{client_id} );
        return;
    }

    $self->save_pdf_result;

    return 1;
}

sub _xml_report_filename {
    my $self          = shift;
    my $search_option = $self->{search_option};
    return "$self->{folder}/xml/" . $self->{client_id} . ".$search_option";
}

sub _pdf_report_filename {
    my $self          = shift;
    my $search_option = $self->{search_option};
    return "$self->{folder}/pdf/" . $self->{client_id} . ".$search_option.pdf";
}

1;

=head1 NAME

Experian::IDAuth - Experian's ID Authenticate service

=head1 VERSION

Version 2.0.0

=head1 DESCRIPTION

This module provides an interface to Experian's Identity Authenticate service.
http://www.experian.co.uk/identity-and-fraud/products/authenticate.html

First create a subclass of this module to override the defaults method
with your own data.

    package My::Experian;
    use strict;
    use warnings;
    use base 'Experian::IDAuth';

    # if you're using a logger
    use Log::Log4perl;

    sub defaults {
        my $self = shift;

        return (
            $self->SUPER::defaults,
            logger        => Log::Log4perl::get_logger,
            username      => 'my_user',
            password      => 'my_pass',
            residence     => $residence,
            postcode      => $postcode || '',
            date_of_birth => $date_of_birth || '',
            first_name    => $first_name || '',
            last_name     => $last_name || '',
            phone         => $phone || '',
            email         => $email || '',
        );
    }

    1;

Then use this module.

    use My::Experian;

    # search_option can either be ProveID_KYC or CheckID
    my $prove_id = My::Experian->new(
        search_option => 'ProveID_KYC',
    );

    my $prove_id_result = $prove_id->get_result();

    if (!$prove_id->has_done_request) {
        # connection problems
        die;
    }

    if ($prove_id_result->{age_verified}) {
        # client's age is verified
    }
    if ($prove_id_result->{deceased} || $prove_id_result->{fraud}) {
        # client flagged as deceased or fraud
    }
    if ($prove_id_result->{deny}) {
        # client on any of PEP, OFAC, or BOE list
        # you can check $prove_id_result->{PEP} etc if you want more detail
    }
    if ($prove_id_result->{fully_authenticated}) {
        # client successfully authenticated, 
        # DOES NOT MEAN NO CONCERNS
    }

    # CheckID is a more simpler version and can be used if ProveID_KYC fails
    my $check_id = My::Experian->new(
        search_option => 'CheckID',
    );

    if (!$check_id->has_done_request) {
        # connection problems
        die;
    }

    if ($check_id->get_result()) {
        # client successfully authenticated
    }

=head1 AUTHOR

binary.com, C<perl at binary.com>

=head1 BUGS

Please report any bugs or feature requests to C<bug-experian-idauth at rt.cpan.org>,
or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Experian-IDAuth>.
We will be notified, and then you'll automatically be notified of progress
on your bug as we make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Experian::IDAuth


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Experian-IDAuth>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Experian-IDAuth>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Experian-IDAuth>

=item * Search CPAN

L<http://search.cpan.org/dist/Experian-IDAuth/>

=back


=head1 DEPENDENCIES

    Locale::Country
    Path::Tiny
    WWW::Mechanize
    XML::Simple
    XML::Twig
    SOAP::Lite
    IO::Socket

=head1 LICENSE AND COPYRIGHT

Copyright 2014 binary.com.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


=cut

1; # End of Experian::IDAuth

