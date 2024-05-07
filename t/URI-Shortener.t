use strict;
use warnings;

use Test::Fatal qw{exception};
use FindBin::libs;
use URI::Shortener;

use Test::More tests => 2;

my $random_letter_ordering = 'zUTibXjNDAmFKPglvdnJLsxqOMYRhrGakBucteyQpSoWfHwVZICE';

subtest 'happy path' => sub {
    my $s = URI::Shortener->new(
        secret => $random_letter_ordering,
        prefix => 'https://go.mydomain.test/short',
        dbname => ':memory:',
        offset => 0,
    );
    my $uri   = 'https://mydomain.test/somePath';
    my $short = $s->shorten($uri);
    is( $short,               'https://go.mydomain.test/short/RI', "I do this...for da shorteez.  Especially URIs" );
    is( $s->lengthen($short), $uri,                                "Lengthens, Hardens, Girthens & Fully Pleasures your URI" );
    $s->prune_before( time() + 10 );
    is( $s->lengthen($short), undef, "Pruning works" );

};

subtest 'Sovereign is he who tests his exceptions' => sub {
    my %bad;

    like( exception { URI::Shortener->new(%bad) }, qr/secret/i, "It's a secret to everyone" );
    $bad{secret} = 'a';
    like( exception { URI::Shortener->new(%bad) }, qr/prefix/i, "You've just been pre-fixated" );
    $bad{prefix} = 'jumbo://hugs';
    like( exception { URI::Shortener->new(%bad) }, qr/dbname/i, "Get in the DB shinji" );
};
