use strict;
use warnings FATAL => 'all';

use 5.014;

use Test::Fatal qw{exception};
use FindBin::libs;
use URI::Shortener;
use Capture::Tiny qw{capture_merged};
use Time::HiRes   qw{time};
use DBI;
use File::Temp qw{tempdir};

use Test::More tests => 7;

# Insert a row that holds the cipher of the next row ID, so that the next new URI collides once.
sub _plant_collision {
    my ( $dbh, $s, $squatter ) = @_;
    $dbh->do( "INSERT INTO uris (uri, created, prefix_id) VALUES (?, ?, (SELECT id FROM prefix LIMIT 1))", undef, $squatter, int( time() ) );
    my ($last_id) = $dbh->selectrow_array("SELECT seq FROM sqlite_sequence WHERE name = 'uris'");
    $dbh->do( "UPDATE uris SET cipher = ? WHERE uri = ?", undef, $s->cipher( $last_id + 1 ), $squatter );
    return 1;
}

sub _shortener_on {
    my ($dbname) = @_;
    return URI::Shortener->new(
        prefix => 'https://go.test.test/short',
        dbname => $dbname,
        seed   => 1337,
        length => 10,
    );
}

sub _dbh_on {
    my ($dbname) = @_;
    return DBI->connect( "dbi:SQLite:dbname=$dbname", "", "", { RaiseError => 1, PrintError => 0 } );
}

subtest 'happy path' => sub {
    my $s = URI::Shortener->new(
        domain => 'ACGT',
        prefix => 'https://go.mydomain.test/short',
        dbname => ':memory:',
        seed   => 1337,
        length => 10,
    );
    my $uri   = 'https://mydomain.test/somePath';
    my $short = $s->shorten($uri);
    is( $short, 'https://go.mydomain.test/short/CTTACCGGTC', "I do this...for da shorteez.  Especially URIs" );
    $short = $s->shorten($uri);
    is( $short,               'https://go.mydomain.test/short/CTTACCGGTC', "caching works" );
    is( $s->lengthen($short), $uri,                                        "Lengthens, Hardens, Girthens & Fully Pleasures your URI" );
    $s->prune_before( time() + 10 );
    is( $s->lengthen($short), undef, "Pruning works" );

};

subtest 'Sovereign is he who tests his exceptions' => sub {
    my %bad;

    like( exception { URI::Shortener->new(%bad) }, qr/prefix/isxaa, "You've just been pre-fixated" );
    $bad{prefix} = 'jumbo://hugs';
    like( exception { URI::Shortener->new(%bad) }, qr/dbname/isxaa, "Get in the DB shinji" );
    $bad{dbname} = ':memory:';
    like( exception { URI::Shortener->new(%bad) }, qr/seed/isxaa, "My seed hath slain the chess dragon" );

    $bad{seed}          = 1337;
    $bad{uri_tablename} = 'uris; DROP TABLE prefix';
    like( exception { URI::Shortener->new(%bad) }, qr/uri_tablename[ ]must[ ]be/isxaa, "A table name that is not an identifier is refused" );
    $bad{uri_tablename} = 'uris';
    is( exception { URI::Shortener->new(%bad) }, undef, "A plain table name is accepted" );
};

# pathological case
subtest 'going to the circle 8 track' => sub {
    my $s = URI::Shortener->new(
        domain => 'A',
        prefix => 'bar',
        dbname => ':memory:',
        seed   => 1337,
        length => 1,
    );
    is( $s->shorten('foo'), 'bar/A', "Works fine, right?" );
    like(
        exception {
            capture_merged { $s->shorten('hug') }
        },
        qr/too[ ]many[ ]failures/isxaa,
        "Stack smashing guard encountered"
    );
};

# Alternative names
subtest 'alternative names' => sub {
    my $s = URI::Shortener->new(
        domain           => 'ACGT',
        prefix           => 'https://go.mydomain.test/short',
        dbname           => ':memory:',
        seed             => 1337,
        length           => 10,
        uri_tablename    => 'shortener_uris',
        prefix_tablename => 'shortener_prefix',
        uri_idxname      => 'shortener_uri_idx',
        prefix_idxname   => 'shortener_prefix_idx',
        cipher_idxname   => 'shortener_cipher_idx',
        created_idxname  => 'shortener_created_idx',
    );
    my $uri   = 'https://mydomain.test/somePath';
    my $short = $s->shorten($uri);
    is( $short, 'https://go.mydomain.test/short/CTTACCGGTC', "I do this...for da shorteez.  Especially URIs" );
    $short = $s->shorten($uri);
    is( $short,               'https://go.mydomain.test/short/CTTACCGGTC', "caching works" );
    is( $s->lengthen($short), $uri,                                        "Lengthens, Hardens, Girthens & Fully Pleasures your URI" );
    $s->prune_before( time() + 10 );
    is( $s->lengthen($short), undef, "Pruning works" );
};

# Migration
subtest 'migration' => sub {
    my $s = URI::Shortener->new(
        prefix => 'https://go.mydomain.test/short',
        dbname => ':memory:',
        seed   => 1337,
        length => 10,
    );
    my $uri   = 'https://mydomain.test/somePath';
    my $short = $s->shorten($uri);
    is( $short, 'https://go.mydomain.test/short/dZennAUZHG', "Can build basic shortener DB" );

    # Slam in uris to force batching
    my $uri2;
    foreach my $idx ( 0 .. 10_000 ) {
        $uri2 = "https://mydomain$idx/somePath";
        eval { $s->shorten($uri2); 1 } or diag("shorten died for $uri2: $@");
    }

    my $s2 = URI::Shortener->new(
        prefix => 'https://go.mydomain.test/short',
        dbname => ':memory:',
        seed   => 1337,
        length => 10,
    );

    $s->migrate($s2);
    my $long = $s2->lengthen( $s->shorten($uri) );
    is( $long, $uri, "First record migrated" );
    $long = $s2->lengthen( $s->shorten($uri2) );
    is( $long, $uri2, "10kth record migrated" );
};

subtest 'the collision limit counts per call' => sub {
    my $dbname = tempdir( CLEANUP => 1 ) . '/uris.db';
    my $s      = _shortener_on($dbname);
    $s->shorten('https://test.test/warmup');
    my $dbh = _dbh_on($dbname);

    my ( $calls, $collided ) = ( 0, 0 );
    foreach my $n ( 1 .. 100 ) {
        _plant_collision( $dbh, $s, "https://test.test/squatter$n" );
        my $uri = "https://test.test/page$n";
        my ( $short, $err );
        my $out = capture_merged {
            $err = exception { $short = $s->shorten($uri) }
        };
        if ($err) {
            fail("shorten() lives through a collision in call $n");
            diag($err);
            last;
        }
        $calls++    if ( $s->lengthen($short) // '' ) eq $uri;
        $collided++ if index( $out, 'cipher collision' ) >= 0;
    }
    is( $calls,    100, "100 calls in a row each shorten a URI that lengthens back" );
    is( $collided, 100, "Each of the 100 calls had one collision, more than the limit of 64 for one call" );
};

# shorten() keeps no state outside the database, so a new object on the same file stands in for a new process.
subtest 'one URI burned twice by separate shorteners' => sub {
    my $dbname = tempdir( CLEANUP => 1 ) . '/uris.db';
    my $uri    = 'https://test.test/burned-twice';

    my $first = _shortener_on($dbname);
    $first->shorten('https://test.test/warmup');
    my $dbh = _dbh_on($dbname);
    _plant_collision( $dbh, $first, 'https://test.test/squatter1' );
    my ( $short, $err );
    capture_merged {
        $err = exception { $short = $first->shorten($uri) }
    };
    is( $err,                     undef, "The first burn of the URI lives" );
    is( $first->lengthen($short), $uri,  "The URI lengthens back after the first burn" );

    # The live row goes away, so the next shortener must store the same URI again.
    $dbh->do( "DELETE FROM uris WHERE uri = ?", undef, $uri );

    my $second = _shortener_on($dbname);
    _plant_collision( $dbh, $second, 'https://test.test/squatter2' );
    capture_merged {
        $err = exception { $short = $second->shorten($uri) }
    };
    is( $err,                      undef, "The second burn of the same URI lives" ) or diag($err);
    is( $second->lengthen($short), $uri,  "The URI lengthens back after the second burn" );

    my ($dead) = $dbh->selectrow_array("SELECT COUNT(*) FROM uris WHERE cipher IS NULL");
    is( $dead, 2, "Both burns left a dead record" );
};

1;

__END__

=head1 DESCRIPTION

Tests that a URI shortens and lengthens, that bad arguments die, that a full code space dies,
that table names can change, and that a database migrates to another one.
Also tests that a cipher collision burns a row and the call lives,
that the limit on collisions is for one call and not for the process,
and that one URI can be burned more than once.

=cut

