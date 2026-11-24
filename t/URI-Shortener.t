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

use Test::More tests => 12;

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
    is( $short, 'https://go.mydomain.test/short/TGTACGGCGT', "I do this...for da shorteez.  Especially URIs" );
    $short = $s->shorten($uri);
    is( $short,                     'https://go.mydomain.test/short/TGTACGGCGT', "caching works" );
    is( $s->lengthen($short),       $uri,                                        "Lengthens, Hardens, Girthens & Fully Pleasures your URI" );
    is( $s->decipher('TGTACGGCGT'), 1,                                           "The cipher of the first row deciphers to row ID 1" );
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

    like( exception { URI::Shortener->new( %bad, algorithm => 'rot13' ) }, qr/algorithm[ ]must[ ]be/isxaa, "An unknown algorithm is refused" );
    like( exception { URI::Shortener->new( %bad, domain => 'ACGTA',      length => 10 ) }, qr/two[ ]times/isxaa, "For ff1, a domain that repeats a character is refused" );
    like( exception { URI::Shortener->new( %bad, domain => '0123456789', length => 5 ) },  qr/1000000/sxaa,      "For ff1, a space of 10**5 URIs is refused" );
    is( exception { URI::Shortener->new( %bad, domain => '0123456789', length => 6 ) }, undef, "For ff1, a space of 10**6 URIs is accepted" );
    like( exception { URI::Shortener->new( %bad, algorithm => 'fortuna', seed => 'not a number' ) }, qr/numeric[ ]seed/isxaa, "For fortuna, a seed that is not a number is refused" );
};

# pathological case
subtest 'going to the circle 8 track' => sub {
    my $s = URI::Shortener->new(
        domain    => 'A',
        prefix    => 'bar',
        dbname    => ':memory:',
        seed      => 1337,
        length    => 1,
        algorithm => 'fortuna',
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
    is( $short, 'https://go.mydomain.test/short/TGTACGGCGT', "I do this...for da shorteez.  Especially URIs" );
    $short = $s->shorten($uri);
    is( $short,               'https://go.mydomain.test/short/TGTACGGCGT', "caching works" );
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
    is( $short, 'https://go.mydomain.test/short/zlwDIPBfuW', "Can build basic shortener DB" );

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

# These ciphers are what version 1, which had only fortuna, gave for row IDs 1 to 3.
subtest 'fortuna gives the ciphers of version 1' => sub {
    my @cases = (
        [ 'seed 1337, length 10',              { seed => 1337, length => 10 },                   [qw{dZennAUZHG cIdAWNLZso GtnZWzLNDY}] ],
        [ 'seed 1337, length 10, domain ACGT', { seed => 1337, length => 10, domain => 'ACGT' }, [qw{CTTACCGGTC GGTTGATCTT ACTCTACTCT}] ],
        [ 'seed 90210, default length',        { seed => 90210 },                                [qw{AaMXOBKJWslu ibdgvOwUmgul kcuOKsJjciMV}] ],
    );
    foreach my $case (@cases) {
        my ( $name, $options, $want ) = @{$case};
        my $s = URI::Shortener->new( prefix => 'https://go.test.test/short', dbname => ':memory:', algorithm => 'fortuna', %{$options} );
        my @got;
        foreach my $id ( 1 .. 3 ) {
            push( @got, $s->cipher($id) );
        }
        is_deeply( \@got, $want, "$name: fortuna gives the same ciphers as version 1" );
    }

    my $s = URI::Shortener->new( prefix => 'https://go.test.test/short', dbname => ':memory:', seed => 1337, length => 10, algorithm => 'fortuna' );
    is( $s->shorten('https://test.test/page'), 'https://go.test.test/short/dZennAUZHG', "shorten() with fortuna stores the version 1 cipher" );
    like( exception { $s->decipher('dZennAUZHG') }, qr/needs[ ]the[ ]ff1/isxaa, "decipher() dies for fortuna, which has no reverse" );
};

subtest 'string seeds' => sub {
    my %common = ( prefix => 'https://go.test.test/short', dbname => ':memory:', length => 10 );

    my $s;
    is( exception { $s = URI::Shortener->new( %common, seed => 'correct horse battery staple' ) }, undef, "ff1 accepts a seed that is not a number" );
    my $short = $s->shorten('https://test.test/page');
    is( $short,               'https://go.test.test/short/OehwilhAKh', "The string seed gives its own cipher" );
    is( $s->lengthen($short), 'https://test.test/page',                "The URI lengthens back" );

    my $number = URI::Shortener->new( %common, seed => 1337 );
    my $string = URI::Shortener->new( %common, seed => '1337' );
    my $next   = URI::Shortener->new( %common, seed => 1338 );
    is( $number->cipher(1), 'zlwDIPBfuW',       "The seed 1337 gives the key of the string '1337'" );
    is( $string->cipher(1), $number->cipher(1), "The number and the string give the same cipher" );
    is( $next->cipher(1),   'onWAoawcaz',       "The seed 1338 gives a cipher that has no relation to that of 1337" );
};

subtest 'space exhausted' => sub {
    my $dbname = tempdir( CLEANUP => 1 ) . '/uris.db';
    my $s      = URI::Shortener->new( prefix => 'https://go.test.test/short', dbname => $dbname, seed => 1337, domain => '0123456789', length => 6 );
    $s->shorten('https://test.test/first');

    # 10 ** 6 strings: the IDs 0 to 999999.
    my $dbh = _dbh_on($dbname);
    $dbh->do("UPDATE sqlite_sequence SET seq = 999998 WHERE name = 'uris'");
    my $last = $s->shorten('https://test.test/last');
    is( $s->decipher( substr( $last, -6 ) ), 999_999, "The row ID 999999, the last of the space, gets a cipher" );
    like( exception { $s->shorten('https://test.test/one-too-many') }, qr/space[ ]exhausted/isxaa, "The row ID 1000000 dies with 'space exhausted'" );
    is( $s->lengthen($last), 'https://test.test/last', "The URIs that were stored before still lengthen" );
};

subtest 'decipher gives the row ID back' => sub {
    my $dbname = tempdir( CLEANUP => 1 ) . '/uris.db';
    my $s      = _shortener_on($dbname);
    foreach my $n ( 1 .. 50 ) {
        $s->shorten("https://test.test/page$n");
    }

    my $rows = _dbh_on($dbname)->selectall_arrayref("SELECT id, cipher FROM uris");
    my @broken;
    foreach my $row ( @{$rows} ) {
        my ( $id, $cipher ) = @{$row};
        push( @broken, $id ) if ( $s->decipher($cipher) // -1 ) != $id;
    }
    is( scalar( @{$rows} ), 50, "50 rows were stored" );
    is_deeply( \@broken, [], "The cipher of each row deciphers to the ID of that row" );
    is( $s->decipher('short'),      undef, "A cipher of the wrong length deciphers to undef" );
    is( $s->decipher('zlwDIPBfu-'), undef, "A cipher with a character that is not in the domain deciphers to undef" );
};

subtest 'upgrade from fortuna to ff1' => sub {
    my $dbname = tempdir( CLEANUP => 1 ) . '/uris.db';
    my $prefix = 'https://go.test.test/short';
    my %common = ( prefix => $prefix, dbname => $dbname, seed => 1337, domain => 'ACGT', length => 10 );

    my $old = URI::Shortener->new( %common, algorithm => 'fortuna' );
    my %legacy;
    capture_merged {
        foreach my $n ( 1 .. 200 ) {
            my $uri = "https://test.test/legacy$n";
            $legacy{ $old->shorten($uri) } = $uri;
        }
    };
    my $dbh           = _dbh_on($dbname);
    my %legacy_cipher = map { $_->[0] => 1 } @{ $dbh->selectall_arrayref("SELECT cipher FROM uris WHERE cipher IS NOT NULL") };

    my $new = URI::Shortener->new(%common);
    my @broken;
    foreach my $short ( keys(%legacy) ) {
        push( @broken, $short ) if ( $new->lengthen($short) // '' ) ne $legacy{$short};
    }
    is_deeply( \@broken, [], "Each of the 200 short URIs that fortuna made still lengthens with ff1" );

    # Find the first new row ID whose ff1 cipher is a fortuna cipher in the database, and make it the next row ID.
    my ($seq) = $dbh->selectrow_array("SELECT seq FROM sqlite_sequence WHERE name = 'uris'");
    my $clash = $seq + 1;
    $clash++ until $legacy_cipher{ $new->cipher($clash) };
    $dbh->do( "UPDATE sqlite_sequence SET seq = ? WHERE name = 'uris'", undef, $clash - 1 );
    my $legacy_short = "$prefix/" . $new->cipher($clash);

    my $uri = 'https://test.test/after-upgrade';
    my ( $short, $err );
    my $out = capture_merged {
        $err = exception { $short = $new->shorten($uri) }
    };
    is( $err, undef, "shorten() lives when the ff1 cipher of row $clash is a fortuna cipher" ) or diag($err);
    like( $out, qr/cipher[ ]collision/isxaa, "shorten() warns of the collision" );
    my ($burned) = $dbh->selectrow_array( "SELECT uri FROM uris WHERE id = ?", undef, $clash );
    is( $burned,                                       "$uri-BURNED-$clash",                    "Row $clash is burned" );
    is( $new->lengthen($short),                        $uri,                                    "The new URI lengthens back" );
    is( $new->decipher( substr( $short, -10 ) ),       $clash + 1,                              "The new URI got the next row ID" );
    is( $new->lengthen($legacy_short),                 $legacy{$legacy_short},                  "The fortuna URI with that cipher still lengthens to its own URI" );
    is( $new->shorten('https://test.test/after-burn'), "$prefix/" . $new->cipher( $clash + 2 ), "The next URI gets the next row ID with no collision" );
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

