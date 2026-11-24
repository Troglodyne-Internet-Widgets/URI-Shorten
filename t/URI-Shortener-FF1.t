use strict;
use warnings FATAL => 'all';

use 5.014;

use Test2::V1 -i;    ## no critic (ProhibitUnusedImports) -i imports every tool, which the policy cannot see
use Test2::Plugin::NoWarnings;
use FindBin::libs;
use URI::Shortener::FF1;

my $DIGITS = join( '', 0 .. 9 );
my $BASE36 = join( '', 0 .. 9,     'a' .. 'z' );
my $LATIN  = join( '', 'a' .. 'z', 'A' .. 'Z' );

my %ALPHABET = ( 10 => $DIGITS, 36 => $BASE36 );

my %KEY = (
    128 => '2B7E151628AED2A6ABF7158809CF4F3C',
    192 => '2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F',
    256 => '2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94',
);

# The nine FF1 samples of NIST, from the examples that go with SP 800-38G.
# Sample, key bits, radix, tweak in hex ('-' for an empty tweak), plaintext, ciphertext.
my @SAMPLES = (
    [qw{1 128 10 -                      0123456789          2433477484}],
    [qw{2 128 10 39383736353433323130   0123456789          6124200773}],
    [qw{3 128 36 3737373770717273373737 0123456789abcdefghi a9tv40mll9kdu509eum}],
    [qw{4 192 10 -                      0123456789          2830668132}],
    [qw{5 192 10 39383736353433323130   0123456789          2496655549}],
    [qw{6 192 36 3737373770717273373737 0123456789abcdefghi xbj3kv35jrawxv32ysr}],
    [qw{7 256 10 -                      0123456789          6657667009}],
    [qw{8 256 10 39383736353433323130   0123456789          1001623463}],
    [qw{9 256 36 3737373770717273373737 0123456789abcdefghi xs8a0azh2avyalyzuwd}],
);

sub _ff1 {
    my (%args) = @_;
    return URI::Shortener::FF1->new( key => pack( 'H*', $KEY{128} ), %args );
}

sub _to_digits {
    my ( $alphabet, $string ) = @_;
    return [ map { index( $alphabet, $_ ) } split( //sxaa, $string ) ];
}

sub _to_string {
    my ( $alphabet, $digits ) = @_;
    return join( '', map { substr( $alphabet, $_, 1 ) } @{$digits} );
}

subtest 'NIST samples' => sub {
    foreach my $bigint ( 0, 1 ) {
        foreach my $sample (@SAMPLES) {
            my ( $n, $bits, $radix, $tweak, $plain, $want ) = @{$sample};
            my $alphabet = $ALPHABET{$radix};
            my $ff1      = URI::Shortener::FF1->new(
                alphabet => $alphabet,
                length   => length($plain),
                key      => pack( 'H*', $KEY{$bits} ),
                tweak    => ( $tweak eq '-' ? '' : pack( 'H*', $tweak ) ),
                bigint   => $bigint,
            );
            my $got = _to_string( $alphabet, $ff1->encrypt_digits( _to_digits( $alphabet, $plain ) ) );
            is( $got,                                                                            $want,  "Sample $n encrypts to the NIST value, bigint=$bigint" );
            is( _to_string( $alphabet, $ff1->decrypt_digits( _to_digits( $alphabet, $want ) ) ), $plain, "Sample $n decrypts to the NIST plaintext, bigint=$bigint" );
        }
    }
};

subtest 'perl integers and Math::BigInt agree' => sub {

    # 511**5 * 256 is just below 2**53, so this is the largest radix with perl integers at length 10.
    my $wide  = join( '', map { chr( 256 + $_ ) } 0 .. 510 );
    my @cases = (
        [ 'ACGT',  10 ],
        [ $LATIN,  12 ],
        [ $LATIN,  13 ],
        [ $wide,   10 ],
        [ $BASE36, 19 ],
    );
    foreach my $case (@cases) {
        my ( $alphabet, $length ) = @{$case};
        my $native = _ff1( alphabet => $alphabet, length => $length );
        my $big    = _ff1( alphabet => $alphabet, length => $length, bigint => 1 );
        my $radix  = length($alphabet);
        my @differ;
        foreach my $id ( 0 .. 20, 999_999, 1_048_575 ) {
            push( @differ, $id ) if $native->encrypt($id) ne $big->encrypt($id);
        }
        is( \@differ, [], "radix $radix, length $length: both kinds of arithmetic give the same ciphers" );
    }

    my $ff1 = _ff1( alphabet => $LATIN, length => 12 );
    my $big = _ff1( alphabet => $LATIN, length => 12, bigint => 1 );
    foreach my $id (qw{999999999999999 1000000000000000 9223372036854775807 390877006486250192895}) {
        is( $ff1->encrypt($id),                  $big->encrypt($id), "Id $id, with " . length($id) . " digits, gives the same cipher on both paths" );
        is( $ff1->decrypt( $ff1->encrypt($id) ), $id,                "Id $id comes back from decrypt()" );
    }
};

subtest 'large radixes, both sides of the 2**53 limit, and long tweaks' => sub {

    # For each radix, the lengths on each side of the largest length that perl integers hold: 4 for radix 65536, 10
    # for radix 255 to 257, and 88 for radix 2.  The tweaks reach past one AES block, and past 255 bytes.
    my %lengths = (
        65_536 => [ 2,  3,  4, 5 ],
        257    => [ 3,  10, 11 ],
        256    => [ 3,  10, 11 ],
        255    => [ 3,  10, 11 ],
        2      => [ 20, 21, 88, 89 ],
    );
    my @tweaks = ( 0, 1, 15, 16, 17, 255, 256, 1000 );
    my $key    = pack( 'H*', '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F' );
    my $i      = 0;
    my ( @problems, %paths );
    foreach my $radix ( sort { $a <=> $b } keys(%lengths) ) {
        my $alphabet = join( '', map { chr( 256 + $_ ) } 0 .. $radix - 1 );
        foreach my $length ( @{ $lengths{$radix} } ) {
            foreach my $tweak_length ( @tweaks[ map { ( $i + $_ ) % @tweaks } 0, 1 ] ) {
                $i++;
                my %args   = ( alphabet => $alphabet, length => $length, key => $key, tweak => join( '', map { chr( ( $i * 7 + $_ ) % 256 ) } 1 .. $tweak_length ) );
                my $native = URI::Shortener::FF1->new(%args);
                my $big    = URI::Shortener::FF1->new( %args, bigint => 1 );
                $paths{ $native->{native} ? 'native' : 'bigint' }++;

                my $plain = [ map { ( $i * 31 + $_ * 7 ) % $radix } 1 .. $length ];
                my $label = "radix $radix, length $length, tweak of $tweak_length bytes";
                my $c     = $native->encrypt_digits($plain);
                push( @problems, "$label: the two paths differ" )                 if "@{$c}" ne "@{ $big->encrypt_digits($plain) }";
                push( @problems, "$label: decrypt_digits() does not reverse it" ) if "@{ $native->decrypt_digits($c) }" ne "@{$plain}";
                push( @problems, "$label: Math::BigInt does not reverse it" )     if "@{ $big->decrypt_digits($c) }" ne "@{$plain}";
            }
        }
    }
    is( \@problems, [], "$i sets of parameters: both kinds of arithmetic give the same output, and decryption reverses it" );
    ok( $paths{native} && $paths{bigint}, "Some of them chose perl integers, and some chose Math::BigInt" );

    # No other implementation publishes a vector with a tweak of more than 255 bytes, so these values come from this
    # one.  They pin the 4-byte tweak length in the first block, which the agreement above cannot see.
    my %pinned = ( 256 => '8501145258', 1000 => '0241388747' );
    foreach my $tweak_length ( sort { $a <=> $b } keys(%pinned) ) {
        foreach my $bigint ( 0, 1 ) {
            my $ff1 = URI::Shortener::FF1->new(
                alphabet => $DIGITS,
                length   => 10,
                key      => pack( 'H*', $KEY{128} ),
                tweak    => join( '', map { chr( $_ % 256 ) } 0 .. $tweak_length - 1 ),
                bigint   => $bigint,
            );
            is( join( '', @{ $ff1->encrypt_digits( [ 0 .. 9 ] ) } ), $pinned{$tweak_length}, "A tweak of $tweak_length bytes gives the pinned cipher of 0123456789, bigint=$bigint" );
        }
    }
};

subtest 'round trip' => sub {
    foreach my $bigint ( 0, 1 ) {
        my $ff1 = _ff1( alphabet => 'ACGT', length => 10, bigint => $bigint );
        my @broken;
        foreach my $id ( 0 .. 50, 524_288, 1_048_575 ) {
            push( @broken, $id ) if ( $ff1->decrypt( $ff1->encrypt($id) ) // -1 ) != $id;
        }
        is( \@broken, [], "decrypt() reverses encrypt(), bigint=$bigint" );
    }

    my $ff1 = _ff1( alphabet => 'ACGT', length => 10 );
    is( $ff1->decrypt('ACGTACGTA'),   undef, "A string that is too short gives undef" );
    is( $ff1->decrypt('ACGTACGTACG'), undef, "A string that is too long gives undef" );
    is( $ff1->decrypt('ACGTACGTAX'),  undef, "A character outside the alphabet gives undef" );
    is( $ff1->decrypt(undef),         undef, "undef gives undef" );
};

subtest 'space exhausted' => sub {
    my $ff1 = _ff1( alphabet => 'ACGT', length => 10 );
    ok( lives { $ff1->encrypt(1_048_575) }, "The last id of the space, 4**10 - 1, is accepted" );
    like( dies { $ff1->encrypt(1_048_576) }, qr/space[ ]exhausted/sxaa, "The id 4**10 dies with 'space exhausted'" );

    my $large = _ff1( alphabet => $LATIN, length => 12 );
    ok( lives { $large->encrypt('390877006486250192895') }, "52**12 - 1 is accepted, through Math::BigInt" );
    like( dies { $large->encrypt('390877006486250192896') }, qr/space[ ]exhausted/sxaa, "52**12 dies with 'space exhausted'" );

    my %seen;
    foreach my $id ( 1_048_000 .. 1_048_575 ) {
        $seen{ $ff1->encrypt($id) } = 1;
    }
    is( scalar( keys(%seen) ), 576, "The ids at the top of the space give different ciphers and do not cycle" );
};

subtest 'bad input' => sub {
    like( dies { _ff1( alphabet => 'ACGTA', length => 10 ) }, qr/two[ ]times/sxaa, "An alphabet that repeats a character is refused" );
    like( dies { _ff1( alphabet => $DIGITS, length => 5 ) },  qr/1000000/sxaa,     "10**5 strings is less than the minimum, and is refused" );
    ok( lives { _ff1( alphabet => $DIGITS, length => 6 ) }, "10**6 strings is the minimum, and is accepted" );
    like( dies { _ff1( alphabet => 'A', length => 30 ) }, qr/2[ ]to[ ]65536/sxaa, "An alphabet of one character is refused" );
    like(
        dies {
            _ff1( alphabet => join( '', map { chr($_) } 0 .. 65_536 ), length => 2 )
        },
        qr/2[ ]to[ ]65536/sxaa,
        "An alphabet of 65537 characters is refused"
    );
    ok(
        lives {
            _ff1( alphabet => join( '', map { chr($_) } 0 .. 65_535 ), length => 2 )
        },
        "An alphabet of 65536 characters is accepted"
    );
    like(
        dies {
            _ff1( alphabet => join( '', map { chr($_) } 0 .. 65_535 ), length => 1 )
        },
        qr/length/sxaa,
        "A length of 1 is refused"
    );
    like( dies { _ff1( alphabet => 'ACGT', length => 4_294_967_296 ) },          qr/less[ ]than[ ]2[*][*]32/sxaa, "A length of 2**32 is refused, before new() computes 4 ** length" );
    like( dies { URI::Shortener::FF1->new( alphabet => 'ACGT', length => 10 ) }, qr/key/sxaa,                     "A key is required" );

    my $ff1 = _ff1( alphabet => 'ACGT', length => 10 );
    like( dies { $ff1->encrypt(-1) },    qr/integer/sxaa, "A negative id is refused" );
    like( dies { $ff1->encrypt(1.5) },   qr/integer/sxaa, "An id with a fraction is refused" );
    like( dies { $ff1->encrypt(undef) }, qr/integer/sxaa, "An undef id is refused" );
};

done_testing();

1;

__END__

=head1 DESCRIPTION

Tests URI::Shortener::FF1 against the nine FF1 samples of NIST, with and without a tweak.
Tests that perl integers and Math::BigInt give the same output, also for radixes up to 65536 and tweaks up to 1000 bytes, that decrypt() reverses encrypt(),
that an id past the end of the space dies, and that bad options die.

=cut
