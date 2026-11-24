use strict;
use warnings FATAL => 'all';
no autovivification;

use 5.014;

use Test2::V1 -i;    ## no critic (ProhibitUnusedImports) -i imports every tool, which the policy cannot see
use Test2::Plugin::NoWarnings;
use FindBin::libs;
use FindBin          qw{$Bin};
use Cpanel::JSON::XS qw{decode_json};
use JSON::Validator;
use List::Util qw{first max min sum};
use Math::BigInt;
use URI::Shortener::FF1;

my $ACVP_FILE = "$Bin/data/acvp-ff1/internalProjection.json";

# The path that the POD of URI::Shortener::FF1 promises, under ARITHMETIC: perl integers while radix ** ceil(n / 2) * 256 < 2**53.
sub _native_expected {
    my ( $radix, $length ) = @_;
    my $v = $length - int( $length / 2 );
    return Math::BigInt->new($radix)->bpow($v)->bmul(256) < Math::BigInt->new(2)->bpow(53) ? 1 : 0;
}

# Runs one known answer on the Math::BigInt path, and on the perl integer path where the POD says that new() picks it.
# $case has label, alphabet, key, tweak, pt and ct, with the key and tweak as bytes and pt and ct as digits.
# Both directions run, because a pair of plaintext and ciphertext checks decryption as well as encryption.
# Returns the problems as strings, and counts each path that ran in %$paths.
sub _known_answer {
    my ( $case, $paths ) = @_;
    my ( $label, $pt, $ct ) = @{$case}{qw{label pt ct}};
    my $length = scalar( @{$pt} );
    my $native = _native_expected( length( $case->{alphabet} ), $length );
    my @problems;
    foreach my $bigint ( 0, 1 ) {
        my $ff1 = URI::Shortener::FF1->new(
            alphabet => $case->{alphabet},
            length   => $length,
            key      => $case->{key},
            tweak    => $case->{tweak},
            bigint   => $bigint,
        );
        my $path = $bigint || !$native ? 'bigint' : 'native';

        # Peeks at the choice of new(), so that a change to the choice cannot send every case down the same path unseen.
        push( @problems, "$label: new() did not choose the $path path" ) if ( $ff1->{native} ? 'native' : 'bigint' ) ne $path;

        # Without bigint, a case that is too large for perl integers is the same as the run with bigint.
        next if !$bigint && !$native;
        $paths->{$path}++;

        push( @problems, "$label: encrypt, $path" ) if join( ',', @{ $ff1->encrypt_digits($pt) } ) ne join( ',', @{$ct} );
        push( @problems, "$label: decrypt, $path" ) if join( ',', @{ $ff1->decrypt_digits($ct) } ) ne join( ',', @{$pt} );
    }
    return @problems;
}

sub _to_digits {
    my ( $alphabet, $string ) = @_;
    my %index;
    my @chars = split( //sxaa, $alphabet );
    @index{@chars} = 0 .. $#chars;
    return [ map { $index{$_} // die "'$_' is not in the alphabet\n" } split( //sxaa, $string ) ];
}

# The ACVP file comes from outside this distribution, so its structure is checked before any value in it is used.
my $ACVP_SCHEMA = {
    type       => 'object',
    required   => [qw{algorithm revision testGroups}],
    properties => {
        algorithm  => { const => 'ACVP-AES-FF1' },
        revision   => { const => '1.0' },
        testGroups => {
            type     => 'array',
            minItems => 1,
            items    => {
                type       => 'object',
                required   => [qw{tgId direction keyLen alphabet radix tests}],
                properties => {
                    tgId      => { type => 'integer' },
                    direction => { enum => [qw{encrypt decrypt}] },
                    keyLen    => { enum => [ 128, 192, 256 ] },
                    alphabet  => { type => 'string',  minLength => 2, maxLength => 65_536 },
                    radix     => { type => 'integer', minimum   => 2, maximum   => 65_536 },
                    tests     => {
                        type     => 'array',
                        minItems => 1,
                        items    => {
                            type       => 'object',
                            required   => [qw{tcId key tweak tweakLen pt ct}],
                            properties => {
                                tcId => { type => 'integer' },

                                ## no critic (RegularExpressions::ProhibitRegexInStrings) JSON Schema takes a pattern as a string
                                key   => { type => 'string', pattern => '^(?:[0-9A-F]{2})+$' },
                                tweak => { type => 'string', pattern => '^(?:[0-9A-F]{2})*$' },
                                ## use critic
                                tweakLen => { type => 'integer', minimum   => 0 },
                                pt       => { type => 'string',  minLength => 2 },
                                ct       => { type => 'string',  minLength => 2 },
                            },
                        },
                    },
                },
            },
        },
    },
};

# Returns the groups of the ACVP file, with each case checked against its group.
sub _acvp_groups {
    open( my $fh, '<:raw', $ACVP_FILE ) or die "open $ACVP_FILE: $!";
    my $json = do { local $/ = undef; <$fh> };
    close($fh) or die "close $ACVP_FILE: $!";
    my $data = decode_json($json);

    my @errors = JSON::Validator->new()->schema($ACVP_SCHEMA)->validate($data);
    die "$ACVP_FILE does not have the expected structure:\n" . join( "\n", @errors ) . "\n" if @errors;

    foreach my $group ( @{ $data->{testGroups} } ) {
        my $where = "$ACVP_FILE, group $group->{tgId}";
        die "$where: the radix is not the length of the alphabet\n" if length( $group->{alphabet} ) != $group->{radix};
        foreach my $case ( @{ $group->{tests} } ) {
            die "$where, case $case->{tcId}: the key does not have keyLen bits\n"       if 4 * length( $case->{key} ) != $group->{keyLen};
            die "$where, case $case->{tcId}: tweakLen is not the length of the tweak\n" if $case->{tweakLen} != 4 * length( $case->{tweak} );
            die "$where, case $case->{tcId}: pt and ct have different lengths\n"        if length( $case->{pt} ) != length( $case->{ct} );
            $case->{pt_digits} = _to_digits( $group->{alphabet}, $case->{pt} );
            $case->{ct_digits} = _to_digits( $group->{alphabet}, $case->{ct} );
        }
    }
    return $data->{testGroups};
}

# A few cases of a group that between them reach its corners: the shortest plaintext, the shortest plaintext of odd
# length, and the longest tweak.  The groups of AES-128 encryption also give their longest plaintext, because in the
# two long cases of each group the AES output of a round is more than one block, and they cost the most time.
sub _representative {
    my ($group)   = @_;
    my $tests     = $group->{tests};
    my @by_length = sort { length( $a->{pt} ) <=> length( $b->{pt} ) || $a->{tcId} <=> $b->{tcId} } @{$tests};
    my $max_tweak = max( map { $_->{tweakLen} } @{$tests} );
    my @longest   = $group->{direction} eq 'encrypt' && $group->{keyLen} == 128 ? ( $by_length[-1] ) : ();
    my %pick;
    foreach my $case ( $by_length[0], @longest, ( first { length( $_->{pt} ) % 2 } @by_length ), ( first { $_->{tweakLen} == $max_tweak } @by_length ) ) {
        $pick{ $case->{tcId} } = $case if defined $case;
    }
    return @pick{ sort { $a <=> $b } keys(%pick) };
}

subtest 'NIST ACVP vectors' => sub {
    my $groups = _acvp_groups();
    is( scalar( @{$groups} ),                                 30,  "The ACVP file has 30 groups" );
    is( sum( map { scalar( @{ $_->{tests} } ) } @{$groups} ), 750, "The ACVP file has 750 cases" );

    my $all = $ENV{RELEASE_TESTING};
    note( $all ? "RELEASE_TESTING is set, so every case runs" : "Some cases of each group run.  Set RELEASE_TESTING to run all 750." );

    my ( %paths, $cases );
    foreach my $group ( @{$groups} ) {
        my @problems;
        my @tests = $all ? @{ $group->{tests} } : _representative($group);
        foreach my $case (@tests) {
            $cases++;
            push(
                @problems,
                _known_answer(
                    {
                        label    => "case $case->{tcId}",
                        alphabet => $group->{alphabet},
                        key      => pack( 'H*', $case->{key} ),
                        tweak    => pack( 'H*', $case->{tweak} ),
                        pt       => $case->{pt_digits},
                        ct       => $case->{ct_digits},
                    },
                    \%paths
                )
            );
        }
        my $lengths = join( ' to ', min( map { length( $_->{pt} ) } @tests ), max( map { length( $_->{pt} ) } @tests ) );
        is( \@problems, [], sprintf( "Group %d: %d cases of AES-%d, %s, radix %d, length %s", $group->{tgId}, scalar(@tests), @{$group}{qw{keyLen direction radix}}, $lengths ) );
    }
    is( $paths{bigint}, $cases, "Every case ran on the Math::BigInt path" );
    ok( $paths{native}, "Some cases ran on the perl integer path too" );
    is( $paths{native}, 330, "The 330 cases that are small enough ran on the perl integer path" ) if $all;
};

# FF1 test vectors of other implementations, as literal values.  They reach parameters that the ACVP file does not: radix
# 256 and 1024, radixes from 28 to 95 with alphabets of their own, alphabets outside ASCII, a tweak of 255 bytes, and
# lengths up to 1804.  The test files that they come from are:
#
# bc:   Bouncy Castle, testFF1w and testFF1Rounding.
#       https://github.com/bcgit/bc-java/blob/8cbfc3aafe209054f84c6880194e70d42e86af50/core/src/test/java/org/bouncycastle/crypto/test/SP80038GTest.java
# rust: the Rust crate fpe.  Vector 10 comes from the Go library of Capital One, and vectors 11 to 14 from Zcash.
#       Vector 14 has the tweak of 255 bytes, and vector 15 has a key of zeros.
#       https://github.com/str4d/fpe/blob/3cedf68f8b69875da94057a893e88ba9e744c876/src/ff1/test_vectors.rs
# ubiq: the C library of Ubiq.  Its "standard" alphabet for radix 62 is 0-9A-Za-z, the order of GMP.
#       https://github.com/ubiqsecurity/ubiq-fpe-c/blob/3af25888f9baf9d80373af0438f064ff77cd8d61/src/test/ff1.cpp
#
# The vectors of these files that are the nine NIST samples are left out, because t/URI-Shortener-FF1.t has them.
# The radix 1024 and 256 vectors of Bouncy Castle are packed digits: pt and ct are hex, which unpack with the template
# in pack gives the digits.

my @VECTORS = (
    {
        source => 'bc',
        name   => 'testFF1w',
        radix  => 1024,
        pack   => 'n*',
        key    => 'EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6',
        tweak  => '39383736353433323130',
        pt     => '0327035100210215',
        ct     => '022701f80217020a',
    },
    {
        source => 'bc',
        name   => 'testFF1Rounding',
        radix  => 256,
        pack   => 'C*',
        key    => '000102030405060708090A0B0C0D0E0F',
        tweak  => '0001020304050607',
        pt     => '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738',
        ct     => 'dc18bef8b7d23aa77d1daf7a50c2253c4bacb772129f70805ecd413775bc3bdf7927ce70f455dacf4fdf61b61ac73a5c90fd3d1759dca0bf27',
    },
    {
        source   => 'rust',
        name     => 'vector 10',
        alphabet => '0123456789abcdefghijklmnopqrstuvwxyz',
        key      => '2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94',
        tweak    => '',
        pt       => join(
            '', qw{
              xs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0
              azh2avyalyzuwdxs8a0azh2avyal
            }
        ),
        ct => join(
            '', qw{
              lwulibfp1ju3ksztumqomwenpv7duy9q7pg7zf3eg3rjlfy46gmgkqjfwvromfjjktmbey8meqk9zkcmgvkv4s9ll5ctozme1hf1
              5w7xo6zsylqcr0nbx9jbf10umzok
            }
        ),
    },
    {
        source   => 'rust',
        name     => 'vector 11',
        alphabet => '01',
        key      => '2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94',
        tweak    => '',
        pt       => '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        ct       => '0000100100110101011101111111110011000001101100111110011101110101011010100100010011001111',
    },
    {
        source   => 'rust',
        name     => 'vector 12',
        alphabet => '01',
        key      => '2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94',
        tweak    => '',
        pt       => '0000100100110101011101111111110011000001101100111110011101110101011010100100010011001111',
        ct       => '1101101011010001100011110000010011001111110110011101010110100001111001000101011111011000',
    },
    {
        source   => 'rust',
        name     => 'vector 13',
        alphabet => '01',
        key      => '2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94',
        tweak    => '',
        pt       => '0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101',
        ct       => '0000111101000001111011010111011111110001100101000000001101101110100010010111001100100110',
    },
    {
        source   => 'rust',
        name     => 'vector 14',
        alphabet => '01',
        key      => '2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94',
        tweak    =>
          '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFE',
        pt => '0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101',
        ct => '0111110110001000000111010110000100010101101000000011100111100100100010101101111010100011',
    },
    {
        source   => 'rust',
        name     => 'vector 15',
        alphabet => '01',
        key      => '0000000000000000000000000000000000000000000000000000000000000000',
        tweak    => '',
        pt       => '00000000000000000000000000000000',
        ct       => '11011110100111110010000011011000',
    },
    {
        source   => 'ubiq',
        name     => 'base2',
        alphabet => '01',
        key      => 'F4A116D6EE406A53A56CBE0F4AA7B1001CDC0A55CAC963CF5ACE390488B3477A',
        tweak    => 'FD7F4B9945A3C535ADB4720027116CA0F4987D7F3FDBA9BBC40E75375FEAA63C',
        pt       => '00000101011011011101001001010011100111100011001',
        ct       => '10110101001110101101110000011000000011111100111',
    },
    {
        source   => 'ubiq',
        name     => 'base2_a',
        alphabet => '01',
        key      => 'F4A116D6EE406A53A56CBE0F4AA7B1001CDC0A55CAC963CF5ACE390488B3477A',
        tweak    => 'FD7F4B9945A3C535ADB4720027116CA0F4987D7F3FDBA9BBC40E75375FEAA63C',
        pt       => join(
            '', qw{
              0000101011000111110100001110011000010110100111101001001100100100000001010000110000000011111101011111
              00111001001001100100100110101111110000011101010111001111010000010010111110101100001001100011
            }
        ),
        ct => join(
            '', qw{
              1111100011011100100101100010101000011010110010100110101110010011011010000111100001101100000011010111
              10101100001101000011101110110101001111100001011010010000010111001110010011001100001111100101
            }
        ),
    },
    {
        source   => 'ubiq',
        name     => 'base2_b',
        alphabet => '01',
        key      => 'F4A116D6EE406A53A56CBE0F4AA7B1001CDC0A55CAC963CF5ACE390488B3477A',
        tweak    => 'FD7F4B9945A3C535ADB4720027116CA0F4987D7F3FDBA9BBC40E75375FEAA63C',
        pt       => join(
            '', qw{
              0000011101101001010111111001111000101111100011010000010100101000110000110111100001000010101110010001
              0111011101001010010100101010100011010101010000101111111001111100110100001100011001011010010000110
            }
        ),
        ct => join(
            '', qw{
              0011001100100011110001011111000100011011011001001010110100101110100110101001000111100101010010000111
              0101010101101110110010100110101110111011111010110010101110000001101000101010100011010100111011000
            }
        ),
    },
    {
        source   => 'ubiq',
        name     => 'base2_c',
        alphabet => '01',
        key      => 'F4A116D6EE406A53A56CBE0F4AA7B1001CDC0A55CAC963CF5ACE390488B3477A',
        tweak    => 'FD7F4B9945A3C535ADB4720027116CA0F4987D7F3FDBA9BBC40E75375FEAA63C',
        pt       => join(
            '', qw{
              0000110001000111000100011110010000111111011000000000101000000111110000011110010111011110110010101100
              1010010010001011100000100100011100010111111000111101010111010110011001000010000101000100000111011001
              0000100001110010101001011110111111001111111010100011111011111010001011111011001010010000101101010111
              0001101100111010110100110010010110100000011110010011000000111101100011001111000001101110111100111010
              1101111001001111010101011001100011001111001110
            }
        ),
        ct => join(
            '', qw{
              1010110100111111011011000101010111011101101010100111001111110110110100000111001010011011001101110100
              0101010001111101100000110000101110000000110001011000100000111001111011101011100011100010100001010011
              1101000100010010000011011100101101111000101010010001001000000101111000001010000101000110011000111111
              1001110011111001110011111101100110101110001010011000110011100010000010101111111010001111001110100101
              0110001000011010011011101001101000001100110100
            }
        ),
    },
    {
        source   => 'ubiq',
        name     => 'base2_d',
        alphabet => '01',
        key      => 'F4A116D6EE406A53A56CBE0F4AA7B1001CDC0A55CAC963CF5ACE390488B3477A',
        tweak    => 'FD7F4B9945A3C535ADB4720027116CA0F4987D7F3FDBA9BBC40E75375FEAA63C',
        pt       => join(
            '', qw{
              0000100001110000110111000100110011101011100100100000011011100101010101010100111000001001001010110110
              1011000100011111111010011001000011100000011011001010001100000011011001001101011011011110110101000101
              0011010111001110110100100001010011011110111100010000101101001100000000001100101011000011011111001011
              1110001010111000011100010010100111011110010100110101000100101010010100001110010101001100010001111000
              011110001101011010001010110110010000111001110110101
            }
        ),
        ct => join(
            '', qw{
              0101111000110110000111000111011100110111101000100000100010100110100010001101000101111000100000111000
              0000111101110010011010101000011111001001011001000000000000111000111100101000100000100010011011000111
              0011111010111000010111101010011110000011100000011101101101010111110011010100011000111011000111001111
              1000111110010000100010000101010110000010010100001111011010110111011111101000100000010111101010000011
              011110001000000011111010110010100101001000111101110
            }
        ),
    },
    {
        source   => 'ubiq',
        name     => 'base2_e',
        alphabet => '01',
        key      => 'F4A116D6EE406A53A56CBE0F4AA7B1001CDC0A55CAC963CF5ACE390488B3477A',
        tweak    => 'FD7F4B9945A3C535ADB4720027116CA0F4987D7F3FDBA9BBC40E75375FEAA63C',
        pt       => join(
            '', qw{
              0000100001110000110111000100110011101011100100100000011011100101010101010100111000001001001010110110
              1011000100011111111010011001000011100000011011001010001100000011011001001101011011011110110101000101
              0011010111001110110100100001010011011110111100010000101101001100000000001100101011000011011111001011
              1110001010111000011100010010100111011110010100110101000100101010010100001110010101001100010001111000
              0111100011010110100010101101100100001110011101101010000100001110000110111000100110011101011100100100
              0000110111001010101010101001110000010010010101101101011000100011111111010011001000011100000011011001
              0100011000000110110010011010110110111101101010001010011010111001110110100100001010011011110111100010
              0001011010011000000000011001010110000110111110010111110001010111000011100010010100111011110010100110
              1010001001010100101000011100101010011000100011110000111100011010110100010101101100100001110011101101
              0100001000011100001101110001001100111010111001001000000110111001010101010101001110000010010010101101
              1010110001000111111110100110010000111000000110110010100011000000110110010011010110110111101101010001
              0100110101110011101101001000010100110111101111000100001011010011000000000011001010110000110111110010
              1111100010101110000111000100101001110111100101001101010001001010100101000011100101010011000100011110
              0001111000110101101000101011011001000011100111011010100001000011100001101110001001100111010111001001
              0000001101110010101010101010011100000100100101011011010110001000111111110100110010000111000000110110
              0101000110000001101100100110101101101111011010100010100110101110011101101001000010100110111101111000
              1000010110100110000000000110010101100001101111100101111100010101110000111000100101001110111100101001
              1010100010010101001010000111001010100110001000111100001111000110101101000101011011001000011100111011
              0101
            }
        ),
        ct => join(
            '', qw{
              0000010100010011101101101111101011010101110011111000100110100110001101001001111110001100001010111011
              0010011011000111100101111111111000111111111110111000001010000001011011000110011101100110111101110111
              0110111111011000010100001111110110010010010101011011101010111100101100000110000010000011011011011100
              1101010101001111101111010111010111001101101000000101100001000100100001111001001001001000001010010000
              1010001101110100100000100101010000001111111010010111011111110001001010011001100011110011011100010101
              1001100000000010101100101011011001110110011100111001011101101010111010010011101011100001001101000000
              1001001111110110001110010110111101101000001100101101100010101101010110010001001110010001100110101100
              0110010100100110011001010100011110101000001010100111110100011101100001111010101111111011010010011100
              0111011011111110010100101011001001100001111111011111000001001011011011110011010100011100001101010010
              0001101001010001110000011110001110101001010110011111100010001011001110110100000001010001010101001000
              0110000010100100011101100010110000100100111110111010011100101001010010000111111000111111111100001101
              1100110110100111111101001101111010110101111101001010100010001101001111101010010101100110011011010101
              1110110000010110111101001100000001011000010000110111100111110001101011011000010010011111101010001100
              0100100011001111111100111010001111101010011000110101001001101101110100100100011000011010001110000000
              1000011110101000101111110001111100111100011100111010011001011000010100010000100000110010000010010101
              1001000001011010000000000011100110001001011111001011101010100001101101000111101010111000101001000001
              1000111100001011111001101101000011110011100111111110001000110000100000001101101010111010010100000010
              1101001010111110110010001111010111010111010101011000111010000000001010001100011101101111010011111111
              1100
            }
        ),
    },
    {
        source   => 'ubiq',
        name     => 'base10_a',
        alphabet => '0123456789',
        key      => 'F4A116D6EE406A53A56CBE0F4AA7B1001CDC0A55CAC963CF5ACE390488B3477A',
        tweak    => 'FD7F4B9945A3C535ADB4720027116CA0F4987D7F3FDBA9BBC40E75375FEAA63C',
        pt       => join(
            '', qw{
              0000100001110000110111000100110011101011100100100000011011100101010101010100111000001001001010110110
              1011000100011111111010011001000011100000011011001010001100000011011001001101011011011110110101000101
              0011010111001110110100100001010011011110111100010000101101001100000000001100101011000011011111001011
              1110001010111000011100010010100111011110010100110101000100101010010100001110010101001100010001111000
              0111100011010110100010101101100100001110011101101010000100001110000110111000100110011101011100100100
              0000110111001010101010101001110000010010010101101101011000100011111111010011001000011100000011011001
              0100011000000110110010011010110110111101101010001010011010111001110110100100001010011011110111100010
              0001011010011000000000011001010110000110111110010111110001010111000011100010010100111011110010100110
              1010001001010100101000011100101010011000100011110000111100011010110100010101101100100001110011101101
              0100001000011100001101110001001100111010111001001000000110111001010101010101001110000010010010101101
              1010110001000111111110100110010000111000000110110010100011000000110110010011010110110111101101010001
              0100110101110011101101001000010100110111101111000100001011010011000000000011001010110000110111110010
              1111100010101110000111000100101001110111100101001101010001001010100101000011100101010011000100011110
              0001111000110101101000101011011001000011100111011010100001000011100001101110001001100111010111001001
              0000001101110010101010101010011100000100100101011011010110001000111111110100110010000111000000110110
              0101000110000001101100100110101101101111011010100010100110101110011101101001000010100110111101111000
              1000010110100110000000000110010101100001101111100101111100010101110000111000100101001110111100101001
              1010100010010101001010000111001010100110001000111100001111000110101101000101011011001000011100111011
              0101
            }
        ),
        ct => join(
            '', qw{
              3553494089916656541184478908087049735544912674297349664796606620188730753059002844128234255625871546
              0448543952099629267847241285607135122488086872111497445981954127129404681637740966283506209514137118
              0395051859461737335154439385637345032008752326202238394564812737206247823114803847184401487113279442
              1592688429360388632538622007325709023114489620502858661369331722385345630805557726657301103731476891
              9393565406251908612238312020188690595235979953032900741210794287214570717564165727280291777468109003
              0702025953776541020192996308698230783718650936423695651199935014732372101033285784777438606764423370
              3989840323109138134072973241903156111826976160812600185129257000146824574348291127595725594892501619
              6345081284887318923529872071545380432758652067204074317019865794985757646256824057934381164863153299
              0492473499362419217553890772800554600677983634775128115851486225635252648171806412256458036721795623
              7464358103196538875291283690155429858297253893898279060676625001618108275714219171491371113956773762
              8449410349474720265913412523390341366279982532338176062500248412304630675335670899356037563015658203
              6907992770075880594877232176326562887134990320424916251328140225008783439325998792578467844041190059
              8614732588243252529912937631866659880744158524571625718103685314053287308120410823249151599910726383
              3592555925399463798611830344584907443020670492366670201417636106518517689550097325173364006508384087
              6471642382922580172058014433381381660422267650718334155800530874250517040647851723711592345799244203
              4329915124651627732600793249273733794088807416454414747271994796609670521986503851051553369292884493
              5643745262148979965104585734396695198858261542610708115500778494220330634943543687565842345781978573
              6023595538905965591477826899612756902034387706342271573792681987751093723147446032465846998921423434
              6399
            }
        ),
    },
    {
        source   => 'ubiq',
        name     => 'base62',
        alphabet => '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        key      => 'F4A116D6EE406A53A56CBE0F4AA7B1001CDC0A55CAC963CF5ACE390488B3477A',
        tweak    => 'FD7F4B9945A3C535ADB4720027116CA0F4987D7F3FDBA9BBC40E75375FEAA63C',
        pt       => '1234567890ABCDEFabcdef',
        ct       => '6KNFyZss7SBQ7w7udUwsv8',
    },
    {
        source   => 'ubiq',
        name     => 'base72_custom_radix',
        alphabet => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!\@#\$%^&*()",
        key      => 'F4A116D6EE406A53A56CBE0F4AA7B1001CDC0A55CAC963CF5ACE390488B3477A',
        tweak    => 'FD7F4B9945A3C535ADB4720027116CA0F4987D7F3FDBA9BBC40E75375FEAA63C',
        pt       => '1234567890ABCDEFabcdef',
        ct       => "x%\$lEuv\$QuA5HykL#2WZW0",
    },
    {
        source   => 'ubiq',
        name     => 'base_long_radix_non_std',
        alphabet => " !\"#\$%&'()*+,-./0123456789:;<=>?\@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`{|}~",
        key      => 'F4A116D6EE406A53A56CBE0F4AA7B1001CDC0A55CAC963CF5ACE390488B3477A',
        tweak    => 'FD7F4B9945A3C535ADB4720027116CA0F4987D7F3FDBA9BBC40E75375FEAA63C',
        pt       => ' 1234567890ABCDEFGHIJKLMNOP',
        ct       => "&4E+ZZ^}TF9+G/]]:E\"WV3|%3G]",
    },
    {
        source   => 'ubiq',
        name     => 'base_short_radix_non_std',
        alphabet => " 1-3%56789ABCD\"FGHIJKLMNOPQRSTUVWXYZabcdefghijklm",
        key      => 'F4A116D6EE406A53A56CBE0F4AA7B1001CDC0A55CAC963CF5ACE390488B3477A',
        tweak    => 'FD7F4B9945A3C535ADB4720027116CA0F4987D7F3FDBA9BBC40E75375FEAA63C',
        pt       => "1-3%56789 ABCD\"FGHIJKLMNOP",
        ct       => "KQmGM7H\"DLd1a1l%OOTD8CiCOD",
    },
    {
        source   => 'ubiq',
        name     => 'base_short_radix_non_stdb',
        alphabet => " !\"#\$%&'()*+,-./0123456789:;<=>?\@ABCDEFGHIJKLMNOP",
        key      => 'F4A116D6EE406A53A56CBE0F4AA7B1001CDC0A55CAC963CF5ACE390488B3477A',
        tweak    => 'FD7F4B9945A3C535ADB4720027116CA0F4987D7F3FDBA9BBC40E75375FEAA63C',
        pt       => "1-3%56789 ABCD\"FGHIJKLMNOP",
        ct       => "'OJ22H:+= I2L6ME-MEO%I0\@:M",
    },
    {
        source   => 'ubiq',
        name     => 'generic',
        alphabet => " !\"#\$%&'()*+,-./0123456789:;<=>?\@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
        key      => 'F4A116D6EE406A53A56CBE0F4AA7B1001CDC0A55CAC963CF5ACE390488B3477A',
        tweak    => 'FD7F4B9945A3C535ADB4720027116CA0F4987D7F3FDBA9BBC40E75375FEAA63C',
        pt       => "1-3%56789 ABCD\"FGHIJKLMNOP",
        ct       => "(7I6S-pi4iT#G|7w\\BXBiJV(m\\",
    },
    {
        source   => 'ubiq',
        name     => 'base_short_radix_std2',
        alphabet => " 1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`{|}~",
        key      => 'F4A116D6EE406A53A56CBE0F4AA7B1001CDC0A55CAC963CF5ACE390488B3477A',
        tweak    => 'FD7F4B9945A3C535ADB4720027116CA0F4987D7F3FDBA9BBC40E75375FEAA63C',
        pt       => ' 1234567890ABCDEFGHIJKLMNOP',
        ct       => 'EYCQ{|K`PYP1_AKZDMDOVGNCMTE',
    },
    {
        source   => 'ubiq',
        name     => 'so_alphanum_po',
        alphabet => ' 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        key      => 'EB7AD81756D84C6701B15F5B68003CBD9D17F7F8032A1A624A303387CC12368E',
        tweak    => 'DC4D52AA15D87E710DDEA1765E6A59488F9DFE8D603633FFC0B595EEFC233880',
        pt       => '1234',
        ct       => 'ZO7G',
    },
    {
        source   => 'ubiq',
        name     => 'ascii8',
        alphabet => " 0123456789abcABC\N{U+00CA}\N{U+00CB}\N{U+00CC}\N{U+00CD}\N{U+00CE}\N{U+00CF}\N{U+00F0}\N{U+00F1}\N{U+00F2}\N{U+00F3}\N{U+00F4}",
        key      => 'EB7AD81756D84C6701B15F5B68003CBD9D17F7F8032A1A624A303387CC12368E',
        tweak    => 'DC4D52AA15D87E710DDEA1765E6A59488F9DFE8D603633FFC0B595EEFC233880',
        pt       => '0123456789abcABC',
        ct       => "46b3 \N{U+00F0}\N{U+00CF}a\N{U+00F0}43\N{U+00CC}\N{U+00CA}09B",
    },
    {
        source   => 'ubiq',
        name     => 'ascii8_b',
        alphabet => " 0123456789abcABC\N{U+00CA}\N{U+00CB}\N{U+00CC}\N{U+00CD}\N{U+00CE}\N{U+00CF}\N{U+00F0}\N{U+00F1}\N{U+00F2}\N{U+00F3}\N{U+00F4}",
        key      => 'EB7AD81756D84C6701B15F5B68003CBD9D17F7F8032A1A624A303387CC12368E',
        tweak    => 'DC4D52AA15D87E710DDEA1765E6A59488F9DFE8D603633FFC0B595EEFC233880',
        pt       => "0123456789abcABC\N{U+00CA}\N{U+00CB}\N{U+00CC}\N{U+00CD}\N{U+00CE}\N{U+00CF}\N{U+00F0}\N{U+00F1}\N{U+00F2}\N{U+00F3}\N{U+00F4}",
        ct       => "\N{U+00CE}\N{U+00F4}5\N{U+00CD}21b\N{U+00F1}\N{U+00CA}2CA\N{U+00F4}6 C\N{U+00F3}B6\N{U+00CA}A00\N{U+00F0}\N{U+00CD}8C",
    },
    {
        source   => 'ubiq',
        name     => 'ascii8_c',
        alphabet => " 0123456789abcABC\N{U+00CA}\N{U+00CB}\N{U+00CC}\N{U+00CD}\N{U+00CE}\N{U+00CF}\N{U+00F0}\N{U+00F1}\N{U+00F2}\N{U+00F3}\N{U+00F4}",
        key      => 'EB7AD81756D84C6701B15F5B68003CBD9D17F7F8032A1A624A303387CC12368E',
        tweak    => 'DC4D52AA15D87E710DDEA1765E6A59488F9DFE8D603633FFC0B595EEFC233880',
        pt       => "\N{U+00CA}\N{U+00CB}\N{U+00CC}\N{U+00CD}\N{U+00CE}\N{U+00CF}\N{U+00F0}\N{U+00F1}\N{U+00F2}\N{U+00F3}\N{U+00F4}",
        ct       => "C21A7bA47c\N{U+00F3}",
    },
    {
        source   => 'ubiq',
        name     => 'unicode',
        alphabet => " \N{U+00CA}\N{U+00CB}\N{U+00CC}\N{U+00CD}\N{U+00CE}\N{U+00CF}\N{U+00F0}\N{U+00F1}\N{U+00F2}\N{U+00F3}\N{U+00F4}\N{U+0135}\N{U+0136}\N{U+0137}\N{U+0138}\N{U+0139}\N{U+03FA}\N{U+03FB}\N{U+03FC}\N{U+03FD}\N{U+03FE}\N{U+03FF}0123456789abcABC",
        key      => 'EB7AD81756D84C6701B15F5B68003CBD9D17F7F8032A1A624A303387CC12368E',
        tweak    => 'DC4D52AA15D87E710DDEA1765E6A59488F9DFE8D603633FFC0B595EEFC233880',
        pt       => '123456789abcABC',
        ct       => "\N{U+00CF}3\N{U+00CB}c\N{U+03FE}\N{U+0137}a\N{U+00F3}5\N{U+03FE}1\N{U+03FA}6c\N{U+0139}",
    },
    {
        source   => 'ubiq',
        name     => 'unicode_b',
        alphabet => " \N{U+00CA}\N{U+00CB}\N{U+00CC}\N{U+00CD}\N{U+00CE}\N{U+00CF}\N{U+00F0}\N{U+00F1}\N{U+00F2}\N{U+00F3}\N{U+00F4}\N{U+0135}\N{U+0136}\N{U+0137}\N{U+0138}\N{U+0139}\N{U+03FA}\N{U+03FB}\N{U+03FC}\N{U+03FD}\N{U+03FE}\N{U+03FF}0123456789abcABC",
        key      => 'EB7AD81756D84C6701B15F5B68003CBD9D17F7F8032A1A624A303387CC12368E',
        tweak    => 'DC4D52AA15D87E710DDEA1765E6A59488F9DFE8D603633FFC0B595EEFC233880',
        pt       => "\N{U+0135}\N{U+0136}\N{U+0137}\N{U+0138}\N{U+0139}\N{U+03FA}\N{U+03FB}\N{U+03FC}\N{U+03FD}\N{U+03FE}\N{U+03FF}",
        ct       => "\N{U+00CC}9a \N{U+00CF}\N{U+00CB}8A\N{U+00CC}\N{U+00CE}\N{U+00CB}",
    },
    {
        source   => 'ubiq',
        name     => 'unicode_c',
        alphabet => " \N{U+00CA}\N{U+00CB}\N{U+00CC}\N{U+00CD}\N{U+00CE}\N{U+00CF}\N{U+00F0}\N{U+00F1}\N{U+00F2}\N{U+00F3}\N{U+00F4}\N{U+0135}\N{U+0136}\N{U+0137}\N{U+0138}\N{U+0139}\N{U+03FA}\N{U+03FB}\N{U+03FC}\N{U+03FD}\N{U+03FE}\N{U+03FF}0123456789abcABC",
        key      => 'EB7AD81756D84C6701B15F5B68003CBD9D17F7F8032A1A624A303387CC12368E',
        tweak    => 'DC4D52AA15D87E710DDEA1765E6A59488F9DFE8D603633FFC0B595EEFC233880',
        pt       => "3456789abcAB\N{U+0135}\N{U+0136}\N{U+0137}\N{U+0138}\N{U+0139}\N{U+03FA}\N{U+03FB}\N{U+03FC}\N{U+03FD}\N{U+03FE}\N{U+03FF}3456789abcAB",
        ct       => "8\N{U+03FE}\N{U+0135}\N{U+03FA}\N{U+00CE}1\N{U+03FC}1\N{U+00F3}\N{U+00CB}\N{U+0138}A14430\N{U+03FF}C\N{U+03FA}\N{U+0137}\N{U+03FD}\N{U+03FB}\N{U+0139}1245\N{U+0137}2\N{U+00CF}2\N{U+00F3}\N{U+00F4}9",
    },
);

my @REFUSED = (
    {
        source   => 'ubiq',
        name     => 'base_short_radix_std3',
        alphabet => "  !\"#\$%&'()*+,-./0123456789:;<=>?\@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`{|}~",
        key      => 'F4A116D6EE406A53A56CBE0F4AA7B1001CDC0A55CAC963CF5ACE390488B3477A',
        tweak    => 'FD7F4B9945A3C535ADB4720027116CA0F4987D7F3FDBA9BBC40E75375FEAA63C',
        pt       => ' 1234567890ABCDEFGHIJKLMNOP',
        ct       => ":Y\@=\\?^V[)},4'KL4>{M,H75\"C8",
    },
);

subtest 'vectors of other implementations' => sub {
    my %paths;
    foreach my $vector (@VECTORS) {
        my %case = (
            label => "$vector->{source} $vector->{name}",
            key   => pack( 'H*', $vector->{key} ),
            tweak => pack( 'H*', $vector->{tweak} ),
        );
        if ( $vector->{pack} ) {
            $case{alphabet} = join( '', map { chr( 256 + $_ ) } 0 .. $vector->{radix} - 1 );
            @case{qw{pt ct}} = map { [ unpack( $vector->{pack}, pack( 'H*', $_ ) ) ] } @{$vector}{qw{pt ct}};
        }
        else {
            $case{alphabet} = $vector->{alphabet};
            @case{qw{pt ct}} = map { _to_digits( $vector->{alphabet}, $_ ) } @{$vector}{qw{pt ct}};
        }
        my @problems = _known_answer( \%case, \%paths );
        is( \@problems, [], sprintf( "%s: radix %d, length %d, tweak of %d bytes", $case{label}, length( $case{alphabet} ), scalar( @{ $case{pt} } ), length( $case{tweak} ) ) );
    }
    is( $paths{bigint}, scalar(@VECTORS), "Every vector ran on the Math::BigInt path" );
    ok( $paths{native}, "Some vectors ran on the perl integer path too" );
};

subtest 'a vector whose alphabet repeats a character' => sub {
    foreach my $vector (@REFUSED) {
        like(
            dies {
                URI::Shortener::FF1->new(
                    alphabet => $vector->{alphabet},
                    length   => length( $vector->{pt} ),
                    key      => pack( 'H*', $vector->{key} ),
                    tweak    => pack( 'H*', $vector->{tweak} ),
                )
            },
            qr/two[ ]times/sxaa,
            "$vector->{source} $vector->{name}: new() refuses the alphabet, which has the space two times"
        );
    }
};

done_testing();

1;

__END__

=head1 DESCRIPTION

Tests URI::Shortener::FF1 against FF1 test vectors from outside this distribution.
The NIST ACVP vectors are in F<t/data/acvp-ff1/>, whose README says where they come from.
By default a few cases of each ACVP group run, and all 750 run when RELEASE_TESTING is set.
The vectors of Bouncy Castle, the Rust crate fpe and the Ubiq C library are literal values in this file.
Each vector runs in both directions, on the Math::BigInt path and also on the perl integer path where new() picks it.

=cut
