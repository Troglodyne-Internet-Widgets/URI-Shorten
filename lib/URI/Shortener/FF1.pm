package URI::Shortener::FF1;

#ABSTRACT: NIST SP 800-38G FF1 format-preserving encryption, as URI::Shortener uses it

use strict;
use warnings FATAL => 'all';
no autovivification;

use 5.014;

use Crypt::Cipher::AES;
use List::Util qw{uniq};
use Math::BigInt try => 'GMP,LTM';

=head1 SYNOPSIS

    my $ff1 = URI::Shortener::FF1->new(
        alphabet => 'ACGT',
        length   => 10,
        key      => $sixteen_bytes,
    );
    my $string = $ff1->encrypt(42);         # 10 characters from 'ACGT'
    my $id     = $ff1->decrypt($string);    # 42

=head1 DESCRIPTION

FF1 is a format-preserving cipher.
It is in NIST Special Publication 800-38G.
A format-preserving cipher changes a string of digits into a different string of the same length and with the same digits.
Here a "digit" is a character of the alphabet.

The cipher is a bijection on the set of strings.
A bijection is a function that gives each input a different output, and that you can reverse.
So two different numbers never give the same string.

This class changes a number into a string of digits and then encrypts that string.
The number must be less than C<length(alphabet) ** length>.

The key is an AES key.
The tweak is empty unless you give one.
URI::Shortener makes the key from its seed.

=head2 ARITHMETIC

The cipher works on numbers as large as C<length(alphabet) ** ceil(length / 2)>.
When that number times 256 is less than 2**53, perl integers hold every value without loss.
Then the cipher uses perl integers.
Otherwise it uses L<Math::BigInt>, which is 100 to 150 times slower.
It uses the GMP or LTM library of Math::BigInt when one is installed.
CryptX includes LTM.
This class chooses between the two in new(), and both give the same output.

=head1 CONSTRUCTOR

=head2 $class->new(%options)

=over 4

=item C<alphabet>

A string of 2 to 65536 characters.
No character can be in the string two times.

=item C<length>

The length of each output string.
It must be 2 or more.

C<length(alphabet) ** length> must be 1,000,000 or more.
This is the minimum that NIST SP 800-38G sets.

=item C<key>

An AES key of 16, 24 or 32 bytes.

=item C<tweak>

Optional bytes that change the output, but do not have to be secret.
The default is an empty tweak.

=item C<bigint>

When true, use Math::BigInt even when perl integers are sufficient.
This is for tests that compare the two kinds of arithmetic.

=back

new() dies when an option is not correct.

=cut

my $MIN_SPACE = 1_000_000;
my $MAX_RADIX = 65_536;
my $ROUNDS    = 10;
my $BLOCK     = 16;
my $TWO_32    = 4_294_967_296;

# Every integer below 2**53 is exact in a double.
my $NATIVE_LIMIT = Math::BigInt->new(2)->bpow(53);

# A number with this many decimal digits or fewer is less than 2**53.
my $NATIVE_DIGITS = 15;

sub new {
    my ( $class, %args ) = @_;

    my @alphabet = split( //sxaa, $args{alphabet} // '' );
    die "The alphabet must not have a character two times\n" if scalar( uniq(@alphabet) ) != scalar(@alphabet);
    my $radix = scalar(@alphabet);
    die "The alphabet must have 2 to $MAX_RADIX characters\n" if $radix < 2 || $radix > $MAX_RADIX;

    my $length = $args{length} // '';
    die "The length must be an integer of 2 or more\n" if $length !~ m{\A\d+\z}sxaa || $length < 2;

    my $space = Math::BigInt->new($radix)->bpow($length);
    die "The space of alphabet ** length has $space strings, and FF1 needs $MIN_SPACE or more.  Use a longer alphabet or length.\n" if $space < $MIN_SPACE;

    my $tweak = $args{tweak} // '';
    my $u     = int( $length / 2 );
    my $v     = $length - $u;
    my $mod_u = Math::BigInt->new($radix)->bpow($u);
    my $mod_v = Math::BigInt->new($radix)->bpow($v);

    # b in the standard: the number of bytes that hold any number below radix ** v.
    my $bytes = int( ( length( $mod_v->copy->bdec->as_bin ) - 2 + 7 ) / 8 );

    # d in the standard: the number of bytes of AES output that each round uses.
    my $out_bytes = 4 * int( ( $bytes + 3 ) / 4 ) + 4;

    my $native = !$args{bigint} && $mod_v->copy->bmul(256) < $NATIVE_LIMIT;

    my $aes = Crypt::Cipher::AES->new( $args{key} // die "A key is required\n" );

    # P in the standard.  It is the first block of every CBC-MAC, so its MAC is the same for every round.
    my $head = pack( 'CCC', 1, 2, 1 ) . substr( pack( 'N', $radix ), 1 ) . pack( 'CCNN', $ROUNDS, $u % 256, $length, length($tweak) );

    my %self = (
        aes       => $aes,
        alphabet  => \@alphabet,
        index     => { map { $alphabet[$_] => $_ } 0 .. $#alphabet },
        radix     => $radix,
        length    => $length,
        u         => $u,
        v         => $v,
        space     => $space,
        space_int => ( $space->length() <= $NATIVE_DIGITS ? $space->numify() : undef ),
        bytes     => $bytes,
        out_bytes => $out_bytes,
        head_mac  => $aes->encrypt($head),
        tweak_pad => $tweak . ( "\0" x ( ( -length($tweak) - $bytes - 1 ) % $BLOCK ) ),
        native    => $native,
        mod_u     => ( $native ? $mod_u->numify() : $mod_u ),
        mod_v     => ( $native ? $mod_v->numify() : $mod_v ),
    );
    return bless( \%self, $class );
}

=head1 METHODS

=head2 encrypt( INTEGER $id )

Returns the string for $id.
Each $id gives a different string.

Dies when $id is not an integer of 0 or more.
Dies with "space exhausted" when $id is C<length(alphabet) ** length> or more.

=cut

sub encrypt {
    my ( $self, $id ) = @_;
    die "The id must be an integer of 0 or more\n" unless defined $id && $id =~ m{\A\d+\z}sxaa;

    my $digits;
    if ( length($id) <= $NATIVE_DIGITS ) {
        die _exhausted( $self, $id ) if defined $self->{space_int} && $id >= $self->{space_int};
        $digits = _int_to_digits( 0 + $id, @{$self}{qw{radix length}} );
    }
    else {
        my $big = Math::BigInt->new($id);
        die _exhausted( $self, $id ) if $big >= $self->{space};
        $digits = _big_to_digits( $big, @{$self}{qw{radix length}} );
    }
    return join( '', @{ $self->{alphabet} }[ @{ $self->encrypt_digits($digits) } ] );
}

sub _exhausted {
    my ( $self, $id ) = @_;
    return "URI::Shortener space exhausted: id $id is not less than $self->{space}, the number of strings of $self->{length} characters from the domain\n";
}

=head2 decrypt( STRING $string )

The reverse of encrypt().
Returns the integer that gives $string.
Returns undef when $string has the wrong length, or has a character that is not in the alphabet.

The return value is a decimal string when it is too large for a perl integer.

=cut

sub decrypt {
    my ( $self, $string ) = @_;
    return if length( $string // '' ) != $self->{length};

    my @digits;
    foreach my $char ( split( //sxaa, $string ) ) {
        my $digit = $self->{index}->{$char};
        return unless defined $digit;
        push( @digits, $digit );
    }
    my $plain = $self->decrypt_digits( \@digits );
    return _digits_to_int( $plain, $self->{radix} ) if defined $self->{space_int};
    return _digits_to_big( $plain, $self->{radix} )->bstr();
}

=head2 encrypt_digits( ARRAYREF $digits ) and decrypt_digits( ARRAYREF $digits )

FF1 itself.
Each digit is an integer from 0 to C<length(alphabet) - 1>, and the most significant digit is first.
Returns a new array reference of the same length.

The caller must give exactly C<length> digits in that range.
These methods do not check.

=cut

sub encrypt_digits {
    my ( $self, $digits ) = @_;
    return $self->{native} ? $self->_rounds_native( $digits, 0 ) : $self->_rounds_bigint( $digits, 0 );
}

sub decrypt_digits {
    my ( $self, $digits ) = @_;
    return $self->{native} ? $self->_rounds_native( $digits, 1 ) : $self->_rounds_bigint( $digits, 1 );
}

# The Feistel rounds of FF1, step 6 of algorithms 7 and 8 in the standard, with perl integers.
# The conversions are written in line, because calls to subs for them cost a third of the time.
sub _rounds_native {
    my ( $self, $digits, $decrypt ) = @_;
    my ( $radix, $u, $v, $mod_u, $mod_v, $width ) = @{$self}{qw{radix u v mod_u mod_v bytes}};

    my @left  = @{$digits}[ 0 .. $u - 1 ];
    my @right = @{$digits}[ $u .. $#{$digits} ];
    foreach my $step ( 0 .. $ROUNDS - 1 ) {
        my $round = $decrypt ? $ROUNDS - 1 - $step : $step;
        my ( $m, $mod ) = $round % 2 ? ( $v, $mod_v ) : ( $u, $mod_u );

        my $num = 0;
        $num = $num * $radix + $_ for ( $decrypt ? @left : @right );

        # $num is below 2**45 here, so two 32-bit words hold it, and the division by 2**32 is exact.
        my $num_bytes = substr( pack( 'NN', int( $num / $TWO_32 ), $num % $TWO_32 ), 8 - $width );

        my $y = 0;
        $y = ( $y * 256 + $_ ) % $mod for unpack( 'C*', $self->_round_output( $round, $num_bytes ) );

        my $c = 0;
        $c = $c * $radix + $_ for ( $decrypt ? @right : @left );
        $c = ( $decrypt ? $c - $y : $c + $y ) % $mod;
        my @digits = (0) x $m;
        foreach my $i ( reverse( 0 .. $m - 1 ) ) {
            $digits[$i] = $c % $radix;
            $c = ( $c - $digits[$i] ) / $radix;
        }

        if ($decrypt) {
            @right = @left;
            @left  = @digits;
        }
        else {
            @left  = @right;
            @right = @digits;
        }
    }
    return [ @left, @right ];
}

# The same rounds as _rounds_native(), with Math::BigInt.
sub _rounds_bigint {
    my ( $self, $digits, $decrypt ) = @_;
    my ( $radix, $u, $v, $mod_u, $mod_v, $width ) = @{$self}{qw{radix u v mod_u mod_v bytes}};

    my @left  = @{$digits}[ 0 .. $u - 1 ];
    my @right = @{$digits}[ $u .. $#{$digits} ];
    foreach my $step ( 0 .. $ROUNDS - 1 ) {
        my $round = $decrypt ? $ROUNDS - 1 - $step : $step;
        my ( $m, $mod ) = $round % 2 ? ( $v, $mod_v ) : ( $u, $mod_u );

        my $hex       = substr( _digits_to_big( $decrypt ? \@left : \@right, $radix )->as_hex(), 2 );
        my $num_bytes = pack( 'H*', ( '0' x ( 2 * $width - length($hex) ) ) . $hex );
        my $y         = Math::BigInt->from_hex( unpack( 'H*', $self->_round_output( $round, $num_bytes ) ) );

        # bmod gives a result of 0 or more for a positive modulus.
        my $c = _digits_to_big( $decrypt ? \@right : \@left, $radix );
        $c = ( $decrypt ? $c->bsub($y) : $c->badd($y) )->bmod($mod);
        my @digits = @{ _big_to_digits( $c, $radix, $m ) };

        if ($decrypt) {
            @right = @left;
            @left  = @digits;
        }
        else {
            @left  = @right;
            @right = @digits;
        }
    }
    return [ @left, @right ];
}

# S in the standard, steps 6.i to 6.iv: the first d bytes of the AES output for one round.
sub _round_output {
    my ( $self, $round, $num_bytes ) = @_;
    my $aes = $self->{aes};

    my $msg = $self->{tweak_pad} . pack( 'C', $round ) . $num_bytes;
    my $r   = $self->{head_mac};
    foreach my $block ( 0 .. length($msg) / $BLOCK - 1 ) {
        $r = $aes->encrypt( $r ^ substr( $msg, $block * $BLOCK, $BLOCK ) );
    }

    my $s = $r;
    my $j = 0;
    while ( length($s) < $self->{out_bytes} ) {
        $j++;
        $s .= $aes->encrypt( $r ^ pack( 'x12N', $j ) );
    }
    return substr( $s, 0, $self->{out_bytes} );
}

# The rest of this file converts between digits and numbers, with perl integers and with Math::BigInt.
# The perl integer subs are only called with numbers below 2**53.

sub _digits_to_int {
    my ( $digits, $radix ) = @_;
    my $x = 0;
    $x = $x * $radix + $_ for @{$digits};
    return $x;
}

sub _int_to_digits {
    my ( $x, $radix, $m ) = @_;
    my @digits = (0) x $m;
    foreach my $i ( reverse( 0 .. $m - 1 ) ) {
        $digits[$i] = $x % $radix;
        $x = ( $x - $digits[$i] ) / $radix;
    }
    return \@digits;
}

sub _digits_to_big {
    my ( $digits, $radix ) = @_;
    my $x = Math::BigInt->bzero();
    foreach my $digit ( @{$digits} ) {
        $x->bmul($radix)->badd($digit);
    }
    return $x;
}

sub _big_to_digits {
    my ( $x, $radix, $m ) = @_;
    my @digits = (0) x $m;
    my $rest   = $x->copy();
    foreach my $i ( reverse( 0 .. $m - 1 ) ) {
        my ( $quotient, $remainder ) = $rest->bdiv($radix);
        $digits[$i] = $remainder->numify();
        $rest = $quotient;
    }
    return \@digits;
}

1;
