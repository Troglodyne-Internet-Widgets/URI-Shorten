use strict;
use warnings FATAL => 'all';

use 5.014;

use Test2::V1 -i;    ## no critic (ProhibitUnusedImports) -i imports every tool, which the policy cannot see
use Test2::Plugin::NoWarnings;
use FindBin::libs;
use File::Temp  qw{tempdir};
use POSIX       ();
use Time::HiRes qw{time};
use URI::Shortener::FF1;

# ACGT ** 10 is 1,048,576 strings, the smallest space of this alphabet that FF1 accepts.
my $RADIX   = 4;
my $LENGTH  = 10;
my $SPACE   = $RADIX**$LENGTH;
my $WORKERS = 4;

my $ff1 = URI::Shortener::FF1->new(
    alphabet => 'ACGT',
    length   => $LENGTH,
    key      => pack( 'H*', '2B7E151628AED2A6ABF7158809CF4F3C' ),
);

# Encrypts the ids from $first to $last, and sets one bit for each output in a string of $SPACE bits.
# Returns the bits, and the number of outputs that were already set.
sub _encrypt_range {
    my ( $first, $last )    = @_;
    my ( $bits,  $repeats ) = ( '', 0 );
    foreach my $id ( $first .. $last ) {
        my @digits = (0) x $LENGTH;
        my $rest   = $id;
        foreach my $i ( reverse( 0 .. $LENGTH - 1 ) ) {
            $digits[$i] = $rest % $RADIX;
            $rest = ( $rest - $digits[$i] ) / $RADIX;
        }
        my $out = 0;
        $out = $out * $RADIX + $_ for @{ $ff1->encrypt_digits( \@digits ) };
        $repeats++ if vec( $bits, $out, 1 );
        vec( $bits, $out, 1 ) = 1;
    }
    return ( $bits, $repeats );
}

subtest 'every id of a full space gives a different string' => sub {
    my $start = time();
    my $dir   = tempdir( CLEANUP => 1 );
    my $share = $SPACE / $WORKERS;

    # Each worker writes its bits to a file, and the parent puts them together.
    my %pids;
    foreach my $worker ( 0 .. $WORKERS - 1 ) {
        my $pid = fork() // die "fork failed: $!";
        if ( !$pid ) {
            my ( $bits, $repeats ) = _encrypt_range( $worker * $share, ( $worker + 1 ) * $share - 1 );
            open( my $fh, '>:raw', "$dir/$worker" ) or die "open $dir/$worker: $!";
            print {$fh} $bits                       or die "write $dir/$worker: $!";
            close($fh)                              or die "close $dir/$worker: $!";

            # _exit, so that the child does not run the END blocks of Test2, which belong to the parent.
            POSIX::_exit( $repeats ? 1 : 0 );
        }
        $pids{$pid} = $worker;
    }

    my @failed;
    foreach my $pid ( keys(%pids) ) {
        waitpid( $pid, 0 );
        push( @failed, $pids{$pid} ) if $?;
    }
    is( \@failed, [], "No worker got the same string two times in its share of the ids" );

    my $union = '';
    my $total = 0;
    foreach my $worker ( 0 .. $WORKERS - 1 ) {
        open( my $fh, '<:raw', "$dir/$worker" ) or die "open $dir/$worker: $!";
        my $bits = do { local $/ = undef; <$fh> };
        close($fh) or die "close $dir/$worker: $!";
        $total += unpack( '%32b*', $bits );
        $union |= $bits;
    }
    is( $total,                    $SPACE, "The workers together encrypted all $SPACE ids" );
    is( unpack( '%32b*', $union ), $SPACE, "The $SPACE ids gave $SPACE different strings, so FF1 is a bijection on this space" );
    note( sprintf( "The full space took %.1f seconds with %d workers", time() - $start, $WORKERS ) );
};

done_testing();

1;

__END__

=head1 DESCRIPTION

Encrypts every id of the space ACGT ** 10, which has 1,048,576 members, and checks that no two give the same string.
Four processes share the work, so that the test takes a few seconds.

=cut
