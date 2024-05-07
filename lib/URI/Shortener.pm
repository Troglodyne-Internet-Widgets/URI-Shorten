package URI::Shortener;

#ABSTRACT: Shorten URIs so that you don't have to rely on external services

use strict;
use warnings;

use v5.012;

use Carp::Always;
use POSIX qw{floor};
use DBI;
use DBD::SQLite;
use List::Util qw{shuffle};
use File::Touch;

=head1 SYNOPSIS

    # Just run this and store it somewhere, hardcode it if you like
    my $secret = new_letter_ordering();
    ...
    # Actually shortening the URIs
    my $s = URI::Shortener->new(
        secret => $secret,
        prefix => 'https://go.mydomain.test/short',
        dbname => '/opt/myApp/uris.db',
        offset => 90210,
    );
    my $uri = 'https://mydomain.test/somePath';
    # Persistently memoizes via sqlite
    my $short = $s->shorten( $uri );
    # Short will look like 'https://go.mydomain.test/short/szAgqIE
    ...
    # Presumption here is that your request router knows what to do with this, e.g. issue a 302:
    my $long = $s->lengthen( $short );
    ...
    # Prune old URIs
    $s->prune_before(time());

=head1 DESCRIPTION

Provides utility methods so that you can:

1) Create a new short uri and store it for usage later
2) Persistently pull it up
3) Store a creation time so you can prune the database later.

We use sqlite for persistence.

=head2 ALGORITHM

The particular algorithm used to generate the ciphertext composing the shortened URI is simple.

Suppose $rowId is the database row corresponding to a given URI.

The text will be of this length:

floor($rowId / len($secret)) + 1;

It then adds a character from $secret at the position:

$rowId % len($secret)

And for each additional character, we then select the next character in $secret, modulus the length so that we wrap around if needed.

In short, it's a crude substitution cipher and one-time pad.

=head2 IMPORTANT

This can be improved to make corresponding DB IDs more difficult to guess by including an Identifier salt (the 'offset' parameter).
The difficulty of bruting for valid URIs scales with the size of the secret; a-zA-Z would be factorial(26+26)=8e67 possible permutations.

That said you shouldn't store particularly sensitive information in any URI, or attempt to use this as a means of access control.
It only takes one right guess to ruin someone's day.
You shouldn't use link shorteners for this at all, but many have done so and many will in the future.

I strongly recommend that you configure whatever serves these URIs be behind a fail2ban rule that bans 3 or more 4xx responses.

The secret used is not stored in the DB, so don't lose it.
You can't use a DB valid for any other secret and expect anything but GIGO.

Multiple different prefixes for the shortened URIs are OK though.
The more you use, the harder it is to guess valid URIs.
Sometimes, CNAMEs are good for something.

=head2 OTHER CONSEQUENCES

If you prune old DB records and your database engine will then reuse these IDs, be aware that this will result in some old short URIs resolving to new pages.

The ciphertext generated will be unique supposing that every character in $secret is as well.
The new_letter_ordering() subroutine is provided which can give you precisely that.
It's a random ordering of a..zA..z.
If you need more than those characters, use a different secret.

I would recommend passing List::Util::uniq(split(//, $secret)) to avoid issues with duplicated characters in $secret if you can't manually verify it.

=head2 UTF-8

I have not tested this module with UTF8 secrets.
My expectation is that it will not work at all with it, but this could be patched straighforwardly.

=cut

our $SCHEMA = qq{
CREATE TABLE IF NOT EXISTS uris (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix_id INTEGER NOT NULL REFERENCES prefix(id) ON DELETE CASCADE,
    uri TEXT NOT NULL UNIQUE,
    cipher TEXT DEFAULT NULL UNIQUE,
    created INTEGER
);

CREATE TABLE IF NOT EXISTS prefix (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix TEXT NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS uri_idx     ON uris(uri);
CREATE INDEX IF NOT EXISTS prefix_idx  ON prefix(prefix);
CREATE INDEX IF NOT EXISTS cipher_idx  ON uris(cipher);
CREATE INDEX IF NOT EXISTS created_idx ON uris(created);
};

=head1 CONSTRUCTOR

=head2 $class->new(%options)

See SYNOPSIS for supported optiosn.

We setting a default 'offset' of 0, and strip trailing slash(es) from the prefix.

The 'dbfile' you pass will be created automatically for you if possible.
Otherwise we will croak the first time you run shorten() or lengthen().

=cut

sub new {
    my ( $class, %options ) = @_;
    foreach my $required (qw{secret prefix dbname}) {
        die "$required required" unless $options{$required};
    }

    $options{offset} //= 0;

    # Strip trailing slash from prefix
    $options{prefix} =~ s|/+$||;
    return bless( \%options, $class );
}

=head1 METHODS

=head2 new_letter_ordering()

Static method.  Returns a shuffle of a-zA-Z.

This results in a secret which produces URIs which can be spoken aloud in NATO phonetic alphabet.
I presume this is the primary usefulness of URL shorteners aside from phishing scams.

=cut

# Use to generate $random_letter_ordering
sub new_letter_ordering {
    my @valid    = ( 'a' .. 'z', 'A' .. 'Z' );
    return join( '', shuffle(@valid) );
}

=head2 cipher( STRING $secret, INTEGER $id )

Expects a bytea[] style string (e.g. "Good old fashioned perl strings") as opposed to the char[] you get when the UTF8 flag is high.
Returns the string representation of the provided ID via the algorithm described above.

=cut

sub cipher {
    my ( $secret, $id ) = @_;

    my $len = length($secret);
    my $div = floor( $id / $len ) + 1;
    my $rem = $id % $len;

    my $ciphertext = '';
    my $cpos       = $rem;
    for ( 0 .. $div ) {
        $ciphertext .= substr( $secret, $cpos, 1 );
        $cpos++;
        $cpos = ( $cpos % $len );
    }

    return $ciphertext;
}

=head2 shorten($uri)

Transform original URI into a shortened one.

=cut

# Like with any substitution cipher, reversal is trivial when the secret is known.
# But, if we have to fetch the URI anyways, we may as well just store the cipher for reversal (aka the "god algorithm").
# This allows us the useful feature of being able to use many URI prefixes.
sub shorten {
    my ( $self, $uri ) = @_;

    my $query = "SELECT id, cipher FROM uris WHERE uri=?";

    my $rows = $self->_dbh()->selectall_arrayref( $query, { Slice => {} }, $uri );
    $rows //= [];
    if (@$rows) {
        return $rows->[0]{cipher} if $rows->[0]{cipher};
        my $ciphered = $self->cipher( $rows->[0]{id} );
        $self->_dbh()->do( "UPDATE uris SET cipher=? WHERE id=?", undef, $ciphered, $rows->[0]{id} ) or die $self->dbh()->errstr;
        return $self->{prefix} . "/" . $ciphered;
    }

    # Otherwise we need to store the URI and retrieve the ID.
    my $pis        = "SELECT id FROM prefix WHERE prefix=?";
    my $has_prefix = $self->_dbh->selectall_arrayref( $pis, { Slice => {} }, $self->{prefix} );
    unless (@$has_prefix) {
        $self->_dbh()->do( "INSERT INTO prefix (prefix) VALUES (?)", undef, $self->{prefix} ) or die $self->_dbh()->errstr;
    }

    my $qq = "INSERT INTO uris (uri,created,prefix_id) VALUES (?,?,(SELECT id FROM prefix WHERE prefix=?))";
    $self->_dbh()->do( $qq, undef, $uri, time(), $self->{prefix} ) or die $self->dbh()->errstr;
    goto \&shorten;
}

=head2 lengthen($uri)

Transform shortened URI into it's original.

=cut

sub lengthen {
    my ( $self, $uri ) = @_;
    my ($cipher) = $uri =~ m|^\Q$self->{prefix}\E/(.*)$|;

    my $query = "SELECT uri FROM uris WHERE cipher=? AND prefix_id IN (SELECT id FROM prefix WHERE prefix=?)";

    my $rows = $self->_dbh()->selectall_arrayref( $query, { Slice => {} }, $cipher, $self->{prefix} );
    $rows //= [];
    return unless @$rows;
    return $rows->[0]{uri};
}

=head2 prune_before(TIME_T $when)

Remove entries older than UNIX timestamp $when.

=cut

sub prune_before {
    my ( $self, $when ) = @_;
    $self->_dbh()->do( "DELETE FROM uris WHERE created < ?", undef, $when ) or die $self->dbh()->errstr;
    return 1;
}

my $dbh = {};

sub _dbh {
    my ($self) = @_;
    my $dbname = $self->{dbname};
    return $dbh->{$dbname} if exists $dbh->{$dbname};

    # Some systems splash down without this.  YMMV.
    File::Touch::touch($dbname) if $dbname ne ':memory:' && !-f $dbname;

    my $db = DBI->connect( "dbi:SQLite:dbname=$dbname", "", "" );
    $db->{sqlite_allow_multiple_statements} = 1;
    $db->do($SCHEMA) or die "Could not ensure database consistency: " . $db->errstr;
    $db->{sqlite_allow_multiple_statements} = 0;
    $dbh->{$dbname} = $db;

    # Turn on fkeys
    $db->do("PRAGMA foreign_keys = ON") or die "Could not enable foreign keys";

    # Turn on WALmode, performance
    $db->do("PRAGMA journal_mode = WAL") or die "Could not enable WAL mode";

    return $db;
}

1;
