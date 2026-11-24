package URI::Shortener;

#ABSTRACT: Shorten URIs so that you don't have to rely on external services

use strict;
use warnings FATAL => 'all';
no autovivification;

use 5.014;

use Capture::Tiny qw{capture_merged};
use Carp::Always;
use DBI;
use File::Touch;
use Crypt::PRNG;
use Digest::SHA  qw{hmac_sha256};
use Scalar::Util qw{looks_like_number};
use Time::HiRes  qw{time};
use URI::Shortener::FF1;

=head1 SYNOPSIS

    # Actually shortening the URIs
    my $s = URI::Shortener->new(
        domain => 'ACGT',
        prefix => 'https://go.mydomain.test/short',
        dbname => '/opt/myApp/uris.db',
        seed   => 90210,
        length => 12,
    );
    my $uri = 'https://mydomain.test/somePath';
    # Persistently memoizes via sqlite
    my $short = $s->shorten( $uri );
    # Short will look like 'https://go.mydomain.test/short/GAATTACTAGTT'
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

We use sqlite for persistence by default with WALmode on, so it should be safe to use in a preforking multiple worker situation.

Alternatively, you can choose to use postgres or mysql.

=head2 WHY?

URI shorteners are typically used for media requiring fixed-width content, such as text email.
Email in particular benefits when you have intermediate servers that alter complex URIs in bodies to "protect" their users.
This tends to make DKIM signed messages fail for predictable reasons.

They are also useful for being easy to say in phonetic alphabets.

On the other hand, they're also an unavoidable mechanism to implement user tracking, such as is commonly done by social networking applications.
Similarly, they are the backbone of many phishing spam campaigns.

You could also use this to build a site (or make portions of it) resistant to indexing due to random URIs.
This is common practice for "unlisted" posts sent by mailing lists which want some degree of exclusivity without resorting fully to a paywall.

=head2 ALGORITHM

The short part of each URI is the "cipher".
cipher() makes it from the database row ID.
There are two algorithms.

=over 4

=item ff1 (the default)

FF1 is a format-preserving cipher from NIST Special Publication 800-38G.
cipher() writes the row ID as a number of C<length> digits in base C<length(domain)>.
Each character of the domain is one digit.
Then FF1 encrypts these digits with AES and an empty tweak.
The result is C<length> characters from the domain.

FF1 is a bijection: each row ID gives a different cipher, and decipher() gives the row ID back.
So two rows that use ff1 never get the same cipher.

The AES key is the first 16 bytes of HMAC-SHA256 of the seed and a fixed label, "URI::Shortener FF1 v1".
The seed is used as a string, so it can be any string.
Seeds that are near each other, such as 1337 and 1338, give keys that have no relation to each other.

The number of possible ciphers is C<length(domain) ** length>.
cipher() dies with "space exhausted" for a row ID that is that number or more.
Then you must use a new domain or length, or prune.

=item fortuna

This is the algorithm of version 1 and earlier.
Use C<< algorithm => 'fortuna' >> to keep it.
It seeds the Fortuna generator of Crypt::PRNG with the seed plus the row ID, and takes C<length> random characters from the domain.
Two row IDs can give the same cipher.
The seed must be a number.

=back

When a new cipher is the same as a cipher that is already in the database, shorten() burns the row and tries again with a new row.
"Burn" means that the row stays as a dead record.
The dead record keeps its ID, and its uri becomes the original URI followed by "-BURNED-" and the ID.
With fortuna, this can occur at any time, and it occurs more frequently as the database fills.
If you run out of possible URIs, each new try fails again and adds one more dead record to your disk.

One call to shorten() dies when it gets more than 64 collisions.
The count starts again at zero for each call.
This is also why a pruning method for old records has been provided.

=head2 UPGRADE FROM FORTUNA TO FF1

Version 2 changes the default algorithm from fortuna to ff1.
If you do not set C<algorithm>, an existing database gets ff1 ciphers for its new rows.
Use the same domain, length and seed as before.

shorten() calls cipher() only for a row that has no cipher yet.
Stored ciphers do not change, and lengthen() reads them from the database.
So the short URIs that you made before the upgrade continue to work.

A new ff1 cipher can be the same as an old fortuna cipher that is in the database.
Then shorten() burns that row and tries the next row ID, as described above.
The ff1 cipher of each row ID is different.
So each old cipher can block one row ID at most, one time, for the life of the database.
The number of burns after an upgrade is never more than the number of old rows.

To keep the old ciphers for new rows too, use C<< algorithm => 'fortuna' >>.

=head2 IMPORTANT

It must be stressed that choosing a sufficiently large domain and length is important.
Sane defaults are used, but if you choose something lesser, you will have to prune aggressively to prevent bad outcomes.
You are basically "locked in" to your choice of domain/length/seed once you put something based upon this into production.

The difficulty of bruting for valid URIs scales with the size of the domain and length.

You shouldn't store particularly sensitive information in any URI, or attempt to use this as a means of access control.
It only takes one right guess to ruin someone's day.

I strongly recommend that you configure whatever serves these URIs be behind a fail2ban rule that bans 3 or more 4xx responses.

The domain, length, seed and algorithm are not stored in the DB, so don't lose them.
You can't use a DB valid for any other domain/seed and expect anything but GIGO.

Multiple different prefixes for the shortened URIs are OK though.
The more you use, the harder it is to guess valid URIs.
Sometimes, CNAMEs are good for something.

=head2 OTHER CONSEQUENCES

If you prune old DB records and your database engine will then reuse these IDs, be aware that this will result in some old short URIs resolving to new pages.

=head2 UTF-8

I have not tested this module with a UTF8 domain.
My expectation is that it will not work at all with it, but this could be patched straighforwardly.

=head2 OTHER DATABASES

We support use of other databases than sqlite, should you so desire.
Set the dbhost, dbport, dbuser, dbpass and specify an appropriate dbtype (supported: sqlite, pg, mysql).

While we choose to use the largest possible autoincrementing primary key type,
be aware you will be fundamentally limited to the largest integer that can represent.
Mysql's BIGINT in particular is different than Postgres' BIGSERIAL and SQLite's INTEGER.

If the names of the tables/indexes collides with stuff already in your DB, you can pass parameters to the constructor to fix that.
Here are the defaults:

    uri_tablename    => 'uris',
    prefix_tablename => 'prefix',
    uri_idxname      => 'uri_idx',
    prefix_idxname   => 'prefix_idx',
    cipher_idxname   => 'cipher_idx',
    created_idxname  => 'created_idx',

Be aware that this is done via regexp replacement, so if you have too similar of names, bad things will occur.

=head2 GRANTS

On DBs that support grants, it is your responsibility to setup grants for the various users accessing these tables.
In general we make the assumption that the creator of the tables is the exclusive user of it, and this is generally a wise policy.
Specific functions on public DBs should have their own users to minimize the impact of any given login being compromised.
This module is designed to be self-contained and never really needs to be queried in any way other than normal operation.

=head2 MYSQL LIMITATIONS

Due to the nature of mysql's text handling, we don't make the 'uri' or 'prefix' fields in their respective tables unique.
Similarly, the cipher (domain) length is limited to 180 chars, as this is about as big as you can prudently use on utf8mb4.

We also are not creating any indices whatsoever.
Pull requests welcome.


=cut

# The version in this label is part of the key.  A new way to make the key needs a new label.
my $FF1_KEY_LABEL = 'URI::Shortener FF1 v1';

my $SCHEMA_NAMES = {
    uri_tablename    => 'uris',
    prefix_tablename => 'prefix',
    uri_idxname      => 'uri_idx',
    prefix_idxname   => 'prefix_idx',
    cipher_idxname   => 'cipher_idx',
    created_idxname  => 'created_idx',
};

our $SCHEMA_SQLITE = qq{
CREATE TABLE IF NOT EXISTS prefix_tablename (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS uri_tablename (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix_id INTEGER NOT NULL REFERENCES prefix_tablename(id) ON DELETE CASCADE,
    uri TEXT NOT NULL UNIQUE,
    cipher TEXT DEFAULT NULL UNIQUE,
    created INTEGER
);

CREATE INDEX IF NOT EXISTS uri_idxname     ON uri_tablename(uri);
CREATE INDEX IF NOT EXISTS prefix_idxname  ON prefix_tablename(prefix);
CREATE INDEX IF NOT EXISTS cipher_idxname  ON uri_tablename(cipher);
CREATE INDEX IF NOT EXISTS created_idxname ON uri_tablename(created);
};

our $SCHEMA_PG = qq{
CREATE TABLE IF NOT EXISTS prefix_tablename (
    id SERIAL PRIMARY KEY,
    prefix TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS uri_tablename (
    id BIGSERIAL PRIMARY KEY,
    prefix_id INTEGER NOT NULL REFERENCES prefix_tablename(id) ON DELETE CASCADE,
    uri TEXT NOT NULL UNIQUE,
    cipher TEXT DEFAULT NULL UNIQUE,
    created INTEGER
);

CREATE INDEX IF NOT EXISTS uri_idxname     ON uri_tablename(uri);
CREATE INDEX IF NOT EXISTS prefix_idxname  ON prefix_tablename(prefix);
CREATE INDEX IF NOT EXISTS cipher_idxname  ON uri_tablename(cipher);
CREATE INDEX IF NOT EXISTS created_idxname ON uri_tablename(created);
};

our $SCHEMA_MYSQL = qq{
CREATE TABLE IF NOT EXISTS prefix_tablename (
    id INTEGER AUTO_INCREMENT,
    prefix TEXT NOT NULL,
    PRIMARY KEY(id)
);

CREATE TABLE IF NOT EXISTS uri_tablename (
    id BIGINT AUTO_INCREMENT,
    prefix_id INTEGER NOT NULL REFERENCES prefix_tablename(id) ON DELETE CASCADE,
    uri TEXT NOT NULL,
    cipher VARCHAR(180) DEFAULT NULL UNIQUE,
    created INTEGER,
    PRIMARY KEY(id)
);

};

=head1 CONSTRUCTOR

=head2 $class->new(%options)

=over 4

=item C<dbname>

Name of the database to use.  Filename when using sqlite.

=item C<dbtype>

Type of database to use.  Supported: (sqlite, mysql, pg)

=item C<dbhost,dbport,dbuser,dbpass>

Means to connect to remote databases, such as is the case with mysql/pg

dbhost defaults to localhost, and dbport defaults to the relevant default port.
Otherwise the relevant ENV vars are obeyed when no options are passed.

See _my_dbh() and _pg_dbh() for the particulars.

Also, mysql will obey the mysql_read_default_file/group parameters, and defaults to using ~/.my.cnf and the 'client' group.

=item C<prefix>

URI prefix of shortened output.  Trailing slashes will be stripped.  Example: https://big.hugs/go/

=item C<length>

Length of the minified path component. Defaulted to 12 when not a member of the natural numbers.

=item C<domain>

Input domain string. Shortened path components are a char within this string. By default a..zA..Z.

For ff1, no character can be in the domain two times, and the domain can have 65,536 characters at most.

=item C<seed>

The secret that makes the ciphers.
For ff1 it can be any string.
For fortuna it must be a number.

=item C<algorithm>

C<ff1> (the default) or C<fortuna>.
See L</ALGORITHM> and L</UPGRADE FROM FORTUNA TO FF1>.

=back

Each of the C<length> characters can be any character of the domain.
So the number of possible URIs is C<length(domain) ** length>.
With the default domain of 52 characters and length of 12, this is:

    52 ** 12 = 390,877,006,486,250,192,896

Which I should hope is more than enough for most use cases.

For ff1, new() dies when this number is less than 1,000,000, the minimum that NIST SP 800-38G sets.
For example, a domain of 4 characters needs a length of 10 or more.

new() also dies when C<algorithm> is not C<ff1> or C<fortuna>.

=cut

sub new {
    my ( $class, @args ) = @_;
    my %options = (
        %$SCHEMA_NAMES,
        @args,
    );
    $options{dbtype} //= 'sqlite';

    $options{domain} ||= join( '', ( 'a' .. 'z', 'A' .. 'Z' ) );

    foreach my $required (qw{domain prefix dbname seed}) {
        die "$required required" unless $options{$required};
    }
    $options{length} = 12 if !$options{length} || $options{length} < 0;

    $options{algorithm} //= 'ff1';
    if ( $options{algorithm} eq 'ff1' ) {
        $options{ff1} = URI::Shortener::FF1->new(
            alphabet => $options{domain},
            length   => $options{length},
            key      => substr( hmac_sha256( "$options{seed}", $FF1_KEY_LABEL ), 0, 16 ),
        );
    }
    elsif ( $options{algorithm} eq 'fortuna' ) {
        die "The fortuna algorithm needs a numeric seed\n" unless looks_like_number( $options{seed} );
    }
    else {
        die "algorithm must be 'ff1' or 'fortuna'\n";
    }

    # Strip trailing slash from prefix
    $options{prefix} =~ s{/+\z}{}sxaa;

    $options{sqlite_schema} = $SCHEMA_SQLITE;
    $options{mysql_schema}  = $SCHEMA_MYSQL;
    $options{pg_schema}     = $SCHEMA_PG;

    # Mongle the schema appropriately
    foreach my $sql_obj ( keys(%$SCHEMA_NAMES) ) {

        # These names are put into SQL text, as a placeholder cannot stand for an identifier.
        die "$sql_obj must be a plain SQL identifier" unless $options{$sql_obj} =~ m{\A[[:alpha:]_][[:alnum:]_]*\z}sxaa;
        $options{sqlite_schema}                                                 =~ s/\Q$sql_obj\E/$options{$sql_obj}/gmsxaa;
        $options{mysql_schema}                                                  =~ s/\Q$sql_obj\E/$options{$sql_obj}/gmsxaa;
        $options{pg_schema}                                                     =~ s/\Q$sql_obj\E/$options{$sql_obj}/gmsxaa;
    }

    $options{dbh} = {};

    return bless( \%options, $class );
}

=head1 METHODS

=head2 cipher( INTEGER $id )

Returns the cipher of the row ID $id: a string of C<length> characters from the domain.
See L</ALGORITHM>.

For ff1, dies with "space exhausted" when $id is C<length(domain) ** length> or more.

=cut

sub cipher {
    my ( $self, $id ) = @_;
    return $self->{ff1}->encrypt($id) if $self->{ff1};
    my $rr = Crypt::PRNG->new( 'Fortuna', $self->{seed} + $id );
    return $rr->string_from( @{$self}{qw{domain length}} );
}

=head2 decipher( STRING $cipher )

The reverse of cipher() for the ff1 algorithm.
Returns the row ID that gives $cipher.
Returns undef when $cipher has the wrong length, or has a character that is not in the domain.

decipher() does not read the database.
So it returns an ID for each string of the right form, also when no row has that ID.

Dies for the fortuna algorithm, because fortuna has no reverse.

=cut

sub decipher {
    my ( $self, $cipher ) = @_;
    die "decipher() needs the ff1 algorithm\n" unless $self->{ff1};
    return $self->{ff1}->decrypt($cipher);
}

=head2 shorten( STRING $uri)

Transform original URI into a shortened one.

=cut

# The table names that are put into the SQL below are checked by new() to be plain identifiers.
# A placeholder cannot stand for an identifier, and every value goes through a placeholder.
## no critic (ValuesAndExpressions::PreventSQLInjection)
sub shorten {
    my ( $self, $uri ) = @_;

    my $query      = "SELECT id, cipher FROM $self->{uri_tablename} WHERE uri=?";
    my $collisions = 0;

    # Each pass returns, stores the URI for the next pass to find, or burns a row whose cipher collided.
    while (1) {
        my $rows = $self->_dbh()->selectall_arrayref( $query, { Slice => {} }, $uri );
        $rows //= [];
        if ( !@$rows ) {
            $self->_insert_uri($uri);
            next;
        }

        my ($row) = @{$rows};
        return $self->{prefix} . "/" . $row->{cipher} if $row->{cipher};
        my $ciphered = $self->cipher( $row->{id} );
        my $worked   = $self->_dbh()->do( "UPDATE $self->{uri_tablename} SET cipher=? WHERE id=?", undef, $ciphered, $row->{id} );
        return $self->{prefix} . "/" . $ciphered if $worked;

        # The row ID is unique, so the new uri of the dead record is unique too.
        warn "DANGER: cipher collision detected.";
        $self->_dbh()->do( "UPDATE $self->{uri_tablename} SET uri=? WHERE id=?", undef, "$uri-BURNED-$row->{id}", $row->{id} ) or die "Could not burn row";
        $collisions++;
        die "Too many failures to avoid name collisions encountered, prune your DB!" if $collisions > 64;
    }
    return;
}

sub _insert_uri {
    my ( $self, $uri ) = @_;

    my $pis        = "SELECT id FROM $self->{prefix_tablename} WHERE prefix=?";
    my $has_prefix = $self->_dbh->selectall_arrayref( $pis, { Slice => {} }, $self->{prefix} );
    unless (@$has_prefix) {
        $self->_dbh()->do( "INSERT INTO $self->{prefix_tablename} (prefix) VALUES (?)", undef, $self->{prefix} ) or die $self->_dbh()->errstr;
    }

    my $qq = "INSERT INTO $self->{uri_tablename} (uri,created,prefix_id) VALUES (?,?,(SELECT id FROM $self->{prefix_tablename} WHERE prefix=?))";
    $self->_dbh()->do( $qq, undef, $uri, int( time() ), $self->{prefix} ) or die $self->_dbh()->errstr;
    return 1;
}

=head2 lengthen( STRING $uri)

Transform shortened URI into it's original.

=cut

sub lengthen {
    my ( $self, $uri ) = @_;
    my ($cipher) = $uri =~ m{\A\Q$self->{prefix}\E/(.*)\z}msxaa;

    my $query = "SELECT uri FROM $self->{uri_tablename} WHERE cipher=? AND prefix_id IN (SELECT id FROM $self->{prefix_tablename} WHERE prefix=?)";

    my $rows = $self->_dbh()->selectall_arrayref( $query, { Slice => {} }, $cipher, $self->{prefix} );
    $rows //= [];
    return unless @$rows;
    my ($row) = @{$rows};
    return $row->{uri};
}

=head2 prune_before(TIME_T $when)

Remove entries older than UNIX timestamp $when.

=cut

sub prune_before {
    my ( $self, $when ) = @_;
    $self->_dbh()->do( "DELETE FROM $self->{uri_tablename} WHERE created < ?", undef, $when ) or die $self->_dbh()->errstr;
    return 1;
}
## use critic

my %db_dispatch = (
    sqlite => \&_sqlite_dbh,
    pg     => \&_pg_dbh,
    mysql  => \&_my_dbh,
);

sub _dbh {
    my ($self) = @_;
    return $db_dispatch{ $self->{dbtype} }->($self);
}

sub _sqlite_dbh {
    my ($self) = @_;
    my $dbname = $self->{dbname};
    return $self->{dbh}->{$dbname} if exists $self->{dbh}->{$dbname};

    # Some systems splash down without this.  YMMV.
    File::Touch::touch($dbname) if $dbname ne ':memory:' && !-e $dbname;

    my $db = DBI->connect( "dbi:SQLite:dbname=$dbname", "", "" );
    $db->{sqlite_allow_multiple_statements} = 1;
    $db->do( $self->{sqlite_schema} ) or die "Could not ensure database consistency: " . $db->errstr;
    $db->{sqlite_allow_multiple_statements} = 0;
    $self->{dbh}->{$dbname} = $db;

    # Turn on fkeys
    $db->do("PRAGMA foreign_keys = ON") or die "Could not enable foreign keys";

    # Turn on WALmode, performance
    $db->do("PRAGMA journal_mode = WAL") or die "Could not enable WAL mode";

    return $db;
}

sub _pg_dbh {
    my ($self) = @_;
    my $dbname = $self->{dbname};
    return $self->{dbh}->{$dbname} if exists $self->{dbh}->{$dbname};

    my $host = $self->{dbhost} // $ENV{PGHOST} || 'localhost';
    my $port = $self->{dbport} // $ENV{PGPORT} || 5432;
    my $user = $self->{dbuser} // $ENV{PGUSER};
    my $pass = $self->{dbpass} // $ENV{PGPASSWORD};

    my $db = DBI->connect( "dbi:Pg:dbname=$dbname;host=$host;port=$port", $user, $pass );

    #XXX pg is noisy even when you say 'IF NOT EXISTS'
    my $result;
    capture_merged { $result = $db->do( $self->{pg_schema} ) };
    die "Could not ensure database consistency: " . $db->errstr unless $result;

    $self->{dbh}->{$dbname} = $db;
    return $db;
}

sub _my_dbh {
    my ($self) = @_;
    my $dbname = $self->{dbname};
    return $self->{dbh}->{$dbname} if exists $self->{dbh}->{$dbname};

    my $host = $self->{dbhost} // $ENV{MYSQL_HOST}     || 'localhost';
    my $port = $self->{dbport} // $ENV{MYSQL_TCP_PORT} || 3306;
    my $user = $self->{dbuser} // $ENV{DBI_USER};
    my $pass = $self->{dbpass} // $ENV{MYSQL_PWD};

    # Handle the mysql defaults file
    my $defaults_file  = $self->{mysql_read_default_file}  // "$ENV{HOME}/.my.cnf";
    my $defaults_group = $self->{mysql_read_default_group} // 'client';
    my $df             = "";
    $df .= "mysql_read_default_file=$defaults_file;"   if -e $defaults_file;
    $df .= "mysql_read_default_group=$defaults_group;" if $defaults_group;

    my $dsn = "dbi:mysql:mysql_multi_statements=1;database=$dbname;" . $df . "host=$host;port=$port";

    my $db = DBI->connect( $dsn, $user, $pass );
    $db->do( $self->{mysql_schema} ) or die "Could not ensure database consistency: " . $db->errstr;

    $self->{dbh}->{$dbname} = $db;
    return $db;
}

=head2 migrate(URI::Shortener $to)

Migrate data in one shortener to another.

Useful when going from sqlite to pg, etc.

Only supports importing into an empty DB.
To support this would require re-ID/indexing everything which is nontrivial work, but doable.

=cut

# Table names are checked by new() to be plain identifiers, see shorten().
## no critic (ValuesAndExpressions::PreventSQLInjection)
sub migrate {
    my ( $self, $new ) = @_;
    my $from_dbh = $self->_dbh();
    my $to_dbh   = $new->_dbh();

    my $prefixes = $from_dbh->selectall_arrayref(qq|SELECT * FROM $self->{prefix_tablename}|);
    _batch_insert( $to_dbh, $new->{prefix_tablename}, @$prefixes ) if @$prefixes;

    my $uris = $from_dbh->selectall_arrayref(qq|SELECT * FROM $self->{uri_tablename}|);
    _batch_insert( $to_dbh, $new->{uri_tablename}, @$uris ) if @$uris;
    return 1;
}

# Gotta batch stuff cuz sqlite has a 10k param limit
sub _batch_insert {
    my ( $dbh, $tbl, @data ) = @_;
    my $ncols = @{ $data[0] };
    die "No columns in table $tbl" unless $ncols;

    while ( my @batch = splice( @data, 0, int( 10_000 / $ncols ) ) ) {
        my $param = join( ',', map { '?' } @{ $batch[0] } );
        my $bind  = join( ',', map { "($param)" } @batch );

        my $query = "INSERT INTO $tbl VALUES $bind";

        print "Migrating " . scalar(@batch) . " rows (" . scalar(@data) . " left) to $tbl...";
        $dbh->do( $query, undef, map { @$_ } @batch );
        print "Done.\n";
    }
    return 1;
}
## use critic

1;
