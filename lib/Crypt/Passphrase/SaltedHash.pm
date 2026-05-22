package Crypt::Passphrase::SaltedHash;

$Crypt::Passphrase::SaltedHash::VERSION = '0.01';

use strict;
use warnings;

use parent 'Crypt::Passphrase::Validator';

use Digest       ();
use MIME::Base64 ();

my  %DIGESTS = (
    GOST    => [ 256, "GOST" ],
    HMACMD5 => [ 128, "HMAC-MD5" ],     # Note: Digest::HMAC does not work with Crypt::SaltedHash
    HMACSHA => [ 160, "HMAC-SHA-1" ],
    MD2     => [128],
    MD4     => [128],
    MD5     => [128],
    MD6     => [256],
    SHA     => [ 160, "SHA-1" ],
    SHA224  => [ 224, "SHA-224" ],
    SHA256  => [ 256, "SHA-256" ],
    SHA384  => [ 384, "SHA-384" ],
    SHA512  => [ 512, "SHA-512" ],
);

sub new {
    my $class = shift;
    return bless {}, $class;
}

sub accepts_hash {
    my ( $self,     $hash ) = @_;
    my ( $has_salt, $alg )  = $hash =~ /^\{(S)?(\w+)\}/ or return;
    return exists $DIGESTS{ uc $alg };
}

sub verify_password {
    my ( $self, $password, $hash ) = @_;

    my ( $has_salt, $alg ) = $hash =~ /^\{(S)?(\w+)\}/ or return;
    my $meta = $DIGESTS{ uc $alg } or return;

    my $name   = $meta->[1] // $alg;
    my $bytes  = $meta->[0] / 8;
    my $digest = Digest->new($name);
    my $bin    = MIME::Base64::decode_base64( substr( $hash, length($alg) + 2 + ( $has_salt ? 1 : 0 ) ) );
    my $salt   = $has_salt ? substr( $bin, $bytes ) : "";
    my $maybe  = $digest->add( $password . $salt )->digest;

    return $self->secure_compare( $maybe, substr( $bin, 0, $bytes ) );
}

1;
