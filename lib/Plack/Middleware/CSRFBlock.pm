package Plack::Middleware::CSRFBlock;
use parent qw(Plack::Middleware);
use strict;
use warnings;
our $VERSION = '0.05';

use HTML::Parser;
use Plack::TempBuffer;
use Plack::Util;
use Digest::SHA1;
use Plack::Util::Accessor qw(
    parameter_name token_length session_key blocked onetime
    _param_re _token_generator
);

sub prepare_app {
    my $self = shift;

    $self->parameter_name('SEC') unless defined $self->parameter_name;
    $self->token_length(16) unless defined $self->token_length;
    $self->session_key('csrfblock.token') unless defined $self->session_key;

    my $parameter_name = $self->parameter_name;
    my $token_length = $self->token_length;

    $self->_param_re({
        'application/x-www-form-urlencoded' => qr/
            (?:^|&)
            $parameter_name=([0-9a-f]{$token_length})
            (?:&|$)
        /x,
        'multipart/form-data' => qr/
            ; ?name="?$parameter_name"?(?:;[^\x0d]*)?\x0d\x0a
            (?:[^\x0d]+\x0d\x0a)*
            \x0d\x0a
            ([0-9a-f]{$token_length})\x0d\x0a
        /x,
    });

    $self->_token_generator(sub {
        my $token = Digest::SHA1::sha1_hex(rand() . $$ . {} . time);
        substr($token, 0 , $token_length);
    });
}

sub call {
    my($self, $env) = @_;

    my $session = $env->{'psgix.session'};
    if(not $session) {
        die "CSRFBlock needs Session.";
    }

    # input filter
    if(
        $env->{REQUEST_METHOD} =~ m{^post$}i and
        ($env->{CONTENT_TYPE} =~ m{^(application/x-www-form-urlencoded)}i or
         $env->{CONTENT_TYPE} =~ m{^(multipart/form-data)}i)
    ) {
        my $ct = $1;
        my $token = $session->{$self->session_key}
            or return $self->token_not_found($env);

        my $cl = $env->{CONTENT_LENGTH};
        my $re = $self->_param_re->{$ct};
        my $input = $env->{'psgi.input'};
        my $buffer;

        if ($env->{'psgix.input.buffered'}) {
            $input->seek(0, 0);
        } else {
            $buffer = Plack::TempBuffer->new($cl);
        }

        my $buf = '';
        my $done;
        my $found;
        my $spin = 0;
        while ($cl) {
            $input->read(my $chunk, $cl < 8192 ? $cl : 8192);
            my $read = length $chunk;
            $cl -= $read;
            if($done) {
                $buffer->print($chunk) if $buffer;
            }
            else {
                $buf .= $chunk;
                if(length $buf >= 8192 or $cl == 0) {
                    if($buf =~ $re and $1 eq $token) {
                        $found = 1;
                        last if not $buffer;
                    }
                    $buffer->print($buf) if $buffer;
                    undef $buf;
                    $done = 1;
                }
            }

            if ($read == 0 && $spin++ > 2000) {
                die "Bad Content-Length: maybe client disconnect? ($cl bytes remaining)";
            }
        }

        if($found) {
            # clear token if onetime option is enabled.
            delete $session->{$self->session_key} if $self->onetime;
        }
        else {
            return $self->token_not_found($env);
        }

        if($buffer) {
            $env->{'psgi.input'} = $buffer->rewind;
            $env->{'psgix.input.buffered'} = Plack::Util::TRUE;
        }
        else {
            $input->seek(0,0);
        }
    }


    return $self->response_cb($self->app->($env), sub {
        my $res = shift;
        my $ct = Plack::Util::header_get($res->[1], 'Content-Type');
        if($ct !~ m{^text/html}i and $ct !~ m{^application/xhtml[+]xml}i){
            return $res;
        }

        my @out;
        my $http_host = exists $env->{HTTP_HOST} ? $env->{HTTP_HOST} : $env->{SERVER_NAME};
        my $token = $session->{$self->session_key} ||= $self->_token_generator->();
        my $parameter_name = $self->parameter_name;

        my $p = HTML::Parser->new(
            api_version => 3,
            start_h => [sub {
                my($tag, $attr, $text) = @_;
                push @out, $text;

                no warnings 'uninitialized';
                if(
                    lc($tag) ne 'form' or
                    lc($attr->{'method'}) ne 'post' or
                    ($attr->{'action'} =~ m{^https?://([^/:]+)[/:]} and $1 ne $http_host)
                ) {
                    return;
                }
                # TODO: determine xhtml or html?

                push @out, qq{<input type="hidden" name="$parameter_name" value="$token" />};

            }, "tagname, attr, text"],
            default_h => [\@out , '@{text}'],
        );
        my $done;

        return sub {
            return if $done;

            if(defined(my $chunk = shift)) {
                $p->parse($chunk);
            }
            else {
                $p->eof;
                $done++;
            }
            join '', splice @out;
        }
    });
}

sub token_not_found {
    my $self = shift;
    if(my $app_for_blocked = $self->blocked) {
        return $app_for_blocked->(@_);
    }
    else {
        my $body = 'CSRF detected';
        return [
            403,
            [ 'Content-Type' => 'text/plain', 'Content-Length' => length($body) ],
            [ $body ]
        ];
    }
}

1;
__END__

=head1 NAME

Plack::Middleware::CSRFBlock - CSRF are never propageted to app

=head1 SYNOPSIS

  use Plack::Builder;

  my $app = sub { ... }

  builder {
    enable 'Session';
    enable 'CSRFBlock';
    $app;
  }

=head1 DESCRIPTION

This middleware blocks CSRF. You can use this middleware without any modifications
to your application, in most cases. Here is the strategy:

=over 4

=item output filter

When the application response content-type is "text/html" or
"application/xhtml+xml", this inserts hidden input tag that contains token
string into C<form>s in the response body. For example, the application
response body is:

  <html>
    <head><title>input form</title></head>
    <body>
      <form action="/receive" method="post">
        <input type="text" name="email" /><input type="submit" />
      </form>
  </html>

this becomes:

  <html>
    <head><title>input form</title></head>
    <body>
      <form action="/api" method="post"><input type="hidden" name="SEC" value="0f15ba869f1c0d77" />
        <input type="text" name="email" /><input type="submit" />
      </form>
  </html>

This affects C<form> tags with C<method="post">, case insensitive.

=item input check

For every POST requests, this module checks input parameters contain the
collect token parameter. If not found, throws 403 Forbidden by default.

Supports C<application/x-www-form-urlencoded> and C<multipart/form-data>.

=back

=head1 OPTIONS

  use Plack::Builder;
  
  my $app = sub { ... }
  
  builder {
    enable 'Session';
    enable 'CSRFBlock',
      parameter_name => 'csrf_secret',
      token_length => 20,
      session_key => 'csrf_token',
      blocked => sub {
        [302, [Location => 'http://www.google.com'], ['']];
      },
      onetime => 0,
      ;
    $app;
  }

=over 4

=item parameter_name (default:"SEC")

Name of the input tag for the token.

=item token_length (default:16);

Length of the token string. Max value is 40.

=item session_key (default:"csrfblock.token")

This middleware uses L<Plack::Middleware::Session> for token storage. this is
the session key for that.

=item blocked (default:403 response)

The application called when CSRF is detected.

Note: This application can read posted data, but DO NOT use them!

=item onetime (default:FALSE)

If this is true, this middleware uses B<onetime> token, that is, whenever
client sent collect token and this middleware detect that, token string is
regenerated.

This makes your applications more secure, but in many cases, is too strict.

=back

=head1 CAVEATS

This middleware doesn't work with pure Ajax POST request, because it cannot
insert the token parameter to the request. We suggest, for example, to use
jQuery Form Plugin like:

  <script type="text/javascript" src="jquery.js"></script>
  <script type="text/javascript" src="jquery.form.js"></script>

  <form action="/api" method="post" id="theform">
    ... blah ...
  </form>
  <script type="text/javascript>
    $('#theform').ajaxForm();
  </script>

so, the middleware can insert token C<input> tag next to C<form> start tag,
and the client can send it by Ajax form.

=head1 AUTHOR

Rintaro Ishizaki E<lt>rintaro@cpan.orgE<gt>

=head1 SEE ALSO

L<Plack::Middleware::Session>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
