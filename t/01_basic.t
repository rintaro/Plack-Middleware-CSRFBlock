use Test::More;

use strict;
use warnings;

use Plack::Test;
use HTTP::Request::Common;
use Plack::Builder;
use Plack::Session::State::Cookie;

my $form = <<FORM;
<html>
    <head><title>the form</title></head>
    <body>
        <form action="/post" method="post">
            <input type="text" />
            <input type="submit" />
        </form>
    </body>
</html>
FORM

my $base_app = sub {
    my $req = Plack::Request->new(shift);
    my $name = $req->param('name') or die 'name not found';
    return  [ 200, [ 'Content-Type' => 'text/plain' ], [ "Hello " . $name ] ]
};

my $mapped = builder {
    mount "/post" => $base_app;
    mount "/form/html" => sub { [ 200, [ 'Content-Type' => 'text/html' ], [ $form ] ] };
    mount "/form/xhtml" => sub { [ 200, [ 'Content-Type' => 'application/xhtml+xml' ], [ $form ] ] };
    mount "/form/text" => sub { [ 200, [ 'Content-Type' => 'text/plain' ], [ $form ] ] };
};

my $app = builder {
    enable 'Session', state => Plack::Session::State::Cookie->new(session_key => 'sid');
    enable 'CSRFBlock';
    $mapped;
};

test_psgi app => $app, client => sub {
    my $cb = shift;

    my $res = $cb->(POST "http://localhost/post", [name => 'Plack']);
    is $res->code, 403;

    my $h_cookie = $res->header('Set-Cookie');
    $h_cookie =~ /sid=([^; ]+)/;
    my $sid = $1;

    ok($sid);

    $res = $cb->(POST "http://localhost/post", [name => 'Plack'], Cookie => "sid=$sid");
    is $res->code, 403;
    $res = $cb->(POST "http://localhost/post", [SEC => '1234567890123456', name => 'Plack'], Cookie => "sid=$sid");
    is $res->code, 403;
    $res = $cb->(GET "http://localhost/form/html", Cookie => "sid=$sid");
    is $res->code, 200;
    ok $res->content =~ /<input type="hidden" name="SEC" value="([0-9a-f]{16})" \/>/;
    my $token = $1;
    $res = $cb->(POST "http://localhost/post", [SEC => $token, name => 'Plack'], Cookie => "sid=$sid");
    is $res->code, 200;
    $res = $cb->(POST "http://localhost/post", [SEC => $token, x => 'x' x 20000, name => 'Plack'], Cookie => "sid=$sid");
    is $res->code, 200;
    $res = $cb->(POST "http://localhost/post", [SEC => '1234567890123456', x => 'x' x 20000, name => 'Plack'], Cookie => "sid=$sid");
    is $res->code, 403;

    $res = $cb->(GET "http://localhost/form/xhtml", Cookie => "sid=$sid");
    like $res->content, qr/<input type="hidden" name="SEC" value="$token" \/>/;
    $res = $cb->(GET "http://localhost/form/text", Cookie => "sid=$sid");
    unlike $res->content, qr/<input type="hidden" name="SEC" value="$token" \/>/;
};

my $app2 = builder {
    enable 'Session', , state => Plack::Session::State::Cookie->new(session_key => 'sid');
    enable 'CSRFBlock',
        token_length => 8,
        parameter_name => 'TKN',
        onetime => 1,
        blocked => sub {
            [ 404,
                ['Content-Type' => 'text/plain'],
                [ 'csrf' ] 
            ]
        }
    ;
    $mapped;
};

test_psgi app => $app2, client => sub {
    my $cb = shift;

    my $res = $cb->(GET "http://localhost/form/xhtml");
    is $res->code, 200;

    my $h_cookie = $res->header('Set-Cookie');
    $h_cookie =~ /sid=([^; ]+)/;
    my $sid = $1;

    ok $res->content =~ /<input type="hidden" name="TKN" value="([0-9a-f]{8})" \/>/;
    my $token = $1;
    $res = $cb->(POST "http://localhost/post", [TKN => $token, name => 'Plack'], Cookie => "sid=$sid");
    is $res->code, 200;
    $res = $cb->(POST "http://localhost/post", [TKN => $token, name => 'Plack'], Cookie => "sid=$sid");
    is $res->code, 404;

    for(1..2) {
        $res = $cb->(GET "http://localhost/form/xhtml", Cookie => "sid=$sid");
        is $res->code, 200;
        ok $res->content =~ /<input type="hidden" name="TKN" value="([0-9a-f]{8})" \/>/;
        $token = $1;

        $res = $cb->(POST "http://localhost/post", [TKN => $token, name => 'Plack'], Cookie => "sid=$sid");
        is $res->code, 200;
    }

    $res = $cb->(POST "http://localhost/post", [TKN => $token, name => 'Plack'], Cookie => "sid=$sid");
    is $res->code, 404;
};

done_testing;
