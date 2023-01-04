#!/usr/bin/perl -w

# this package has been copied from here:
# https://forum.fhem.de/index.php/topic,119865.msg1222670.html#msg1222670
# https://forum.fhem.de/index.php?action=dlattach;topic=119865.0;attach=162308

package TapoP100;

use Crypt::CBC;
use Crypt::Cipher::AES;   # Debian/Ubuntu: libcryptx-perl
use Crypt::OpenSSL::RSA;
use Digest::SHA qw(sha1_hex);
use JSON;
use LWP;
use MIME::Base64;
use UUID;


sub new {
	my $proto=shift;
	my $class=ref($proto) || $proto;
	my($host)=@_;
	my $self={};

	$self->{HOST}=$host;
	$self->{URL}='http://'.$self->{HOST}.'/app';
	$self->{UUID}=UUID::uuid();
	$self->{RSAKEY}=Crypt::OpenSSL::RSA->generate_key(1024);
	$self->{RSAKEY}->use_pkcs1_padding();
	bless($self, $class);

	return $self;
}


# Make TP JSON command
sub jsoncmd {
	my($self, $cmd, %args)=@_;

	return encode_json({
		method => $cmd,
		requestTimeMils => time*1000,
		terminalUUID => $self->{UUID},
		params => \%args
	});
}


sub error_check {
	my($self, $errno)=@_;
	return if ($errno == 0);

	my %errmsg=(
		'1002' => 'Incorrect Request',
		'-1003' => 'JSON formatting error',
		'-1008' => 'JSON variable type error',
		'-1010' => 'Invalid Public Key Length',
		'-1012' => 'Invalid terminalUUID',
		'-1501' => 'Invalid Request or Credentials'
	);

	my $info=defined $errmsg{$errno} ? $errmsg{$errno} : 'Unknown error';
	print STDERR "ERROR $errno: $info\n";
	exit(-1);
}


# POST TP JSON string to device and get response
sub jsonpost {
	my($self, $json)=@_;

	my $ua=LWP::UserAgent->new();
	my $url=$self->{URL};
	$url.='?token='.$self->{TPTOKEN} if (defined $self->{TPTOKEN});
	my $request=HTTP::Request->new(POST => $url);
	$request->header('content-type' => 'application/json');
	$request->header('Cookie' => $self->{COOKIE}) if (defined $self->{COOKIE});

	$request->content($json);
	my $res=$ua->request($request);
	if (!$res->is_success) {
		print STDERR 'HTTP return code: '.$res->code."\n";
		print STDERR 'HTTP message: '.$res->message."\n";
		exit(-1);
	}

	if (!defined $self->{COOKIE}) {
		my $cookie=$res->header('Set-Cookie');
		if ($cookie=~/(TP_SESSIONID=\w+)/) {
			$self->{COOKIE}=$1;
		} else {
			print STDERR "UNKNOWN COOKIE HEADER: $cookie\n";
		}
	}

	my %ret=%{decode_json($res->decoded_content)};
	if ($ret{error_code} != 0) {
		$self->error_check($ret{error_code});
		return ();
	}

	return %ret;
}


# Make TP JSON command, encrypt, POST and decrypt response
sub post_encrypted {
	my($self, $cmd, %args)=@_;
	if (!defined $self->{TPKEY}) {
		print STDERR "NOT LOGGED IN\n";
		exit(-1);
	}

	my $json=$self->jsoncmd($cmd, %args);

	# openssl enc -nosalt -aes-128-cbc -K <key> -iv <iv>
	my $cipher=Crypt::CBC->new(-cipher => 'Cipher::AES', -keysize => 128/8,
		-header => 'none', -literal_key => 1,
		-key => $self->{TPKEY}, -iv => $self->{TPIV}
	);
	my $json_encrypted=$self->base64($cipher->encrypt($json));

	my %ret=$self->jsonpost(encode_json({method => 'securePassthrough',
		params => {request => $json_encrypted}
	}));
	return () if (!%ret);

	my $response_encrypted=decode_base64($ret{result}->{response});
	my $response=$cipher->decrypt($response_encrypted);
	%ret=%{decode_json($response)};
	$self->error_check($ret{error_code});

	return %ret;
}


sub base64 {
	my($self, $data)=@_;
	my $encoded=encode_base64($data);
	$encoded=~s/\n//g;
	return $encoded;
}


# Send RSA public key to device and get AES CBC key/init vector
sub handshake {
	my($self)=@_;

	my %ret=$self->jsonpost($self->jsoncmd('handshake', (
		key => $self->{RSAKEY}->get_public_key_x509_string()
	)));

	my $tpkey_crypted=decode_base64($ret{result}->{key});
	my $tpkey=$self->{RSAKEY}->decrypt($tpkey_crypted);
	$self->{TPKEY}=substr($tpkey, 0, 16);
	$self->{TPIV}=substr($tpkey, 16, 16);
}


# Login to device with username/password and get access token
sub login {
	my($self, $username, $password)=@_;
	my $username_encoded=$self->base64(sha1_hex($username));
	my $password_encoded=$self->base64($password);

	$self->handshake() if (!defined $self->{TPKEY});

	my %ret=$self->post_encrypted('login_device', (
		username => $username_encoded,
		password => $password_encoded
	));

	$self->{TPTOKEN}=$ret{result}->{token};
}


# Switch device on/off
sub switch {
	my($self, $on)=@_;

	$self->post_encrypted('set_device_info', (
		device_on => $on ? JSON::true : JSON::false
	));
}


# Get info hash from device
sub info {
	my($self)=@_;
	my %ret=$self->post_encrypted('get_device_info', ());
	return %ret;
}


# Get switch state of device
sub isOn {
	my($self)=@_;
	my %ret=$self->info();
	return ($ret{result}->{device_on} == JSON::true);
}


# Get nickname of device
sub name {
	my($self)=@_;
	my %ret=$self->info();
	return decode_base64($ret{result}->{nickname});
}


1;
