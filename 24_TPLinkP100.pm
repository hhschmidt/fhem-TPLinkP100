################################################################
#  Copyright notice
#
#  (c) 2023 Copyright: Henning Schmidt
#  e-mail: fhem at hhschmidt dot de
#
#  Description:
#  This is an FHEM-Module for the TP Link TPLinkP100/110 
#  wifi controlled power outlet.
#  It support switching on and of the outlet 
#
#  Requirements
#  	Perl Module: IO::Socket::Timeout
#  	Perl Module: IO::Socket::INET
#  	Perl Module: Crypt::CBC
#  	Perl Module: Crypt:OpenSSL::RSA
#                installing this module may require system package 'libssl-dev'
#  	Perl Module: UUID
#                installing this module may require system package 'uuid-dev'
#  	
#  Origin: #  https://github.com/hhschmidt/fhem-TPLinkP100
#
################################################################


# package Tapo100
########################################################################
{
	# this package has been copied from here:
	# https://forum.fhem.de/index.php/topic,119865.msg1222670.html#msg1222670
	# https://forum.fhem.de/index.php?action=dlattach;topic=119865.0;attach=162308
	# credit goes to Peter "erdferkel" (https://forum.fhem.de/index.php?action=profile;u=51277)
	package TapoP100;
	
	use Digest::SHA qw(sha1_hex);
	use Crypt::CBC;
	use Crypt::Cipher::AES;   # Debian/Ubuntu: libcryptx-perl
	use Crypt::OpenSSL::RSA;
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
		print STDERR "TapoP100: ERROR $errno: $info\n";
		return ();
	}
	
	
	# POST TP JSON string to device and get response
	sub jsonpost {
		my($self, $json)=@_;
	
		my $ua=LWP::UserAgent->new(timeout => 10);
		my $url=$self->{URL};
		$url.='?token='.$self->{TPTOKEN} if (defined $self->{TPTOKEN});
		my $request=HTTP::Request->new(POST => $url);
		$request->header('content-type' => 'application/json');
		$request->header('Cookie' => $self->{COOKIE}) if (defined $self->{COOKIE});
	
		$request->content($json);
		my $res=$ua->request($request);
		if (!$res->is_success) {
			# print STDERR 'TapoP100: HTTP return code: '.$res->code."\n";
			print STDERR 'TapoP100: HTTP message: '.$res->message."\n";
			return ();
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
		return () if (!%ret);
	
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
	
		return () if ((!defined $self->{TPKEY}) && !$self->handshake());
	
		my %ret=$self->post_encrypted('login_device', (
			username => $username_encoded,
			password => $password_encoded
		));
		return () if (!%ret);
	
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
		return (-1) if (!%ret);
		return ($ret{result}->{device_on} == JSON::true);
	}
	
	
	# Get nickname of device
	sub name {
		my($self)=@_;
		my %ret=$self->info();
		return () if (!%ret);
		return decode_base64($ret{result}->{nickname});
	}
	
}

#######################################################################
package main;

use strict;
use warnings;
use SetExtensions;

sub TPLinkP100_Initialize($) {
	my ($hash) = @_;

	$hash->{DefFn}    = "TPLinkP100_Define";
	$hash->{UndefFn}  = "TPLinkP100_Undefine";
	$hash->{GetFn}    = "TPLinkP100_Get";
	$hash->{SetFn}    = "TPLinkP100_Set";
}

sub TPLinkP100_Define($$) {
    my ($hash, $def) = @_;
    
	my @a = split("[ \t][ \t]*", $def);
	return "Wrong syntax: use define <name> TPLinkP100 <hostname/ip> [username [passwd [intervall]]]" if (int(@a) < 3);
	
	my $name     = $a[0];
	my $module   = $a[1];
	my $url      = $a[2];
	my $username = "unknown\@gmail.com";
	my $passwd   = "secret";
	my $inter    = 300;

	if (int(@a) > 3) {
		$username = $a[3];
		
		if (int(@a) > 4) {
			$passwd = $a[4];
			
			if (int(@a) > 5) {
				$inter = $a[5]; 
				if ($inter < 5) {
					Log3 $hash, 1, "TPLinkP100: interval defined too small (".$inter."). Resetting to default : 300";
					$inter = 300;
				}
			}
		}
	}
	
	
	# Debug ("TPLinkP100_Define: $name $url $username $passwd $inter");
	
	$hash->{url} 		= $url;
	$hash->{username} 	= $username;
	$hash->{passwd} 	= $passwd;
	$hash->{Interval}	= $inter;
	$hash->{P100}       = undef;
	$hash->{STATE}      = "disconnected";
	
	TPLinkP100_GetUpdate ($hash);
    return undef;
}

sub TPLinkP100_Undefine($$) {
    my ($hash, $arg) = @_; 
	
    # delete instance
	my $p100 = $hash->{P100};
	undef $p100;
	$hash->{P100} = undef;

    return undef;
}

sub TPLinkP100_Get($$@) {
	my ($hash, $name, $opt, @args) = @_;
	return undef if IsDisabled ($hash);	
	return "get needs at least one argument" unless(defined($opt));
	
	if($opt eq "status") {
		return ReadingsVal ($hash->{NAME}, "status", "off");;
	} 
	return "unknown argument $opt choose one of status";
}

sub TPLinkP100_Set($$@) {
	my ($hash, $name, $cmd, @args) = @_;
	return undef if IsDisabled ($hash);
	return "\"set $name\" needs at least one argument" unless(defined($cmd));

	my $cmdList = "on off status";
	my $setOnOff = -1;
	if($cmd eq "on") {
		$setOnOff = 1;
	} elsif ($cmd eq "off") {
		$setOnOff = 0;
	} elsif ($cmd eq "status") {
		if($args[0] eq "on") {
			$setOnOff = 1;
		} elsif ($args[0] eq "off") {
			$setOnOff = 0;
		} else {
			return "Unknown value $args[0] for $cmd, choose one of on off";
		}
	}
	if ($setOnOff != -1) {
		# Debug ("TPLinkP100: setOnOff $setOnOff ");
		my $p100 = $hash->{P100};
		return "TPLinkP100_Set() invalid device ref" if !$p100;
		if (!$p100->switch($setOnOff)) {
			TPLinkP100_Disconnect ($hash);
		}
		return undef;
	}
	
	if($cmd eq "?")
	{
		return "unknown argument $cmd choose one of status:on,off ";
	}
	
	# wenn der übergebene Befehl nicht durch X_Set() verarbeitet werden kann, Weitergabe an SetExtensions()
	return SetExtensions($hash, $cmdList, $name, $cmd, @args);
}

sub TPLinkP100_GetUpdate ($) {
	my ($hash) = @_;
	
	# repeated polling of data from device
	InternalTimer(gettimeofday()+$hash->{Interval}, "TPLinkP100_GetUpdate", $hash);
	
	return if IsDisabled ($hash);
	return if (($hash->{STATE} eq "disconnected") && !TPLinkP100_Connect ($hash));
	
	my $p100 = $hash->{P100};
	return "TPLinkP100_GetUpdate() invalid device ref" if !$p100;
	my $oldStatus = ReadingsVal ($hash->{NAME}, "status", "off");
	
	# Debug ("TPLinkP100_GetUpdate() : starting communication to device ...");
	my $ret = $p100->isOn();
	# Debug ("TPLinkP100_GetUpdate() : ... call returned");
	if (-1 == $ret) {
		# Debug ("TPLinkP100_getUpdate() ... isOn() failed");
		TPLinkP100_Disconnect ($hash);
		return ();
	}
	my $newStatus = $p100->isOn() ? "on" : "off";
	if ($oldStatus ne $newStatus) {
		my $ret = readingsSingleUpdate ($hash, "status", $newStatus, 1);
		# Debug ("TPLinkP100_GetUpdate() : readingsSingleUpdate( $oldStatus $newStatus -> $ret )");
	}
}

sub TPLinkP100_Connect ($) {
	my ($hash) = @_;
	if ($hash->{P100}) { undef $hash->{P100}; }
	return 0 if IsDisabled ($hash); 
	
	my $p100 = TapoP100->new($hash->{url});
	
	# this is a blocking call, can get stuck completely when device not available -> TODO change to async
	if (! $p100->login($hash->{username}, $hash->{passwd})) {
		# Debug ("TPLinkP100_connect() ... login() failed");
		return 0;
	}
	$hash->{P100} = $p100;
	$hash->{STATE} = "active";
	# Debug ("TPLinkP100_connect() ... OK");
	return 1;
}

sub TPLinkP100_Disconnect ($) {
	my ($hash) = @_;
	undef $hash->{P100} if ($hash->{P100});

	$hash->{STATE} = "disconnected";
	$hash->{P100} = undef;
	# Debug ("TPLinkP100_disconnect() ... done");
	return 1;
}


1;

=pod
=begin html

<a id="Hello"></a>
<h3>Hello</h3>
<ul>
    <i>Hello</i> implements the classical "Hello World" as a starting point for module development. 
    You may want to copy 98_Hello.pm to start implementing a module of your very own. See 
    <a href="http://wiki.fhem.de/wiki/DevelopmentModuleIntro">DevelopmentModuleIntro</a> for an 
    in-depth instruction to your first module.
    <br><br>
    <a id="Hello-define"></a>
    <b>Define</b>
    <ul>
        <code>define &lt;name&gt; Hello &lt;greet&gt;</code>
        <br><br>
        Example: <code>define HELLO Hello TurnUrRadioOn</code>
        <br><br>
        The "greet" parameter has no further meaning, it just demonstrates
        how to set a so called "Internal" value. See <a href="http://fhem.de/commandref.html#define">commandref#define</a> 
        for more info about the define command.
    </ul>
    <br>
    
    <a id="Hello-set"></a>
    <b>Set</b><br>
    <ul>
        <code>set &lt;name&gt; &lt;option&gt; &lt;value&gt;</code>
        <br><br>
        You can <i>set</i> any value to any of the following options. They're just there to 
        <i>get</i> them. See <a href="http://fhem.de/commandref.html#set">commandref#set</a> 
        for more info about the set command.
        <br><br>
        Options:
        <ul>
              <li><i>satisfaction</i><br>
                  Defaults to "no"</li>
              <li><i>whatyouwant</i><br>
                  Defaults to "can't"</li>
              <li><i>whatyouneed</i><br>
                  Defaults to "try sometimes"</li>
        </ul>
    </ul>
    <br>

    <a id="Hello-get"></a>
    <b>Get</b><br>
    <ul>
        <code>get &lt;name&gt; &lt;option&gt;</code>
        <br><br>
        You can <i>get</i> the value of any of the options described in 
        <a href="#Helloset">paragraph "Set" above</a>. See 
        <a href="http://fhem.de/commandref.html#get">commandref#get</a> for more info about 
        the get command.
    </ul>
    <br>
    
    <a id="Hello-attr"></a>
    <b>Attributes</b>
    <ul>
        <code>attr &lt;name&gt; &lt;attribute&gt; &lt;value&gt;</code>
        <br><br>
        See <a href="http://fhem.de/commandref.html#attr">commandref#attr</a> for more info about 
        the attr command.
        <br><br>
        Attributes:
        <ul>
            <li><i>formal</i> no|yes<br>
                When you set formal to "yes", all output of <i>get</i> will be in a
                more formal language. Default is "no".
            </li>
        </ul>
    </ul>
</ul>

=end html

=cut
