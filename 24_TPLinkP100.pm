################################################################
# $Id: 24_TPLinkP100.pm 25206 2021-11-09 11:55:44Z vk $
#
#  Release 2020-04-12
#
#  Copyright notice
#
#  (c) 2016 Copyright: Volker Kettenbach
#  e-mail: volker at kettenbach minus it dot de
#
#  Description:
#  This is an FHEM-Module for the TP Link TPLinkP100110/110 
#  wifi controlled power outlet.
#  It support switching on and of the outlet as well as switching
#  on and of the nightmode (green led off).
#  It supports reading several readings as well as the
#  realtime power readings of the HS110.
#
#  Requirements
#  	Perl Module: IO::Socket::INET
#  	Perl Module: IO::Socket::Timeout
#  	
#  	In recent debian based distributions IO::Socket::Timeout can
#  	be installed by "apt-get install libio-socket-timeout-perl"
#  	In older distribution try "cpan IO::Socket::Timeout"
#
#  Origin:
#  https://gitlab.com/volkerkettenbach/FHEM-TPLink-Kasa
#
################################################################

package main;

use strict;
use TapoP100;
use warnings;
use SetExtensions;

# TODO
# * UseCase: status persistance over server restart
# * UseCase: device restart while server running
#            siehe hier: https://wiki.fhem.de/wiki/DevelopmentModuleIntro#X_Ready
# * Description

# NOTES
# Internals: für Geräte spezifische Informationen, werden in _Define gesetzt // Attribute können zur Laufzeit geändert werden

#####################################
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
	
	
	Debug ("TPLinkP100_Define: $name $url $username $passwd $inter");
	
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
	
	my $result = "<undef>";
	if($opt eq "status") 
	{
		Debug ("TPLinkP100: Get(status)");
		my $p100 = $hash->{P100};
		return "TPLinkP100_Get() invalid device ref" if !$p100;
		return $p100->isOn() ? "on" : "off";
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
		Debug ("TPLinkP100: setOnOff $setOnOff ");
		my $p100 = $hash->{P100};
		return "TPLinkP100_Set() invalid device ref" if !$p100;
		$p100->switch($setOnOff);
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
	
	if ($hash->{STATE} eq "disconnected") {
		TPLinkP100_Connect ($hash);
	}
	
	if (! IsDisabled ($hash)) {
		my $p100 = $hash->{P100};
		return "TPLinkP100_GetUpdate() invalid device ref" if !$p100;
		my $oldStatus = ReadingsVal ($hash->{NAME}, "status", "off");
		my $newStatus = $p100->isOn() ? "on" : "off";
	
		if ($oldStatus ne $newStatus) {
			my $ret = readingsSingleUpdate ($hash, "status", $newStatus, 1);
			Debug ("TPLinkP100_GetUpdate() : readingsSingleUpdate( $oldStatus $newStatus -> $ret )");
		}
	}
	
	InternalTimer(gettimeofday()+$hash->{Interval}, "TPLinkP100_GetUpdate", $hash);
}

sub TPLinkP100_Connect ($) {
	my ($hash) = @_;
	if ($hash->{P100}) { undef $hash->{P100}; }
	return 0 if IsDisabled ($hash); 
	
	my $p100 = TapoP100->new($hash->{url});
	$p100->login($hash->{username}, $hash->{passwd});
	$hash->{P100} = $p100;
	$hash->{STATE} = "active";
	return 1; # TODO: error handling
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
