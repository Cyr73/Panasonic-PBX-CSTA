#ver 0.01 (C)Cyr
use strict;
use warnings;
use diagnostics;
use IO::Socket;
use Convert::ASN1;
use Data::Dumper;
use Carp;
use POSIX;
my $CSTAapdu;
my $socket;
my @devices;
sub deviceNumber{
	my $deviceNumber = shift;
	my $deviceType = $deviceNumber & 0xFFFF0000;
	if 		($deviceType==0x1310000) {
		$deviceType='CO' 
	} elsif ($deviceType==0x1210000) {
		$deviceType='PS'
	} elsif ($deviceType==0x1110000) {
		$deviceType='EXT'
	} elsif ($deviceType==0x1550000) {
		$deviceType='DISA'
	}
	$deviceNumber = $deviceNumber & 0x0000FFFF;
	return $deviceType.sprintf("%03s",$deviceNumber);
}
sub decode_msg_header {
	my $bin = shift;
	my $len = unpack('n', $bin);
	return $len;
}
sub encode_msg_header {
	my $len = shift;
	die "Message larger than allowed!" unless ($len <= 240);
	my $bin = pack('n', $len);
	return $bin;
}
sub convert_to_hex {
	my $pdu = $_[0];
	my $hexdata = unpack('H*', $pdu);
	$hexdata =~ tr/a-z/A-Z/;
	$hexdata =~ s/(..)/$1 /g;
	$hexdata =~ s/ $//g;
	return $hexdata;
}
sub send_pdu {
	my $pdu = $_[0];
	my $header = encode_msg_header(length($pdu));
	$socket->write($header); 
	$socket->write($pdu);
#	my $hexdata = convert_to_hex($pdu);
#	print("SENT:    [$hexdata]\n"); 
} 
sub csta_connect {
	my %args = %{$_[0]}; 
	open_csta_socket($args{host}, $args{port});
	# A-ASSOCIATE Request
	my $pdu = "602380020780A10706052B0C00815ABE14281206072B0C00821D8148A007A0050303000800";
    $pdu = pack('H*', $pdu);
	send_pdu($pdu);
	# A-ASSOCIATE Result 
	$pdu = receive_stuff();
	my $hexdata = convert_to_hex($pdu);
	if ($hexdata =~/A2 03 02 01 01/){
		print "rejected-permanent\n";
		exit 0
	}
	#SystemStatus Request
	$pdu = receive_stuff();
	my $out = $CSTAapdu->decode($pdu);
	my $invokeID  = $out->{svcRequest}->{invokeID};
	SystemStatusResult($invokeID);
}
	
sub open_csta_socket {
	my $host = shift;
	my $port = shift;
	$socket = new IO::Socket::INET(
        PeerAddr => $host,
        PeerPort => $port,
		Blocking => 1,
		Proto => 'tcp') || die "Error creating socket: $!\n";
	$socket->autoflush(1);
	print("opened a connection to $host on port $port\n");
}	
sub receive_stuff {
	my $header = '';
	my $pdu = '';
	my $nbytes;
	$nbytes = $socket->sysread($header, 2);
	if ($nbytes==1) { # фрагмент пакета
		my $header2;
		my $nbytes2= $socket->sysread($header2, 1);
		$header = $header.$header2;
		$nbytes = 2;
	} 
	croak "Didn't receive the specified amount of data (2 bytes)!\n".chr(7) unless ($nbytes == 2);
	my $len = decode_msg_header($header);
	$nbytes = $socket->sysread($pdu, $len);
	if ($nbytes<$len) { # фрагмент пакета
		my $pdu2;
		my $nbytes2= $socket->sysread($pdu2, $len-$nbytes);
		$pdu = $pdu.$pdu2;
		$nbytes = $nbytes + $nbytes2;
	} 
	croak "Didn't receive the specified amount of data ($len bytes)!\n".chr(7) unless ($nbytes == $len);
#	my $hexdata = convert_to_hex($pdu);
#	print("RECEIVED:[$hexdata]\n");
	return $pdu;
}
sub GetSystemData{
	my $DeviceCategory = shift;
	#EXT=5
	#CO	=2
	my $pdu = $CSTAapdu->encode({svcRequest=>{
 									invokeID=>4,
									serviceID=>51,
									serviceArgs=>{
										privateData=>{
											private=>{
												kmeSystemData=>{
													getSystemData=>{
														request=>{
															deviceList=>{
																category=>{
 																	standardDevice=>$DeviceCategory
																	}
																}
															}
														}
													}
												}
											}
										}
 									}
								});
	#my $pdu = "A11602020602020133300DA40BA009A407A105A0030A010".$DeviceCategory;
	#$pdu = pack('H*', $pdu);
	send_pdu($pdu);
	# getSystemDataPosAck
	$pdu = receive_stuff();
	my $out = $CSTAapdu->decode($pdu);
	my $crossRefID = $out->{svcResult}->{result}->{serviceResult}->{extensions}->{privateData}[0]->{private}->{kmeSystemData}->{getSystemDataPosAck};
	my $lastSegment=0;
	# systemDataLinkedReply
	while (!$lastSegment) {
		$pdu = receive_stuff();
		my $out = $CSTAapdu->decode($pdu);
		my $systemDataLinkedReply = $out->{svcRequest}->{serviceArgs}->{privateData}->{private}->{kmeSystemData}->{systemDataLinkedReply};
		if (defined $systemDataLinkedReply) {
			if ($systemDataLinkedReply->{crossRefID} cmp $crossRefID) {next}
			$lastSegment = $systemDataLinkedReply->{lastSegment};
			foreach my $KmeDeviceStateEntry (@{$systemDataLinkedReply->{sysData}->{deviceList}}) {
				if	($KmeDeviceStateEntry->{status}==0) {
#					print "device:",$KmeDeviceStateEntry->{number},"\n";
					push @devices, ($KmeDeviceStateEntry->{device}->{deviceIdentifier}->{deviceNumber});
				}
			}
		}	
	}
}
sub MonitorStartArgument{
my $device = shift;
my $pdu = $CSTAapdu->encode({svcRequest=>{
                                invokeID=>9,
								serviceID=>71,
                                serviceArgs=>{
										monitorObject=>{
											deviceObject=>{
												deviceIdentifier=>{
													deviceNumber=>$device
																}
															}
														},
										requestedMonitorFilter=>{}
											}
										}
                            });
send_pdu($pdu);
#$pdu = receive_stuff();	
}
sub deviceID{
	my $deviceIdentifier = shift;
	$deviceIdentifier = $deviceIdentifier->{deviceIdentifier};
	if     (defined $deviceIdentifier->{dialingNumber}) {
		return $deviceIdentifier->{dialingNumber}
	} elsif (defined $deviceIdentifier->{deviceNumber}) {
		return deviceNumber($deviceIdentifier->{deviceNumber})
	} elsif (defined $deviceIdentifier->{other}) 		{
		return $deviceIdentifier->{other}
	}
}
sub SystemStatusResult{
	my $invokeID = shift;
	my $pdu = $CSTAapdu->encode({svcResult=>{invokeID=>$invokeID,result=>{serviceID=>211,serviceResult=>{noData=>1}}}});
	send_pdu($pdu); # send SystemStatus Result
}
$Data::Dumper::Indent=1;
$Data::Dumper::Pair=' ';
$Data::Dumper::Quotekeys=0;
$Data::Dumper::Varname='calls';				
# parse ASN.1 desciptions
my $asn = Convert::ASN1->new;
#$asn->configure(tagdefault=>'EXPLICIT');
$asn->prepare_file('d:/111/asn_perl/kxtde.asn') or die "prepare: ", $asn->error;
my %serviceArgs = ( 21=> 'CSTAEventReportArgument',
					51=> 'EscapeArgument',
					71=> 'MonitorStartArgument',
					211=> 'SystemStatusArg');
foreach (keys %serviceArgs) {
	$asn->registertype('serviceArgs',$_,$asn->find($serviceArgs{$_}));
}
my %serviceResults = (  51=> 'EscapeResult',
						71=> 'MonitorStartResult',
						211=> 'SystemStatusRes');
foreach (keys %serviceResults) {
	$asn->registertype('serviceResult',$_,$asn->find($serviceResults{$_}));
} 
$CSTAapdu = $asn->find('CSTAapdu');
csta_connect({'host'=>'192.168.0.101', 'port'=>33333});
GetSystemData(2);
GetSystemData(5);
foreach my $number (@devices) {
	MonitorStartArgument($number);
}
while (1) {
	my $pdu = receive_stuff();
	#Convert::ASN1::asn_hexdump($pdu);
	#Convert::ASN1::asn_dump($pdu);
	my $out = $CSTAapdu->decode($pdu);
	print Dumper($out);
	if  (defined  $out->{svcRequest})   {
			my $serviceID = $out->{svcRequest}->{serviceID};
			my $invokeID  = $out->{svcRequest}->{invokeID};
			my $serviceArgs = $out->{svcRequest}->{serviceArgs};
			if ($serviceID==211) { # if SystemStatus Request
				SystemStatusResult($invokeID);
			}
	}
}