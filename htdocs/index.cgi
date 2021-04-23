#! /usr/bin/perl

# + Register new user, confirmation by netmail
# + Redirect to https (by apache)
# + dynip
# - Anonymous: add node missing in the nodelist and response on binkd, expire on 3 weeks if not in the nodelist
# - If host: can edit any nodes in his network (incl. missing in nodelist)
# - If RC: can edit only independent nodes under region (incl. missing in nodelist)
# + Sysop: can edit own record
# + Any new record should response with binkp.
# + Records created with this interface added to binkp.net in addition to the informaion specified in the nodelist
# + Info from fidonet.net fill to the database as its start state
# + Change password
# + Reset password (Forget password)
# - Remember me (stored cookie)
# - Logout
# - check if hostname has several IPs (verify binkp at all of them?)
# - use Net::DNS
# - Logging (syslog?)
# - Query state (http://binkp.net/?a=2:5000/111)
# - Show hostmaster email
# - Print warnings (cname to cname; more then one fqdn; fqdn+ina, not in nodelist)
# + Points
# - Check for infinite loops (cname to itself or a->b, b->a)

use strict;
use warnings;

use CGI "-oldstyle_urls";
use POSIX;
use Socket;
use DBI;
use Digest::MD5 'md5_base64';
use DB_File;

my $myname = $ENV{"REQUEST_URI"};
$myname =~ s/\?.*//;
my $proto = $ENV{"REQUEST_SCHEME"};
my $myfullname = "$proto://$ENV{HTTP_HOST}$myname";
my $config = $ENV{"DOCUMENT_ROOT"} . "/../binkp-net.conf";
my $debug  = 0;
my $VERSION = "0.3";
my $title = "BINKP.NET DNS EDITOR $VERSION";
my $templates = $ENV{"DOCUMENT_ROOT"} . "/../tpl";

readcfg();
process();
exit(0);

my %conf;
my $q;
my $dbh;
my $id;
my $hostparam;
my ($zone, $net, $fnode, $point);
my $node;
my $accept_cookie;
my ($pw, $pwc);

sub readcfg
{
	my $fh;
	unless (open($fh, '<', $config)) {
		http_head();
		mdie("Can't open config $config");
	}
	while (<$fh>) {
		chomp();
		s/\b#.*$//;
		next if /^\s*$/;
		next unless /^\s*([a-z_][a-z0-9_]+)\s*=\s*(\S(.*\S)?)\s*$/i;
		my ($key, $value) = ($1, $2);
		$key =~ tr/A-Z/a-z/;
		$conf{$key} = $value;
	}
	close($fh);
	unless (defined($conf{"mysql_db"}) && defined($conf{"mysql_utable"}) && defined($conf{"mysql_htable"}) &&
	        defined($conf{"mysql_user"}) && defined($conf{"mysql_pwd"})) {
		http_head();
		mdie("MySQL config parameters not defined");
	}
	foreach my $i (qw(cookie_seed tpl_dir nodelist_db sendmail email_from update_flag myaka)) {
		if (!defined($conf{$i})) {
			http_head();
			mdie("$i config parameter not defined");
		}
	}

	$q = new CGI;
}

sub process
{
	my $start_time = time();
	my $mode = 'l';
	$node = $q->param("node") if defined($q->param("node"));
	$pw = $q->param("pw") if defined($q->param("pw"));
	$pwc = $q->param("pwc") if defined($q->param("pwc"));
	my $code = $q->param("code") if defined($q->param("code"));
	my $rcode = $q->param("rcode") if defined($q->param("rcode"));
	$mode = $q->param("m") if defined($q->param("m"));
	$mode = "c" if ($code && !$q->param("m"));
	$mode = "rc" if ($rcode && !$q->param("m"));
	#debug("node: '" . ($node // '') . "', pwc: '" . ($pwc // '') . "', mode: '" . ($mode // '') . "'");

	$accept_cookie = ($q->cookie("binkp_start") ? 1 : 0);
	if ($mode eq "l") {
		http_head();
		print_tpl("login");
		return;
	}
	if ($mode eq "r") {
		http_head();
		print_tpl("register");
		return;
	}
	if ($mode eq "m") {
		http_head();
		print_tpl("forget");
		return;
	}
	$node = $q->cookie("node") if !$node && defined($q->cookie("node"));
	debug("cookies read, node: '$node', pwc: '$pwc', mode: '$mode'");
	if (!$node) {
		http_head();
		mdie("Internal error (unknown node for mode '$mode'), send info to hostmaster about it");
	}
	if ($node !~ /^((\d+):)?(\d+)\/(\d+)(\.(\d+))?$/) {
		http_head();
		mdie("Incorrect nodenumber syntax $node");
	}
	($zone, $net, $fnode, $point) = ($2, $3, $4, $6);
	$node =~ s/\.0+//;
	unless ($zone) {
		$zone = 2;
		$node = "$zone:$node";
	}
	if ($mode eq "c" && $node && $code) {
		if ($code eq gen_cookie($node)) {
			http_head();
			print_tpl("reg_success", "code" => $code);
		} else {
			http_head();
			mdie("Invalid confirmation code");
		}
		return;
	}
	if ($mode eq "rc" && $node && $rcode) {
		if ($rcode eq gen_cookie_reset($node)) {
			http_head();
			print_tpl("reset", "code" => $rcode);
		} else {
			http_head();
			mdie("Invalid confirmation code");
		}
		return;
	}

	my $dsn = "DBI:mysql:$conf{mysql_db}:$conf{mysql_host}";
	unless ($dbh = DBI->connect($dsn, $conf{"mysql_user"}, $conf{"mysql_pwd"}, { PrintError => 0 })) {
		http_head();
		mdie("Can't connect to MySQL server: $DBI::err ($DBI::errstr)");
	}

	if ($mode eq "r2") {
		register();
		return;
	}
	if ($mode eq "m2") {
		reset_pwd();
		return;
	}

	$pwc = pwd_crypt($pw) if $pw && !$pwc;
	$pwc = $q->cookie("pwd") if !$pwc && defined($q->cookie("pwd"));

	if ($mode eq "setpass" && $node && ($code || $rcode)) {
		if ($code eq gen_cookie($node) || $rcode eq gen_cookie_reset($node)) {
			if ($q->param("pw") && $q->param("pw") eq $q->param("pw2")) {
				set_password($q->param("pw"), $code ? 1 : 0);
				return;
			} else {
				http_head();
				print_tpl("failsetpass", "code" => $code, "rcode" => $rcode, "error" => ($q->param("pw") ? "Passwords mismatch" : "Empty password"));
				return;
			}
		} else {
			http_head();
			mdie("Invalid confirmation code");
		}
	}
	my $sth = $dbh->prepare("select id, passwd, password(passwd) from $conf{mysql_utable} where node = ?");
	unless ($sth->execute($node)) {
		my $err = $dbh->errstr;
		$sth->finish();
		$dbh->disconnect();
		http_head();
		mdie("Can't select: $err");
	}
	my @res = $sth->fetchrow_array();
	$sth->finish();
	if (!@res || $res[1] eq '') {
		http_head();
		mdie("Unregistered node $node");
	}

	if ($pwc ne $res[1] && $pwc ne $res[2] || $res[1] eq '*') {
		http_head();
		mdie("Incorrect pasword");
	}
	# OK, it's correct node and password
	if ($pw && $pwc eq $res[1]) {
		# Store plain password
		mysql_do("update $conf{mysql_utable} set passwd = ? where id = $res[0]", $pw);
	}
	$id = $res[0];
	if (!$accept_cookie) {
		$hostparam = "&node=" . tocgi($node) . "&pwc=" . tocgi($pwc);
	}
	if ($mode eq "u") {
		update();
		return;
	}
	if ($mode =~ /^e([01]?)$/) {
		edit($1);
		return;
	}
	if ($mode eq "l2") {
		login2();
		return;
	}
	if ($mode eq "p") {
		http_head();
		print_tpl("chpass");
		return;
	}
	if ($mode eq "p2") {
		chpass();
		return;
	}
	http_head();
	mdie("Internal error (unknown mode '$mode'), send info to hostmaster about it");
}

sub update
{
	my(%host, %port, $rc, %templ);

	# check submitted information
	my $j = 0;
	$templ{"hostname"} = ($point ? "p$point." : "") . "f$fnode.n$net.z$zone";
	foreach my $i (qw(1 2 3 4)) {
		next unless $q->param("host$i");
		$host{++$j} = $q->param("host$i");
		$port{$j} = $q->param("port$i");
		$port{$j} = 24554 unless $port{$j};
		$host{$j} =~ tr/A-Z/a-z/;
		$templ{"host$j"} = $host{$j};
		$templ{"port$j"} = $port{$j};
	}
	my $dynupdate = 0;
	foreach my $i (sort keys %host) {
		$rc = check_data($host{$i}, $port{$i});
		if ($rc) {
			putlog("Verify data for node $node host $host{$i}:$port{$i} failed: $rc");
			http_head();
			$templ{"result"} = "Update failed: $rc";
			print_tpl("edit", %templ);
			return;
		}
		putlog("Verify data for node $node host $host{$i}:$port{$i} ok");
		$dynupdate = 1 if $host{$i} =~ /^dyn:/;
	}
	# all correct - save
	mysql_do("start transaction");
	mysql_do("delete from " . $conf{"mysql_htable"} . " where id = $id");
	foreach my $i (sort keys %host) {
		mysql_do("insert ignore $conf{mysql_htable} set id=$id, host=?, port=?", $host{$i}, $port{$i});
	}
	mysql_do("commit");
	putlog("Update info for node $node success");
	http_head();
	$templ{"result"} = "Your information successfully updated";
	print_tpl("edit", %templ);
	touch($conf{"update_flag"});
	touch($conf{"dyn_update_flag"}) if $dynupdate;
}

sub touch
{
	my ($fname) = @_;
	if (open(my $fh, '>', $fname)) {
		close($fh);
	} else {
		putlog("Can't touch '$fname': $!");
	}
}

sub validate_ip
{
    my ($iaddr) = @_;
    my @bad_networks = qw(
        0.0.0.0/8
        127.0.0.0/8
        10.0.0.0/8
        172.16.0.0/12
        192.168.0.0/16
        100.64.0.0/10
        169.254.0.0/16
        224.0.0.0/4
        255.255.255.255/32
    );
    my $ip = unpack("N", $iaddr);
    foreach my $network (@bad_networks) {
        my ($bad_addr, $network_len) = split('/', $network)
            or next;
        my $bad_ip = unpack("N", inet_aton($bad_addr));
        if ($ip >> (32-$network_len) == $bad_ip >> (32-$network_len)) {
            return "Incorrect address " . inet_ntoa($iaddr) . ": network $network reserved";
        }
    }
    return "";
}

sub check_data
{
	my($host, $port) = @_;

	unless ($port =~ /^[1-9][0-9]*$/) {
		return "Incorrect port value '$port', should be number";
	}
	return "" if $host eq "dyn";
	$host =~ s/^dyn://;
	my $iaddr = inet_aton($host) ||
		return "Host '$host' not found";
	if (my $result = validate_ip($iaddr)) {
		return $result;
	}
	my $paddr = sockaddr_in($port, $iaddr);
	socket(my $sock, PF_INET, SOCK_STREAM, getprotobyname('tcp')) ||
		return "Internal error, cannot create socket ($!), send info to hostmaster about it.";
	my $timeout = 0;
	$SIG{ALRM} = sub { close($sock); $timeout = 1; };
	alarm 10;
	unless (connect($sock, $paddr)) {
		alarm 0;
		close($sock) unless $timeout;
		return "Error connect to $host:$port: ". ($timeout ? "timeout" : $!);
	}
	my $resp = '';
	my $ok = 0;
	$timeout = 0;
	alarm 10;
	my $str = "VER binkp.net/$VERSION/Linux binkp/1.0";
	syswrite($sock, "\x80" . chr(length($str) + 1) . "\x00" . $str);
	syswrite($sock, "\x80" . chr(length($conf{"myaka"}) + 1) . "\x01" . $conf{"myaka"});
	while (sysread($sock, my $r, 16384)>0) {
	        #debug("<< $r");
	        $resp .= $r;
	        if ($resp =~ m@binkp/1.[01]|TIME @i) {
	                $ok = 1;
	                last;
	        }
	}
	alarm 0;
	close($sock) unless $timeout;
	return "" if $ok;
	return "Error connect to $host:$port: " . ($timeout ? "chat timeout" : ($! ? "$!" : "Connection closed"));
}

sub login2
{
	if ($accept_cookie) {
		http_head("$myfullname?m=e$hostparam", "node=" . tocgi($node), "pwd=" . tocgi($pwc));
	} else {
		edit();
	}
}

sub edit
{
	my($chpass_result) = $_[0];
	my(%templ);

	my $query = sprintf("select host, port from %s where id = %u", 
	                 $conf{"mysql_htable"}, $id);
	my $sth = $dbh->prepare($query);
	unless ($sth->execute()) {
		my $err = $dbh->errstr;
		$sth->finish();
		$dbh->disconnect();
		http_head();
		mdie("Can't select: $err");
	}
	my $i = 0;
	while (my ($host, $port) = $sth->fetchrow_array()) {
		$i++;
		$templ{"host$i"} = $host;
		$templ{"port$i"} = $port;
	}
	#$sth->finish();
	http_head();
	$templ{"hostname"} = ($point ? "p$point." : "") . "f$fnode.n$net.z$zone";
	if ($chpass_result eq "0") {
		$templ{"result"} = "Password successfully changed.";
	} elsif ($chpass_result eq "1") {
		$templ{"result"} = "Password successfully set.";
	}
	print_tpl("edit", %templ);
}

sub register
{
	# Check entered information, send confirmation code
	my $sysop = $q->param("sysop");
	my %nodelist;
	unless (tie(%nodelist, 'DB_File', $conf{"nodelist_db"}, O_RDONLY)) {
		http_head();
		mdie("Internal error (cannot open nodelist database), send info to hostmaster about it.");
	} 
	my $nline = $nodelist{"$zone:$net/$fnode"};
	my $daynum = $nodelist{"daynum"};
	untie %nodelist;
	if (!defined($nline)) {
		http_head();
		mdie("Node $node missing in the nodelist.$daynum");
	}
	if (!$point) {
		my $sysopname = (split(/,/, $nline))[4];
		$sysopname =~ tr/_A-Z/ a-z/;
		my $s = $sysop;
		$s =~ tr/_A-Z/ a-z/;
		if ($s ne $sysopname) {
			http_head();
			mdie("'$sysop' is incorrect sysop name for node $node in the nodelist.$daynum");
		}
	}

	my $sth = $dbh->prepare("select id, passwd from $conf{mysql_utable} where node = ?");
	unless ($sth->execute($node)) {
		my $err = $dbh->errstr;
		$sth->finish();
		$dbh->disconnect();
		http_head();
		mdie("Can't select: $err");
	}
	my @res = $sth->fetchrow_array();
	$sth->finish();
	if (@res && $res[1] ne '') {
		http_head();
		mdie("Node $node already registered in this system, use login");
	}
	# Ok, send netmail
	$sysop =~ tr/ /_/;
	my $fh;
	unless (open($fh, '|-', $conf{"sendmail"})) {
		http_head();
		mdie("Internal error (cannot run sendmail), send info to hostmaster about it.");
	}
	print $fh "From: $conf{email_from}\n";
	print $fh "To: $sysop\@" . ($point ? "p$point." : "") . "f$fnode.n$net.z$zone.fidonet.org.ua\n";
	print $fh "Subject: Your binkp.net confirmation code\n";
	print $fh "\n";
	print $fh "Hello\n";
	print $fh "\n";
	print $fh "You (or someone from IP $ENV{REMOTE_ADDR}) requested registration code for binkp.net.\n";
	print $fh "For confirm your registration please go to the following link:\n";
	print $fh "$myfullname?node=" . tocgi($node) . "&code=" . tocgi(gen_cookie($node)) . "\n";
	print $fh "\n";
	print $fh "--- binkp.net\n";
	unless (close($fh)) {
		http_head();
		mdie("Sendmail error");
	}
	http_head();
	print_tpl("code_sent");
	$sysop =~ tr/_/ /;
	putlog("Registration code sent to $sysop $node");
}

sub reset_pwd
{
	# Send confirmation code
	my %nodelist;
	unless (tie(%nodelist, 'DB_File', $conf{"nodelist_db"}, O_RDONLY)) {
		http_head();
		mdie("Internal error (cannot open nodelist database), send info to hostmaster about it.");
	} 
	my $nline = $nodelist{"$zone:$net/$fnode"};
	my $daynum = $nodelist{"daynum"};
	untie %nodelist;
	if (!defined($nline)) {
		http_head();
		mdie("Node $node missing in the nodelist.$daynum");
	}
	my $sysopname;
	if ($point) {
		$sysopname = "SysOp";
	} else {
		$sysopname = (split(/,/, $nline))[4];
	}

	my $sth = $dbh->prepare("select id, passwd, reset_freq, reset_last from $conf{mysql_utable} where node = ?");
	unless ($sth->execute($node)) {
		my $err = $dbh->errstr;
		$sth->finish();
		$dbh->disconnect();
		http_head();
		mdie("Can't select: $err");
	}
	my @res = $sth->fetchrow_array();
	#$sth->finish();
	if (!@res || $res[1] eq '') {
		http_head();
		mdie("Node $node is not registered in this system, use register");
	}
	# Calculate new reset freq value
	my $curtime = time();
	my $num = $res[2] / exp(($curtime-$res[3])/$conf{"reset_period"}*log(2));
	putlog("Actual reset freq is $num");
	if ($num > $conf{"reset_limit"}) {
		http_head();
		mdie("Too many password reset requests for $node. Try later.");
	}
	$num++;
	if (!$dbh->do("update $conf{mysql_utable} set reset_freq=$num, reset_last=$curtime where id=$res[0]")) {
		putlog("Update reset password data error: $DBI::err ($DBI::errstr)");
		# Ignore this error
	}

	# Ok, send netmail
	$sysopname =~ tr/ /_/;
	my $fh;
	unless (open($fh, "|-", $conf{"sendmail"})) {
		http_head();
		mdie("Internal error (cannot run sendmail), send info to hostmaster about it.");
	}
	print $fh "From: $conf{email_from}\n";
	print $fh "To: $sysopname\@" . ($point ? "p$point." : "") . "f$fnode.n$net.z$zone.fidonet.org.ua\n";
	print $fh "Subject: Your binkp.net password reset code\n";
	print $fh "\n";
	print $fh "Hello\n";
	print $fh "\n";
	print $fh "You (or someone from IP $ENV{REMOTE_ADDR}) requested reset password for binkp.net.\n";
	print $fh "For set new password please go to the following link:\n";
	print $fh "$myfullname?node=" . tocgi($node) . "&rcode=" . tocgi(gen_cookie_reset($node)) . "\n";
	print $fh "If you did not request password reset please ignore this message.\n";
	print $fh "\n";
	print $fh "--- binkp.net\n";
	unless (close($fh)) {
		http_head();
		mdie("Sendmail error");
	}
	http_head();
	print_tpl("pw_reset_code_sent");
	$sysopname =~ tr/_/ /;
	putlog("Password reset code sent to $sysopname $node");
}

sub pwd_crypt
{
	my($pwd) = @_;

	my $sth = $dbh->prepare("select password(?)");
	unless ($sth->execute($pwd)) {
		my $err = $dbh->errstr;
		$sth->finish();
		$dbh->disconnect();
		http_head();
		mdie("Can't select: $err");
	}
	my @row = $sth->fetchrow_array();
	$sth->finish();
	return $row[0];
}

sub set_pwd
{
	my($user, $pwd) = @_;

	my $query = "update $conf{mysql_utable} set passwd = ? where node = ?";
	debug($query);
	mysql_do($query, $pwd, $node);
}

sub mysql_do
{
	my $request = shift;
	unless ($dbh->do($request, undef, @_)) {
		my $err = $dbh->errstr;
		$dbh->disconnect();
		http_head();
		putlog("Failed mysql query: '$request'");
		mdie("Can't update database: $err");
	}
}

sub set_password
{
	my($pwd, $new) = @_;

	my $sth = $dbh->prepare("select id, passwd from $conf{mysql_utable} where node = ?");
	unless ($sth->execute($node)) {
		my $err = $dbh->errstr;
		$sth->finish();
		$dbh->disconnect();
		http_head();
		mdie("Can't select: $err");
	}
	my @res = $sth->fetchrow_array();
	$sth->finish();
	if (!@res) {
		mysql_do("insert $conf{mysql_utable} set node=?, passwd=''", $node);
	}
	elsif ($res[1] ne '' && $new) {
		http_head();
		mdie("Node $node already registered, use login");
	}

	set_pwd($node, $pwd);
	$pwc = pwd_crypt($pwd);

	if ($accept_cookie) {
		http_head("$myfullname?m=e$new", "node=" . tocgi($node), "pwd=" . tocgi($pwc));
	} else {
		$hostparam = "&node=" . tocgi($node) . "&pwc=" . tocgi($pwc);
		edit($new);
	}
}

sub chpass
{
	if (pwd_crypt($pw) ne $pwc) {
		print_tpl("failchpass", "error" => "Incorrect password");
		return;
	}
	if ($q->param("newpw") && $q->param("newpw") eq $q->param("newpw2")) {
		set_password($q->param("newpw"), 0);
	} else {
		http_head();
		print_tpl("failchpass", "pw" => $pw, "error" => ($q->param("newpw") ? "Passwords mismatch" : "Empty password"));
	}
	return;
}

sub gen_cookie
{
	my ($param) = @_;

	return md5_base64("$conf{cookie_seed}:$param:$conf{cookie_seed}");
}

sub gen_cookie_reset
{
	my ($param) = @_;

	return md5_base64("$conf{cookie_reset_seed}:$param:$conf{cookie_reset_seed}");
}

sub mdie
{
	putlog($_[0]);
	print_tpl("error", "error" => $_[0]);
	exit(0);
}

sub debug
{
	#print "<!-- $_[0] -->" if $debug;
	putlog("DEBUG: $_[0]") if $debug;
}

sub http_head
{
	my($location, @cookie);
	$location = shift(@_);
	@cookie = @_;
	print "Content-Type: text/html; charset=koi8-r\n";
	foreach (@cookie) {
		print "Set-Cookie: $_\n" if $_;
	}
	print "Set-Cookie: binkp_start=" . time() . "\n" unless $accept_cookie;
	if ($location) {
		print "Location: $location\n\n";
		return;
	}
	print "\n";
	return;
}

sub start_html {
	print "<HTML>\n<HEAD>\n<TITLE>\n$title\n</TITLE>\n";
	print "<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=koi8-r\">\n";
	print "<B>$title</B><HR></HEAD><BODY>\n";
}

sub end_html
{
	print "</BODY></HTML>\n";
}

sub print_tpl
{
	my ($tplname, %templ) = @_;

	print template($tplname, %templ);
}

sub template
{
	my ($tplname, %templ) = @_;
	my ($res, $cond, @cond, @wastrue);
	my (@fh);

	$templ{"HTTP_USER_AGENT"} = $ENV{"HTTP_USER_AGENT"};
	$templ{"myname"} = $myname;
	$templ{"title"} = $title;
	$templ{"node"} = $node if $node;
	$templ{"pwc"} = $pwc if $pwc;
	$templ{"myaka"} = $conf{"myaka"};
	$templ{"myip"} = $conf{"myip"} if defined($conf{"myip"});
	$tplname = $conf{"tpl_dir"} . "/$tplname.tpl" unless $tplname =~ m@^/@;
	open(my $fh, '<', $tplname) || die("Cannot open $tplname: $!\n");
	$cond = 1;
	while (1) {
		if (!defined($_ = <$fh>)) {
			close($fh);
			$fh = pop(@fh);
			last if !defined($fh);
		} elsif (/^\$!include\s+(\S+)\s*$/) {
			push(@fh, $fh);
			undef($fh);
			$tplname = $1;
			$tplname = "$templates/$tplname" unless $tplname =~ m@^/@;
			open($fh, '<', $tplname) || die("Cannot open $tplname: $!\n");
		} elsif (/^\$!set\s+([^=]+)=(.*)$/) {
			$templ{$1} = $2;
		} elsif (/^\$!ifdef\s+(\S+)\s*$/) {
			push(@cond, defined($templ{$1}));
			push(@wastrue, $cond[$#cond]);
			$cond &= $cond[$#cond];
		} elsif (/^\$!ifndef\s+(\S+)\s*$/) {
			push(@cond, !defined($templ{$1}));
			push(@wastrue, $cond[$#cond]);
			$cond &= $cond[$#cond];
		} else {
			s/\[\[([^\[\]]+)\]\]/$templ{$1}/g;
			s/\{\{([^\{\}]+)\}\}/eval "$1"/ge;
			if (/^\$!(els)?if\s+(.*)$/) {
				if ($1 eq "els") {
					pop(@cond);
					if ($wastrue[$#wastrue]) {
						push(@cond, 0);
						$cond = 0;
						next;
					} else {
						pop(@wastrue);
						$cond = 1;
						$cond &= $_ foreach @cond;
					}
				}
				push(@cond, cond($2, %templ));
				debug("Condition result: " . $cond[$#cond]);
				push(@wastrue, $cond[$#cond]);
				$cond &= $cond[$#cond];

			} elsif (/^\$!else\s*$/) {
				if ($wastrue[$#wastrue]) {
					$cond[$#cond] = 0;
					$cond = 0;
				} else {
					$cond[$#cond] = 1;
					$cond = 1;
					$cond &= $_ foreach @cond;
				}
			} elsif (/^\$!endif\s*$/) {
				pop(@cond);
				pop(@wastrue);
				$cond = 1;
				$cond &= $_ foreach @cond;
			} elsif (/^\$!/) {
				debug("Unknown template line: '$_'");
			} else {
				$_ = $` if /\\$/;
				$res .= $_ if $cond;
			}
		}
	}
	return $res;
}

sub cond
{
	my ($expr, %templ) = @_;

	if ($expr =~ /^(?:(\S+)\s*(<|>|<=|>=|==|!=|=~|!~)\s*(\S+)|(defined)\((\S+)\))\s*$/) {
		if ($4 eq "defined") {
			debug("Condition '$expr'");
			return defined($templ{$5});
		} elsif ($2 eq "<") {
			return ($1 < $3);
		} elsif ($2 eq ">") {
			return ($1 > $3);
		} elsif ($2 eq "<=") {
			return ($1 <= $3);
		} elsif ($2 eq ">=") {
			return ($1 >= $3);
		} elsif ($2 eq "==") {
			return ($1 eq $3);
		} elsif ($2 eq "!=") {
			return ($1 ne $3);
		} elsif ($2 eq "=~") {
			return ($1 =~ /$3/);
		} elsif ($2 eq "!~") {
			return ($1 !~ /$3/);
		}
	} else {
		debug("Cannot parse condition: '$expr'");
	}
	return 0;
}

sub tocgi
{
	my($s) = @_;
	$s =~ s/([^-A-Za-z0-9*_.$@%])/sprintf("%%%02x",ord($1))/ges;
	return $s;
}

sub putlog
{
	open(my $fh, '>>', $conf{"log"}) || return;
	print $fh localtime() . " " . $ENV{"REMOTE_ADDR"} . " " . $ENV{"QUERY_STRING"} . " $_[0]\n";
	close($fh);
}

