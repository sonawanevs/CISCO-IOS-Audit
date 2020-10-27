#!/usr/bin/perl
use strict;
use warnings;

print "-----------------------------------------\n";
# Searching for all the configuration files inside the directory
my @files = <./configurations/*>;		# Hardcoded Directory .....

# Looking in the files for the content if exist!
if ($#files > "-1") {
	foreach my $file (@files) {

		#----- Open, Read and Close the Configuration File
		my $line="";
		open (FILE, "<", $file);
		while (<FILE>) {
			s/(\s)+$//g;       		# Removing Trailing Spaces
			$line = $line . $_ . "\n";	# File content copied to $line variable
		}
		close FILE;
		my @findings= "";


		#------ Analysing the Configuration File
		print "\n* Analysing File: $file\n";

		# Check 1 : Device enable password not set
		if ($line =~ /\n(\bset enablepass.*\b)/i) {
			my $status = "Check 1: Device enable password not set\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: Enable password is set\n";
			$status = $status . "configuration: $1\n";

			push @findings, $status;
		} else {
			my $status = "Check 1: Device enable password not set\n\n";
			$status = $status . "Status: Unsafe\n";
			$status = $status . "Unsafe Factor: Enable password is not set\n";

			push @findings, $status;
		}

		# Check 2 : Insecure remote access
		if ($line =~ /\n(\bset ip permit enable telnet\b)/i)  {
			my $status = "\n\nCheck 2 : Insecure remote access\n\n";
			$status = $status . "Status: Unsafe\n";
			$status = $status . "Unsafe Factor: Telnet is configured for remote administration\n";
			$status = $status . "configuration: $1\n";

			push @findings, $status;
		}
		else {
			if ($line =~ /\n(\bset ip permit disable telnet\b)/i) {
				my $status = "Check 2 : Insecure remote access\n\n";
				$status = $status . "Status: Safe\n";
				$status = $status . "Safe Factor: Telnet is disabled for remote administration\n";
				$status = $status . "configuration: $1\n";

				push @findings, $status;
			}
			else {
				my $status = "Check 2 : Insecure remote access\n\n";
				$status = $status . "Status: Safe\n";
				$status = $status . "Safe Factor: Telnet is not configured for remote administration\n";

				push @findings, $status;
			}
		}

		# Check 3 : Remote access is not restricted
		#my @permit_list = ($line =~ /\n(\bset ip permit (?:\d+).(?:\d+).(?:\d+).(?:\d+) .*\b)/ig);
		my @permit_protocol = ($line =~ /\n\bset ip permit enable (.*)\b/ig);
		my (@temp_unsafe1) = ();
		foreach my $protocol (@permit_protocol) {
			if ( $line !~ /\n(set ip permit (?:\d+).(?:\d+).(?:\d+).(?:\d+)\s+$protocol)\n/)  {
				push @temp_unsafe1, $protocol;
			}
		}

		if ($#temp_unsafe1 > "-1") {
			my $status = "\n\nCheck 3 : Remote access is not restricted\n\n";
			$status = $status . "Status: Unsafe\n";
			$status = $status . "Unsafe Factor: Remote access is not restricted\n";
			$status = $status . "Configuration: Remote access is not restricted for the for following protocols: ";

			my $vty_lines = "";
			foreach my $unsafe (@temp_unsafe1) {
					$vty_lines = $vty_lines . $unsafe. ", ";
			}
			$vty_lines =~ s/,\s+$//;
			$status = $status . $vty_lines . "\n";

			push @findings, $status;
		}
		else {
			my $status = "Check 3 : Remote access is not restricted\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: Remote access is restricted\n";

			push @findings, $status;
		}

		# Check 4 : Unattended terminals not secured
		if ($line =~ /\n(\bset logout \d+\b)/i) {
			$line =~ /\n\bset logout (\d+)\b/i;
			my $timeout = $1;

			if ($timeout > 10)  {
				my $status = "\n\nCheck 4 : Unattended terminals not secured\n\n";
				$status = $status . "Status: Unsafe\n";
				$status = $status . "Unsafe Factor: Idle session timeout is not configured securely\n";
				$status = $status . "configuration: Timeout value is set to (minutes): $timeout\n";

				push @findings, $status;
			}
			else {
				my $status = "\n\nCheck 4 : Unattended terminals not secured\n\n";
				$status = $status . "Status: Safe\n";
				$status = $status . "Safe Factor: Idle session timeout is configured securely\n";
				$status = $status . "configuration: Timeout value is set to (minutes): $timeout\n";

				push @findings, $status;
			}
		}
		else {
			my $status = "\n\nCheck 4 : Unattended terminals not secured\n\n";
			$status = $status . "Status: Unsafe\n";
			$status = $status . "Unsafe Factor: Idle session timeout is not configured\n";

			push @findings, $status;
		}

		# Check 5: User authentication not configured
		if ( ($line =~ /\n(\bset authentication login tacacs enable.*\b)/i) || ($line =~ /\n(\bset authentication login radius enable.*\b)/i) || ($line =~ /\n(\bset localuser user .* password .* privilege 15\b)/i) || ($line =~ /\n(\bset localuser user .* password .*\b)/i) ) {

			my $status = "\n\nCheck 5: User authentication not configured\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: User authentication is configured on the device\n";

			push @findings, $status;
		}
		else {
			my $status = "\n\nCheck 5: User authentication not configured\n\n";
			$status = $status . "Status: Unsafe\n";
			$status = $status . "Unsafe Factor: User authentication is not configured on the device\n";

			push @findings, $status;
		}

		# Check 6: Unnecessary services running
		
		if (($line =~ /\n(\bset ip dns disable\b)/i) && ($line =~ /\n(\bset ip http server disable\b)/i) && ($line =~ /\n(\bset ntp client disable\b)/i))  {
			my $status = "\n\nCheck 6: Unnecessary services running\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: Unnecessary services are not running on the device\n";

			push @findings, $status;
		}
		else {
			my $status = "\n\nCheck 6: Unnecessary services running\n\n";
			$status = $status . "Status: Review\n";
			$status = $status . "Configuration: Review the requirement of following services: ";
			my @services = ();
			if ($line !~ /\n(\bset ip dns disable\b)/i) {
				push @services, "DNS";
			}
			if ($line !~ /\n(\bset ip http server disable\b)/i) {
				push @services, "HTTP Server";
			}
			if ($line !~ /\n(\bset ntp client disable\b)/i) {
				push @services, "NTP";
			}
							
			my $vty_lines = "";
			foreach my $unsafe (@services) {
					$vty_lines = $vty_lines . $unsafe. ", ";
			}
			$vty_lines =~ s/,\s+$//;
			$status = $status . $vty_lines . "\n";

			push @findings, $status;
		}
		
		# Check 7: CDP is running
		if ( $line !~ /\n(\bset cdp disable\b)/i ) {
			my $status = "\n\nCheck 7: CDP is running\n\n";
			$status = $status . "Status: Unsafe\n";
			$status = $status . "Unsafe Factor: CDP protocol is enabled on the device\n";

			push @findings, $status;
		}
		else {
			my $status = "\n\nCheck 7: CDP is running\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: CDP protocol is disable on the device\n";

			push @findings, $status;
		}

		# Check 8: SNMP service is not secured
		if ( $line !~ /\n(\bset snmp disable\b)/i ) {

			if ( ($line =~ /\n(\bset snmp community read-only\s+public\b)/i) || ($line =~ /\n(\bset snmp community read-write\s+private\b)/i) || ($line =~ /\n(\bset snmp community read-write-all\s+secret\b)/i) ) {
	
				my $status = "\n\nCheck 8: SNMP service is not secured\n\n";
				$status = $status . "Status: Safe\n";
				$status = $status . "Safe Factor: SNMP Service is not securely configured.\n";
				$status = $status . "Configuration: Following SNMP Community strings are configured insecurely: \n";

				my @services = ();
				if ($line =~ /\n(\bset snmp community read-only\s+public\b)/i) {
					push @services, $1;
				}
				if ($line =~ /\n(\bset snmp community read-write\s+ private\b)/i) {
					push @services, $1;
				}
				if ($line =~ /\n(\bset snmp community read-write-all\s+secret\b)/i) {
					push @services, $1;
				}
							
				my $vty_lines = "";
				foreach my $unsafe (@services) {
						$vty_lines = $vty_lines . $unsafe. ", ";
				}
				$vty_lines =~ s/,\s+$//;
				$status = $status . $vty_lines . "\n";

				push @findings, $status;

			}
			else {
				my $status = "\n\nCheck 8: SNMP service is not secured\n\n";
				$status = $status . "Status: Safe\n";
				$status = $status . "Safe Factor: SNMP Service is securely configured.\n";

				push @findings, $status;
			}
		}
		else {
			my $status = "\n\nCheck 8: SNMP service is not secured\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: SNMP Service is not running.\n";

			push @findings, $status;
		}

		# Check 9: Device sends IP unreachable messages
		if ( $line !~ /\n(\bset ip unreachable disable\b)/i ) {
			my $status = "\n\nCheck 9: Device sends IP unreachable messages\n\n";
			$status = $status . "Status: Unsafe\n";
			$status = $status . "Unsafe Factor: IP unreachable message is enabled on the device\n";

			push @findings, $status;
		}
		else {
			my $status = "\n\nCheck 9: Device sends IP unreachable messages\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: IP unreachable message is disabled on the device\n";
			
			push @findings, $status;
		}


		# Check 10: Unsafe logging configuration
		if ($line !~ /\n(\bset logging server enable\b)/i) {
			my $status = "\n\nCheck 10: Unsafe logging configuration\n\n";
			$status = $status . "Status: Unsafe\n";
			$status = $status . "Unsafe Factor: Logging on centralized server is not enabled\n";

			push @findings, $status;
		}
		else {
			if ($line !~ /\n(\bset logging server (?:\d+).(?:\d+).(?:\d+).(?:\d+)\b)/i) {
				my $status = "\n\nCheck 10: Unsafe logging configuration\n\n";
				$status = $status . "Status: Unsafe\n";
				$status = $status . "Unsafe Factor: Centralized Logging server IP address is not configured\n";

				push @findings, $status;
			}
			elsif ($line !~ /\n(\bset logging level.*\b)/i) {
				my $status = "\n\nCheck 10: Unsafe logging configuration\n\n";
				$status = $status . "Status: Unsafe\n";
				$status = $status . "Unsafe Factor: Centralized Logging server IP address is not configured\n";

				push @findings, $status;
			}
			else {
				my $status = "\n\nCheck 10: Unsafe logging configuration\n\n";
				$status = $status . "Status: Safe\n";
				$status = $status . "Safe Factor: Device is securely configured for logging\n";

				push @findings, $status;			
			}
		}

		# Check	11: Device sends IP redirects
		if ( $line !~ /\n(\bset ip redirect disable\b)/i ) {
			my $status = "\n\n Check 11: Device sends IP redirects\n\n";
			$status = $status . "Status: Unsafe\n";
			$status = $status . "Unsafe Factor: IP redirect message is enabled on the device\n";

			push @findings, $status;
		}
		else {
			my $status = "\n\n Check 11: Device sends IP redirects\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: IP redirect message is disabled on the device\n";
			
			push @findings, $status;
		}
		

		# Check 12: Unsafe Time zone setting
		if ($line =~ /\b(set timezone .*)\b/i)  {
			my $timezone = $1;
			my $status = "\n\nCheck 12: Unsafe Time zone setting\n\n";
			$status = $status . "Status: Manual Review\n";
			$status = $status . "Configuration: Following timezone is configured. Manually Review it: $timezone\n";

			# Summer time
			if ($line !~ /\b(set summertime.*)\b/i) { 
				# Summer time is not configured only....
				$status = $status . "\nStatus: Manual Review\n";
				$status = $status . "Summer-time Configuration: Check over internet if the country follows Daylight Saving Time. If it follows, then mark this check as UNSAFE as they must configure 'set summertime' command along with 'set timezone' command on device. If country does not follow Daylight Saying Time, then decide safe/unsafe based on timezone setting.";
			}
			else {
				# Summer time is configured but is it set to correct timezone?
				$status = $status . "\nStatus: Manual Review\n";
				$status = $status . "Summer-time Configuration: Check over internet if the country follows Daylight Saving Time. 'set summertime' command is configured. Check for the timezone and other settings as per checklist.\nSummer time Setting: $1";				
			}
			
			push @findings, $status;
		}
		else {
			my $status = "\n\nCheck 12: Unsafe Time zone setting\n\n";
			
			# Time zone
			$status = $status . "Status: Manual Review\n";
			$status = $status . "Timezone Configuration: Timezone is not configured on the device. Check the output of the 'sh clock' command in the configuration to see what timezone is set by default.\n";
	
			# Summer time
			if ($line !~ /\b(set summertime.*)\b/i) {
				# Summer time is not configured only....
				$status = $status . "\nStatus: Manual Review\n";
				$status = $status . "Summer-time Configuration: Check over internet if the country follows Daylight Saving Time. If it follows, then mark this check as UNSAFE as they must configure 'set summertime' command along with 'set timezone' command on device. If country does not follow Daylight Saying Time, then decide safe/unsafe based on timezone setting.";
			}
			else {
				# Summer time is configured but is it set to correct timezone?
				$status = $status . "\nStatus: Manual Review\n";
				$status = $status . "Summer-time Configuration: Check over internet if the country follows Daylight Saving Time. 'set summertime' command is configured. Check for the timezone and other settings as per checklist.\nSummer time Setting: $1";				
			}

			push @findings, $status;
		}


		# Check 13 : Telnet banner is enabled
		if ($line =~ /\bset banner telnet disable\b/i)  {
			my $timezone = $1;
			my $status = "\n\nCheck 13 : Telnet banner is enabled\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Configuration: Telnet banner is disabled\n";

			push @findings, $status;
		}
		else {
			my $status = "\n\nCheck 13 : Telnet banner is enabled\n\n";
			$status = $status . "Status: Unsafe\n";
			$status = $status . "Configuration: Telnet banner is not disabled\n";

			push @findings, $status;
		}
		
		# Check 14 : System statutory warning not set
		if ($line =~ /\bset banner motd.*\b/i){
			my $timezone = $1;
			my $status = "\n\nCheck 14 : System statutory warning not set\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Configuration: System statutory banner is set\n";

			push @findings, $status;
		}
		else {
			my $status = "\n\nCheck 14 : System statutory warning not set\n\n";
			$status = $status . "Status: Unsafe\n";
			$status = $status . "Configuration: System statutory banner is not set\n";

			push @findings, $status;
		}

		#------ Generate Report File
		&reporting ($file, @findings);

		print "\n* Completed Analysing File: $file\n\n----------------------------------------\n";
	}
}

# Message for no files found in the configuration directory
else {
	print "\nHey you forgot to copy configuration files, Dude :-)\n\n";
}

# Function for generate Vulnerability assessment report
sub reporting () {
	my ($name, @findings)= @_;
	($name =~ /(.*)\/(.*)/);
	my $filename= $2;
	my $report_file = "./reports/".$filename."_VA_Report.txt";
	open (HTML, ">", $report_file) or die "File error: $!";
	foreach my $finding (@findings) {
		print HTML $finding;
	}
	close HTML;
}
#END
