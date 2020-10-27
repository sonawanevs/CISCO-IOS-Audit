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



#------------------------------------------------------------------------------------------------------------------------------
		# Check 1 : Device enable secret password not set
		if ($line =~ /\b(no enable secret.*)\b/i) {
			my $status = "\n\nCheck 1: Device enable secret password not set\n\n";
			$status = $status . "Status: Unsafe\n";
			$status = $status . "Unsafe Factor: Enable Secret password is not set\n";
			$status = $status . "configuration: $1\n";

			push @findings, $status;
		}
		else {
			if ($line =~ /(enable\s+secret\s+(?:.*))/i) {
				my $status = "Check 1: Device enable secret password not set\n\n";
				$status = $status . "Status: Safe\n";
				$status = $status . "Safe Factor: Enable Secret password is set\n";
				$status = $status . "configuration: $1\n";

				push @findings, $status;
			} else {
				my $status = "Check 1: Device enable secret password not set\n\n";
				$status = $status . "Status: Unsafe\n";
				$status = $status . "Unsafe Factor: Enable Secret password is not set\n";

				push @findings, $status;
			}
		}



#------------------------------------------------------------------------------------------------------------------------------
		# Check 2 : Password encryption is not enabled

		if ($line =~ /\b(no service password-encryption)\b/i) {
			my $status = "\n\nCheck 2: Password encryption is not enabled\n\n";
			$status = $status . "Status: Unsafe\n";
			$status = $status . "Unsafe Factor: Password encryption is not enabled\n";
			$status = $status . "configuration: $1\n";

			push @findings, $status;
		}
		else {
			if ($line =~ /\b(service password-encryption)\b/i) {
				my $status = "\n\nCheck 2: Password encryption is not enabled\n\n";
				$status = $status . "Status: Safe\n";
				$status = $status . "Safe Factor: Password encryption is enabled\n";
				$status = $status . "configuration: $1\n";

				push @findings, $status;
			}
			else {
				my $status = "\n\nCheck 2: Password encryption is not enabled\n\n";
				$status = $status . "Status: Unsafe\n";
				$status = $status . "Unsafe Factor: Password encryption is not enabled\n";

				push @findings, $status;
			}
		}


#------------------------------------------------------------------------------------------------------------------------------
		#--- Preparation :-)
		my @vtylines = ( $line =~ /(line\svty(?:.*?)(?=!|line))/isg );	# All VTY lines Defined
		my @conlines = ( $line =~ /(line\scon(?:.*?)(?=!|line))/isg );	# All Con lines Defined
		my @auxlines = ( $line =~ /(line\saux(?:.*?)(?=!|line))/isg );	# All Aux lines Defined
		#----


#------------------------------------------------------------------------------------------------------------------------------
		# Check 3 : Unencrypted remote administration
		if ($#vtylines >= 0) {
			my (@temp_safe, @temp_unsafe);
			foreach my $vtyline (@vtylines) {

				if ($vtyline =~ /\b(no\sexec|transport\sinput\snone|transport input ssh)\b/) {
					($vtyline =~ /(line\s+vty(?:.*))/);
					 push @temp_safe, $1;
				}
				else{
					($vtyline =~ /(line\s+vty(?:.*))/);
					 push @temp_unsafe, $1;
				}
			}

			if ($#temp_unsafe > "-1") {
				my $status = "\n\nCheck 3: Unencrypted remote administration\n\n";
				$status = $status . "Status: Unsafe\n";
				$status = $status . "Unsafe Factor: Telnet is configured for remote administration\n";
				$status = $status . "Configuration: Following VTY lines are configured: ";
				my $vty_lines = "";
				foreach my $unsafe (@temp_unsafe) {
						$vty_lines = $vty_lines . $unsafe. ", ";
				}
				$vty_lines =~ s/,\s+$//;
				$status = $status . $vty_lines . "\n";

				push @findings, $status;
			}
			else {
				my $status = "\n\nCheck 3: Unencrypted remote administration\n\n";
				$status = $status . "Status: Safe\n";
				$status = $status . "Safe Factor: Telnet is disabled for remote administration\n";

				push @findings, $status;
			}
		}
		else  {
			my $status = "\n\nCheck 3: Unencrypted remote administration\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: Telnet is not configured for remote administration\n";

			push @findings, $status;
		}




#------------------------------------------------------------------------------------------------------------------------------
		# Check 4 : Unrestricted Remote Administration
		if ($#vtylines >= 0) {
			my (@temp_safe, @temp_unsafe1, @temp_unsafe2, @temp_unsafe3);
			foreach my $vtyline (@vtylines) {
				if ($vtyline =~ /\b(no\sexec|transport\sinput\snone)\b/) {
					($vtyline =~ /(line\s+vty(?:.*))/);
					 push @temp_safe, $1;
				}
				else  {
					($vtyline =~ /(line\s+vty(?:.*))/);
					my $vtylinenumber = $1;

					if ($vtyline !~ /(access-class(?:.*)in)/i) {
						push @temp_unsafe1, $vtylinenumber;
					}
					else {
						my @access_classes = ($vtyline =~ /(access-class\s+\d+\s+in)/isg);
						foreach my $accesslist (@access_classes) {
							($accesslist =~ /access-class\s+(\d+)\s+.*/i);
							my $access_list_no = $1;
							# Check if the Access list is defined....
							# if not defined then, mark as unsafe 
							# If defined, then proceed for any source check...
							if ($line !~ /(access-list\s+\b$access_list_no\b.*)/ig) {
								push @temp_unsafe3, "$vtylinenumber => Access List No: $access_list_no";
							}
							else {
								my @access_list = ($line =~ /(access-list\s+\b$access_list_no\b\s+permit\s+any(?:.*))/ig);
								if ($#access_list > "-1") {
									push @temp_unsafe2, "$vtylinenumber => Access List No: $access_list_no";
								}
							}
						}
					}
				}
			}

			if (($#temp_unsafe1 > "-1") || ($#temp_unsafe2 > "-1") || ($#temp_unsafe3 > "-1")) {
				my $status = "\n\nCheck 4: Unrestricted Remote Administration\n\n";
				$status = $status . "Status: Unsafe\n";
				push @findings, $status;

				# Check for access-class not defined on vty line
				if ($#temp_unsafe1 > "-1") {
					my $status1;
					$status1 = "Unsafe Factor: Access list control for incoming connections is not applied to the VTY lines via access-class.\n";
					$status1 = $status1 . "Configuration: Following VTY lines are configured with unrestricted access: ";
					my $vty_lines = "";
					foreach my $unsafe (@temp_unsafe1) {
							$vty_lines = $vty_lines . $unsafe. ", ";
					}
					$vty_lines =~ s/,\s+$//;
					$status1 = $status1 . $vty_lines . "\n";

					push @findings, $status1;
				}
				
				# Check for access-list not created only
				if ($#temp_unsafe3 > "-1") {
					my $status3;
					$status3 = "Unsafe Factor: Access-class is maped to an undefined access list. Access List is not configured on device.\n";
					$status3 = $status3 . "Configuration: Following VTY lines are configured with unrestricted access: ";
					my $vty_lines = "";
					foreach my $unsafe (@temp_unsafe3) {
							$vty_lines = $vty_lines . $unsafe. ", ";
					}
					$vty_lines =~ s/,\s+$//;
					$status3 = $status3 . $vty_lines . "\n";

					push @findings, $status3;
				}

				# Check for source assigned to 'any'..here we found access list and checking for insecure configuration....
				if ($#temp_unsafe2 > "-1") {
					my $status2;
					$status2 = "Unsafe Factor: Access to any source is allowed by the access list configured for the VTY lines\n";
					$status2 = $status2 . "Configuration: Following VTY lines are configured with unrestricted access: ";
					my $vty_lines = "";
					foreach my $unsafe (@temp_unsafe2) {
							$vty_lines = $vty_lines . $unsafe. ", ";
					}
					$vty_lines =~ s/,\s+$//;
					$status2 = $status2 . $vty_lines . "\n";

					push @findings, $status2;
				}
			}
			else {
				if ($#temp_safe > "-1") {
					my $status = "\n\nCheck 4: Unrestricted Remote Administration\n\n";
					$status = $status . "Status: Safe\n";
					$status = $status . "Safe Factor: Remote administration is disabled\n";

					push @findings, $status;
				}
				else {
					my $status = "\n\nCheck 4: Unrestricted Remote Administration\n\n";
					$status = $status . "Status: Safe\n";
					$status = $status . "Safe Factor: Remote administration is restricted with the help of access list\n";

					push @findings, $status;
				}
			}
		}
		else  {
			my $status = "\n\nCheck 4: Unrestricted Remote Administration\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: Line VTY is not configured for remote administration\n";

			push @findings, $status;
		}




#------------------------------------------------------------------------------------------------------------------------------
		# Check 5 : User Authentication Not Configured
		if (($#vtylines > "-1") || ($#auxlines > "-1") || ($#conlines > "-1")) {
			my (@temp_unsafe1, @temp_unsafe2, @temp_unsafe3);

			# Con Lines
			if ($#conlines > "-1") {
				    foreach my $conline (@conlines) {
				            if ($conline =~ /\b(no\sexec|transport\sinput\snone)\b/) {
								# SAFE CON line is disabled
				            }
				            else{
				                    if ($conline !~ /(login local|login authentication.*)/i) {
				                            ($conline =~ /(line\s+con(?:.*))/);
				                            my $conlinenumber = $1;
				                            push @temp_unsafe2, $conlinenumber;
				                    }
				            }
				    }
			}

			# Aux Lines
			if ($#auxlines > "-1") {
				    foreach my $auxline (@auxlines) {
				            if ($auxline =~ /\b(no\sexec|transport\sinput\snone)\b/) {
								# SAFE AUX line is disabled
				            }
				            else  {
				                    if ($auxline !~ /(login local|login authentication.*)/i) {
				                            ($auxline =~ /(line\s+aux(?:.*))/);
				                            my $auxlinenumber = $1;
				                            push @temp_unsafe3, $auxlinenumber;
				                    }
				            }
				    }
			}

			# VTY Lines
			if ($#vtylines > "-1") {
				foreach my $vtyline (@vtylines) {
					if ($vtyline =~ /\b(no\sexec|transport\sinput\snone)\b/) {
						# SAFE VTY line is disabled
					}
					else  {
						if ($line =~ /no aaa new-model/i) {
							if ($vtyline !~ /(login local|login authentication (.*))/i) {
								($vtyline =~ /(line\s+vty(?:.*))/);
								my $vtylinenumber = $1;

								push @temp_unsafe1, $vtylinenumber;
							}
						}
						else {
							if ($line =~ /(aaa new-model|aaa authentication login default)/i) {
								# SAFE
							}
							else {
								if ($vtyline !~ /(login local|login authentication (.*))/i) {
									($vtyline =~ /(line\s+vty(?:.*))/);
									my $vtylinenumber = $1;

									push @temp_unsafe1, $vtylinenumber;
								}
							}
						}
					}
				}
			}

			# Reporting issues if they exist :-)
			if (($#temp_unsafe1 > "-1") || ($#temp_unsafe2 > "-1") || ($#temp_unsafe3 > "-1")) {
				my $status = "\n\nCheck 5: User Authentication Not Configured\n\n";
				$status = $status . "Status: Unsafe\n";
				push @findings, $status;

				# VTY Lines
				if ($#temp_unsafe1 > "-1") {
				        my $status1;
				        $status1 = "Unsafe Factor: User authentication is not configured for VTY Lines\n";
				        $status1 = $status1 . "Configuration: Following VTY lines are configured without authentication: ";
				        my $vty_lines = "";
				        foreach my $unsafe (@temp_unsafe1) {
				                        $vty_lines = $vty_lines . $unsafe. ", ";
				        }
				        $vty_lines =~ s/,\s+$//;
				        $status1 = $status1 . $vty_lines . "\n";

				        push @findings, $status1;
				}

				# Con Lines
				if ($#temp_unsafe2 > "-1") {
				        my $status2;
				        $status2 = "Unsafe Factor: User authentication is not configured for CON Lines\n";
				        $status2 = $status2 . "Configuration: Following CON lines are configured without authentication: ";
				        my $vty_lines = "";
				        foreach my $unsafe (@temp_unsafe2) {
				                        $vty_lines = $vty_lines . $unsafe. ", ";
				        }
				        $vty_lines =~ s/,\s+$//;
				        $status2 = $status2 . $vty_lines . "\n";

				        push @findings, $status2;
				}

				# Aux Lines
				if ($#temp_unsafe3 > "-1") {
				        my $status3;
				        $status3 = "Unsafe Factor: User authentication is not configured for AUX Lines\n";
				        $status3 = $status3 . "Configuration: Following AUX lines are configured without authentication: ";
				        my $vty_lines = "";
				        foreach my $unsafe (@temp_unsafe3) {
				                        $vty_lines = $vty_lines . $unsafe. ", ";
				        }
				        $vty_lines =~ s/,\s+$//;
				        $status3 = $status3 . $vty_lines . "\n";

				        push @findings, $status3;
				}
			}
			else {
				    my $status = "\n\nCheck 5: User Authentication Not Configured\n\n";
				    $status = $status . "Status: Safe\n";
				    $status = $status . "Safe Factor: User authentication is configured for remote administration\n";

				    push @findings, $status;
			}
		}
		else  {
			my $status = "\n\nCheck 5: User Authentication Not Configured\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: Remote Administration is disabled\n";

			push @findings, $status;
		}		



#------------------------------------------------------------------------------------------------------------------------------
		# Check 6 : No time out for idle sessions
		if (($#vtylines > "-1") || ($#auxlines > "-1") || ($#conlines > "-1")) {
			my (@temp_unsafe1, @temp_unsafe2, @temp_unsafe3);
			# VTY Lines
			if ($#vtylines > "-1") {
				foreach my $vtyline (@vtylines) {
					if ($vtyline =~ /\b(no\sexec|transport\sinput\snone)\b/) {
						#SAFE
					}
					elsif ($vtyline !~ /exec-timeout(.*)/i) {
						# SAFE
					}
					else {
						($vtyline =~ /exec-timeout\s+(\d+)\s+(\d+)/i);
						my $min = $1;
						my $sec = $2;
						if (( ($min eq "0") && ($sec eq "0") ) || ( $min > 10 ))  {
							($vtyline =~ /(line\s+vty(?:.*))/);
							my $vtylinenumber = $1;
							push @temp_unsafe1, "$vtylinenumber => Timeout: $min:$sec";
						}
					}
				}
			}
			# CON Lines
			if ($#conlines > "-1") {
				foreach my $conline (@conlines) {
					if ($conline =~ /\b(no\sexec|transport\sinput\snone)\b/) {
						# SAFE
					}
					elsif ($conline !~ /exec-timeout(.*)/i) {
						# SAFE
					}
					else {
						($conline =~ /exec-timeout\s+(\d+)\s+(\d+)/i);
						my $min = $1;
						my $sec = $2;
						if (( ($min eq "0") && ($sec eq "0") ) || ( $min > 10 ))  {
							($conline =~ /(line\s+con(?:.*))/);
							my $conlinenumber = $1;
							push @temp_unsafe2, "$conlinenumber => Timeout: $min:$sec";
						}
					}
				}
			}
			# Aux Lines
			if ($#auxlines > "-1") {
				foreach my $auxline (@auxlines) {
					if ($auxline =~ /\b(no\sexec|transport\sinput\snone)\b/) {
						# SAFE
					}
					elsif ($auxline !~ /exec-timeout(.*)/i) {
						# SAFE
					}

					else  {
						($auxline =~ /exec-timeout\s+(\d+)\s+(\d+)/i);
						my $min = $1;
						my $sec = $2;
						if (( ($min eq "0") && ($sec eq "0") ) || ( $min > 10 ))  {
							($auxline =~ /(line\s+aux(?:.*))/);
							my $auxlinenumber = $1;
							push @temp_unsafe3, "$auxlinenumber => Timeout: $min:$sec";
						}
					}
				}
			}

			if (($#temp_unsafe1 > "-1") || ($#temp_unsafe2 > "-1") || ($#temp_unsafe3 > "-1")) {
				my $status = "\n\nCheck 6: No time out for idle sessions\n\n";
				$status = $status . "Status: Unsafe\n";
				push @findings, $status;

				# VTY Lines
				if ($#temp_unsafe1 > "-1") {
					my $status1;
					$status1 = "Unsafe Factor: Idle session timeout is not configured securely\n";
					$status1 = $status1 . "Configuration: Following VTY lines are configured with insecure idle session timeout value: ";
					my $vty_lines = "";
					foreach my $unsafe (@temp_unsafe1) {
							$vty_lines = $vty_lines . $unsafe. ", ";
					}
					$vty_lines =~ s/,\s+$//;
					$status1 = $status1 . $vty_lines . "\n";

					push @findings, $status1;
				}

				# Con Lines
				if ($#temp_unsafe2 > "-1") {
					my $status2;
					$status2 = "Unsafe Factor: Idle session timeout is not configured securely\n";
					$status2 = $status2 . "Configuration: Following CON lines are configured with insecure idle session timeout value: ";
					my $vty_lines = "";
					foreach my $unsafe (@temp_unsafe2) {
							$vty_lines = $vty_lines . $unsafe. ", ";
					}
					$vty_lines =~ s/,\s+$//;
					$status2 = $status2 . $vty_lines . "\n";

					push @findings, $status2;
				}

				# Aux Lines
				if ($#temp_unsafe3 > "-1") {
					my $status3;
					$status3 = "Unsafe Factor: Idle session timeout is not configured securely\n";
					$status3 = $status3 . "Configuration: Following AUX lines are configured with insecure idle session timeout value: ";
					my $vty_lines = "";
					foreach my $unsafe (@temp_unsafe3) {
							$vty_lines = $vty_lines . $unsafe. ", ";
					}
					$vty_lines =~ s/,\s+$//;
					$status3 = $status3 . $vty_lines . "\n";

					push @findings, $status3;
				}
			}
			else {
				my $status = "\n\nCheck 6: No time out for idle sessions\n\n";
				$status = $status . "Status: Safe\n";
				$status = $status . "Safe Factor: Device is configured securely against idle sessions\n";

				push @findings, $status;
			}
		}
		else  {
			my $status = "\n\nCheck 6: No time out for idle sessions\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: Remote Administration is disabled\n";

			push @findings, $status;
		}



#------------------------------------------------------------------------------------------------------------------------------
		# Check 7 : Unsafe log generation and log collection
		if ($line =~ /\b(no logging trap)\b/i) {
			my $status = "\n\nCheck 7: Unsafe log generation and log collection\n\n";
			$status = $status . "Status: Unsafe\n";
			$status = $status . "Unsafe Factor: Centralized logging is disabled\n";
			$status = $status . "configuration: $1\n";

			push @findings, $status;
		}
		else {
			if ($line =~ /(logging\s+(?:\d+)\.(?:\d+)\.(?:\d+)\.(?:\d+))/i)  {
				my $status = "\n\nCheck 7: Unsafe log generation and log collection\n\n";
				$status = $status . "Status: Safe\n";
				$status = $status . "Safe Factor: Centralized logging is enabled.\n";

				push @findings, $status;
			}
			else {
				my $status = "\n\nCheck 7: Unsafe log generation and log collection\n\n";
				$status = $status . "Status: Unsafe\n";
				$status = $status . "Unsafe Factor: No Centralized logging is configured\n";

				push @findings, $status;
			}
		}



#------------------------------------------------------------------------------------------------------------------------------
		# Check 8 : Time server not designated
		if ($line =~ /\bno ntp server.*\b/i) {
			my $status = "\n\nCheck 8: Time server not designated\n\n";
			$status = $status . "Status: Unsafe\n";
			$status = $status . "Safe Factor: NTP Server is not configured\n";
			
			push @findings, $status;
		}
		else {
			if ($line =~ /\b(ntp server (?:.*))\b/i) {
				my $status = "\n\nCheck 8: Time server not designated\n\n";
				$status = $status . "Status: Safe\n";
				$status = $status . "Safe Factor: NTP Server is configured\n";

				push @findings, $status;
			}
			else {
				my $status = "\n\nCheck 8: Time server not designated\n\n";
				$status = $status . "Status: Unsafe\n";
				$status = $status . "Unsafe Factor: NTP Server is not configured\n";

				push @findings, $status;
			}
		}		



#------------------------------------------------------------------------------------------------------------------------------
		# Check 9 : No timestamp on logs and debug information

		if (($line =~ /no service timestamps log datetime.*/) || ($line =~ /no service timestamps debug datetime.*/)) {
			my $status = "\n\nCheck 9: No timestamp on logs and debug information\n\n";
			$status = $status . "Status: Unsafe\n";

			if ($line =~ /no service timestamps log datetime.*/) {
				$status = $status . "Unsafe Factor: Timestamp on logs information is not set\n";
			}
			if ($line =~ /no service timestamps debug datetime.*/){
				$status = $status . "Unsafe Factor: Timestamp on debug information is not set\n";
			}

			push @findings, $status;
		}
		else {
			if (($line !~ /service timestamps log datetime(.*)/) || ($line !~ /service timestamps debug datetime(.*)/)) {
				my $status = "\n\nCheck 9: No timestamp on logs and debug information\n\n";
				$status = $status . "Status: Unsafe\n";

				if ($line !~ /service timestamps log datetime (?:.*)/) {
					$status = $status . "Unsafe Factor: Timestamp on logs information is not set\n";
				}
				if ($line !~ /service timestamps debug datetime (?:.*)/){
					$status = $status . "Unsafe Factor: Timestamp on debug information is not set\n";
				}

				push @findings, $status;
			}
			else {
				my $status = "\n\nCheck 9: No timestamp on logs and debug information\n\n";
				$status = $status . "Status: Safe\n";
				$status = $status . "Safe Factor: Timestamp on logs and debug information is set\n";

				push @findings, $status;
			}
		}
		
		



#------------------------------------------------------------------------------------------------------------------------------
		# Check 14 : SNMPv1 or SNMPv2 is being used for device management and monitoring
		if ($line =~ /\bno snmp-server\b/) {
			my $status = "\n\nCheck 14: SNMPv1 or SNMPv2 is being used for device management and monitoring\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: SNMP is not used for device management\n";
			$status = $status . "configuration: $1\n";

			push @findings, $status;
		}
		else {
			if ($line !~ /\bsnmp-server.*\b/)  {
			my $status = "\n\nCheck 14: SNMPv1 or SNMPv2 is being used for device management and monitoring\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: SNMP is not used for device management\n";

				push @findings, $status;
			}
			else {
				# snmp-server group command
				my @snmp = ($line =~ /\b(snmp-server group .* v3.*)\b/ig);
				# snmp-server host command
				my @snmp_host = ($line =~ /\b(snmp-server host .* version 3.*)\b/ig);
				if (($#snmp > "-1") || ($#snmp_host > "-1") ) {
					my $status = "\n\nCheck 14: SNMPv1 or SNMPv2 is being used for device management and monitoring\n\n";
					$status = $status . "Status: Safe\n";
					$status = $status . "Safe Factor: SNMP Version 3 is being used for device management\n";

					push @findings, $status;				
				}
				else {
					my $status = "\n\nCheck 14: SNMPv1 or SNMPv2 is being used for device management and monitoring\n\n";
					$status = $status . "Status: Unsafe\n";
					$status = $status . "Unsafe Factor: SNMP Version 3 is not being used for device management\n";

					push @findings, $status;
				}
			}
		}




#------------------------------------------------------------------------------------------------------------------------------
		# Check 15 : Default SNMP Community Strings are used
		if ($line =~ /\bno snmp-server\b/) {
			my $status = "\n\nCheck 15: Default SNMP Community Strings are used\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: SNMP is not used for device management\n";
			$status = $status . "configuration: $1\n";

			push @findings, $status;
		}
		else {
			if ($line !~ /\bsnmp-server.*\b/)  {
			my $status = "\n\nCheck 15: Default SNMP Community Strings are used\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: SNMP is not used for device management\n";

				push @findings, $status;
			}
			else {
				my @snmp = ($line =~ /\b(snmp-server community .*)\b/ig);
				if ($#snmp > "-1") {
					my $count=0;
					my (@temp_unsafe1, @temp_unsafe2) = ();
					foreach my $snmp (@snmp) {
						if ($snmp =~ /\b(snmp-server community (public|private) .*)\b/i) {
							push @temp_unsafe1, $1;
							$count++;
						}
						else {
							push @temp_unsafe2, $1;
							$count++;
						}						
						
					}
					if ($count > 0) {
						my $status = "\n\nCheck 15: Default SNMP Community Strings are used\n\n";

						if ($#temp_unsafe1 > "-1") {
							$status = $status . "Status: Unsafe\n";
							$status = $status . "Unsafe Factor: Default community strings are configured on device\n";
							$status = $status . "Configuration: Following SNMP community strings are configured with default value: ";

							my $vty_lines = "";
							foreach my $unsafe (@temp_unsafe1) {
									$vty_lines = $vty_lines . $unsafe. ", ";
							}
							$vty_lines =~ s/,\s+$//;
							$status = $status . $vty_lines . "\n";

							push @findings, $status;
						}

						if ($#temp_unsafe2 > "-1") {
							$status = $status . "\nStatus: Manual Review\n";
							$status = $status . "Review Factor: Client may have removed community string for security reasons. JUST CHECK BELOW IN 'Configuration' PART OF THIS FINDING ONLY, if client has removed community string. If he has removed community string, we will make this check as REVIEW for client. If you find community string, then mark this check as SAFE.\n\n";
							$status = $status . "Configuration: Following SNMP community strings are configured: ";

							my $vty_lines = "";
							foreach my $unsafe (@temp_unsafe2) {
									$vty_lines = $vty_lines . $unsafe. ", ";
							}
							$vty_lines =~ s/,\s+$//;
							$status = $status . $vty_lines . "\n";

							push @findings, $status;


						}
					}
					else {
						my $status = "\n\nCheck 15: Default SNMP Community Strings are used\n\n";
						$status = $status . "Status: Safe\n";
						$status = $status . "Safe Factor: Default community strings are not configured on the device\n";

						push @findings, $status;
					}
				}
				else {
					my $status = "\n\nCheck 15: Default SNMP Community Strings are used\n\n";
					$status = $status . "Status: Safe\n";
					$status = $status . "Safe Factor: Community strings are not configured on the device\n";

					push @findings, $status;
				}
			}
		}



#------------------------------------------------------------------------------------------------------------------------------
		# Check 18 : Device accepts IP source routed packets
		if ($line =~ /\b(no ip source-route)\b/i) {
			my $status = "\n\nCheck 18: Device accepts IP source routed packets\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: Device does not accept IP source routed packets\n";

			push @findings, $status;
		}
		else {
			my $status = "\n\nCheck 18: Device accepts IP source routed packets\n\n";
			$status = $status . "Status: Unsafe\n";
			$status = $status . "Unsafe Factor: Device accepts IP source routed packets\n";

			push @findings, $status;
		}
		
		
		
#------------------------------------------------------------------------------------------------------------------------------
		# Check 24 : System statutory warning not set
		if ($line =~ /aaa authentication login default group (.*)/i) {
		# AAA Authentication Banner
			if ($line =~ /AAA authentication banner (.*)/i) {
				my $status = "\n\nCheck 24 : System statutory warning not set\n\n";
				$status = $status . "Status: Safe\n";
				$status = $status . "Safe Factor: AAA authentication banner is configured\n";

				push @findings, $status;
			}
			else {
				my $status = "\n\nCheck 24 : System statutory warning not set\n\n";
				$status = $status . "Status: Unsafe\n";
				$status = $status . "Unsafe Factor: AAA authentication banner is not configured\n";

				push @findings, $status;
			}
		}
		else {
			# Login Authentication Banner
			if ($line =~ /banner login.* || banner motd.*/i) {
				my $status = "\n\nCheck 24 : System statutory warning not set\n\n";
				$status = $status . "Status: Safe\n";
				$status = $status . "Safe Factor: Login banner is configured on the device\n";

				push @findings, $status;
			}
			else {
				my $status = "\n\nCheck 24 : System statutory warning not set\n\n";
				$status = $status . "Status: Unsafe\n";
				$status = $status . "Unsafe Factor: Login banner is not configured on the device\n";

				push @findings, $status;
			}
		}
		

		
#------------------------------------------------------------------------------------------------------------------------------
		# Check 26 : Unrestricted SNMP management and monitoring
		if ($line =~ /\bno snmp-server\b/) {
			my $status = "\n\nCheck 26: Unrestricted SNMP management and monitoring\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: SNMP is not used for device management\n";
			$status = $status . "configuration: $1\n";

			push @findings, $status;
		}
		else {
			if ($line !~ /\bsnmp-server.*\b/)  {
			my $status = "\n\nCheck 26: Unrestricted SNMP management and monitoring\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: SNMP is not used for device management\n";

				push @findings, $status;
			}
			else {
				my @snmp = ($line =~ /\b(snmp-server community .*)\b/ig);
				if ($#snmp > "-1") {
					my (@listno, @unsafe, @temp_unsafe1);
					foreach my $snmp (@snmp) {
						if ($snmp =~ /snmp-server community .* (\d+)$/i) {
							push @listno, $1;
						}
						else {
							push @unsafe , $snmp;
						}
					}

					if ($#unsafe > "-1")  {
						my $status = "\n\nCheck 26: Unrestricted SNMP management and monitoring\n\n";
						$status = $status . "Status: Unsafe\n";
						$status = $status . "Unsafe Factor: Access list is not configured to restrict the SNMP access\n";
						$status = $status . "Configuration: Access list is not applied on following SNMP communities: ";

						my $vty_lines = "";
						foreach my $unsafe (@unsafe) {
								$vty_lines = $vty_lines . $unsafe. ", ";
						}
						$vty_lines =~ s/,\s+$//;
						$status = $status . $vty_lines . "\n";

						push @findings, $status;
					}
					else {
						my %list;
						foreach (@listno) {
							$list {$_} = "1";
						}
						my @list_no = keys (%list);

						foreach my $access_list_no (@list_no) {
							my @access_list = ($line =~ /(access-list\s+\b$access_list_no\b.*)/ig);
							if ($#access_list > "-1") {
								# SAFE
							}
							else {
								push @temp_unsafe1, $access_list_no;
							}
						}

						if ($#temp_unsafe1 > "-1") {
							my $status = "\n\nCheck 26: Unrestricted SNMP management and monitoring\n\n";
							$status = $status . "Status: Unsafe\n";
							$status = $status . "Unsafe Factor: Following undefined Access list is applied on SNMP: ";

							my $vty_lines = "";
							foreach my $unsafe (@temp_unsafe1) {
									$vty_lines = $vty_lines . $unsafe. ", ";
							}
							$vty_lines =~ s/,\s+$//;
							$status = $status . $vty_lines . "\n";

							push @findings, $status;


						}
						else {
							my $status = "\n\nCheck 26: Unrestricted SNMP management and monitoring\n\n";
							$status = $status . "Status: Safe\n";
							$status = $status . "Safe Factor: Access list are applied on the SNMP communities\n";

							push @findings, $status;

						}
					}
				}
				else {
					my $status = "\n\nCheck 26: Unrestricted SNMP management and monitoring\n\n";
					$status = $status . "Status: Safe\n";
					$status = $status . "Safe Factor: Community strings are not configured on the device\n";

					push @findings, $status;
				}
			}
		}



#------------------------------------------------------------------------------------------------------------------------------
		# Check 27 : Auxiliary Port is Not Disabled
		if ($#auxlines >= 0) {
			my (@temp_safe, @temp_unsafe);
			foreach my $vtyline (@auxlines) {

				if ($vtyline =~ /\b(no\sexec|transport\sinput\snone)\b/) {
					($vtyline =~ /(line\s+aux(?:.*))/);
					 push @temp_safe, $1;
				}
				else{
					($vtyline =~ /(line\s+aux(?:.*))/);
					 push @temp_unsafe, $1;
				}
			}

			if ($#temp_unsafe > "-1") {
				my $status = "\n\nCheck 27 : Auxiliary Port is Not Disabled\n\n";
				$status = $status . "Status: Unsafe\n";
				$status = $status . "Unsafe Factor: Auxiliary port is configured for remote administration\n";
				$status = $status . "Configuration: Following AUX lines are configured: ";
				my $vty_lines = "";
				foreach my $unsafe (@temp_unsafe) {
						$vty_lines = $vty_lines . $unsafe. ", ";
				}
				$vty_lines =~ s/,\s+$//;
				$status = $status . $vty_lines . "\n";

				push @findings, $status;
			}
			else {
				my $status = "\n\nCheck 27 : Auxiliary Port is Not Disabled\n\n";
				$status = $status . "Status: Safe\n";
				$status = $status . "Safe Factor: Auxiliary port is disabled for remote administration\n";

				push @findings, $status;
			}
		}
		else  {
			my $status = "\n\nCheck 27 : Auxiliary Port is Not Disabled\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: Auxliliary port is not configured for remote administration\n";

			push @findings, $status;
		}




#------------------------------------------------------------------------------------------------------------------------------
		# Check 28 : Old Vulnerable Version of SSH Being Used
		
		# verions check because ssh version 2 is not supported IOS versions below 12.0
		($line =~ /\nversion\s+(.*)/i);
		my $version_no = $1;

		if ($version_no > 12.0) {
			# VTY Lines
			if ($#vtylines > "-1") {
				my (@temp_unsafe3);

				foreach my $vtyline (@vtylines) {
					if ($vtyline =~ /\b(no\sexec|transport\sinput\snone)\b/) {
						# SAFE VTY line is disabled
					}
		                        else {
						push @temp_unsafe3, "enabled";		            	
					}
				}


				if ($#temp_unsafe3 > "-1") {
					if ($line =~ /\b(ip ssh version 2)\b/i) {
						my $status = "\n\nCheck 28 : Old Vulnerable Version of SSH Being Used\n\n";
						$status = $status . "Status: Safe\n";
						$status = $status . "Safe Factor: SSH version 2 is in use\n";

						push @findings, $status;
					}
					elsif ($line =~ /\b(ip ssh version 1)\b/i) {
						my $status = "\n\nCheck 28 : Old Vulnerable Version of SSH Being Used\n\n";
						$status = $status . "Status: Unsafe\n";
						$status = $status . "Safe Factor: SSH version 1 is in use\n";

						push @findings, $status;
					}		
					else {
						my $status = "\n\nCheck 28 : Old Vulnerable Version of SSH Being Used\n\n";
						$status = $status . "Status: Not Applicable\n";
						$status = $status . "Factor: SSH is not enabled on the device\n";

						push @findings, $status;
					}
				}
				else  {
					my $status = "\n\nCheck 28 : Old Vulnerable Version of SSH Being Used\n\n";
					$status = $status . "Status: Not Applicable\n";
					$status = $status . "Factor: Remote Administration is disabled\n";

					push @findings, $status;
				}
			}
			else  {
				my $status = "\n\nCheck 28 : Old Vulnerable Version of SSH Being Used\n\n";
				$status = $status . "Status: Not Applicable\n";
				$status = $status . "Factor: Remote Administration is disabled\n";

				push @findings, $status;
			}

		}
		else {
			my $status = "\n\nCheck 28 : Old Vulnerable Version of SSH Being Used\n\n";
			$status = $status . "Status: Unsafe\n";
			$status = $status . "Unsafe Factor: Cisco IOS version less than 12.1 is installed on device. It does not support SSH version 2.\n";

			push @findings, $status;
		}
		

#------------------------------------------------------------------------------------------------------------------------------
		# Check 30 : Incorrect Time & Time zone setting
		if ($line =~ /\b(clock timezone .*)\b/i)  {
			my $timezone = $1;
			my $status = "\n\nCheck 30 : Incorrect Time & Time zone setting\n\n";
			$status = $status . "Status: Manual Review\n";
			$status = $status . "Configuration: Following timezone is configured. Manually Review it: $timezone\n";

			# Summer time
			if ($line !~ /\b(clock summer-time.*)\b/i) {
				# Summer time is not configured only....
				$status = $status . "\nStatus: Manual Review\n";
				$status = $status . "Summer-time Configuration: Check over internet if the country follows Daylight Saving Time. If it follows, then mark this check as UNSAFE as they must configure 'clock summer-time' command along with 'clock timezone' command on device. If country does not follow Daylight Saying Time, then decide safe/unsafe based on timezone setting.";
			}
			else {
				# Summer time is configured but is it set to correct timezone?
				$status = $status . "\nStatus: Manual Review\n";
				$status = $status . "Summer-time Configuration: Check over internet if the country follows Daylight Saving Time. 'clock summer-time' command is configured. Check for the timezone and other settings as per checklist.\nSummer time Setting: $1";				
			}
			
			push @findings, $status;
		}
		else {
			my $status = "\n\nCheck 30 : Incorrect Time & Time zone setting\n\n";
			
			# Time zone
			$status = $status . "Status: Manual Review\n";
			$status = $status . "Timezone Configuration: Timezone is not configured on the device. Check the output of the 'sh clock' command in the configuration to see what timezone is set by default.\n";
	
			# Summer time
			if ($line !~ /\b(clock summer-time.*)\b/i) {
				# Summer time is not configured only....
				$status = $status . "\nStatus: Manual Review\n";
				$status = $status . "Summer-time Configuration: Check over internet if the country follows Daylight Saving Time. If it follows, then mark this check as UNSAFE as they must configure 'clock summer-time' command along with 'clock timezone' command on device. If country does not follow Daylight Saying Time, then decide safe/unsafe based on timezone setting.";
			}
			else {
				# Summer time is configured but is it set to correct timezone?
				$status = $status . "\nStatus: Manual Review\n";
				$status = $status . "Summer-time Configuration: Check over internet if the country follows Daylight Saving Time. 'clock summer-time' command is configured. Check for the timezone and other settings as per checklist.\nSummer time Setting: $1";				
			}

			push @findings, $status;
		}

		# ------------------------------------------------
		# Preparation :-)

		my (@interfaces, @open_interfaces, @valid_interfaces, @check20, @check21, @check22, @check25, @check19_v11, @check19_v12, @check16_mop, @check16_no_mop, @check29_absence, @check29_presence, @check29_access_list) = ();
		
		# Capturing all the interfaces present on the device
		@interfaces = ( $line =~ /\n(interface\s(?:.*?)!)/igs );

		if ($#interfaces >= 0) {
			# Interface - shutdown or not and whether ip address is configured on that interface ?
			foreach my $interface (@interfaces) {
				if (($interface !~ /shutdown/i) && ($interface =~ /ip address (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)/i)) {
					push @open_interfaces, $interface;
				}
			}
			# Interface - Exceptional case for interfaces having both ip address and switchport access vlan command
			foreach my $interface (@open_interfaces) {
				if (($interface !~ /switchport access vlan \d+/i) && ($interface =~ /ip address (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)/i)) {
					push @valid_interfaces, $interface;
				}
			}
			
			if ($#valid_interfaces > "-1") {
				foreach my $vtyline (@valid_interfaces) {

					#Check 20
					if ($vtyline !~ /no ip unreachables/i) {
						($vtyline =~ /interface\s(.*)/i);
						push @check20, $1;
					}

					#Check 21
					if ($vtyline =~ /ip mask-reply/i) {
						($vtyline =~ /interface\s(.*)/i);
						push @check21, $1;
					}

					#Check 22
					if ($vtyline !~ /no ip redirects/i) {
						($vtyline =~ /interface\s(.*)/i);
						push @check22, $1;
					}

					#Check 25
					if ($vtyline !~ /no ip proxy-arp/i) {
						($vtyline =~ /interface\s(.*)/i);
						push @check25, $1;
					}

					#Check 19
					($line =~ /\nversion\s+(.*)/i);
					my $version = $1;
					if ($version < 12) {
						if ($vtyline !~ /no ip directed-broadcast/i) {
							($vtyline =~ /interface\s(.*)/i);
							push @check19_v11, $1;
						}
					}
					else {
						if ($vtyline =~ /ip directed-broadcast/i) {
							($vtyline =~ /interface\s(.*)/i);
							push @check19_v12, $1;
						}
					}

					#Check 16
					if ($vtyline !~ /no mop enabled/i) {
						($vtyline =~ /interface\s(.*)/i);
						push @check16_no_mop, $1;
					}
					if ($vtyline =~ /mop enabled/i) {
						($vtyline =~ /interface\s(.*)/i);
						push @check16_mop, $1;
					}

					# Check 29
					if ($vtyline !~ /ip access-group/i) {
						($vtyline =~ /interface\s(.*)/i);
						push @check29_absence, $1;
					}
					else {
						($vtyline =~ /interface\s(.*)/i);
						push @check29_presence, $1;

						my @acs_group = ($vtyline =~ /ip access-group\s+\d+\s+in/isg);
						foreach my $accesslist (@acs_group) {
							($accesslist =~ /ip access-group (\d+) in/i);
							push @check29_access_list, $1;
						}
					}
				}
				# -------------------------------------------------------

				# Check 20 : Device sends IP unreachable messages
				my $status1 = "\n\nCheck 20 : Device sends IP unreachable messages\n\n";
				if ($#check20 >= 0) {
					$status1 = $status1 . "Status: Unsafe\n";
					$status1 = $status1 . "Unsafe Factor: Interfaces are configured without \"no ip unreachables\" command\n";
					$status1 = $status1 . "Configuration: Following interfaces are without the \"no ip unreachables\" configuration:-\n";

					my $vty_lines = "";
					foreach my $unsafe (@check20) {
							$vty_lines = $vty_lines . $unsafe. ", ";
					}
					$vty_lines =~ s/,\s+$//;
					$status1 = $status1 . $vty_lines . "\n";

					push @findings, $status1;
				}
				else {
					$status1 = $status1 . "Status: Safe\n";
					$status1 = $status1 . "Safe Factor: \"no ip unreachables\" command is configured on each interface\n";

					push @findings, $status1;
				}

				# Check 21 : Device sends ICMP mask-reply
				my $status2 = "\n\nCheck 21 : Device sends ICMP mask-reply\n\n";
				if ($#check21 >= 0) {
					$status2 = $status2 . "Status: Unsafe\n";
					$status2 = $status2 . "Unsafe Factor: Interfaces are configured with \"ip mask-reply\" command\n";
					$status2 = $status2 . "Configuration: Following interfaces are with the \"ip mask-reply\" configuration:-\n";

					my $vty_lines = "";
					foreach my $unsafe (@check21) {
							$vty_lines = $vty_lines . $unsafe. ", ";
					}
					$vty_lines =~ s/,\s+$//;
					$status2 = $status2 . $vty_lines . "\n";

					push @findings, $status2;
				}
				else {
					$status2 = $status2 . "Status: Safe\n";
					$status2 = $status2 . "Safe Factor: \"ip mask-reply\" command is not configured on any interface\n";

					push @findings, $status2;
				}

				# Check 22 : Device sends IP redirects
				my $status3 = "\n\nCheck 22 : Device sends IP redirects\n\n";
				if ($#check22 >= 0) {
					$status3 = $status3 . "Status: Unsafe\n";
					$status3 = $status3 . "Unsafe Factor: Interfaces are configured without \"no ip redirects\" command\n";
					$status3 = $status3 . "Configuration: Following interfaces are without the \"no ip redirects\" configuration:-\n";

					my $vty_lines = "";
					foreach my $unsafe (@check22) {
							$vty_lines = $vty_lines . $unsafe. ", ";
					}
					$vty_lines =~ s/,\s+$//;
					$status3 = $status3 . $vty_lines . "\n";

					push @findings, $status3;
				}
				else {
					$status3 = $status3 . "Status: Safe\n";
					$status3 = $status3 . "Safe Factor: \"no ip redirects\" command is configured on each interface\n";

					push @findings, $status3;
				}

				# Check 25 : Proxy ARP is Not Disabled
				my $status4 = "\n\nCheck 25 : Proxy ARP is Not Disabled\n\n";
				if ($#check25 >= 0) {
					$status4 = $status4 . "Status: Unsafe\n";
					$status4 = $status4 . "Unsafe Factor: Interfaces are configured without \"no ip proxy-arp\" command\n";
					$status4 = $status4 . "Configuration: Following interfaces are without the \"no ip proxy-arp\" configuration:-\n";

					my $vty_lines = "";
					foreach my $unsafe (@check25) {
							$vty_lines = $vty_lines . $unsafe. ", ";
					}
					$vty_lines =~ s/,\s+$//;
					$status4 = $status4 . $vty_lines . "\n";

					push @findings, $status4;
				}
				else {
					$status4 = $status4 . "Status: Safe\n";
					$status4 = $status4 . "Safe Factor: \"no ip proxy-arp\" command is configured on each interface\n";

					push @findings, $status4;
				}

				# Check 19 : Device processes directed broadcasts
				my $status5 = "\n\nCheck 19 : Device processes directed broadcasts\n\n";
				if ($#check19_v11 >= 0) {
					$status5 = $status5 . "Status: Unsafe\n";
					$status5 = $status5 . "Unsafe Factor: Interfaces are configured without \"no ip directed-broadcast\" command\n";
					$status5 = $status5 . "Configuration: Following interfaces are without the \"no ip directed-broadcast\" configuration:-\n";

					my $vty_lines = "";
					foreach my $unsafe (@check19_v11) {
							$vty_lines = $vty_lines . $unsafe. ", ";
					}
					$vty_lines =~ s/,\s+$//;
					$status5 = $status5 . $vty_lines . "\n";

					push @findings, $status5;
				}
				elsif ($#check19_v12 >= 0) {
					$status5 = $status5 . "Status: Unsafe\n";
					$status5 = $status5 . "Unsafe Factor: Interfaces are configured with \"ip directed-broadcast\" command\n";
					$status5 = $status5 . "Configuration: Following interfaces are with the \"ip directed-broadcast\" configuration:-\n";

					my $vty_lines = "";
					foreach my $unsafe (@check19_v12) {
							$vty_lines = $vty_lines . $unsafe. ", ";
					}
					$vty_lines =~ s/,\s+$//;
					$status5 = $status5 . $vty_lines . "\n";

					push @findings, $status5;
				}
				else {
					$status5 = $status5 . "Status: Safe\n";
					$status5 = $status5 . "Safe Factor: Devices are securely configured for not to process directed broadcast\n";

					push @findings, $status5;
				}

				# Check 29 : Anti-Spoof access control lists are not configured
				my $status6 = "\n\nCheck 29 : Anti-Spoof access control lists are not configured\n\n";

				if ($#check29_absence > "-1") {
					$status6 = $status6 . "Status: Unsafe\n";
					$status6 = $status6 . "Unsafe Factor: Interfaces are configured without \"ip access-group\" command\n";
					$status6 = $status6 . "Configuration: Following interfaces are without the \"ip access-group\" configuration:-\n";

					my $vty_lines = "";
					foreach my $unsafe (@check29_absence) {
							$vty_lines = $vty_lines . $unsafe. ", ";
					}
					$vty_lines =~ s/,\s+$//;
					$status6 = $status6 . $vty_lines . "\n";

					push @findings, $status6;

				}
				if ($#check29_presence > "-1") {
					my %ac_list;
					foreach (@check29_access_list) {
						$ac_list {$_} = "1";
					}
					my @access_list_no = keys(%ac_list);
					my @unsafe;
					foreach my $list_no (@access_list_no) {
						my $count=0;
	
						if ($line !~ /access-list $list_no deny icmp any any redirect/) {
							$count++;
						}
						if ($line !~ /access-list $list_no deny 127.0.0.0 0.255.255.255 any log/) {
							$count++;
						}
						if ($line !~ /access-list $list_no deny 224.0.0.0 0.255.255.255 any log/) {
							$count++;
						}
						if ($line !~ /access-list $list_no deny ip host 0.0.0.0 any log/) {
							$count++;
						}
						if ($line !~ /access-list $list_no deny ip (10\.\d+\.\d+\.\d+) .* any log/) {
							$count++;
						}
						if ($line !~ /access-list $list_no deny ip (172\.{16-32}\.\d+\.\d+) .* any log/) {
							$count++;
						}
						if ($line !~ /access-list $list_no deny ip (192\.168\.\d+\.\d+) .* any log/) {
							$count++;
						}
						if ($line !~ /access-list $list_no deny ip (128\.0.\d+\.\d+) .* any log/) {
							$count++;
						}
						if ($line !~ /access-list $list_no deny ip (192\.0\.0.\d+) .* any log/) {
							$count++;
						}
						if ($line !~ /access-list $list_no deny ip ({224-254}\.0\.0\.0) .* any log/) {
							$count++;
						}
						if ($line !~ /access-list $list_no deny ip (191\.255\.\d+\.\d+) .* any log/) {
							$count++;
						}
						if ($count > 0) {
							push @unsafe, $list_no;						
						}						
					}
					
					my $status7;
					
					if ($#unsafe > "-1") {
						my $status6 = "";
						my $vty_lines = "";
						foreach my $unsafe (@unsafe) {
								$vty_lines = $vty_lines . $unsafe. ", ";
						}
						$vty_lines =~ s/,\s+$//;
						$status6 = $status6 . $vty_lines . "\n";
						chomp ($status6);
				
						$status7 = "Configuration: Anti-spoof ACLs- $status6 are not properly configured for Reserved IPs and Internal IPs \n";
					}
					else {
						$status7 = "Configuration: Anti-spoof ACLs are properly configured\n";
					}

					push @findings, $status7;
				}
			}
			else {
				my $status = "\n\nChecks: 19, 20, 21, 22, 25, 29\n\n";
				$status = $status . "Status: Safe\n";
				$status = $status . "Safe Factor: All the interfaces are shutdown\n";

				push @findings, $status;
			}
		}
		else {
				my $status = "\n\nChecks: 19, 20, 21, 22, 25, 29\n\n";
				$status = $status . "Status: Safe\n";
				$status = $status . "Safe Factor: No interfaces are present in the devices\n";

				push @findings, $status;
		}



#--------------------------------------------------------------------------------------------------------------------------------------
		# Check 17: CDP is running
		my $status = "\n\nCheck 17 : CDP is running\n\n";

		if ( $line =~ /no cdp run/i ) {
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: \"no cdp run\" command is configured on device\n";

			push @findings, $status;
		}
		else {		
			my (@interfc, @open_interfc, @check17);

			# Capturing all the interfaces present on the device
			@interfc = ( $line =~ /\n(interface\s(?:.*?)!)/igs );

			if ($#interfc >= 0) {
				# Interface - shutdown or not and whether ip address is configured on that interface ?
				foreach my $interface (@interfc) {
					if ($interface !~ /shutdown/i) {
						push @open_interfc, $interface;
					}
				}

				foreach my $vtyline (@open_interfc) {
					if ($vtyline !~ /no cdp enable/i) {
						($vtyline =~ /interface\s(.*)/i);
						push @check17, $1;
					}
				}


				if ($#check17 >= 0) {
					$status = $status . "Status: Unsafe\n";
					$status = $status . "Unsafe Factor: Interfaces are configured without \"no cdp enable\" command\n";
					$status = $status . "Configuration: Following interfaces are without the \"no cdp enable\" configuration:-\n";

					my $vty_lines = "";
					foreach my $unsafe (@check17) {
							$vty_lines = $vty_lines . $unsafe. ", ";
					}
					$vty_lines =~ s/,\s+$//;
					$status = $status . $vty_lines . "\n";

					push @findings, $status;
				}
				else {
					$status = $status . "Status: Safe\n";
					$status = $status . "Safe Factor: \"no cdp enable\" command is configured on each interface\n";

					push @findings, $status;
				}
			}	
			else {
					my $status = "\n\nCheck 17 : CDP is running\n\n";
					$status = $status . "Status: Safe\n";
					$status = $status . "Safe Factor: No interfaces are present on the devices\n";

					push @findings, $status;
			}
		}

#--------------------------------------------------------------------------------------------------------------------------------------
		# Check 16 : Unnecessary services running
		my @services = ();

		# Version Independant services
		if ( $line !~ /\bno ip bootp server\b/i ) {
			push @services , "BOOTP";
		}
		if ( $line !~ /no service pad/i ) {
			push @services , "PAD";
		}
		if ( $line !~ /no service dhcp/i ) {
			push @services , "DHCP";
		}
		if ( $line =~ /IP identd/i ) {
			push @services , "IDENTD";
		}
		if ( $line =~ /ip http server enable/i ) {
			push @services , "HTTP";
		}

		# Version dependant services
		($line =~ /\nversion\s+(.*)/i);
		my $version = $1;

		if ($version > 11.2) {
			if ( $line =~ /service tcp-small-servers/i ) {
				push @services , "tcp-small-servics";
			}
			if ( $line =~ /service udp-small-servers/i ) {
				push @services , "udp-small-servers";
			}
		}
		if ($version < 12.1) {
			if ( $line !~ /no service finger/i ) {
				push @services , "Finger";
			}
		}
		if ($version < 12.2) {
			if ( $line !~ /no ip domain-lookup/i ) {
				push @services , "DNS";
			}
		}
		else {
			if ( $line !~ /no ip domain lookup/i ) {
				push @services , "DNS";
			}
		}

		my $status7 = "\n\nCheck 16 : Unnecessary services running\n\n";

		if (($#services > "-1") || ($#check16_mop > "-1") || ($#check16_no_mop > "-1")) {
			$status7 = $status7 . "Status: Review\n";
			$status7 = $status7 . "Configuration: Review the requirement of the following services: \n";

			if ($#services > "-1")  {
					my $vty_lines = "";
					foreach my $unsafe (@services) {
							$vty_lines = $vty_lines . $unsafe. ", ";
					}
					$vty_lines =~ s/,\s+$//;
					$status7 = $status7 . $vty_lines . "\n";
			}

			if ($#check16_no_mop > "-1") {
				$status7 = $status7 . "\nStatus: Review\n";
				$status7 = $status7 . "Service Mop: Ethernet\n";
				$status7 = $status7 . "Configuration: Review that the interfaces listed below are ethernet only: \n";

				my $vty_lines = "";
				foreach my $unsafe (@check16_no_mop) {
						$vty_lines = $vty_lines . $unsafe. ", ";
				}
				$vty_lines =~ s/,\s+$//;
				$status7 = $status7 . $vty_lines . "\n";
			}

			if ($#check16_mop > "-1") {
				$status7 = $status7 . "\nStatus: Review\n";
				$status7 = $status7 . "Service Mop: Other Interfaces (Exclude Ethernet Interfaces)\n";
				$status7 = $status7 . "Configuration: Review that the interfaces listed below are not ethernet interfaces: \n";

				my $vty_lines = "";
				foreach my $unsafe (@check16_mop) {
						$vty_lines = $vty_lines . $unsafe. ", ";
				}
				$vty_lines =~ s/,\s+$//;
				$status7 = $status7 . $vty_lines . "\n";
			}

			push @findings, $status7;
		}
		else {
			$status7 = $status7 . "Status: Safe\n";
			$status7 = $status7 . "Safe Factor: Unnecesary services are not running\n";

			push @findings, $status7;
		}




#--------------------------------------------------------------------------------------------------------------------------------------
		# Check 23: UDP broadcast forwarding is enabled
		if ($line !~ /ip helper-address.*/i) {
			my $status = "\n\nCheck 23: UDP broadcast forwarding is enabled\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: Device does not redirect UDP broadcasts\n";

			push @findings, $status;
		}
		else {
			if ($line !~ /no ip forward-protocol udp (\d+)/i) {
				my $status = "\n\nCheck 23: UDP broadcast forwarding is enabled\n\n";
				$status = $status . "Status: Unsafe\n";
				$status = $status . "Unsafe Factor: Default forwarding UDP protocol is not disabled\n";

				push @findings, $status;
			}
			else {
				my @temp_unsafe = ();
				my @port_nos = ($line =~ /no ip forward-protocol udp (\d+)/ig);
				foreach my $port (@port_nos) {
					if ( ($port ne "37") || ($port ne "49") || ($port ne "42") || ($port ne "53") || ($port ne "69") || ($port ne "137") || ($port ne "138") || ($port ne "67") || ($port ne "68"))  {
						push @temp_unsafe, $port;	
					}
				}
				if ($#temp_unsafe > "-1")  {
					my $status = "\n\nCheck 23: UDP broadcast forwarding is enabled\n\n";
					$status = $status . "Status: Unsafe\n";
					$status = $status . "Unsafe Factor: Default forwarding UDP protocol is not disabled\n";
					$status = $status . "Configutation: Default forwarding UDP protocol is disabled only on following ports: ";

					my $vty_lines = "";
					foreach my $unsafe (@temp_unsafe) {
							$vty_lines = $vty_lines . $unsafe. ", ";
					}
					$vty_lines =~ s/,\s+$//;
					$status = $status . $vty_lines . "\n";

					push @findings, $status;
				}
				else {
					my $status = "\n\nCheck 23: UDP broadcast forwarding is enabled\n\n";
					$status = $status . "Status: Safe\n";
					$status = $status . "Safe Factor: Default forwarding UDP protocol is disabled\n";

					push @findings, $status;
				}
			}
		}



#--------------------------------------------------------------------------------------------------------------------------------------
		# Check 10 : Insecure RIP Configuration
		if ( $line !~ /\n\brouter rip\b/i ) {
			my $status = "\n\nCheck 10 : Insecure RIP Configuration\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: RIP protocol is not configured\n";

			push @findings, $status;
		}
		else {
			my $status = "\n\nCheck 10 : Insecure RIP Configuration\n\n";
			$status = $status . "Status: Manual Review\n";
			$status = $status . "Configuration: RIP protocol is configured, Manually Review it.\n";

			push @findings, $status;
		}


#--------------------------------------------------------------------------------------------------------------------------------------
		# Check 11 : Insecure EIGRP configuration
		if ( $line !~ /\n\brouter eigrp\b/i ) {
			my $status = "\n\nCheck 11 : Insecure EIGRP configuration\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: EIGRP protocol is not configured\n";

			push @findings, $status;
		}
		else {
			my $status = "\n\nCheck 11 : Insecure EIGRP configuration\n\n";
			$status = $status . "Status: Manual Review\n";
			$status = $status . "Configuration: EIGRP protocol is configured, Manually Review it.\n";

			push @findings, $status;
		}



#--------------------------------------------------------------------------------------------------------------------------------------
		# Check 12 : Insecure OSPF configuration
		if ( $line !~ /\n\brouter ospf\b/i ) {
			my $status = "\n\nCheck 12 : Insecure OSPF configuration\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: OSPF protocol is not configured\n";

			push @findings, $status;
		}
		else {
			my $status = "\n\nCheck 12 : Insecure OSPF configuration\n\n";
			$status = $status . "Status: Manual Review\n";
			$status = $status . "Configuration: OSPF protocol is configured, Manually Review it.\n";

			push @findings, $status;
		}



#--------------------------------------------------------------------------------------------------------------------------------------
		# Check 13 : Insecure BGP configuration
		if ( $line !~ /\n\brouter bgp\b/i ) {
			my $status = "\n\nCheck 13 : Insecure BGP configuration\n\n";
			$status = $status . "Status: Safe\n";
			$status = $status . "Safe Factor: BGP protocol is not configured\n";

			push @findings, $status;
		}
		else {
			my $status = "\n\nCheck 13 : Insecure BGP configuration\n\n";
			$status = $status . "Status: Manual Review\n";
			$status = $status . "Configuration: BGP protocol is configured, Manually Review it.\n";

			push @findings, $status;
		}


#--------------------------------------------------------------------------------------------------------------------------------------
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
