# cisco_ios_config_audit
Perl scripts to automate security configuration review for CISCO IOS devices including Router and Switches

------------------------------------------------------------------------------
Prerequisites: 

Install Perl on you system :-
On Windows: ActivePerl
On Linux: Perl (In most distributions, it comes preinstalled)
------------------------------------------------------------------------------

Follow these steps to get the output :-)

1. Opne the directory... 
	catalyst_Switch_catOS 	 -> For Catalyst Switches
	cisco_Router_IOS	 -> For Cisco Routers
	cisco_Switch_IOS	 -> For Cisco Switches (Both Layer 2 as well as layer 3)

	You will observe 2 directories viz... "configurations" and "reports" and one Perl script file
 
2. Copy all the configuration files in the "configurations" directory

3. Open command Prompt in case of windows OS or terminal in Linux.

4. Move to the directory using cd command:
	
	cd <directory name>

5. Run Perl file present in the directory by following command:

	perl filename.pl

6. Reports will be generated in the "reports" directory.
------------------------------------------------------------------------------


When to carry out the analysis Manually?  :(
-> Only when in the analysis report, you are observing "Manually Review".
	
------------------------------------------------------------------------------


For all your feedbacks/doubts/issues, Kindly mail me @ sonawanevs@gmail.com :D


Cheers!
Vaibhav Sonawane
