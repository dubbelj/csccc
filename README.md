# csccc
Cisco Switch Configuration Compliance Checker

##### Usage
```
csccc.pl <-f switch_configuration_file> [-c template_file] [-v] [-e]
	-v: Verbose output. This will print out not only DEVIATIONS but aswell where compliance is OK and WARNINGS.
	-e: Print out the comments from template file so it can explain what the match is supposed to check.
	-c: A template file to check against. If not given the script will use default template from "sub return_default_conf"
	-f: Cisco switch configuration file to check (Mandatory option)
```

##### Basic Documentation
The script parses a Cisco switch configuration file and match it against a rulebase to check that expected settings is set.

So for example. We have the switch configuration "/tmp/myswitch.conf" we like to verify that 'ntp server' have been defined, then make a file "/tmp/mytemplate.conf" containing
```
ntp server .* # A NTP server should be set
```
Then run
```
./csccc.pl -f /tmp/myswitch.conf -c /tmp/mytemplate.conf
```
If your config does have NTP defined, you should not get any output (unless -v flag is used.).
But if your config does not have NTP defined you should get something like:
```
./csccc.pl -f /tmp/myswitch.conf -c /tmp/mytemplate.conf
DEVIATION: 'ntp server .*' set and was NOT found in file.
```
and if you add the -e option:
```
./csccc.pl -e -v -f /tmp/myswitch.conf -c /tmp/mytemplate.conf
# A NTP server should be set
DEVIATION: 'ntp server .*' set and was NOT found in file.
```

The matching is used with perl regular expressions https://perldoc.perl.org/perlre.html
so if you like to be specific to match one particular ntp server, edit mytemplate.conf to be. As '.' is matched as any character you need to prepend with '\' to match '.' otherwise example "poolsntp.org" may pass as OK.
```
# Use pool.ntp.org as NTP source
ntp server pool\.ntp\.org
```

Aswell as checking if something is found in the configuration we can verify that something is NOT found.
In this example we want to check that enable password is not set. (type 7 passwords are easy to crack)
Then we add '!' in the begining to mark that the value should not be found.
Add this to the template.
```
# Do not use enable password as they are easy cracked
!enable password
# A enable secret should be set
enable secret
```

##### Advanced Documentation
You may want to check that if some option exist in the configuration, then another option should be set aswell.
This is done by adding the secondary option within '{' '}' after the first option. 
In this example, check if central european timezone, summertime settings need to be set (to se or CEST) aswell.
Then add this to template file:
```
# If central european timezone, summertime settings need to be set (to se or CEST)
clock timezone CET 1{
	clock summer-time [sC][eE]S*T* recurring last Sun Mar 2:00 last Sun Oct 2:00
}
```

The switch configuration file is parsed as different sections first it is: 
```
_main_section
``` 
Here is settings like 'hostname' and 'vtp mode' etc defined.

Then everywhere in the configuration where the next row is begining with a space it is considered as a section.
Ex.
```
interface FastEthernet0
 no ip address
 shutdown
interface GigabitEthernet1/0/1
 description MyPort
line con 0
 exec-timeout 60 0
```
This defined as sections 'interface FastEthernet0', 'interface GigabitEthernet1/0/1' and 'line con 0'

So we can match if a interface description contain "access", we like to verify that the interface do not log port up/down messages. And if it have 802.1x AND mab enabled the settings are entered in the correct order.
```
# If interface description match access
# It should not logg when con/disconnected.
description .*access.*{
	no logging event link-status
	dot1x pae authenticator{
		mab{
			# If 802.1x and mab is enabled, verify that order/priority is set.
			authentication order mab dot1x
			authentication priority dot1x mab
		}
	}
}
```

Further we can add option "==>" to do a force check in a specific section.
In all line sections a timeout should be defined.
```
line .*==>exec-timeout # A exec timeout should be set
```

In this example. If description is missing and we are in a section "interface ", then shutdown should be found.
So check that all interfaces that do not have a port description should be shutdown.
```
## All interfaces that do not have a description should be shutdown.
!description{
	interface .*==>shutdown
}
```

If '#' is used in port descriptions etc it can be escaped with '\' for pattern maching
```
# If "#" is used used in configuration matching it need to be escaped with "\", as it is for comments in this configuration file
description \#\# This is not a comment \#\#{ # Here is the comment...
	shutdown
}
```


#Have fun!
