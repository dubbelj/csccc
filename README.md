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

##### Documentation
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

The switch configuration file is parsed as different sections first it is: 
```
_main_section
``` 
Here is settings like 'hostname' and 'vtp mode' etc defined.

Then everywhere in the configuration where the next row is begining with a space it is considered as a section. Ex.
```
interface FastEthernet0
 no ip address
 shutdown
interface GigabitEthernet1/0/1
 description MyPort
```
Get defined as section 'interface FastEthernet0' and section 'interface GigabitEthernet1/0/1'

