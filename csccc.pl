#!/usr/bin/perl -w
# Cisco Switch Configuration Compliance Checker
# script to check that options is set in cisco switch configuration files
# created 2017-08-02 by Jacob Jacobson
# v. 1.0 initial config
#
# 
use strict;
use Getopt::Std;
my $name_of_main_section="_main_section";
my $defaultconfig=return_default_conf();

my %opts=();
my %conf;
my @always_section=("^interface .*"); # Always create a section if this is matched

get_cmd_options();

# We should now have a readable file and config hash to match.
# Ready to rock and roll...
# Read in the file to check into a hash.

my %hfile;
#dprint ("DEBUG: calling parse_file_to_hash\n");
parse_file_to_hash();

#dprint ("DEBUG: config hash;\n");
#phash(\%conf);
#dprint ("DEBUG: file hash;\n");
#phash(\%hfile);
#dprint ("DEBUG: end hash dump.\n");

#dprint ("DEBUG: calling check_config_to_file\n");
check_config_to_file(\%conf);

sub check_config_to_file{
	my $ptrhash=shift;
	my %hash=%$ptrhash;
	my $dependency=shift;
	# Start looping the configuration hash.
	foreach (sort my_conf_key_sort keys %hash){
		#dprint ("DEBUG: check_config_to_file processing '$_'\n");
		if ($hash{$_}=~/^HASH\(0x[\daAbBcCdDeEfF]+\)/){
			#dprint "DEBUG: $_ Matched a hash, recursion incomming...\n";
			my $subvalue;
			if (defined $dependency){
				# This is a subvalue
				$subvalue="$dependency->$_";
			}else{
				$subvalue="$_";
			}
					
			#dprint "DEBUG: check_config_to_file (\%{$hash{$_}},$subvalue);\n";
		 	check_config_to_file (\%{$hash{$_}},$subvalue);
		}else{
			my $value=$_;
			my $comment=$hash{$_};
			my $comment_printed=0;
			my $invert=0;
			my $invert_value="";
			my $section="";
			my $have_notified=0;
			if (/(.*)==>(.*)/){
				$section=$1; # Section is first match
				$value=$2; # Value is second match
			}
			if ($value=~/^!/){
				# result should *not* match
				$invert=1;
				$invert_value=$'; # set $invert_value to post match
			}
			# Loop all sections
			my %sub_matches=();
			foreach(sort keys %hfile){
				my $sub_section=$_;
				if ($section){
					# This is a forced section. i.e operator ==> have been used in configuration file.
					if ($sub_section=~/$section/){
						# We have a match, so continue...
						#dprint ("DEBUG: \$section=$section \$sub_section=$sub_section \$value=$value this match.\n");
					}else{
						# This do not match forced section, so we go to next section.
						#dprint ("DEBUG: \$section=$section \$sub_section=$sub_section \$value=$value NO match.\n");
						next;
					}
					#print ("DEBUG: will continue \$section=$section \$sub_section=$sub_section \$value=$value.\n");
				}
				dprint ("DEBUG: checking section '$sub_section' for '$value'\n");
				if (defined $dependency){
					$sub_matches{$sub_section}{'dependency'}=$dependency;
					my @depends=split(/->/,$dependency);
					my $allok=1;
					foreach(@depends){
						my ($wasfound,@tmp)=first_value_found_in_rest($_, keys %{$hfile{$sub_section}});
						$allok=0 unless $wasfound;
					}
					$sub_matches{$sub_section}{'dependency_allok'}=$allok;
					dprint ("DEBUG: \$dependency=$dependency \$allok=$allok\n");
				}
				# If no match was found in the section and dependencies are not met. Remove the hash value.
				my ($wasfound,@matches)=first_value_found_in_rest($value, keys %{$hfile{$sub_section}});
				if ($section){
					# this match a forced section
					my $do_check=1;
					if($dependency){
							unless ($sub_matches{$sub_section}{'dependency_allok'}){
								# As all dependencys are not ok, we don't need to do the check
								$do_check=0;
							}
					}
					if ($do_check){
						if ($wasfound){
							foreach(@matches){
								if ($invert){
									unless ($comment_printed){ eprint("$comment") ; $comment_printed=1; }
									print ("DEVIATION: '$value' set but was found in forced section '$sub_section' value '$_'");
									print (" with requirements '$dependency'") if ($dependency);
									print ("\n");
								}else{
									vprint ("OK: '$value' was found in forced section '$sub_section' value '$_'");
									vprint (" with requirements '$dependency'") if ($dependency);
									vprint ("\n");
								}
							}
						}else{
							if ($invert){
								vprint ("OK: '$value' set and was not found in forced section '$sub_section'");
								vprint (" with requirements '$dependency'") if ($dependency);
								vprint ("\n");
							}else{
								unless ($comment_printed){ eprint("$comment") ; $comment_printed=1; }
								print "DEVIATION: '$value' not found in forced section '$sub_section'";
								print (" with requirements '$dependency'") if ($dependency);
								print ("\n");
							}
						}
						$have_notified=1;
					}
				}
				dprint ("DEBUG: \$wasfound=$wasfound \@matches'@matches'\n");
				if(@matches){
					foreach(@matches){
						push(@{$sub_matches{$sub_section}{'matches'}},$_);
					}
				}
				if (not defined $sub_matches{$sub_section}{'matches'}){
					if (not $sub_matches{$sub_section}{'dependency_allok'}){
						dprint ("DEBUG: No match and no dependency match, removing hash keys for '$sub_section'.\n");
						# This entry do not match and dependencys do not match
						delete $sub_matches{$sub_section}{'dependency'};
						delete $sub_matches{$sub_section};
					}
				}
			}
			next if ($have_notified); # If we have already printed, go to next section.
			
			# dprint ("DEBUG: Content of \%sub_matches\n");
			# phash(\%sub_matches);
			if (!keys %sub_matches) {
				# No sub dependencies found
				if ($invert){
					vprint ("OK: '$value' set and was NOT found in file.\n");
				}else{
					if ($dependency){
						vprint ("WARNING: '$value' set and was NOT found in file. But requirements '$dependency' are not met.\n");
					}else{
						unless ($comment_printed){ eprint("$comment") ; $comment_printed=1; }
						print "DEVIATION: '$value' set and was NOT found in file.\n";
					}
				}
			}else{
				# Sub dependencies found are found here
				my $was_found=0;
				foreach(sort keys %sub_matches){
					my $sub_section=$_;
					if (defined $sub_matches{$sub_section}{'dependency_allok'}){
						# Dependency is defined
						if ($sub_matches{$sub_section}{'dependency_allok'}){
							# All dependencys match this section.
							if (defined $sub_matches{$sub_section}{'matches'}){
								if ($invert){
									foreach( @{$sub_matches{$sub_section}{'matches'}} ){
										unless ($comment_printed){ eprint("$comment") ; $comment_printed=1; }
										print "DEVIATION: All dependencys '$dependency' is ok. But '$invert_value' was matched in section '$sub_section' value '$_'\n";
									}
								}else{
									foreach( @{$sub_matches{$sub_section}{'matches'}} ){
										vprint ("OK: '$value' set fullfilling dependency '$dependency'. in section '$sub_section' value '$_'\n");
									}
								}
							}else{
								if ($invert){
									vprint ("OK: '$value' set fullfilling dependency '$dependency' and was not found in section '$sub_section'\n");
								}else{
									unless ($comment_printed){ eprint("$comment") ; $comment_printed=1; }
									print "DEVIATION: All dependencys '$dependency' is ok. But '$value' not found in section '$sub_section'\n";
								}
							}
						}else{
							# Not all dependencys are met.
							if (defined $sub_matches{$sub_section}{'matches'}){
									vprint ("WARNING: '$value' set and matched in section '$sub_section' but all dependencys '$dependency' are not met.\n");
							}else{
								# Dependencys are not met and no match on the line. This should not happpen.
								print "DEBUG: This should not happen... or should it?\n";
								print "DEBUG: \$sub_section:$sub_section matches:$sub_matches{$sub_section}{'matches'} dependency_allok:$sub_matches{$sub_section}{'dependency_allok'}\n";
								#phash(\%sub_matches);
							}
						}
					}else{
						if (defined $sub_matches{$sub_section}{'matches'}){
							if ($invert){
								unless ($comment_printed){ eprint("$comment") ; $comment_printed=1; }
								foreach( @{$sub_matches{$sub_section}{'matches'}} ){
									print "DEVIATION: '$invert_value' was matched in section '$sub_section' value '$_' but should not be found.\n";
								}
							}else{
								foreach( @{$sub_matches{$sub_section}{'matches'}} ){
									vprint ("OK: '$value' found in section '$sub_section' value '$_'\n");
								}
							}
						}else{
							if ($invert){
								vprint ("OK: '$value' set and was not found in section '$sub_section'\n");
							}else{
								unless ($comment_printed){ eprint("$comment") ; $comment_printed=1; }
								print "DEVIATION: '$value' not found in section '$sub_section'\n";
							}
						}
					}
				}
			}
		}
	}
}

sub parse_file_to_hash{
	open my $fh, '<', $opts{'f'} or die $!;
	my $in_section="";
	my $prev_value="";
	while (<$fh>) {
		s/\r\n/\n/g; #Convert Dos TO Unix
		chomp;
		next if (/^$/); # Continue if empty line.
		if (/^ /){
			s/^ +//; # Remove leading space.
			if ($in_section){
				#dprint ("DEBUG: \$prev_value=$prev_value; \$in_section=$in_section; \$_=$_\n");
				$hfile{"$in_section"}{"$_"}++;
			}else{
				$in_section=$prev_value;
				#dprint ("DEBUG: \$prev_value=$prev_value; \$in_section=$in_section; \$_=$_\n");
				delete $hfile{"$in_section"};
				$hfile{"$in_section"}{"$_"}++;
			}
			$prev_value="$_";
		}else{
			dprint ("DEBUG: \$prev_value='$prev_value' \$in_section='$in_section' \$_='$_'\n");
			if (defined $hfile{"$in_section"}{"__empty__key__"}){
				my $empty_key=0;
				foreach my $key (keys %{$hfile{"$in_section"}}){
					next if ("$key" eq "__empty__key__");
					$empty_key=1;
				}
				if ($empty_key){
					delete $hfile{"$in_section"}{"__empty__key__"};
					dprint ("DEBUG: Removing \$hfile{'$in_section'}{'__empty__key__'}\n");
				}
			}
			my $match_always_section=0;
			foreach my $match (@always_section){
				$match_always_section=1 if (/$match/);
			}
			if($match_always_section){
				# Define this as a key
				$in_section=$_;
				$prev_value=$_;
				$hfile{"$in_section"}{"__empty__key__"}=1;
			}else{
				$hfile{"$_"}++;
				$in_section="";
				$prev_value=$_;
			}
		}
	}
	close $fh or die $!;
	my @mainsection=();
	my @sub_sections=();
	foreach (keys %hfile){
		if ($hfile{$_}=~/^HASH\(0x[\daAbBcCdDeEfF]+\)/){
			push(@sub_sections,$_);
		}else{
			push(@mainsection,$_);
		}
	}
	foreach(@mainsection){
		# Move the main section to a sub key in the file hash, so the same method can be used for all matching, hopefully removing bugs.
		$hfile{$name_of_main_section}{"$_"}=1;
		delete $hfile{"$_"};
	}
	push(@sub_sections,$name_of_main_section);
}

sub first_value_found_in_rest{
	my $first_value=shift;
	my $invert=0;
	my @matches=();
	my $value;
	# dprint "DEBUG: first_value_found_in_rest($first_value,@_)\n";
	if ($first_value=~/^!/){
		# result should *not* match
		$invert=1;
		$first_value=$'; # Set value to look for to what's after '!'
	}
	foreach (@_){
		$value=$_;
		# dprint "DEBUG: Checking if $first_value match $value\n";
		if (/$first_value/){
			push @matches, $value;
		}
	}
	if (@matches){
		if ($invert){
			return 0, @matches;
		}else{
			return 1, @matches;
		}
	}else{
		if ($invert){
			return 1;
		}else{
			return 0;
		}
	}
}

sub parse_config{
	my $input=shift;
	my %hash;
	my $inbracket=0;
	my @bracketvalue;
	my $match;
	my $endmatch="";
	$input=~s/\r\n/\n/g; #Convert Dos TO Unix
	my @lines=split(/\n/,$input);
	my @comments=();
	foreach (@lines) {
		chomp;
		if (/#/){
			s/\\#/This_is_a_escaped_hash/g; # If a hash have been escaped it should not be replaced.
			/(#.*)/;
			my $comment=$1;
			$comment=~s/^\s+//;
			s/#.*//; # Remove comments
			s/This_is_a_escaped_hash/#/g; # Set it back
			push (@comments,$comment);
		}
		s/^\t+//; # Remove leading tabs
		s/^\s+//; # Remove leading space
		s/\s+$//; # Remove trailing space
		next if (/^$/); # Skip blank lines
		if (/{/){
			my $match=$`;
			# dprint "DEBUG: Start bracket $match\n";
			$inbracket++;
			push(@bracketvalue,$match);
			next;
		}
		if (/}/){
			$inbracket--;
			my $tmp= pop(@bracketvalue);
			# dprint "DEBUG: end bracket $tmp\n";
			next;
		}
		my $comments=join (" ",@comments);
		if (scalar @bracketvalue > 0){
			my $foo=join('\'}{\'',@bracketvalue);
			# dprint "DEBUG: eval \$hash{\'$foo\'}{'" .$_ ."'}=1\n";
			if (@comments){
				# Keep only approved characters, as we do eval and we don't know what data is in the comment.
				$comments=~tr/#a-zA-Z0-9 //dc; 
				eval "\$hash{\'$foo\'}{'$_'}='$comments'";
			}else{
				eval "\$hash{\'$foo\'}{'$_'}='set'";
			}
			@comments=();
		}else{
			# dprint "DEBUG: setting \hash{$_}=1\n";
			if (@comments){
				$hash{$_}="$comments";
			}else{
				$hash{$_}='set';
			}
			@comments=();
		}
	}
	return %hash;
}

sub get_cmd_options{
	getopts("vdef:c:", \%opts);
	help() unless defined $opts{'f'};
	unless ( -r $opts{'f'}){ help(); };
	if (defined $opts{'c'}){
		if (-r $opts{'c'}){
			my $filecontent;
			open my $fh, '<', $opts{'c'} or die $!;
				while (<$fh>) {
				$filecontent.=$_;
			}
				close $fh or die $!;
			%conf=parse_config($filecontent);
		}else{
			print STDERR "-c given but file is not readable, reding in default config\n";
			%conf=parse_config($defaultconfig);
		}
	}else{
		%conf=parse_config($defaultconfig);
	}
}

sub my_conf_key_sort{
	my $clean_a=my_clean($a);
	my $clean_b=my_clean($b);
	return $clean_a cmp $clean_b;
}

sub my_clean{
	$_=shift;
	# When comparing we like to compare the string value so remove some text for a more expected sort.
	s/^!//;
	s/^no //;
	s/.*==>//;
	return $_;
}

sub vprint{
	if (defined $opts{'v'}){
		print "@_";
	}
}

sub dprint{
	if (defined $opts{'d'}){
		print "@_";
	}
}

sub eprint{
	if (defined $opts{'e'}){
		foreach my $line (@_){
			unless ($line eq "set"){
				print "$line\n";
			}
		}
	}
}

sub help{
	print "$0 <-f file2check> [-c configurationfile] [-v] [-e]
	-v: verbose output
	-e: Print out the comments from configuration file to explain why it was matched.
	-c: script configuration file. containing what to match.
	-f: Cisco switch configuration file to check.";
	exit;
}

sub phash{
        my $ptrhash=shift;
        my %hash=%$ptrhash;
        my $tablevel=shift; $tablevel=0 unless defined $tablevel;
        my $tabs;
        my $tabchar="\t";
        for my $n (1 ... $tablevel){$tabs.="$tabchar"}
	$tabs="" if ($tablevel==0);
        foreach (sort keys %hash){
                if ($hash{$_}=~/^HASH\(0x[\daAbBcCdDeEfF]+\)/){
                        print "${tabs}$_=h{\n";
                        phash (\%{$hash{$_}}, $tablevel+1);
                        print "${tabs}}\n";
                }elsif ($hash{$_}=~/^ARRAY\(0x[\daAbBcCdDeEfF]+\)/){
                        print "${tabs}$_=a(\n";
                        # phash (\%{$hash{$_}}, $tablevel+1);
                        foreach (@{$hash{$_}}){
                                print "${tabs}${tabchar}$_\n";
                        }
                        print "${tabs})\n";
                }else{
                        print "${tabs}'$_'='$hash{$_}'\n";
                }
        }
}

sub return_default_conf{
	return '
# A hostname need to be set.
hostname .*
#Setup basic config. So ssh keys can be created.
ip domain-name .* #domain name should be set
aaa new-model # aaa new-model should be activated
# We should have a local user defined with md5 password
username .* secret .*
# The user should not have "Type 7" password, as they are easy cracked http://www.ifm.net.nz/cookbooks/passwordcracker.html
!username .* password .*
# Do not use enable password as they are easy cracked
!enable password
# A enable secret should be set
enable secret
# Some services that need to be enabled.
service password-encryption
service tcp-keepalives-in # Remove half-open or orphaned connections 
service tcp-keepalives-out # Remove half-open or orphaned connections
spanning-tree mode rapid-pvst # Activate rapid spanning tree
ntp server .* # A NTP server should be set
# Verify that remote logging is enabled.
login on-failure log
login on-success log
logging origin-id hostname
logging host .*
# errdisable recovery should be set.
errdisable recovery interval \d+
# timezone should be set
clock timezone .*
# If central european timezone, summertime settings need to be set (to se or CEST)
clock timezone CET 1{
	clock summer-time [sC][eE]S*T* recurring last Sun Mar 2:00 last Sun Oct 2:00
}
# Some services that should be disabled.
no ip domain-lookup # Disable name resolution.
no ip http server # http should be disabled, use: ip http secure-server
no vstack # Smart install should be disabled if not used ex. CVE-2018-0171
!ip rcmd rsh-enable # rsh should be disabled
!ip rcmd rcp-enable # rcp should be disabled
!ip finger # finger should be disabled.
!service udp-small-servers # Small servers should be disabled.
!service tcp-small-servers # Small servers should be disabled.
# Verify that transport input have been defined on the vtys
line vty .*==>transport input
line .*==>exec-timeout # A exec timeout should be set
# Telnet should be disabled.
!transport input .*telnet.*
# If interface description match trunk, it should be a trunkport
# And it should logg if interface go up and down.
description .*[Tt]runk.*{
	switchport mode trunk
	!no logging event link-status
}
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
spanning-tree portfast{
	# If a switchport have portfast enabled, then bpduguard should be enable to prevent user loops
	spanning-tree bpduguard enable
}
# If "#" is used used in configuration matching it need to be escaped with "\", as it is for comments in this configuration file
description \#\# This is not a comment \#\#{ # Here is the comment...
	shutdown
}
# Verify that snmp-readonly is set and have a ACL
snmp-server community .* RO [\w\d]+
# Verify that all RO communitys have ACL defiened.
!snmp-server community .* RO$
# If snmp rw is set, verify that it have a ACL.
snmp-server community .* RW{
	snmp-server community .* RW [\w\d]+
}
## All interfaces that do not have a description should be shutdown.
!description{
	interface .*==>shutdown
}
';
}
