 #######################################################################################
 #             DaemonWolf Labs - Threat Intelligence Generator for Bro                 #
 #######################################################################################
 # PREREQUISITS
 # You must have Bro installed, and bro-otx (https://github.com/hosom/bro-otx) installed to "/opt/bro/share/bro/site".
 # You must have mal-dnssearch (https://github.com/jonschipp/mal-dnssearch) installed. *Easiest Method
 # or just copy either mal-dns2bro.sh|py script and path to it under each line below.
 # 
 # BEGIN
 #
 # Download's the latest BBcan177 Malicious Domains_blocklist, then formats the file and exports the intel file to /var/tmp/bbcan177_domains_new.intel
 curl -s https://gist.githubusercontent.com/BBcan177/4a8bf37c131be4803cb2/raw | grep -v '^#' | sed '/^\s*$/d' > /var/tmp/bbcan177_domains_new.txt &&
 mal-dns2bro -T dns -f /var/tmp/bbcan177_domains_new.txt -s https://gist.githubusercontent.com/BBcan177/4a8bf37c131be4803cb2/raw -n true > /var/tmp/bbcan177.intel

 # Download's the latest C&C Domains blocklist, then formats the file and exports the intel file to /var/tmp/cc_domains_new.intel
 curl -s http://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt | grep -v '^#' | sed 's/,.*//' | sed '/^\s*$/d' > /var/tmp/cc_domains_new.txt &&
 mal-dns2bro -T dns -f /var/tmp/cc_domains_new.txt -s http://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt -n true > /var/tmp/cc.intel

 # Download's the latest Immortal Domains blocklist, then formats the file and exports the intel file to /var/tmp/immortal_domains.intel
 curl -s http://mirror2.malwaredomains.com/files/immortal_domains.txt | grep -v '^#' | sed '/^\s*$/d' > /var/tmp/immortal_domains_new.txt &&
 mal-dns2bro -T dns -f /var/tmp/immortal_domains_new.txt -s http://mirror2.malwaredomains.com/files/immortal_domains.txt -n true > /var/tmp/immortal.intel
 
 # Download's the latest Ransomware Tracker blocklist, then formats the file and exports the intel file to /var/tmp/ransomware_domains_new.txt
 curl -s https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt | grep -v '^#' | sed '/^\s*$/d' > /var/tmp/ransomware_domains_new.txt &&
 mal-dns2bro -T dns -f /var/tmp/ransomware_domains_new.txt -s https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt -n true > /var/tmp/ransomware.intel
 
 # Download's the latest Dshield Malicious Domains blocklist, then formats the file and exports the intel file to /var/tmp/dshield_domains_new.intel
 curl -s https://secure.dshield.org/feeds/suspiciousdomains_Low.txt | grep -v '^#' | sed '/Site/d' | sed '/^\s*$/d' > /var/tmp/dshield_domains_new.txt &&
 mal-dns2bro -T dns -f /var/tmp/dshield_domains_new.txt -s https://secure.dshield.org/feeds/suspiciousdomains_Low.txt -n true > /var/tmp/dshield.intel
 
 # Download's the latest Zeus Malicious Domains blocklist, then formats the file and exports the intel file to /var/tmp/zeus_domains_new.intel
 curl -s https://zeustracker.abuse.ch/blocklist.php?download=baddomains | grep -v '^#' |sed '/^\s*$/d' | sed '/^\s*$/d' > /var/tmp/zeus_domains_new.txt &&
 mal-dns2bro -T dns -f /var/tmp/zeus_domains_new.txt -s https://zeustracker.abuse.ch/blocklist.php?download=baddomains -n true > /var/tmp/zeus.intel
 
 # Download's the latest Binary Defence IP Banlist, then formats the file and exports the intel file to /var/tmp/binarydefence_ips_new.intel
 curl -s https://www.binarydefense.com/banlist.txt | grep -v '^#' |sed '/^\s*$/d' | sed '/^\s*$/d' > /var/tmp/binarydefence_ips_new.txt &&
 mal-dns2bro -T ip -f /var/tmp/binarydefence_ips_new.txt -s https://www.binarydefense.com/banlist.txt -n true > /var/tmp/binarydefence.intel

 # Download's the latest Malc0de IP Banlist, then formats the file and exports the intel file to /var/tmp/malc0de_ip_new.intel
 curl -s http://malc0de.com/bl/IP_Blacklist.txt | grep -v '^#' | grep -v '^//' |sed '/^\s*$/d' | sed '/^\s*$/d' > /var/tmp/malc0de_ip_new.txt &&
 mal-dns2bro -T ip -f /var/tmp/malc0de_ip_new.txt -s http://malc0de.com/bl/IP_Blacklist.txt -n true > /var/tmp/malc0de.intel

 # Download's the latest MalwareDomain's IP Banlist, then formats the file and exports the intel file to /var/tmp/malwaredomains_iplist_new.intel
 curl -s https://panwdbl.appspot.com/lists/mdl.txt | grep -v '^#' |sed '/^\s*$/d' | sed '/^\s*$/d' > /var/tmp/malwaredomains_iplist_new.txt &&
 mal-dns2bro -T ip -f /var/tmp/malwaredomains_iplist_new.txt -s https://panwdbl.appspot.com/lists/mdl.txt -n true > /var/tmp/malwaredomains.intel

 # Download's the latest EmergingThreats IP Banlist, then formats the file and exports the intel file to /var/tmp/et_iplist_new.intel
 curl -s http://rules.emergingthreats.net/blockrules/compromised-ips.txt | grep -v '^#' |sed '/^\s*$/d' | sed '/^\s*$/d' > /var/tmp/et_iplist_new.txt &&
 mal-dns2bro -T ip -f /var/tmp/et_iplist_new.txt -s http://rules.emergingthreats.net/blockrules/compromised-ips.txt -n true > /var/tmp/et.intel

 # Download's the latest Firehol Level 1 IP Banlist, then formats the file and exports the intel file to /var/tmp/firehol_level1_new_iplist.intel
 curl -s https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1_new.netset | grep -v '^#' | sed -n 's/\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}/\nip&\n/gp' | grep ip | sed 's/ip//'| sort | uniq |sed '/^\s*$/d' > /var/tmp/firehol_level1_new.txt &&
 mal-dns2bro -T ip -f /var/tmp/firehol_level1_new.txt -s https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1_new.netset -n true > /var/tmp/firehol_level1.intel
 
 # Download's the latest Bambenek Domain Banlist, then formats the file and exports the intel file to /var/tmp/bambenek_domains_new.intel
 curl -s http://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt | grep -v '^#' | cut -d, -f1 | sed '/^\s*$/d' | sed '/^\s*$/d' > /var/tmp/bambenek_domains_new.txt &&
 mal-dns2bro -T dns -f /var/tmp/bambenek_domains_new.txt -s http://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt -n true > /var/tmp/bambenek.intel
 
 # Download's the latest OpenPhish URL's, then formats the file and exports the intel file to /var/tmp/openphish_new.txt
 curl -s https://openphish.com/feed.txt | grep -v '^#' | sed '/^\s*$/d' > /var/tmp/openphish_new.txt &&  
 mal-dns2bro -T url -f /var/tmp/openphish_new.txt -s https://openphish.com/feed.txt -n true > /var/tmp/openphish.intel
 
 # Move to bro load directory
 mv /var/tmp/bbcan177.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/cc.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/dshield.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/immortal.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/ransomware.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/zeus.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/binarydefence.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/malc0de.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/malwaredomains.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/et.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/firehol_level1.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/bambenek.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/openphish.intel /opt/bro/share/bro/site/bro-otx/scripts
 
 cat > /opt/bro/share/bro/site/bro-otx/scripts/__load__.bro << EOF
 @load frameworks/intel/seen
 @load frameworks/intel/do_notice
 @load frameworks/files/hash-all-files

 redef Intel::read_files += {
                fmt("%s/otx.dat", @DIR),
		fmt("%s/bbcan177.intel", @DIR),
		fmt("%s/cc.intel", @DIR),
		fmt("%s/dshield.intel", @DIR),
		fmt("%s/immortal.intel", @DIR),
		fmt("%s/ransomware.intel", @DIR),
		fmt("%s/zeus.intel", @DIR),
		fmt("%s/binarydefence.intel", @DIR),
		fmt("%s/malc0de.intel", @DIR),
		fmt("%s/malwaredomains.intel", @DIR),
		fmt("%s/et.intel", @DIR),
		fmt("%s/firehol_level1.intel", @DIR),
		fmt("%s/openphish.intel", @DIR),
		fmt("%s/bambenek.intel", @DIR)
 };
EOF

 # Restart Bro
 /opt/bro/bin/broctl deploy
