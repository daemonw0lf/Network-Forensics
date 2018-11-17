 #######################################################################################
 #             DaemonWolf Labs - Threat Intelligence Generator for Bro                 #
 #######################################################################################
 # PREREQUISITS
 # You must have Bro installed (obviously), and bro-otx (https://github.com/hosom/bro-otx) installed to "/opt/bro/share/bro/site".
 # "local.bro" must be loaded with seen and do_notice at the bottom.
 # Edit "__load__.bro" under redef section add lines for each new intel file. Learn more about this in: http://blog.bro.org/2014/01/intelligence-data-and-bro_4980.html
 # BEGIN
 #
 # Download's the latest BBcan177 Malicious Domains_blocklist, then formats the file and exports the intel file to /var/tmp/bbcan177_domains.intel
 curl -s https://gist.githubusercontent.com/BBcan177/4a8bf37c131be4803cb2/raw | grep -v '^#' | awk '{print $0"\tIntel::DOMAIN\t-\t-\tT\t-\t-\t-\t-\t-\n"}' | sed '/^\s*$/d' > /var/tmp/bbcan177_domains.intel

 # Download's the latest C&C Domains blocklist, then formats the file and exports the intel file to /var/tmp/cc_domains.intel
 curl -s http://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt | grep -v '^#' | sed 's/,.*//' | awk '{print $0"\tIntel::DOMAIN\t-\t-\tT\t-\t-\t-\t-\t-\n"}' | sed '/^\s*$/d' > /var/tmp/cc_domains.intel

 # Download's the latest Immortal Domains blocklist, then formats the file and exports the intel file to /var/tmp/immortal_domains.intel
 curl -s http://mirror2.malwaredomains.com/files/immortal_domains.txt | grep -v '^#' | awk '{print $0"\tIntel::DOMAIN\t-\t-\tT\t-\t-\t-\t-\t-\n"}' | sed '/^\s*$/d' > /var/tmp/imortal_domains.intel

 # Download's the latest Ransomware Tracker blocklist, then formats the file and exports the intel file to /var/tmp/ransomware_domains.intel
 curl -s https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt | grep -v '^#' | awk '{print $0"\tIntel::DOMAIN\t-\t-\tT\t-\t-\t-\t-\t-\n"}' | sed '/^\s*$/d' > /var/tmp/ransomware_domains.intel

 # Download's the latest Dshield Malicious Domains blocklist, then formats the file and exports the intel file to /var/tmp/dshield_domains.intel
 curl -s https://secure.dshield.org/feeds/suspiciousdomains_Low.txt | grep -v '^#' | sed '/Site/d' | awk '{print $0"\tIntel::DOMAIN\t-\t-\tT\t-\t-\t-\t-\t-\n"}' | sed '/^\s*$/d' > /var/tmp/dshield_domains.intel

 # Download's the latest Zeus Malicious Domains blocklist, then formats the file and exports the intel file to /var/tmp/zeus_domains.intel
 curl -s https://zeustracker.abuse.ch/blocklist.php?download=baddomains | grep -v '^#' |sed '/^\s*$/d' | awk '{print $0"\tIntel::DOMAIN\t-\t-\tT\t-\t-\t-\t-\t-\n"}' | sed '/^\s*$/d' > /var/tmp/zeus_domains.intel

 # Download's the latest Binary Defence IP Banlist, then formats the file and exports the intel file to /var/tmp/binarydefence_ips.intel
 curl -s https://www.binarydefense.com/banlist.txt | grep -v '^#' |sed '/^\s*$/d' | awk '{print $0"\tIntel::ADDR\t-\t-\tT\t-\t-\t-\t-\t-\n"}' | sed '/^\s*$/d' > /var/tmp/binarydefence_ips.intel

 # Download's the latest Malc0de IP Banlist, then formats the file and exports the intel file to /var/tmp/malc0de_ip.intel
 curl -s http://malc0de.com/bl/IP_Blacklist.txt | grep -v '^#' | grep -v '^//' |sed '/^\s*$/d' | awk '{print $0"\tIntel::ADDR\t-\t-\tT\t-\t-\t-\t-\t-\n"}' | sed '/^\s*$/d' > /var/tmp/malc0de_ip.intel

 # Download's the latest Malc0de IP Banlist, then formats the file and exports the intel file to /var/tmp/malwaredomains_iplist.intel
 curl -s https://panwdbl.appspot.com/lists/mdl.txt | grep -v '^#' |sed '/^\s*$/d' | awk '{print $0"\tIntel::ADDR\t-\t-\tT\t-\t-\t-\t-\t-\n"}' | sed '/^\s*$/d' > /var/tmp/malwaredomains_iplist.intel

 # Download's the latest EmergingThreats IP Banlist, then formats the file and exports the intel file to /var/tmp/et_iplist.intel
 curl -s http://rules.emergingthreats.net/blockrules/compromised-ips.txt | grep -v '^#' |sed '/^\s*$/d' | awk '{print $0"\tIntel::ADDR\t-\t-\tT\t-\t-\t-\t-\t-\n"}' | sed '/^\s*$/d' > /var/tmp/et_iplist.intel

 # Download's the latest Firehol Level 1 IP Banlist, then formats the file and exports the intel file to /var/tmp/firehol_level1_iplist.intel
 curl -s https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset | grep -v '^#' | sed -n 's/\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}/\nip&\n/gp' | grep ip | sed 's/ip//'| sort | uniq |sed '/^\s*$/d' | awk '{prin$
 
 # Download's the latest Bambenek IP Banlist, then formats the file and exports the intel file to /var/tmp/bambenek_domains.intel
 curl -s http://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt | grep -v '^#' | cut -d, -f1 | sed '/^\s*$/d' | awk '{print $0"\tIntel::ADDR\t-\t-\tT\t-\t-\t-\t-\t-\n"}' | sed '/^\s*$/d' > /var/tmp/bambenek_domains.intel

 # Move to bro load directory
 mv /var/tmp/bbcan177_domains.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/cc_domains.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/dshield_domains.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/imortal_domains.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/ransomware_domains.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/zeus_domains.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/binarydefence_ips.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/malc0de_ip.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/malwaredomains_iplist.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/et_iplist.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/firehol_level1_iplist.intel /opt/bro/share/bro/site/bro-otx/scripts
 mv /var/tmp/bambenek_domains.intel /opt/bro/share/bro/site/bro-otx/scripts
 
 # Restart Bro
 /opt/bro/bin/broctl deploy
