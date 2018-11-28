 #######################################################################################
 #             DaemonWolf Labs - Threat Intelligence Generator for Bro #
 #######################################################################################
 #  This script will install dependancies.
 #  Blocklists are downloaded, parsed and pre-formatted. They are then loaded into Bro to be matched against seen traffic.
 #
 #  Credit to jonschipp (https://github.com/jonschipp/mal-dnssearch)
 # 
 # BEGIN
 # Dependancy Check for mal-dnssearch (credit to jonschipp)
 if [ ! -d mal-dnssearch ]; then
   echo "DOES NOT EXIST"
     git clone https://github.com/jonschipp/mal-dnssearch
      cd mal-dnssearch
       make install
 else
   echo "Requirements = PASS"
 fi
 # Download's the latest BBcan177 Malicious Domains_blocklist, then formats the file and exports the intel file to /var/tmp/bbcan177_domains_new.intel
 curl -s https://gist.githubusercontent.com/BBcan177/4a8bf37c131be4803cb2/raw | grep -v '^#' | sed '/^\s*$/d' > /var/tmp/bbcan177_domains_new.txt &&
 mal-dns2bro -T dns -f /var/tmp/bbcan177_domains_new.txt -s https://gist.githubusercontent.com/BBcan177/4a8bf37c131be4803cb2/raw -n true > /var/tmp/bbcan177.intel
 if [ -e "/var/tmp/bbcan177.intel" ]; then
 echo "bbcan177 list Ok"
 else
 echo "failed to download bbcan177"
 fi
 # Download's the latest C&C Domains blocklist, then formats the file and exports the intel file to /var/tmp/cc_domains_new.intel
 curl -s http://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt | grep -v '^#' | sed 's/,.*//' | sed '/^\s*$/d' > /var/tmp/cc_domains_new.txt &&
 mal-dns2bro -T dns -f /var/tmp/cc_domains_new.txt -s http://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt -n true > /var/tmp/cc.intel
 if [ -e "/var/tmp/cc.intel" ]; then
 echo "C&C Domains list Ok"
 else
 echo "failed to download C&C Domains"
 fi
 # Download's the latest Immortal Domains blocklist, then formats the file and exports the intel file to /var/tmp/immortal_domains.intel
 curl -s http://mirror2.malwaredomains.com/files/immortal_domains.txt | grep -v '^#' | sed '/^\s*$/d' > /var/tmp/immortal_domains_new.txt &&
 mal-dns2bro -T dns -f /var/tmp/immortal_domains_new.txt -s http://mirror2.malwaredomains.com/files/immortal_domains.txt -n true > /var/tmp/immortal.intel
 if [ -e "/var/tmp/immortal.intel" ]; then
 echo "immortal list Ok"
 else
 echo "failed to download immortal"
 fi
 # Download's the latest Ransomware Tracker blocklist, then formats the file and exports the intel file to /var/tmp/ransomware_domains_new.txt
 curl -s https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt | grep -v '^#' | sed '/^\s*$/d' > /var/tmp/ransomware_domains_new.txt &&
 mal-dns2bro -T dns -f /var/tmp/ransomware_domains_new.txt -s https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt -n true > /var/tmp/ransomware.intel
 if [ -e "/var/tmp/ransomware.intel" ]; then
 echo "ransomware list Ok"
 else
 echo "failed to download ransomware"
 fi
 # Download's the latest Dshield Malicious Domains blocklist, then formats the file and exports the intel file to /var/tmp/dshield_domains_new.intel
 curl -s https://secure.dshield.org/feeds/suspiciousdomains_Low.txt | grep -v '^#' | sed '/Site/d' | sed '/^\s*$/d' > /var/tmp/dshield_domains_new.txt &&
 mal-dns2bro -T dns -f /var/tmp/dshield_domains_new.txt -s https://secure.dshield.org/feeds/suspiciousdomains_Low.txt -n true > /var/tmp/dshield.intel
 if [ -e "/var/tmp/dshield.intel" ]; then
 echo "dshield list Ok"
 else
 echo "failed to download dshield"
 fi
 # Download's the latest Zeus Malicious Domains blocklist, then formats the file and exports the intel file to /var/tmp/zeus_domains_new.intel
 curl -s https://zeustracker.abuse.ch/blocklist.php?download=baddomains | grep -v '^#' |sed '/^\s*$/d' | sed '/^\s*$/d' > /var/tmp/zeus_domains_new.txt &&
 mal-dns2bro -T dns -f /var/tmp/zeus_domains_new.txt -s https://zeustracker.abuse.ch/blocklist.php?download=baddomains -n true > /var/tmp/zeus.intel
 if [ -e "/var/tmp/zeus.intel" ]; then
 echo "zeus list Ok"
 else
 echo "failed to download zeus"
 fi
 # Download's the latest Binary Defence IP Banlist, then formats the file and exports the intel file to /var/tmp/binarydefence_ips_new.intel
 curl -s https://www.binarydefense.com/banlist.txt | grep -v '^#' |sed '/^\s*$/d' | sed '/^\s*$/d' > /var/tmp/binarydefence_ips_new.txt &&
 mal-dns2bro -T ip -f /var/tmp/binarydefence_ips_new.txt -s https://www.binarydefense.com/banlist.txt -n true > /var/tmp/binarydefence.intel
 if [ -e "/var/tmp/binarydefence.intel" ]; then
 echo "binarydefence list Ok"
 else
 echo "failed to download binarydefence"
 fi
 # Download's the latest Malc0de IP Banlist, then formats the file and exports the intel file to /var/tmp/malc0de_ip_new.intel
 curl -s http://malc0de.com/bl/IP_Blacklist.txt | grep -v '^#' | grep -v '^//' |sed '/^\s*$/d' | sed '/^\s*$/d' > /var/tmp/malc0de_ip_new.txt &&
 mal-dns2bro -T ip -f /var/tmp/malc0de_ip_new.txt -s http://malc0de.com/bl/IP_Blacklist.txt -n true > /var/tmp/malc0de.intel
 if [ -e "/var/tmp/malc0de.intel" ]; then
 echo "malc0de list Ok"
 else
 echo "failed to download malc0de"
 fi
 # Download's the latest MalwareDomain's IP Banlist, then formats the file and exports the intel file to /var/tmp/malwaredomains_iplist_new.intel
 curl -s https://panwdbl.appspot.com/lists/mdl.txt | grep -v '^#' |sed '/^\s*$/d' | sed '/^\s*$/d' > /var/tmp/malwaredomains_iplist_new.txt &&
 mal-dns2bro -T ip -f /var/tmp/malwaredomains_iplist_new.txt -s https://panwdbl.appspot.com/lists/mdl.txt -n true > /var/tmp/malwaredomains.intel
 if [ -e "/var/tmp/malwaredomains.intel" ]; then
 echo "malwaredomains list Ok"
 else
 echo "failed to download malwaredomains"
 fi
 # Download's the latest EmergingThreats IP Banlist, then formats the file and exports the intel file to /var/tmp/et_iplist_new.intel
 curl -s http://rules.emergingthreats.net/blockrules/compromised-ips.txt | grep -v '^#' |sed '/^\s*$/d' | sed '/^\s*$/d' > /var/tmp/et_iplist_new.txt &&
 mal-dns2bro -T ip -f /var/tmp/et_iplist_new.txt -s http://rules.emergingthreats.net/blockrules/compromised-ips.txt -n true > /var/tmp/et.intel
 if [ -e "/var/tmp/et.intel" ]; then
 echo "EmergingThreats list Ok"
 else
 echo "failed to download EmergingThreats"
 fi
 # Download's the latest Bambenek Domain Banlist, then formats the file and exports the intel file to /var/tmp/bambenek_domains_new.intel
 curl -s http://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt | grep -v '^#' | cut -d, -f1 | sed '/^\s*$/d' | sed '/^\s*$/d' > /var/tmp/bambenek_domains_new.txt &&
 mal-dns2bro -T dns -f /var/tmp/bambenek_domains_new.txt -s http://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt -n true > /var/tmp/bambenek.intel
 if [ -e "/var/tmp/bambenek.intel" ]; then
 echo "bambenek list Ok"
 else
 echo "failed to download bambenek"
 fi
 # Download's the latest OpenPhish URL's, then formats the file and exports the intel file to /var/tmp/openphish_new.txt
 curl -s https://openphish.com/feed.txt | grep -v '^#' | sed '/^\s*$/d' > /var/tmp/openphish_new.txt &&
 mal-dns2bro -T url -f /var/tmp/openphish_new.txt -s https://openphish.com/feed.txt -n true > /var/tmp/openphish.intel
 if [ -e "/var/tmp/openphish.intel" ]; then
 echo "openphish list Ok"
 else
 echo "failed to download openphish"
 fi
 # Download's the latest EasyList Adservers, then formats the file and exports the intel file to /var/tmp/easylist_new.txt
 curl -s https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt | sed 's/\||//g' | cut -f1 -d"^" > /var/tmp/easylist_new.txt &&
 mal-dns2bro -T dns -f /var/tmp/easylist_new.txt -s https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt -n true > /var/tmp/easylist.intel
 if [ -e "/var/tmp/easylist.intel" ]; then
 echo "easylist list Ok"
 else
 echo "failed to download easylist"
 fi
 # Download's the latest ResCure Domains, then formats the file and exports the intel file to /var/tmp/rescure_domains.txt
 curl -s https://rescure.fruxlabs.com/rescure_domain_blacklist.txt | sed -e '1,11d' | grep -v '^#' | sed '/^\s*$/d' > /var/tmp/rescure_domains.txt &&
 mal-dns2bro -T dns -f /var/tmp/rescure_domains.txt -s https://rescure.fruxlabs.com/rescure_domain_blacklist.txt -n true > /var/tmp/rescure_domains.intel
 if [ -e "/var/tmp/rescure_domains.intel" ]; then
 echo "rescure list Ok"
 else
 echo "failed to download rescure"
 fi
 # The following are hosts in the hpHosts database with the EMD classification ONLY
 curl -s https://hosts-file.net/emd.txt | grep -v '^#' | sed '/^::1/ d' | sed 's/\<127.0.0.1\>//g' | sed '/^ localhost/ d' | tr -d " \r" > /var/tmp/hphosts_emd.txt &&
 mal-dns2bro -T dns -f /var/tmp/hphosts_emd.txt -s https://hosts-file.net/emd.txt -n true > /var/tmp/hphosts_emd.intel
 if [ -e "/var/tmp/hphosts_emd.intel" ]; then
 echo "hphosts_emd list Ok"
 else
 echo "failed to download hphosts_emd"
 fi
 # The following are hosts in the hpHosts database with the AD_servers classification ONLY
 curl -s https://hosts-file.net/ad_servers.txt | grep -v '^#' | sed '/^::1/ d' | sed 's/\<127.0.0.1\>//g' | sed '/^ localhost/ d' | tr -d " \r" > /var/tmp/hphosts_ad_servers.txt && 
 mal-dns2bro -T dns -f /var/tmp/hphosts_ad_servers.txt -s https://hosts-file.net/ad_servers.txt -n true > /var/tmp/hphosts_ad_servers.intel
 if [ -e "/var/tmp/hphosts_ad_servers.intel" ]; then
 echo "hphosts_ad_servers list Ok"
 else
 echo "failed to download hphosts_ad_servers"
 fi
 # The following are hosts in the hpHosts database with the Phishing classification ONLY
 curl -s https://hosts-file.net/psh.txt | grep -v '^#' | sed '/^::1/ d' | sed 's/\<127.0.0.1\>//g' | sed '/^ localhost/ d' | tr -d " \r" > /var/tmp/hphosts_psh.txt && 
 mal-dns2bro -T dns -f /var/tmp/hphosts_psh.txt -s https://hosts-file.net/psh.txt -n true > /var/tmp/hphosts_psh.intel
 if [ -e "/var/tmp/hphosts_psh.intel" ]; then
 echo "hphosts_psh list Ok"
 else
 echo "failed to download hphosts_psh"
 fi
 # The following are hosts in the hpHosts database with the Exploit classification ONLY
 curl -s https://hosts-file.net/exp.txt | grep -v '^#' | sed '/^::1/ d' | sed 's/\<127.0.0.1\>//g' | sed '/^ localhost/ d' | tr -d " \r" > /var/tmp/hphosts_exp.txt && 
 mal-dns2bro -T dns -f /var/tmp/hphosts_exp.txt -s https://hosts-file.net/exp.txt -n true > /var/tmp/hphosts_exp.intel
 if [ -e "/var/tmp/hphosts_exp.intel" ]; then
 echo "hphosts_exp list Ok"
 else
 echo "failed to download hphosts_exp"
 fi
 # The following are hosts in the hpHosts database with the Fraud classification ONLY
 curl -s https://hosts-file.net/fsa.txt | grep -v '^#' | sed '/^::1/ d' | sed 's/\<127.0.0.1\>//g' | sed '/^ localhost/ d' | tr -d " \r" > /var/tmp/hphosts_fsa.txt && 
 mal-dns2bro -T dns -f /var/tmp/hphosts_fsa.txt -s https://hosts-file.net/fsa.txt -n true > /var/tmp/hphosts_fsa.intel
 if [ -e "/var/tmp/hphosts_fsa.intel" ]; then
 echo "hphosts_fsa list Ok"
 else
 echo "failed to download hphosts_fsa"
 fi
 # The following are hosts in the hpHosts database with the Hijack classification ONLY
 curl -s https://hosts-file.net/hjk.txt | grep -v '^#' | sed '/^::1/ d' | sed 's/\<127.0.0.1\>//g' | sed '/^ localhost/ d' | tr -d " \r" > /var/tmp/hphosts_hjk.txt && 
 mal-dns2bro -T dns -f /var/tmp/hphosts_hjk.txt -s https://hosts-file.net/hjk.txt -n true > /var/tmp/hphosts_hjk.intel
 if [ -e "/var/tmp/hphosts_hjk.intel" ]; then
 echo "hphosts_hjk list Ok"
 else
 echo "failed to download hphosts_hjk"
 fi
 # The following are hosts in the hpHosts database with the MMT classification ONLY
 curl -s https://hosts-file.net/mmt.txt | grep -v '^#' | sed '/^::1/ d' | sed 's/\<127.0.0.1\>//g' | sed '/^ localhost/ d' | tr -d " \r" > /var/tmp/hphosts_mmt.txt && 
 mal-dns2bro -T dns -f /var/tmp/hphosts_mmt.txt -s https://hosts-file.net/mmt.txt -n true > /var/tmp/hphosts_mmt.intel
 if [ -e "/var/tmp/hphosts_mmt.intel" ]; then
 echo "hphosts_mmt list Ok"
 else
 echo "failed to download hphosts_mmt"
 fi
 # The following are hosts in the hpHosts database with the Pharmacy classification ONLY
 curl -s https://hosts-file.net/pha.txt | grep -v '^#' | sed '/^::1/ d' | sed 's/\<127.0.0.1\>//g' | sed '/^ localhost/ d' | tr -d " \r" > /var/tmp/hphosts_pha.txt && 
 mal-dns2bro -T dns -f /var/tmp/hphosts_pha.txt -s https://hosts-file.net/pha.txt -n true > /var/tmp/hphosts_pha.intel
 if [ -e "/var/tmp/hphosts_pha.intel" ]; then
 echo "hphosts_pha list Ok"
 else
 echo "failed to download hphosts_pha"
 fi
 # The following are hosts in the hpHosts database with the PUP classification ONLY
 curl -s https://hosts-file.net/pup.txt | grep -v '^#' | sed '/^::1/ d' | sed 's/\<127.0.0.1\>//g' | sed '/^ localhost/ d' | tr -d " \r" > /var/tmp/hphosts_pup.txt && 
 mal-dns2bro -T dns -f /var/tmp/hphosts_pup.txt -s https://hosts-file.net/pup.txt -n true > /var/tmp/hphosts_pup.intel
 if [ -e "/var/tmp/hphosts_pup.intel" ]; then
 echo "hphosts_pup list Ok"
 else
 echo "failed to download hphosts_pup"
 fi
 # The following are hosts in the hpHosts database with the Warez classification ONLY
 curl -s https://hosts-file.net/wrz.txt | grep -v '^#' | sed '/^::1/ d' | sed 's/\<127.0.0.1\>//g' | sed '/^ localhost/ d' | tr -d " \r" > /var/tmp/hphosts_wrz.txt && 
 mal-dns2bro -T dns -f /var/tmp/hphosts_wrz.txt -s https://hosts-file.net/wrz.txt -n true > /var/tmp/hphosts_wrz.intel
 if [ -e "/var/tmp/hphosts_wrz.intel" ]; then
 echo "hphosts_wrz list Ok"
 else
 echo "failed to download hphosts_wrz"
 fi
 # The following is used for testing successful intel.log creating. Curl or browsing to testmyids.com should create an intel log file
 echo "testmyids.com" > /var/tmp/testmyids.txt &&
 mal-dns2bro -T dns -f /var/tmp/testmyids.txt -s http://testmyids.com -n true > /var/tmp/testmyids.intel
 if [ -e "/var/tmp/testmyids.intel" ]; then
 echo "testmyids list Ok"
 else
 echo "failed to download testmyids list"
 fi
 # Check if destination directory exists
 if [ -d "/opt/bro/share/bro/site/intelligence" ]; then
 echo "Directory Check = PASS"
 else
 mkdir "/opt/bro/share/bro/site/intelligence"
 fi
 # Check if load file exists
 if [ -e "/opt/bro/share/bro/site/intelligence/__load__.bro" ]; then
 echo "Load File = PASS"
 else
 touch "/opt/bro/share/bro/site/intelligence/__load__.bro"
 fi
 # Move newly created .intel files to load directory
 mv /var/tmp/bbcan177.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/cc.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/dshield.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/immortal.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/ransomware.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/zeus.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/binarydefence.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/malc0de.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/malwaredomains.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/et.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/bambenek.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/openphish.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/easylist.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/rescure_domains.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/hphosts_emd.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/hphosts_ad_servers.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/hphosts_psh.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/hphosts_exp.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/hphosts_fsa.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/hphosts_hjk.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/hphosts_mmt.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/hphosts_pha.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/hphosts_pup.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/hphosts_wrz.intel /opt/bro/share/bro/site/intelligence
 mv /var/tmp/testmyids.intel /opt/bro/share/bro/site/intelligence
 # Replace the contents of __load__.bro with below
 cat > /opt/bro/share/bro/site/intelligence/__load__.bro << EOF
 @load frameworks/intel/seen
 @load frameworks/intel/do_notice
 @load frameworks/files/hash-all-files
 redef Intel::read_files += {
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
		fmt("%s/openphish.intel", @DIR),
		fmt("%s/easylist.intel", @DIR),
		fmt("%s/hphosts_emd.intel", @DIR),
		fmt("%s/hphosts_ad_servers.intel", @DIR),
		fmt("%s/hphosts_psh.intel", @DIR),
		fmt("%s/hphosts_exp.intel", @DIR),
		fmt("%s/hphosts_fsa.intel", @DIR),
		fmt("%s/hphosts_hjk.intel", @DIR),
		fmt("%s/hphosts_mmt.intel", @DIR),
		fmt("%s/hphosts_pha.intel", @DIR),
		fmt("%s/hphosts_pup.intel", @DIR),
		fmt("%s/hphosts_wrz.intel", @DIR),
		fmt("%s/testmyids.intel", @DIR),
		fmt("%s/rescure_domains.intel", @DIR),
		fmt("%s/bambenek.intel", @DIR)
 };
EOF
 
 # Check local.bro for the new intelligence path, add if not found...
 PATTERN='@load site/intelligence'
 FILE='/opt/bro/share/bro/site/local.bro'
 if grep -Fxq "@load site/intelligence" '/opt/bro/share/bro/site/local.bro';
 then
    echo "yay '$PATTERN' was found in '$FILE'"
 else
    echo "'$PATTERN' was not found in '$FILE', adding now..."
     echo '@load site/intelligence' >> /opt/bro/share/bro/site/local.bro
 fi
 
 # Restart Bro
 /opt/bro/bin/broctl deploy
