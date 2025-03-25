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

# Create the directories if they don't exist
mkdir -p "$INTERNALS_DIR" "$WEB_DIR" "$WIFI_DIR" "$RECON_DIR" "$PASSCRACK_DIR" "$GENERAL_DIR" "$MOBILE_DIR"

# Config variables
echo "alias tools_general='cd $BASE_DIR/general'" >> ~/.zshrc
echo "alias tools_internals='cd $BASE_DIR/internals'" >> ~/.zshrc
echo "alias tools_mobile='cd $BASE_DIR/mobile'" >> ~/.zshrc
echo "alias tools_passcrack='cd $BASE_DIR/passcrack'" >> ~/.zshrc
echo "alias tools_recon='cd $BASE_DIR/recon'" >> ~/.zshrc
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

# Bbot
pipx install bbot

# Bettercap
cd $INTERNALS_DIR
sudo apt install golang git build-essential libpcap-dev libusb-1.0-0-dev libnetfilter-queue-dev
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
echo "alias bloodhound-gui='sudo $INTERNALS_DIR/BloodHound-linux-x64/BloodHound'" >> ~/.zshrc
echo "alias neo4j='sudo /usr/bin/neo4j console'" >> ~/.zshrc
echo "bloodhound-gui" >> ~/.zsh_history
echo "neo4j" >> ~/.zsh_history

# BloodyAD
cd $INTERNALS_DIR
wget https://github.com/CravateRouge/bloodyAD/releases/download/v2.1.7/bloodyAD.exe

# BruteSubdomains
cd $RECON_DIR
git clone https://github.com/afkfr0mkeyb0ard/bruteSubdomains.git

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
python3 -m venv .
source bin/activate
pip3 install -r requirements.txt
deactivate
echo "alias AwsPEASS='$RECON_DIR/CloudPEASS/bin/python3 $RECON_DIR/CloudPEASS/AWSPEASS.py'" >> ~/.zshrc
echo "alias AzurePEASS='$RECON_DIR/CloudPEASS/bin/python3 $RECON_DIR/CloudPEASS/AzurePEASS.py'" >> ~/.zshrc
echo "alias GcpPEASS='$RECON_DIR/CloudPEASS/bin/python3 $RECON_DIR/CloudPEASS/GCPPEASS.py'" >> ~/.zshrc

# Coercer
cd $INTERNALS_DIR
pipx install git+https://github.com/p0dalirius/Coercer.git || echo "[-] Failed to install Coercer"
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
git clone https://github.com/s0lst1c3/eaphammer.git
echo "eaphammer --cert-wizard" >> ~/.zsh_history
echo "eaphammer -i wlan0 --channel 4 --auth wpa-eap --essid CorpWifi --creds" >> ~/.zsh_history

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
echo "ffuf -u 'https://target/FUZZ' -w 'dico.txt' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0' -r -c -p 0.1 -t 3" >> ~/.zsh_history

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

# Hashcat
cd $PASSCRACK_DIR
wget https://github.com/hashcat/hashcat/releases/download/v6.2.6/hashcat-6.2.6.7z

# Hostapd-wpe
cd $WIFI_DIR
sudo apt-get -y install hostapd-wpe
echo "hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf" >> ~/.zsh_history

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
echo "impacket-Get-GPPPassword 'DOMAIN'/'USER':'PASSWORD'@'DOMAIN_CONTROLLER'" >> ~/.zsh_history
echo "impacket-lookupsid DOMAIN/guest@IP" >> ~/.zsh_history
echo "impacket-ntlmrelayx --lootdir "loot_relay" -of ~/ntlmrelay_hashs.txt -t "ldap://<DC-IP>" -smb2support --remove-mic" >> ~/.zsh_history
echo "impacket-ntlmrelayx -of ~/ntlmrelay_hashs.txt -debug -smb2support -t http://<IP-PKI>/certsrv/certfnsh.asp --adcs --template [KerberosAuthentication/DomainController]" >> ~/.zsh_history
echo "impacket-ntlmrelayx -of ~/ntlmrelay_hashs.txt -tf relay.txt -smb2support [-socks]" >> ~/.zsh_history
echo "impacket-GetADUsers -all -dc-ip <DC-IP> domain.local/username" >> ~/.zsh_history
echo "impacket-getTGT domain.local/username -hashes :<NTLM> -dc-ip <DC-IP>" >> ~/.zsh_history
echo "impacket-smbclient 'domain.local/user:pass@10.10.11.222'" >> ~/.zsh_history
echo "impacket-addcomputer -computer-name 'MyComputer$' -computer-pass 'Password123' -dc-host 10.10.11.222 'DOMAIN/user:password'" >> ~/.zsh_history
echo "impacket-secretsdump -target-ip IP [-just-dc-ntlm] [-history] USER@DOMAIN" >> ~/.zsh_history
echo "impacket-psexec 'domain.local/user:pass@10.10.11.222' whoami" >> ~/.zsh_history

# ItWasAllADream
cd $INTERNALS_DIR
pipx install git+https://github.com/byt3bl33d3r/ItWasAllADream || echo "[-] Failed to install ItWasAllADream"
echo "itwasalladream -u user -p password -d domain 192.168.1.0/24" >> ~/.zsh_history

# Jd-gui
cd $MOBILE_DIR
wget https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.jar

# JSLuice
cd $WEB_DIR
go install github.com/BishopFox/jsluice/cmd/jsluice@latest

# Jwt_tool
cd $WEB_DIR
git clone https://github.com/ticarpi/jwt_tool.git

# Kerbrute
cd $INTERNALS_DIR
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
mv kerbrute_linux_amd64 kerbrute
chmod +x kerbrute
echo "alias kerbrute='$INTERNALS_DIR/kerbrute'" >> ~/.zshrc

# KnockKnock
cd $RECON_DIR
git clone https://github.com/waffl3ss/KnockKnock.git
cd KnockKnock
python3 -m venv .
source bin/activate
pip3 install -r requirements.txt
deactivate
echo "alias knockknock='$RECON_DIR/KnockKnock/bin/python3 $RECON_DIR/KnockKnock/KnockKnock.py'" >> ~/.zshrc

# Kraken
cd $GENERAL_DIR
git clone https://github.com/jasonxtn/Kraken.git
cd Kraken
python3 -m venv .
source bin/activate
python3 -m pip install -r requirements.txt
deactivate

# Krbrelayx
cd $INTERNALS_DIR
git clone https://github.com/dirkjanm/krbrelayx.git

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

# Ldapsearch-ad
pipx install git+https://github.com/yaap7/ldapsearch-ad || echo "[-] Failed to install Ldapsearch-ad"
echo "ldapsearch-ad.py -l 10.0.0.1 -t info" >> ~/.zsh_history

# Magisk
cd $MOBILE_DIR
mkdir Magisk
cd Magisk
wget https://github.com/topjohnwu/Magisk/releases/download/canary-28103/app-debug.apk
wget https://github.com/topjohnwu/Magisk/releases/download/canary-28103/app-release.apk

# MailSniper
cd $RECON_DIR
git clone https://github.com/dafthack/MailSniper.git

# Manspider
pipx install git+https://github.com/blacklanternsecurity/MANSPIDER || echo "[-] Failed to install Manspider"
echo "manspider 10.10.10.0/24 -e xml -c DefaultPassword cpassword -n -u USER -p PASS -d DOMAINE" >> ~/.zsh_history

# Mentalist
cd $PASSCRACK_DIR
wget https://github.com/sc0tfree/mentalist/releases/download/v1.0/Mentalist-v1.0-Linux-x86_64.zip
unzip -q Mentalist-v1.0-Linux-x86_64.zip Mentalist
chmod +x Mentalist
rm Mentalist-v1.0-Linux-x86_64.zip

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

# MS17-010
cd $INTERNALS_DIR
git clone https://github.com/worawit/MS17-010.git

# MSOLSpray
cd $RECON_DIR
git clone https://github.com/MartinIngesen/MSOLSpray.git

# Neo-reGeorg
cd $INTERNALS_DIR
git clone https://github.com/L-codes/Neo-reGeorg.git

# Netcredz
cd $INTERNALS_DIR
git clone https://github.com/joey-melo/netcredz.git

# Netexec
cd $INTERNALS_DIR
pipx install git+https://github.com/Pennyw0rth/NetExec || echo "[-] Failed to install Netexec"

# Nomore403
cd $WEB_DIR
wget https://github.com/devploit/nomore403/releases/download/v1.1.0/nomore403_linux_amd64
mv nomore403_linux_amd64 nomore403
chmod +x nomore403

# NoPac
cd $INTERNALS_DIR
git clone https://github.com/Ridter/noPac.git

# NTLMRecon
cd $RECON_DIR
pipx install git+https://github.com/pwnfoo/NTLMRecon.git

# Ntlmscan
cd $RECON_DIR
git clone https://github.com/nyxgeek/ntlmscan.git

# Ntlm_theft
cd $INTERNALS_DIR
git clone https://github.com/Greenwolf/ntlm_theft.git
pipx install xlsxwriter

# NTLMv1-multi
cd $INTERNALS_DIR
git clone https://github.com/evilmog/ntlmv1-multi.git

# O365enum
cd $RECON_DIR
git clone https://github.com/gremwell/o365enum.git

# O365recon
cd $RECON_DIR
git clone https://github.com/nyxgeek/o365recon.git

# O365spray
cd $RECON_DIR
pipx install git+https://github.com/0xZDH/o365spray.git

# Objection
cd $MOBILE_DIR
pipx install git+https://github.com/sensepost/objection.git

# OpenRedireX
cd $WEB_DIR
git clone https://github.com/devanshbatham/OpenRedireX.git

# PassTheCert
cd $INTERNALS_DIR
git clone https://github.com/AlmondOffSec/PassTheCert.git

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

# PKINITtools
cd $INTERNALS_DIR
git clone https://github.com/dirkjanm/PKINITtools.git

# Pre2k
cd $INTERNALS_DIR
git clone https://github.com/garrettfoster13/pre2k.git

# PrintNightmare
cd $INTERNALS_DIR
git clone https://github.com/cube0x0/CVE-2021-1675.git PrintNightmare
git clone https://github.com/ly4k/PrintNightmare.git PrintNightmare-ly4k

# PrivescCheck
cd $INTERNALS_DIR
git clone https://github.com/itm4n/PrivescCheck.git

# Pypycatz
pipx install git+https://github.com/skelsec/pypykatz || echo "[-] Failed to install Pypycatz"

# PyScan
git clone https://github.com/afkfr0mkeyb0ard/PyScan.git

# Responder
cd $INTERNALS_DIR
git clone https://github.com/lgandx/Responder.git

# RottenPotatoNG
cd $INTERNALS_DIR
git clone https://github.com/breenmachine/RottenPotatoNG.git

# RSMangler
cd $PASSCRACK_DIR
git clone https://github.com/digininja/RSMangler.git

# Rtl8812au
cd $WIFI_DIR
sudo apt-get -y install dkms bc mokutil build-essential libelf-dev linux-headers-`uname -r`
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl*
sudo make dkms_install

# SecLists
cd $WEB_DIR
git clone https://github.com/danielmiessler/SecLists.git

# SharpHound
cd $INTERNALS_DIR
wget https://github.com/SpecterOps/SharpHound/releases/download/v2.5.13/SharpHound-v2.5.13.zip
unzip -q SharpHound-v2.5.13.zip -d SharpHound
rm SharpHound-v2.5.13.zip

# Shortscan
cd $WEB_DIR
go install github.com/bitquark/shortscan/cmd/shortscan@latest

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

# Snoop
cd $RECON_DIR
mkdir Snoop
cd Snoop
wget https://github.com/snooppr/snoop/releases/download/v1.4.2__2025-1-1/Snoop_for_GNU_Linux.rar
unrar x Snoop_for_GNU_Linux.rar
rm Snoop_for_GNU_Linux.rar

# Spiderfoot
# Installed by default on Kali
# https://github.com/smicallef/spiderfoot

# Spoofcheck
cd $RECON_DIR
git clone https://github.com/a6avind/spoofcheck.git

# Swaks
cd $RECON_DIR
wget https://github.com/jetmore/swaks/releases/download/v20240103.0/swaks-20240103.0.tar.gz
tar -xzf swaks-20240103.0.tar.gz
rm swaks-20240103.0.tar.gz

# TeamsEnum
cd $RECON_DIR
git clone https://github.com/sse-secure-systems/TeamsEnum.git
cd TeamsEnum
python3 -m venv .
source bin/activate
pip3 install -r requirements.txt
deactivate
echo "alias teamsenum.py='$RECON_DIR/TeamsEnum/bin/python3 $RECON_DIR/TeamsEnum/TeamsEnum.py'" >> ~/.zshrc

# Testssl
cd $WEB_DIR
git clone --depth 1 https://github.com/testssl/testssl.sh.git

# TheHarvester
cd $RECON_DIR
pipx install git+https://github.com/laramies/theHarvester.git

# Timeroast
cd $INTERNALS_DIR
git clone https://github.com/SecuraBV/Timeroast.git

# TomcatSampleWebshell
cd $WEB_DIR
git clone https://github.com/afkfr0mkeyb0ard/TomcatSampleWebshell.git

# TREVORspray
cd $RECON_DIR
pipx install git+https://github.com/blacklanternsecurity/TREVORspray.git

# Trufflehog
cd $RECON_DIR
wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.88.12/trufflehog_3.88.12_linux_amd64.tar.gz
tar -xzf trufflehog_3.88.12_linux_amd64.tar.gz
rm README.md LICENSE trufflehog_3.88.12_linux_amd64.tar.gz
chmod +x trufflehog

# Vita
cd $RECON_DIR
wget https://github.com/junnlikestea/vita/releases/download/0.1.16/vita-0.1.16-x86_64-unknown-linux-musl.tar.gz
tar -xzf vita-0.1.16-x86_64-unknown-linux-musl.tar.gz
rm vita-0.1.16-x86_64-unknown-linux-musl.tar.gz
mv vita-0.1.16-x86_64-unknown-linux-musl/vita .
rm -r vita-0.1.16-x86_64-unknown-linux-musl

# Waybackurls
cd $WEB_DIR
wget https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-linux-amd64-0.1.0.tgz
tar -xzf waybackurls-linux-amd64-0.1.0.tgz
rm waybackurls-linux-amd64-0.1.0.tgz
chmod +x waybackurls
echo "alias waybackurls='cd $WEB_DIR/waybackurls'" >> ~/.zshrc 

# Webclientservicescanner
cd $INTERNALS_DIR
pipx install git+https://github.com/Hackndo/WebclientServiceScanner || echo "[-] Failed to install Webclientservicescanner"
pipx ensurepath

# Weevely3
cd $WEB_DIR
git clone https://github.com/epinna/weevely3.git

# Wef
cd $WIFI_DIR
git clone https://github.com/D3Ext/WEF.git

# Windows-Exploit-Suggester
cd $INTERNALS_DIR
git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git

echo "[+] All repositories have been successfully cloned, and scripts downloaded into their respective directories."

#############################################################
### Installation of the scripts/exploits
#############################################################

echo "[+] Downloading scripts/exploits"

# Cpassword_decrypt
cd $INTERNALS_DIR
wget https://raw.githubusercontent.com/rapid7/metasploit-framework/master/tools/password/cpassword_decrypt.rb
chmod +x cpassword_decrypt.rb

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
