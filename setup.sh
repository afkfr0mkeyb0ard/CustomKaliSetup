#!/bin/bash

# Define the destination directory
BASE_DIR="$HOME"

# Define directories for categories
INTERNALS_DIR="$BASE_DIR/internals"
WEB_DIR="$BASE_DIR/web"
WIFI_DIR="$BASE_DIR/wifi"
RECON_DIR="$BASE_DIR/recon"
PASSGEN_DIR="$BASE_DIR/passgen"
GENERAL_DIR="$BASE_DIR/general"

# Create the directories if they don't exist
mkdir -p "$INTERNALS_DIR" "$WEB_DIR" "$WIFI_DIR" "$RECON_DIR" "$PASSGEN_DIR" "$GENERAL_DIR"

# Config variables
echo 'export tools_internals="$BASE_DIR/internals"' >> ~/.zshrc
echo 'export tools_web="$BASE_DIR/web"' >> ~/.zshrc
echo 'export tools_wifi="$BASE_DIR/wifi"' >> ~/.zshrc
echo 'export tools_recon="$BASE_DIR/recon"' >> ~/.zshrc
echo 'export tools_passgen="$BASE_DIR/passgen"' >> ~/.zshrc
echo 'export tools_general="$BASE_DIR/general"' >> ~/.zshrc

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

# Aquatone
cd $INTERNALS_DIR
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip -q aquatone_linux_amd64_1.7.0.zip aquatone
chmod +x aquatone
rm aquatone_linux_amd64_1.7.0.zip
echo 'alias aquatone="$INTERNALS_DIR/aquatone"' >> ~/.zsh_history

# Assetfinder
cd $RECON_DIR
wget https://github.com/tomnomnom/assetfinder/releases/download/v0.1.1/assetfinder-linux-amd64-0.1.1.tgz
tar -xzf assetfinder-linux-amd64-0.1.1.tgz
rm assetfinder-linux-amd64-0.1.1.tgz

# Bbot
pipx install bbot

# BloodHound
cd $INTERNALS_DIR
pipx install bloodhound

# BloodHound-Legacy
cd $INTERNALS_DIR
wget https://github.com/SpecterOps/BloodHound-Legacy/releases/download/v4.3.1/BloodHound-linux-x64.zip
unzip -q BloodHound-linux-x64.zip
rm BloodHound-linux-x64.zip

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
echo 'alias chisel="$INTERNALS_DIR/chisel_linux"' >> ~/.zshrc
echo 'chisel server -p 8000 --reverse' >> ~/.zsh_history

# Cloud_enum
cd $RECON_DIR
pipx install git+https://github.com/initstring/cloud_enum.git

# Coercer
cd $INTERNALS_DIR
pipx install git+https://github.com/p0dalirius/Coercer.git || echo "[-] Failed to install Coercer"
echo "coercer scan -t IP -u USER -p PASS -d DOMAIN -v" >> ~/.zsh_history
echo "coercer coerce -l IP_LISTERNER -t IP_TARGET -u USER -p PASS -d DOMAINE -v" >> ~/.zsh_history

# CrossLinked
cd $RECON_DIR
pipx install git+https://github.com/m8sec/CrossLinked.git

# Crowbar
cd $INTERNALS_DIR
pipx install git+https://github.com/galkan/crowbar || echo "[-] Failed to install Crowbar"

# CsFalconUninstaller
cd $INTERNALS_DIR
git clone https://github.com/gmh5225/CVE-2022-44721-CsFalconUninstaller.git

# DonPAPI
cd $INTERNALS_DIR
pipx install git+https://github.com/login-securite/DonPAPI.git || echo "[-] Failed to install DonPAPI"

# Eaphammer
cd $WIFI_DIR
git clone https://github.com/s0lst1c3/eaphammer.git

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

# FinalRecon
cd $RECON_DIR
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
python3 -m venv .
source bin/activate
pip3 install -r requirements.txt
deactivate
echo 'alias finalrecon="$RECON_DIR/FinalRecon/bin/python3 $RECON_DIR/FinalRecon/finalrecon.py"' >> ~/.zshrc

# FindADCS
cd $INTERNALS_DIR
git clone https://github.com/afkfr0mkeyb0ard/findADCS.git

# GenUsernames
cd $PASSGEN_DIR
git clone https://github.com/afkfr0mkeyb0ard/GenUsernames.git

# Git-dumper
cd $WEB_DIR
pipx install git+https://github.com/arthaud/git-dumper.git

# Gitleaks
cd $RECON_DIR
wget https://github.com/gitleaks/gitleaks/releases/download/v8.24.0/gitleaks_8.24.0_linux_x64.tar.gz
tar -xzf gitleaks_8.24.0_linux_x64.tar.gz
rm README.md
rm LICENSE
rm gitleaks_8.24.0_linux_x64.tar.gz

# GMSADumper
cd $INTERNALS_DIR
git clone https://github.com/micahvandeusen/gMSADumper.git

# GoMapEnum
cd $RECON_DIR
wget https://github.com/nodauf/GoMapEnum/releases/download/v1.1.0/GoMapEnum_1.1.0_linux_amd64.tar.gz
tar -xzf GoMapEnum_1.1.0_linux_amd64.tar.gz
rm GoMapEnum_1.1.0_linux_amd64.tar.gz

# GoRedOps
cd $GENERAL_DIR
git clone https://github.com/EvilBytecode/GoRedOps.git

# Hashcat
cd $PASSGEN_DIR
wget https://github.com/hashcat/hashcat/releases/download/v6.2.6/hashcat-6.2.6.7z

# Hostapd-wpe
cd $WIFI_DIR
sudo apt-get -y install hostapd-wpe

# Impacket
cd $INTERNALS_DIR
wget https://github.com/fortra/impacket/releases/download/impacket_0_12_0/impacket-0.12.0.tar.gz
tar -xzf impacket-0.12.0.tar.gz
rm impacket-0.12.0.tar.gz
cd impacket-0.12.0
python3 -m venv .
source bin/activate
pip3 install -r requirements.txt
deactivate

# ItWasAllADream
cd $INTERNALS_DIR
pipx install git+https://github.com/byt3bl33d3r/ItWasAllADream || echo "[-] Failed to install ItWasAllADream"
echo "itwasalladream -u user -p password -d domain 192.168.1.0/24" >> ~/.zsh_history

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
echo 'alias kerbrute="$INTERNALS_DIR/kerbrute"' >> ~/.zshrc

# KnockKnock
cd $RECON_DIR
git clone https://github.com/waffl3ss/KnockKnock.git
cd KnockKnock
python3 -m venv .
source bin/activate
pip3 install -r requirements.txt
deactivate
echo 'alias knockknock="$RECON_DIR/KnockKnock/bin/python3 $RECON_DIR/KnockKnock/KnockKnock.py"' >> ~/.zshrc

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
echo 'alias ldapnomnom="$INTERNALS_DIR/ldapnomnom-linux-x64"' >> ~/.zshrc
echo 'alias ldapnomnom_obfuscated="$INTERNALS_DIR/ldapnomnom-linux-x64-obfuscated"' >> ~/.zshrc

# Ldapsearch-ad
pipx install git+https://github.com/yaap7/ldapsearch-ad || echo "[-] Failed to install Ldapsearch-ad"
echo "ldapsearch-ad.py -l 10.0.0.1 -t info" >> ~/.zsh_history

# Manspider
pipx install git+https://github.com/blacklanternsecurity/MANSPIDER || echo "[-] Failed to install Manspider"
echo "manspider 10.10.10.0/24 -e xml -c DefaultPassword cpassword -n -u USER -p PASS -d DOMAINE" >> ~/.zsh_history

# Mentalist
cd $PASSGEN_DIR
wget https://github.com/sc0tfree/mentalist/releases/download/v1.0/Mentalist-v1.0-Linux-x86_64.zip
unzip -q Mentalist-v1.0-Linux-x86_64.zip Mentalist
chmod +x Mentalist
rm Mentalist-v1.0-Linux-x86_64.zip

# Mentalist_chains
cd $PASSGEN_DIR
git clone https://github.com/afkfr0mkeyb0ard/Mentalist_chains.git

# Mhydeath
cd $INTERNALS_DIR
git clone https://github.com/zer0condition/mhydeath.git

# Mitm6
pipx install git+https://github.com/dirkjanm/mitm6 || echo "[-] Failed to install Mitm6"
echo "mitm6 -i eth0 -d domain.local -hb [donotrespondtoFILE] [-hw <target>] [--ignore-nofqnd]" >> ~/.zsh_history

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
cd $PASSGEN_DIR
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

# Smuggler
cd $WEB_DIR
git clone https://github.com/defparam/smuggler.git

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
echo 'alias teamsenum.py="$RECON_DIR/TeamsEnum/bin/python3 $RECON_DIR/TeamsEnum/TeamsEnum.py"' >> ~/.zshrc

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
echo 'alias waybackurls="cd $WEB_DIR/waybackurls"' >> ~/.zshrc 

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
### Installation of the scripts
#############################################################

echo "[+] Downloading scripts"

# Cpassword_decrypt
cd $INTERNALS_DIR
wget https://raw.githubusercontent.com/rapid7/metasploit-framework/master/tools/password/cpassword_decrypt.rb
chmod +x cpassword_decrypt.rb

# iLO4_add_admin
cd $INTERNALS_DIR
wget https://www.exploit-db.com/download/44005
mv 44005 iLO4_add_admin.py
