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

#############################################################
# Installation of the tools

# Dependencies
pipx ensurepath || (echo "[-] Please install pipx first with apt install pipx" && exit 1)

# Aquatone
cd $INTERNALS_DIR
unzip aquatone_linux_amd64_1.7.0.zip aquatone
chmod +x aquatone
rm aquatone_linux_amd64_1.7.0.zip

# Bbot
pipx install bbot

# BloodHound
pipx install bloodhound

# Certipy
cd $INTERNALS_DIR
pipx install git+https://github.com/ly4k/Certipy || echo "[-] Failed to install Certipy"
echo "certipy find -u 'svc_ldap@DOMAIN.local' -p 'pass123' -dc-ip 10.10.11.222" >> ~/.zsh_history
echo "certipy find -u 'svc_ldap@DOMAIN.local' -p 'pass123' -dc-ip 10.10.11.222 -vulnerable" >> ~/.zsh_history

# Chisel
cd $INTERNALS_DIR
gzip -d chisel_1.9.1_linux_amd64.gz
gzip -d chisel_1.9.1_windows_amd64.gz
chmod +x chisel_1.9.1_linux_amd64
chmod +x chisel_1.9.1_windows_amd64
echo 'chisel server -p 8000 --reverse' >> ~/.zsh_history

# Cloud_enum
pipx install git+https://github.com/initstring/cloud_enum

# Coercer
cd $INTERNALS_DIR
pipx install git+https://github.com/p0dalirius/Coercer.git || echo "[-] Failed to install Coercer"
echo "coercer scan -t IP -u USER -p PASS -d DOMAIN -v" >> ~/.zsh_history
echo "coercer coerce -l IP_LISTERNER -t IP_TARGET -u USER -p PASS -d DOMAINE -v" >> ~/.zsh_history

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

# Ffuf
cd $WEB_DIR
tar -xzvf ffuf_2.1.0_linux_amd64.tar.gz ffuf
chmod +x ffuf
rm ffuf_2.1.0_linux_amd64.tar.gz

# FindADCS
cd $INTERNALS_DIR
git clone https://github.com/afkfr0mkeyb0ard/findADCS.git

# GMSADumper
cd $INTERNALS_DIR
https://github.com/micahvandeusen/gMSADumper.git

# ItWasAllADream
pipx install git+https://github.com/byt3bl33d3r/ItWasAllADream || echo "[-] Failed to install ItWasAllADream"
echo "itwasalladream -u user -p password -d domain 192.168.1.0/24" >> ~/.zsh_history

# JSLuice
cd $WEB_DIR
go install github.com/BishopFox/jsluice/cmd/jsluice@latest

# Kerbrute
cd $INTERNALS_DIR
chmod +x kerbrute_linux_amd64

# Krbrelayx
cd $INTERNALS_DIR
git clone https://github.com/dirkjanm/krbrelayx.git

# Ldapnomnom
cd $INTERNALS_DIR
chmod +x ldapnomnom-linux-x64
chmod +x ldapnomnom-linux-x64-obfuscated

# Ldapsearch-ad
pipx install git+https://github.com/yaap7/ldapsearch-ad || echo "[-] Failed to install Ldapsearch-ad"
echo "ldapsearch-ad.py -l 10.0.0.1 -t info" >> ~/.zsh_history

# Manspider
pipx install git+https://github.com/blacklanternsecurity/MANSPIDER || echo "[-] Failed to install Manspider"
echo "manspider 10.10.10.0/24 -e xml -c DefaultPassword cpassword -n -u USER -p PASS -d DOMAINE" >> ~/.zsh_history

# Mentalist
cd $PASSGEN_DIR
unzip Mentalist-v1.0-Linux-x86_64.zip Mentalist
chmod +x Mentalist
rm Mentalist-v1.0-Linux-x86_64.zip

# Mhydeath
cd $INTERNALS_DIR
git clone https://github.com/zer0condition/mhydeath.git

# Mitm6
pipx install git+https://github.com/dirkjanm/mitm6 || echo "[-] Failed to install Mitm6"
echo "mitm6 -i eth0 -d domain.local -hb [donotrespondtoFILE] [-hw <target>] [--ignore-nofqnd]" >> ~/.zsh_history

# MS17-010
cd $INTERNALS_DIR
git clone https://github.com/worawit/MS17-010.git

# Neo-reGeorg
cd $INTERNALS_DIR
git clone https://github.com/L-codes/Neo-reGeorg.git

# Netcredz
cd $INTERNALS_DIR
git clone https://github.com/joey-melo/netcredz.git

# Netexec
pipx install git+https://github.com/Pennyw0rth/NetExec || echo "[-] Failed to install Netexec"

# Nomore403
cd $WEB_DIR
wget https://github.com/devploit/nomore403/releases/download/v1.1.0/nomore403_linux_amd64
chmod +x nomore403_linux_amd64

# NoPac
cd $INTERNALS_DIR
git clone https://github.com/Ridter/noPac.git

# NTLMv1-multi
cd $INTERNALS_DIR
git clone https://github.com/evilmog/ntlmv1-multi.git

# OpenRedireX
cd $WEB_DIR
git clone https://github.com/devanshbatham/OpenRedireX.git

# PassTheCert
cd $INTERNALS_DIR
git clone https://github.com/AlmondOffSec/PassTheCert.git

# PayloadsAllTheThings
cd $WEB_DIR
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git

# PEASS-ng
cd $INTERNALS_DIR
mkdir PEASS-ng
cd PEASS-ng
wget https://github.com/peass-ng/PEASS-ng/releases/download/20250216-fd69e735/winPEAS.bat
wget https://github.com/peass-ng/PEASS-ng/releases/download/20250216-fd69e735/winPEASx64.exe
wget https://github.com/peass-ng/PEASS-ng/releases/download/20250216-fd69e735/linpeas.sh
wget https://github.com/peass-ng/PEASS-ng/releases/download/20250216-fd69e735/linpeas_darwin_amd64
wget https://github.com/peass-ng/PEASS-ng/releases/download/20250216-fd69e735/linpeas_linux_amd64
chmod +x win*
chmod +x lin*

# PetitPotam
cd $INTERNALS_DIR
git clone https://github.com/topotam/PetitPotam.git
git clone https://github.com/ly4k/PetitPotam.git PetitPotam-ly4k

# PCredz
cd $INTERNALS_DIR
cd PCredz
python3 -m venv .
source bin/activate
sudo apt-get install libpcap-dev && pip3 install Cython && pip3 install python-libpcap || echo "[-] Failed to install PCredz"
deactivate

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

# Shortscan
cd $WEB_DIR
go install github.com/bitquark/shortscan/cmd/shortscan@latest

# Smuggler
cd $WEB_DIR
git clone https://github.com/defparam/smuggler.git

# theHarvester
cd $RECON_DIR
cd theHarvester
pip3 install -r requirements/base.txt

# Timeroast
cd $INTERNALS_DIR
git clone https://github.com/SecuraBV/Timeroast.git

# Webclientservicescanner
pipx install git+https://github.com/Hackndo/WebclientServiceScanner || echo "[-] Failed to install Webclientservicescanner"
pipx ensurepath

# Weevely3
cd $WEB_DIR
git clone https://github.com/epinna/weevely3.git

# Windows-Exploit-Suggester
cd $INTERNALS_DIR
git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git

echo "All repositories have been successfully cloned, and scripts downloaded into their respective directories."
