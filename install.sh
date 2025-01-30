#!/bin/bash

# Define the destination directory
BASE_DIR="$HOME"

# Define directories for categories
INTERNALS_DIR="$BASE_DIR/Internals"
WEB_DIR="$BASE_DIR/Web"
WIFI_DIR="$BASE_DIR/WiFi"
RECON_DIR="$BASE_DIR/Recon"
PASSGEN_DIR="$BASE_DIR/PassGen"
GENERAL_DIR="$BASE_DIR/General"

# Config variables
echo 'export INTERNALS_DIR="$HOME/Documents/Internals"' >> ~/.zshrc
echo 'export WEB_DIR="$HOME/Documents/Web"' >> ~/.zshrc
echo 'export WIFI_DIR="$HOME/Documents/WiFi"' >> ~/.zshrc
echo 'export RECON_DIR="$HOME/Documents/Recon"' >> ~/.zshrc
echo 'export PASSGEN_DIR="$HOME/Documents/PassGen"' >> ~/.zshrc
echo 'export GENERAL_DIR="$HOME/Documents/General"' >> ~/.zshrc

# Installation of the tools

# Dependencies
pipx ensurepath || echo "[-] Please install pipx first with apt install pipx" && exit 1

# Aquatone
cd $INTERNALS_DIR
unzip aquatone_linux_amd64_1.7.0.zip aquatone
chmod +x aquatone
rm aquatone_linux_amd64_1.7.0.zip

# Bbot
pipx install bbot

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

# Coercer
cd $INTERNALS_DIR
pipx install git+https://github.com/ly4k/Certipy || echo "[-] Failed to install Certipy" || echo "[-] Failed to install Coercer"
echo "coercer scan -t IP -u USER -p PASS -d DOMAIN -v" >> ~/.zsh_history
echo "coercer coerce -l IP_LISTERNER -t IP_TARGET -u USER -p PASS -d DOMAINE -v" >> ~/.zsh_history

# DonPAPI
cd $INTERNALS_DIR
pipx install git+https://github.com/login-securite/DonPAPI.git || echo "[-] Failed to install DonPAPI"

# Ffuf
cd $WEB_DIR
tar -xzvf ffuf_2.1.0_linux_amd64.tar.gz ffuf
chmod +x ffuf
rm ffuf_2.1.0_linux_amd64.tar.gz

# ItWasAllADream
pipx install git+https://github.com/byt3bl33d3r/ItWasAllADream || echo "[-] Failed to install ItWasAllADream"
echo "itwasalladream -u user -p password -d domain 192.168.1.0/24" >> ~/.zsh_history
deactivate

#JSLuice
cd $WEB_DIR
go install github.com/BishopFox/jsluice/cmd/jsluice@latest

# Kerbrute
cd $INTERNALS_DIR
chmod +x kerbrute_linux_amd64

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

# Mitm6
pipx install git+https://github.com/dirkjanm/mitm6 || echo "[-] Failed to install Mitm6"
echo "mitm6 -i eth0 -d domain.local -hb [donotrespondtoFILE] [-hw <target>] [--ignore-nofqnd]" >> ~/.zsh_history

# Netexec
pipx install git+https://github.com/Pennyw0rth/NetExec || echo "[-] Failed to install Netexec"

# Nomore403
cd $WEB_DIR
cd nomore403
wget https://github.com/devploit/nomore403/releases/download/1.0.2/nomore403_linux_amd64
chmod +x nomore403_linux_amd64

# PCredz
cd $INTERNALS_DIR
cd PCredz
python3 -m venv .
source bin/activate
sudo apt-get install libpcap-dev && pip3 install Cython && pip3 install python-libpcap || echo "[-] Failed to install PCredz"
deactivate

# Pypycatz
pipx install git+https://github.com/skelsec/pypykatz || echo "[-] Failed to install Pypycatz"

# theHarvester
cd $RECON_DIR
cd theHarvester
pip3 install -r requirements/base.txt

# Webclientservicescanner
pipx install git+https://github.com/Hackndo/WebclientServiceScanner || echo "[-] Failed to install Webclientservicescanner"
pipx ensurepath
