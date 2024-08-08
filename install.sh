#!/bin/bash

# Define the destination directory
BASE_DIR="$HOME/Documents"

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
sudo apt install python3.11-venv || echo "[-] Failed to install python3.11-venv"
pip install pipx
pipx ensurepath

# Aquatone
cd $INTERNALS_DIR
unzip aquatone_linux_amd64_1.7.0.zip aquatone
chmod +x aquatone
rm aquatone_linux_amd64_1.7.0.zip

# Certipy
pip3 install certipy-ad || echo "[-] Failed to install certipy-ad"
echo "certipy-ad find -u 'svc_ldap@DOMAIN.local' -p 'pass123' -dc-ip 10.10.11.222" >> ~/.zsh_history
echo "certipy-ad find -u 'svc_ldap@DOMAIN.local' -p 'pass123' -dc-ip 10.10.11.222 -vulnerable" >> ~/.zsh_history

# Chisel
cd $INTERNALS_DIR
gzip -d chisel_1.9.1_linux_amd64.gz
gzip -d chisel_1.9.1_windows_amd64.gz
chmod +x chisel_1.9.1_linux_amd64
chmod +x chisel_1.9.1_windows_amd64
echo 'chisel server -p 8000 --reverse' >> ~/.zsh_history

# Coercer
cd $INTERNALS_DIR
cd Coercer
python3 -m venv .
source ./bin/activate
pip3 install sectools
python3 -m pip install coercer || echo "[-] Failed to install Coercer"
deactivate
echo "alias activate-coercer='cd \$INTERNALS_DIR/Coercer && source ./bin/activate && python3 Coercer.py'" >> ~/.zshrc
echo "python3 Coercer.py scan -t IP -u USER -p PASS -d DOMAIN -v" >> ~/.zsh_history
echo "python3 Coercer.py coerce -l IP_LISTERNER -t IP_TARGET -u USER -p PASS -d DOMAINE -v" >> ~/.zsh_history

# DonPAPI
cd $INTERNALS_DIR
pipx install git+https://github.com/login-securite/DonPAPI.git

# Ffuf
cd $WEB_DIR
tar -xzvf ffuf_2.1.0_linux_amd64.tar.gz ffuf
chmod +x ffuf
rm ffuf_2.1.0_linux_amd64.tar.gz

# ItWasAllADream
cd $INTERNALS_DIR
cd ItWasAllADream
poetry install || echo "[-] Failed to install ItWasAllADream"
echo "alias activate-itwasalladream='cd \$INTERNALS_DIR/ItWasAllADream && poetry shell && itwasalladream -h'" >> ~/.zshrc
echo "itwasalladream -u user -p password -d domain 192.168.1.0/24" >> ~/.zsh_history
deactivate

# Kerbrute
cd $INTERNALS_DIR
chmod +x kerbrute_linux_amd64

# Ldapnomnom
cd $INTERNALS_DIR
chmod +x ldapnomnom-linux-x64
chmod +x ldapnomnom-linux-x64-obfuscated

# Manspider
python3 -m pipx install git+https://github.com/blacklanternsecurity/MANSPIDER || echo "[-] Failed to install Manspider"
echo "alias manspider='\$HOME/.local/share/pipx/venvs/man-spider/bin/manspider'" >> ~/.zshrc
echo "manspider 10.10.10.0/24 -e xml -c DefaultPassword cpassword -n -u USER -p PASS -d DOMAINE" >> ~/.zsh_history

# Mentalist
cd $PASSGEN_DIR
unzip Mentalist-v1.0-Linux-x86_64.zip Mentalist
chmod +x Mentalist
rm Mentalist-v1.0-Linux-x86_64.zip

# Mitm6
cd $INTERNALS_DIR
cd mitm6
python3 -m venv .
source ./bin/activate
pip3 install -r requirements.txt || echo "[-] Failed to install Mitm6"
deactivate
echo "alias activate-mitm6='cd \$INTERNALS_DIR/mitm6 && source ./bin/activate'" >> ~/.zshrc
echo "python3 mitm6.py -i eth0 -d domain.local -hb [donotrespondtoFILE] [-hw <target>] [--ignore-nofqnd]" >> ~/.zsh_history

# Netexec
python3 -m pipx ensurepath
python3 -m pipx install git+https://github.com/Pennyw0rth/NetExec || echo "[-] Failed to install Netexec"

# PCredz
sudo apt-get install libpcap-dev && pip3 install Cython && pip3 install python-libpcap || echo "[-] Failed to install PCredz"

# Pypycatz
pip3 install pypykatz
