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

# Create the directories if they don't exist
mkdir -p "$INTERNALS_DIR" "$WEB_DIR" "$WIFI_DIR" "$RECON_DIR" "$PASSGEN_DIR" "$GENERAL_DIR"

# Define Git repositories for each category
INTERNALS_REPOS=(
  "https://github.com/evilmog/ntlmv1-multi.git"
  "https://github.com/topotam/PetitPotam.git"
  "https://github.com/cube0x0/CVE-2021-1675.git"
  "https://github.com/ly4k/PrintNightmare.git"
  "https://github.com/breenmachine/RottenPotatoNG.git"
  "https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git"
  "https://github.com/byt3bl33d3r/ItWasAllADream.git"
  "https://github.com/dirkjanm/mitm6.git"
  "https://github.com/ly4k/PetitPotam.git"
  "https://github.com/ly4k/Certipy.git"
  "https://github.com/galkan/crowbar.git"
  "https://github.com/dirkjanm/krbrelayx.git"
  "https://github.com/worawit/MS17-010.git"
  "https://github.com/AlmondOffSec/PassTheCert.git"
  "https://github.com/dirkjanm/PKINITtools.git"
  "https://github.com/itm4n/PrivescCheck.git"
  "https://github.com/gmh5225/CVE-2022-44721-CsFalconUninstaller.git"
  "https://github.com/p0dalirius/Coercer.git"
  "https://github.com/Ridter/noPac.git"
  "https://github.com/peass-ng/PEASS-ng.git"
  "https://github.com/lgandx/Responder.git"
  "https://github.com/Hackndo/WebclientServiceScanner.git"
  "https://github.com/lgandx/PCredz.git"
  "https://github.com/skelsec/pypykatz.git"
  "https://github.com/zer0condition/mhydeath.git"
  "https://github.com/afkfr0mkeyb0ard/PyScan.git"
  "https://github.com/afkfr0mkeyb0ard/findADCS.git"
  "https://github.com/L-codes/Neo-reGeorg.git"
  "https://github.com/SecuraBV/Timeroast.git"
  "https://github.com/garrettfoster13/pre2k.git"
)

WEB_REPOS=(
  "https://github.com/devanshbatham/OpenRedireX.git"
  "https://github.com/defparam/smuggler.git"
  "https://github.com/swisskyrepo/PayloadsAllTheThings.git"
  "https://github.com/initstring/cloud_enum.git"
  "https://github.com/devploit/nomore403.git"
)

WIFI_REPOS=(
  "https://github.com/s0lst1c3/eaphammer.git"
)

RECON_REPOS=(
  "https://github.com/afkfr0mkeyb0ard/bruteSubdomains.git"
  "https://github.com/m8sec/CrossLinked.git"
  "https://github.com/0xZDH/o365spray.git"
  "https://github.com/RedSiege/EyeWitness.git"
  "https://github.com/gremwell/o365enum.git"
  "https://github.com/laramies/theHarvester.git"
  "https://github.com/smicallef/spiderfoot.git"
  "https://github.com/a6avind/spoofcheck.git"
  "https://github.com/initstring/cloud_enum.git"
)

PASSGEN_REPOS=(
  "https://github.com/digininja/RSMangler.git"
  "https://github.com/afkfr0mkeyb0ard/Mentalist_chains.git"
  "https://github.com/hashcat/hashcat.git"
)

GENERAL_REPOS=(
  "https://github.com/danielmiessler/SecLists.git"
  "https://github.com/afkfr0mkeyb0ard/PayloadEverything.git"
)

# Define scripts to download for each category
INTERNALS_SCRIPTS=(
  "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/tools/password/cpassword_decrypt.rb"
  "https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip"
  "https://github.com/byt3bl33d3r/CrackMapExec/releases/download/v5.4.0/cme-ubuntu-latest-3.11.zip"
  "https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64"
  "https://www.exploit-db.com/download/44005"
  "https://github.com/fortra/impacket/releases/download/impacket_0_11_0/impacket-0.11.0.tar.gz"
  "https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz"
  "https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz"
  "https://github.com/lkarlslund/ldapnomnom/releases/download/v1.3.0/ldapnomnom-linux-x64"
  "https://github.com/lkarlslund/ldapnomnom/releases/download/v1.3.0/ldapnomnom-linux-x64-obfuscated"
  "https://github.com/CravateRouge/bloodyAD/releases/download/v2.0.6/bloodyAD.exe"
  "https://github.com/BloodHoundAD/SharpHound/releases/download/v2.5.4/SharpHound-v2.5.4.zip"
)

WEB_SCRIPTS=(
  "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz"
)

WIFI_SCRIPTS=(

)

RECON_SCRIPTS=(
  "https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip"
  "https://github.com/jetmore/swaks/releases/download/v20240103.0/swaks-20240103.0.tar.gz"
)

PASSGEN_SCRIPTS=(
  "https://github.com/sc0tfree/mentalist/releases/download/v1.0/Mentalist-v1.0-Linux-x86_64.zip"
)

GENERAL_SCRIPTS=(
  
)

# Function to clone repositories
clone_repositories() {
  local repo_list=("$@")
  local target_dir=$1
  shift
  for REPO in "$@"; do
    case "$REPO" in
      "https://github.com/cube0x0/CVE-2021-1675.git")
        echo "Cloning $REPO and renaming to PrintNightmare-cube0x0..."
        git clone "$REPO" "$target_dir/PrintNightmare-cube0x0" || echo "Failed to clone $REPO"
        ;;
      "https://github.com/ly4k/PrintNightmare.git")
        echo "Cloning $REPO and renaming to PrintNightmare-ly4k..."
        git clone "$REPO" "$target_dir/PrintNightmare-ly4k" || echo "Failed to clone $REPO"
        ;;
      "https://github.com/ly4k/PetitPotam.git")
        echo "Cloning $REPO and renaming to PetitPotam-ly4k..."
        git clone "$REPO" "$target_dir/PetitPotam-ly4k" || echo "Failed to clone $REPO"
        ;;
      *)
        echo "Cloning $REPO into $target_dir..."
        git clone "$REPO" "$target_dir/$(basename "$REPO" .git)" || echo "Failed to clone $REPO"
        ;;
    esac
  done
}

# Clone repositories into respective directories
clone_repositories "$INTERNALS_DIR" "${INTERNALS_REPOS[@]}"
clone_repositories "$WEB_DIR" "${WEB_REPOS[@]}"
clone_repositories "$WIFI_DIR" "${WIFI_REPOS[@]}"
clone_repositories "$RECON_DIR" "${RECON_REPOS[@]}"
clone_repositories "$PASSGEN_DIR" "${PASSGEN_REPOS[@]}"
clone_repositories "$GENERAL_DIR" "${GENERAL_REPOS[@]}"

# Function to download scripts
download_scripts() {
  local script_list=("$@")
  local target_dir=$1
  shift
  mkdir -p "$target_dir"
  cd "$target_dir" || { echo "Failed to access $target_dir"; exit 1; }
  for SCRIPT in "$@"; do
    echo "Downloading $SCRIPT..."
    wget "$SCRIPT" || echo "Failed to download $SCRIPT"
  done
}

# Download scripts into respective directories
download_scripts "$INTERNALS_DIR" "${INTERNALS_SCRIPTS[@]}"
download_scripts "$WEB_DIR" "${WEB_SCRIPTS[@]}"
download_scripts "$WIFI_DIR" "${WIFI_SCRIPTS[@]}"
download_scripts "$RECON_DIR" "${RECON_SCRIPTS[@]}"
download_scripts "$PASSGEN_DIR" "${PASSGEN_SCRIPTS[@]}"
download_scripts "$GENERAL_DIR" "${GENERAL_SCRIPTS[@]}"

echo "All repositories have been successfully cloned, and scripts downloaded into their respective directories."
