# CustomKaliSetup
One script to setup an offensive Linux machine (Debian, Kali) (~20Go).

**All tools are intended for legal and educational use only, use at your own risk.**

### Setup
```
wget https://raw.githubusercontent.com/afkfr0mkeyb0ard/CustomKaliSetup/refs/heads/main/setup.sh && chmod +x setup.sh && ./setup.sh
```

### List of installed tools

```
Adalanche
Adidnsdump
Amass
Android-kit (adb, sqlite3)
Android-unpinner
Apktool
Aquatone
Assetfinder
Autoswagger
Backup_dc_registry
BBot
Bettercap
Binwalk
BloodHound
BloodHound-CE
BloodHound-Legacy
BloodyAD
BruteSubdomains
Burpsuite
Certipy
Chisel
Cloud_enum
CloudPEASS
Coercer
CredMaster
CrossLinked
Crowbar
CsFalconUninstaller
DefaultCreds
Dex2Jar
DonPAPI
Drozer
Eaphammer
Enum4linux-ng
ExetoDll
ExtractBitlockerKeys
EyeWitness
Ffuf
FinalRecon
FindADCS
FindURLS
Frida
GenUsernames
Git-dumper
Gitleaks
GMSADumper
Go-secdump
GoMapEnum
GoRedOps
Gowitness
GPOHound
Hashcat
HExHTTP
Hostapd-wpe
Httpx
Impacket
ItWasAllADream
Jadx
Jd-Gui
JSLuice
Jwt-hack
JWT-Key-Recovery
Jwt-tools
Kerbrute
KnockKnock
Kraken
Krb5-user
Krbrelayx
Ldapnomnom
LdapRelayScan
Ldapsearch-ad
Ldeep
Magisk
MailSniper
Malimite
Manspider
Many-passwords
Mdk4
Mentalist
Mentalist_chains
MFASweep
Mhydeath
Mitm6
Monolith
MS17-010
MSOLSpray
Mssqlrelay
Neo-reGeorg
Netcredz
Netexec
Nmap
Nomore403
NoPac
NTLMRecon
Ntlmscan
NTLMv1-multi
Ntlm_theft
O365enum
O365recon
O365spray
Objection
OpenRedireX
PassTheCert
PayloadEverything
PayloadsAllTheThings
PCredz
PEASS-ng
PetitPotam
Phishing-HTML-linter
PKINITtools
Pre2k
PrintNightmare
PrivescCheck
Probable-Wordlists
Pypycatz
Pyscan
Pywhisker
Pywsus
Rcat
Responder
Ridenum
RootAVD
RottenPotatoNG
RSMangler
RustHound
SCCMHunter
SecLists
SharpHound
ShortScan (IIS Tilde)
Simplify
Sliver
Smbmap
Smuggler
Smugglo
Snoop
Sourcemapper
Spiderfoot
Spoofcheck
SQLmap
Swaks
TargetedKerberoast
TeamsEnum
Testssl
TheHarvester
Timeroast
TomcatSampleWebshell
TREVORspray
Trufflehog
Vita
Waybackurls
WebCacheVulnerabilityScanner
Webclientservicescanner
Weevely3
Wef
Wi-Fi Hotspot
Windows-Exploit-Suggester
Ysoserial
```

### Downloaded exploits 
```
# Cpassword decrypt
https://raw.githubusercontent.com/rapid7/metasploit-framework/master/tools/password/cpassword_decrypt.rb

# CVE-2025-33073 (NTLMreflection)
https://github.com/mverschu/CVE-2025-33073

# CVE-2025-24071 (NTLM auth via ZIP/RAR)
https://github.com/0x6rss/CVE-2025-24071_PoC

# CVE-2017-12542 (iLO4 admin account creation)
https://www.exploit-db.com/download/44005

# Proxyshell
https://github.com/dmaasland/proxyshell-poc.git

#ZeroLogon
https://github.com/dirkjanm/CVE-2020-1472
```

### Modules
```
# Wi-Fi antennas
rtl8812au
```

### Dependencies
```
Cargo
Docker
Docker-compose
Golang
Python3 (+pipx)
```
