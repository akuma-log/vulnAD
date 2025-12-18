# VulnAD

# What this script does:
```
Sets up a complete Active Directory lab with domain "onepiece.local"
Creates OUs, users, groups based on One Piece anime characters
Configures vulnerable AD settings:
Weak password policies
Service accounts with SPNs
Accounts with Kerberos delegation
Accounts without pre-authentication
Installs AD Certificate Services (AD CS) with vulnerable templates
Creates GPOs for different organizational units
```

# Attack vectors you can practice:
```
Kerberoasting - Service accounts with SPNs
AS-REP Roasting - Accounts without pre-authentication (enel.g, shirahoshi, bonclay.b)
Unconstrained Delegation - Accounts with TrustedForDelegation (franky.c, brook.b)
Password Spraying - Weak passwords like "Changeme123!", "Winter2023!"
AD CS Attacks:
ESC1 - Certificate template abuse
ESC8 - Web enrollment + NTLM relay
DCSync - Users in Domain Admins group (luffy.m, roger.g, rayleigh.s)
Group Enumeration - Users added to privileged groups (DnsAdmins, Enterprise Admins, etc.)
SMB Relay - SMB signing disabled
GPO Abuse - Modify GPOs for persistence
```
The lab is designed for AD security testing and red team practice with intentional vulnerabilities to exploit.
