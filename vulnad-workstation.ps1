# =====================================================================
# OnePiece AD Lab - Workstation setup (Win10 / Win11)
#
# Usage:
#   .\vulnad-workstation.ps1                    # prompts for DC IP
#   .\vulnad-workstation.ps1 -DCIP 192.168.56.10
#   .\vulnad-workstation.ps1 -Phase Post        # post-reboot vuln planting
#
# After domain join the VM reboots. Sign in as onepiece\luffy.m /
# Password123! and re-run (the DC IP is cached so no re-prompt).
# =====================================================================

param(
    [ValidateSet('Join','Post','All')]
    [string]$Phase = 'All',

    [string]$DCIP,
    [string]$Domain          = "onepiece.local",
    [string]$NewComputerName = "WS01",
    [string]$JoinUser        = "onepiece\luffy.m",
    [string]$JoinPassword    = "Password123!"
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$Global:Domain          = $Domain
$Global:NewComputerName = $NewComputerName
$Global:JoinUser        = $JoinUser
$Global:JoinPassword    = $JoinPassword

function Read-DCIP {
    param([string]$Provided)

    # Saved from a previous run (so Post phase doesn't re-prompt after reboot)
    $cacheFile = "$env:ProgramData\vulnad-dcip.txt"

    if ($Provided) { $ip = $Provided }
    elseif (Test-Path $cacheFile) { $ip = (Get-Content $cacheFile -Raw).Trim() }
    else { $ip = $null }

    while (-not $ip -or $ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        if ($ip) { Write-Host "[-] '$ip' is not a valid IPv4 address." -ForegroundColor Red }
        $ip = (Read-Host "Enter DC01 IP address").Trim()
    }

    Write-Host "[*] Testing reachability to $ip ..." -ForegroundColor Gray
    if (-not (Test-Connection -ComputerName $ip -Count 2 -Quiet)) {
        Write-Host "[-] $ip did not respond to ping. Continue anyway? (y/N) " -ForegroundColor Yellow -NoNewline
        if ((Read-Host) -ne 'y') { exit 1 }
    } else {
        Write-Host "[+] $ip is reachable" -ForegroundColor Green
    }

    Set-Content -Path $cacheFile -Value $ip -Force
    return $ip
}

$Global:DCIPAddress = Read-DCIP -Provided $DCIP

function Write-Good { param($s) Write-Host "[+] $s" -ForegroundColor Green }
function Write-Bad  { param($s) Write-Host "[-] $s" -ForegroundColor Red }
function Write-Info { param($s) Write-Host "[*] $s" -ForegroundColor Gray }

function Assert-Admin {
    $p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Bad "Run as Administrator."
        exit 1
    }
}

function Set-DNSToDC {
    Write-Info "Pointing primary DNS at DC ($Global:DCIPAddress)..."
    $iface = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1
    if (-not $iface) {
        Write-Bad "No active network adapter found."
        return $false
    }
    Set-DnsClientServerAddress -InterfaceIndex $iface.InterfaceIndex -ServerAddresses $Global:DCIPAddress
    Write-Good "DNS set on $($iface.InterfaceAlias)"

    Write-Info "Testing DNS resolution for $Global:Domain ..."
    try {
        $r = Resolve-DnsName $Global:Domain -ErrorAction Stop
        Write-Good "Resolved $Global:Domain -> $($r[0].IPAddress)"
        return $true
    } catch {
        Write-Bad "Could not resolve domain. Check DC IP and firewall."
        return $false
    }
}

function Join-LabDomain {
    if ((Get-CimInstance Win32_ComputerSystem).Domain -eq $Global:Domain) {
        Write-Good "Already joined to $Global:Domain"
        return $true
    }

    $sec  = ConvertTo-SecureString $Global:JoinPassword -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($Global:JoinUser, $sec)

    Write-Info "Renaming to $Global:NewComputerName and joining $Global:Domain ..."
    try {
        Add-Computer -DomainName $Global:Domain `
                     -NewName   $Global:NewComputerName `
                     -Credential $cred `
                     -Force -Restart -ErrorAction Stop
        Write-Good "Join initiated. Rebooting..."
        return $true
    } catch {
        Write-Bad "Domain join failed: $_"
        return $false
    }
}

# ---------------------------------------------------------------------
# Post-join workstation-side vulnerabilities
# ---------------------------------------------------------------------

function Add-DomainUserToLocalAdmins {
    # Classic password-reuse pivot: a domain user is local admin on WS
    $member = "ONEPIECE\zoro.r"
    Write-Info "Adding $member to local Administrators..."
    try {
        Add-LocalGroupMember -Group "Administrators" -Member $member -ErrorAction Stop
        Write-Good "$member is now local admin on $env:COMPUTERNAME"
    } catch {
        Write-Info "Already a member or failed: $_"
    }
}

function Enable-CachedCredentials {
    Write-Info "Forcing cached logon count to 10 (mimikatz lsa cache target)..."
    $key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $key -Name "CachedLogonsCount" -Value "10" -ErrorAction SilentlyContinue
    Write-Good "CachedLogonsCount = 10"
}

function Disable-DefenderRealtime {
    Write-Info "Disabling Defender real-time protection (lab only!)..."
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
        Set-MpPreference -DisableIOAVProtection     $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableScriptScanning     $true -ErrorAction SilentlyContinue
        Set-MpPreference -MAPSReporting             Disabled -ErrorAction SilentlyContinue
        Set-MpPreference -SubmitSamplesConsent      NeverSend -ErrorAction SilentlyContinue
        Write-Good "Defender RTP off"
    } catch {
        Write-Info "Could not disable Defender (Tamper Protection?): $_"
    }
}

function Install-UnquotedServicePath {
    # Privilege escalation primitive: unquoted service path + writable folder
    $svcName = "VulnSvc"
    $svcDir  = "C:\Program Files\Vuln Service"
    $svcExe  = "$svcDir\service.exe"

    Write-Info "Creating unquoted-service-path target ($svcName)..."
    if (-not (Test-Path $svcDir)) {
        New-Item -ItemType Directory -Path $svcDir -Force | Out-Null
    }
    # Stub exe — copy a benign system binary
    Copy-Item "$env:WINDIR\System32\notepad.exe" $svcExe -Force

    # Make C:\Program Files writable by Authenticated Users (vuln)
    icacls "C:\Program Files" /grant "Authenticated Users:(M)" /T /C 2>&1 | Out-Null

    # sc create with NO quotes around binPath -> unquoted service path
    sc.exe create $svcName binPath= "C:\Program Files\Vuln Service\service.exe" start= auto 2>&1 | Out-Null
    Write-Good "Service '$svcName' created with unquoted path"
}

function Plant-CredentialFile {
    # Loot scenario: creds left on disk for an internal user
    $loot = "C:\Users\Public\Documents\backup-notes.txt"
    @"
backup script credentials (do not delete!!)
host: dc01.onepiece.local
user: backup_svc
pass: Password123!

old admin pass attempts:
- Summer2024!
- Winter2023!
"@ | Out-File -FilePath $loot -Encoding ASCII -Force
    Write-Good "Loot file planted at $loot"
}

function Enable-WinRM-PSRemoting {
    Write-Info "Enabling PSRemoting (lateral movement target)..."
    Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction SilentlyContinue | Out-Null
    Write-Good "WinRM enabled"
}

function Install-VulnMSSQL {
    Write-Info "Installing SQL Server Express (vulnerable config)..."

    if (Get-Service -Name 'MSSQL*' -ErrorAction SilentlyContinue) {
        Write-Info "MSSQL service already present, skipping install"
    } else {
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            Write-Bad "winget not available. Install SQL Express manually then re-run."
            Write-Info "  https://www.microsoft.com/sql-server/sql-server-downloads"
            return
        }
        try {
            winget install --id Microsoft.SQLServer.2022.Express `
                --silent --accept-package-agreements --accept-source-agreements `
                --override "/Q /IACCEPTSQLSERVERLICENSETERMS /ACTION=Install /FEATURES=SQLEngine /INSTANCENAME=MSSQLSERVER /SQLSVCACCOUNT=`"NT AUTHORITY\NETWORK SERVICE`" /SQLSYSADMINACCOUNTS=`"ONEPIECE\sql_svc`" `"ONEPIECE\Domain Admins`" /SECURITYMODE=SQL /SAPWD=`"Sup3rS3cr3t!`" /TCPENABLED=1 /NPENABLED=1" `
                2>&1 | Out-Null
            Write-Good "SQL Express installed (sa / Sup3rS3cr3t!)"
        } catch {
            Write-Bad "SQL install failed: $_"
            return
        }
    }

    # Wait for SQL service
    Start-Sleep -Seconds 10
    $svc = Get-Service -Name 'MSSQLSERVER' -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Running') { Start-Service $svc.Name }

    # Enable xp_cmdshell + create linked server back to DC (real attack primitive)
    Write-Info "Configuring vulnerable SQL settings..."
    $sqlScript = @"
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
-- Linked server back to DC, executes as sql_svc (kerberoastable)
IF NOT EXISTS (SELECT 1 FROM sys.servers WHERE name = 'DC01-LINK')
BEGIN
    EXEC sp_addlinkedserver @server='DC01-LINK', @srvproduct='', @provider='SQLNCLI', @datasrc='dc01.onepiece.local';
    EXEC sp_addlinkedsrvlogin @rmtsrvname='DC01-LINK', @useself='False',
        @rmtuser='sa', @rmtpassword='Sup3rS3cr3t!';
END
-- Grant PUBLIC the ability to impersonate sa (privesc primitive)
GRANT IMPERSONATE ON LOGIN::sa TO [PUBLIC];
"@
    try {
        Invoke-Sqlcmd -ServerInstance "localhost" -Username "sa" -Password "Sup3rS3cr3t!" -Query $sqlScript -ErrorAction Stop
        Write-Good "MSSQL: xp_cmdshell on, linked server DC01-LINK, PUBLIC can impersonate sa"
    } catch {
        # Fallback: sqlcmd
        $tmp = "$env:TEMP\vuln-sql.sql"
        $sqlScript | Out-File $tmp -Encoding ASCII
        sqlcmd.exe -S localhost -U sa -P 'Sup3rS3cr3t!' -i $tmp 2>&1 | Out-Null
        Remove-Item $tmp -Force
        Write-Good "MSSQL configured via sqlcmd"
    }
}

function Enable-PrintSpoolerWS {
    Write-Info "Ensuring Print Spooler running (PrinterBug from WS)..."
    Set-Service -Name Spooler -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name Spooler -ErrorAction SilentlyContinue
    Write-Good "Spooler running"
}

function Configure-LAPSClient {
    Write-Info "Forcing LAPS-managed local admin on this host..."
    # Reg keys mirror the Windows LAPS GPO so we don't depend on GPO propagation
    $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config"
    New-Item -Path $key -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path $key -Name "BackupDirectory"    -Value 2  -Type DWord
    Set-ItemProperty -Path $key -Name "PasswordComplexity" -Value 4  -Type DWord
    Set-ItemProperty -Path $key -Name "PasswordLength"     -Value 14 -Type DWord
    Set-ItemProperty -Path $key -Name "AdministratorAccountName" -Value "LocalAdmin" -Type String
    Set-ItemProperty -Path $key -Name "PasswordAgeDays"    -Value 30 -Type DWord

    # Trigger an initial rotation so password is in AD immediately
    try {
        Invoke-LapsPolicyProcessing -ErrorAction SilentlyContinue
        Write-Good "LAPS policy applied — password backed up to AD"
    } catch {
        Write-Info "Invoke-LapsPolicyProcessing not available (run gpupdate /force manually)"
    }
}

function Set-WDigest-On {
    Write-Info "Enabling WDigest UseLogonCredential (cleartext in LSASS)..."
    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    New-Item -Path $key -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path $key -Name "UseLogonCredential" -Value 1 -Type DWord
    Write-Good "WDigest cleartext caching enabled"
}

function Show-WorkstationSummary {
    Write-Host ""
    Write-Host "=== WORKSTATION VULNS INSTALLED ===" -ForegroundColor Green
    Write-Host "Host:        $env:COMPUTERNAME ($Global:Domain)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Local privesc / loot:" -ForegroundColor Cyan
    Write-Host "  - Unquoted service path:  VulnSvc -> C:\Program Files\Vuln Service\service.exe"
    Write-Host "  - C:\Program Files writable by Authenticated Users"
    Write-Host "  - Loot file:              C:\Users\Public\Documents\backup-notes.txt"
    Write-Host "  - WDigest UseLogonCredential = 1 (cleartext in LSASS)"
    Write-Host "  - CachedLogonsCount = 10"
    Write-Host "  - Defender real-time protection disabled"
    Write-Host ""
    Write-Host "Lateral movement / pivot:" -ForegroundColor Cyan
    Write-Host "  - ONEPIECE\zoro.r is local Administrator"
    Write-Host "  - WinRM/PSRemoting enabled"
    Write-Host "  - Print Spooler running (PrinterBug coercion target)"
    Write-Host ""
    Write-Host "LAPS / MSSQL:" -ForegroundColor Cyan
    Write-Host "  - LAPS managing local 'LocalAdmin' account (kid.e can read pwd)"
    Write-Host "  - MSSQL listening 1433: sa / Sup3rS3cr3t!"
    Write-Host "  - xp_cmdshell enabled, linked server DC01-LINK"
    Write-Host "  - PUBLIC can IMPERSONATE sa"
    Write-Host ""
    Write-Host "Snapshot the VM now!" -ForegroundColor Red
}

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

Assert-Admin

if ($Phase -in @('Join','All')) {
    if (-not (Set-DNSToDC)) { exit 1 }
    Join-LabDomain
    # If join succeeded, machine reboots and we never reach here.
    if ($Phase -eq 'Join') { return }
}

if ($Phase -in @('Post','All')) {
    if ((Get-CimInstance Win32_ComputerSystem).Domain -ne $Global:Domain) {
        Write-Bad "Not domain-joined yet. Run -Phase Join first (or reboot)."
        exit 1
    }
    Add-DomainUserToLocalAdmins
    Enable-CachedCredentials
    Disable-DefenderRealtime
    Install-UnquotedServicePath
    Plant-CredentialFile
    Enable-WinRM-PSRemoting
    Set-WDigest-On
    Configure-LAPSClient
    Enable-PrintSpoolerWS
    Install-VulnMSSQL
    Show-WorkstationSummary
}
