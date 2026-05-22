[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 > $null

$Global:Domain = "onepiece.local"
$Global:NetbiosName = "ONEPIECE"
$Global:SourcePath = "D:\sources\sxs"  # Set this to Windows installation media path if needed

# Flip this to $true (or set $env:VULNAD_VERBOSE='1') to see all the
# intermediate "doing X..." chatter. Off by default for a clean log.
$Global:VulnadVerbose = ($env:VULNAD_VERBOSE -eq '1')

function Write-Good { param( $String ) Write-Host "[+]" $String -ForegroundColor 'Green'}
function Write-Bad  { param( $String ) Write-Host "[-]" $String -ForegroundColor 'Red'}
function Write-Info { param( $String ) if ($Global:VulnadVerbose) { Write-Host "[*]" $String -ForegroundColor 'Gray' } }

# ============================================
# CORE INSTALLATION FUNCTIONS - FIXED
# ============================================

function Configure-StaticIP {
    Write-Info "Checking network configuration..."

    # Find the active adapter (one with a default gateway, status Up)
    $iface = Get-NetIPConfiguration | Where-Object {
        $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq 'Up'
    } | Select-Object -First 1

    if (-not $iface) {
        Write-Bad "No active network adapter with a gateway found. Configure networking manually first."
        return $false
    }

    $alias = $iface.InterfaceAlias
    $idx   = $iface.InterfaceIndex

    # Already static? skip silently
    $ipObj = Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 |
             Where-Object { $_.IPAddress -notlike '169.*' } | Select-Object -First 1
    if ($ipObj -and $ipObj.PrefixOrigin -eq 'Manual') {
        Write-Good "Static IP already configured: $($ipObj.IPAddress)/$($ipObj.PrefixLength) on $alias"
        # Still ensure DNS points at loopback for the DC
        Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses 127.0.0.1 -ErrorAction SilentlyContinue
        return $true
    }

    Write-Info "Current adapter: $alias"
    Write-Info "Current IP:      $($ipObj.IPAddress)/$($ipObj.PrefixLength)"
    Write-Info "Current gateway: $($iface.IPv4DefaultGateway.NextHop)"

    $defIp     = $ipObj.IPAddress
    $defPrefix = $ipObj.PrefixLength
    $defGw     = $iface.IPv4DefaultGateway.NextHop

    Write-Host ""
    Write-Host "Press Enter to keep the current value, or type a new one." -ForegroundColor Yellow
    $ip     = (Read-Host "IP address      [$defIp]").Trim();      if (-not $ip)     { $ip = $defIp }
    $prefix = (Read-Host "Prefix length   [$defPrefix]").Trim();  if (-not $prefix) { $prefix = $defPrefix }
    $gw     = (Read-Host "Default gateway [$defGw]").Trim();      if (-not $gw)     { $gw = $defGw }

    if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        Write-Bad "Invalid IP: $ip"
        return $false
    }

    try {
        Write-Info "Applying static IP $ip/$prefix gw=$gw on $alias ..."
        # Remove existing IP/gateway first so New-NetIPAddress doesn't conflict
        Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike '169.*' } |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetRoute -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

        New-NetIPAddress -InterfaceIndex $idx -IPAddress $ip -PrefixLength $prefix -DefaultGateway $gw -ErrorAction Stop | Out-Null
        Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses 127.0.0.1
        Write-Good "Static IP set. DNS -> 127.0.0.1"
        Start-Sleep -Seconds 3
        return $true
    } catch {
        Write-Bad "Failed to set static IP: $_"
        Write-Info "Configure manually with New-NetIPAddress and re-run."
        return $false
    }
}

function Rename-ComputerToDC01 {
    Write-Info "Setting computer name to DC01..."
    
    if ($env:COMPUTERNAME -eq "DC01") {
        Write-Good "Computer is already named DC01"
        return $true
    }
    
    try {
        Write-Info "Renaming computer from $($env:COMPUTERNAME) to DC01..."
        Rename-Computer -NewName "DC01" -Force -ErrorAction Stop
        Write-Good "Computer renamed to DC01. Restart required."
        return $true
    } catch {
        Write-Bad "Error renaming computer: $_"
        return $false
    }
}

function Install-SingleDC {
    Write-Info "Installing Single Domain Controller..."
    
    # Check if already a DC
    $isDC = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4
    
    if ($isDC) {
        Write-Good "Server is already a Domain Controller. Skipping DC installation."
        return $true
    }
    
    try {
        Write-Info "Installing AD DS feature..."
        
        if ($Global:SourcePath -and (Test-Path $Global:SourcePath)) {
            Write-Info "Using source path: $Global:SourcePath"
            Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -Source $Global:SourcePath -ErrorAction Stop
        } else {
            Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
        }
        
        # Check if installation succeeded
        $adInstalled = (Get-WindowsFeature -Name AD-Domain-Services).InstallState -eq "Installed"
        
        if (-not $adInstalled) {
            Write-Bad "AD installation failed."
            return $false
        }
        
        Write-Good "AD DS feature installed successfully"
        return $true
        
    } catch {
        Write-Bad "Error installing AD DS: $_"
        return $false
    }
}

function Promote-ToDC {
    Write-Info "Promoting server to Domain Controller..."
    
    try {
        # Import module first
        Import-Module ADDSDeployment -ErrorAction Stop
        
        $safeModePassword = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
        
        # Create new domain (single DC)
        $installParams = @{
            DomainName = $Global:Domain
            DomainNetbiosName = $Global:NetbiosName
            SafeModeAdministratorPassword = $safeModePassword
            InstallDns = $true
            NoRebootOnCompletion = $false
            Force = $true
        }
        
        Install-ADDSForest @installParams
        
        Write-Good "DC promotion initiated. Server will restart automatically."
        return $true
        
    } catch {
        Write-Bad "Error promoting to DC: $_"
        return $false
    }
}

function Wait-ForADReady {
    Write-Info "Waiting for AD to be ready..."
    $maxAttempts = 30
    $attempt = 0
    
    while ($attempt -lt $maxAttempts) {
        try {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            $test = Get-ADDomain -ErrorAction SilentlyContinue
            if ($test) {
                Write-Good "AD is ready."
                return $true
            }
        } catch {
            # Continue waiting
        }
        
        Write-Info "Waiting for AD services to start... ($($attempt + 1)/$maxAttempts)"
        Start-Sleep -Seconds 10
        $attempt++
    }
    
    Write-Bad "AD did not become ready after $maxAttempts attempts."
    return $false
}

# ============================================
# AD OBJECT CREATION FUNCTIONS - FIXED
# ============================================

function Create-BasicOUs {
    Write-Info "Creating basic OUs..."
    
    $ous = @(
        @{Name="StrawHats"; Path="DC=onepiece,DC=local"},
        @{Name="Marines"; Path="DC=onepiece,DC=local"},
        @{Name="Warlords"; Path="DC=onepiece,DC=local"},
        @{Name="Yonko"; Path="DC=onepiece,DC=local"},
        @{Name="Revolutionary"; Path="DC=onepiece,DC=local"},
        @{Name="Supernovas"; Path="DC=onepiece,DC=local"},
        @{Name="Services"; Path="DC=onepiece,DC=local"},
        @{Name="Workstations"; Path="DC=onepiece,DC=local"},
        @{Name="Servers"; Path="DC=onepiece,DC=local"}
    )
    
    $created = 0; $existed = 0
    foreach ($ou in $ous) {
        try {
            if (Get-ADOrganizationalUnit -Filter "Name -eq '$($ou.Name)'" -ErrorAction SilentlyContinue) {
                $existed++
            } else {
                New-ADOrganizationalUnit -Name $ou.Name -Path $ou.Path -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue
                $created++
            }
        } catch {
            Write-Info "Error creating OU $($ou.Name): $_"
        }
    }
    Write-Good "OUs: $created created, $existed existed"
}

function Import-OnePieceUsers {
    Write-Info "Creating users..."
    
    $users = @(
        @{Username="luffy.m"; FullName="Monkey D. Luffy"; Password="Password123!"},
        @{Username="zoro.r"; FullName="Roronoa Zoro"; Password="Password456!"},
        @{Username="nami.n"; FullName="Nami"; Password="Password789!"},
        @{Username="sanji.v"; FullName="Vinsmoke Sanji"; Password="Password101!"},
        @{Username="usopp.u"; FullName="Usopp"; Password="Password202!"},
        @{Username="shanks.r"; FullName="Red-Haired Shanks"; Password="Password303!"},
        @{Username="akainu"; FullName="Sakazuki"; Password="Password404!"},
        @{Username="aokiji"; FullName="Kuzan"; Password="Password505!"},
        @{Username="kizaru"; FullName="Borsalino"; Password="Password606!"},
        @{Username="doflamingo"; FullName="Donquixote Doflamingo"; Password="Password707!"},
        @{Username="kaido.b"; FullName="Kaido"; Password="Password808!"},
        @{Username="bigmom"; FullName="Charlotte Linlin"; Password="Password909!"},
        @{Username="blackbeard"; FullName="Marshall D. Teach"; Password="Password010!"},
        @{Username="law.t"; FullName="Trafalgar Law"; Password="Password111!"},
        @{Username="kid.e"; FullName="Eustass Kid"; Password="Password222!"},
        @{Username="enel.g"; FullName="Enel"; Password="Password333!"},
        @{Username="shirahoshi"; FullName="Shirahoshi"; Password="Password444!"},
        @{Username="franky.c"; FullName="Cutty Flam"; Password="Password555!"},
        @{Username="brook.b"; FullName="Brook"; Password="Password666!"},
        @{Username="bonclay.b"; FullName="Bon Clay"; Password="Password777!"},
        # Weak/reused passwords for spraying practice
        @{Username="roger.g";    FullName="Gol D. Roger";   Password="Changeme123!"},
        @{Username="rayleigh.s"; FullName="Silvers Rayleigh"; Password="Winter2023!"},
        @{Username="garp.m";     FullName="Monkey D. Garp"; Password="Changeme123!"},
        @{Username="smoker.c";   FullName="Smoker";         Password="Summer2024!"}
    )
    
    $createdCount = 0
    $errorCount = 0
    
    foreach ($user in $users) {
        try {
            $existingUser = Get-ADUser -Filter "SamAccountName -eq '$($user.Username)'" -ErrorAction SilentlyContinue
            
            if (-not $existingUser) {
                # Split name for given name and surname
                $nameParts = $user.FullName.Split(' ')
                $givenName = $nameParts[0]
                $surname = if ($nameParts.Count -gt 1) { $nameParts[-1] } else { "" }
                
                $userParams = @{
                    Name = $user.FullName
                    GivenName = $givenName
                    Surname = $surname
                    SamAccountName = $user.Username
                    UserPrincipalName = "$($user.Username)@$Global:Domain"
                    AccountPassword = (ConvertTo-SecureString $user.Password -AsPlainText -Force)
                    Enabled = $true
                    PasswordNeverExpires = $true
                    Path = "CN=Users,DC=onepiece,DC=local"
                    ErrorAction = 'Stop'
                }
                
                New-ADUser @userParams
                $createdCount++
            }
        } catch {
            $errorCount++
            Write-Info "Error creating user $($user.Username): $_"
        }
    }

    Write-Good "Users: $createdCount created, $($users.Count - $createdCount - $errorCount) existed, $errorCount errors"
    return $createdCount -gt 0
}

function Move-UsersToOUs {
    Write-Info "Moving users to OUs..."
    
    $userMappings = @{
        "StrawHats" = @("luffy.m", "zoro.r", "nami.n", "sanji.v", "usopp.u", "franky.c", "brook.b")
        "Marines" = @("akainu", "aokiji", "kizaru")
        "Warlords" = @("doflamingo", "law.t")
        "Yonko" = @("shanks.r", "kaido.b", "bigmom", "blackbeard")
        "Supernovas" = @("kid.e", "law.t")
    }
    
    $movedCount = 0
    
    foreach ($ou in $userMappings.Keys) {
        $targetPath = "OU=$ou,DC=onepiece,DC=local"
        
        foreach ($user in $userMappings[$ou]) {
            try {
                $adUser = Get-ADUser -Filter "SamAccountName -eq '$user'" -ErrorAction SilentlyContinue
                if ($adUser) {
                    Move-ADObject -Identity $adUser.DistinguishedName -TargetPath $targetPath -ErrorAction SilentlyContinue
                    $movedCount++
                }
            } catch {
                # FIXED LINE - use string formatting instead of colon
                Write-Info "Could not move user $($user): $($_)"
            }
        }
    }
    
    Write-Good "Moved $movedCount users to themed OUs"
    return $movedCount
}

function Create-EssentialGroups {
    Write-Info "Creating groups..."
    
    $groups = @(
        @{Name="Straw Hat Crew"; Scope="Global"},
        @{Name="Marine Admirals"; Scope="Global"},
        @{Name="Pirate Emperors"; Scope="Global"},
        @{Name="Warlords of the Sea"; Scope="Global"},
        # Supernovas is created under CN=Users to avoid colliding with the
        # OU=Supernovas object (AD enforces unique 'name' per parent).
        @{Name="Supernovas"; Scope="Global"; Path="CN=Users,DC=onepiece,DC=local"},
        @{Name="Domain Admins"; Scope="Global"},
        @{Name="Enterprise Admins"; Scope="Global"},
        @{Name="Schema Admins"; Scope="Global"},
        @{Name="DnsAdmins"; Scope="Global"}
    )
    
    $createdCount = 0
    $existingCount = 0
    
    foreach ($group in $groups) {
        try {
            $exists = Get-ADGroup -Filter "Name -eq '$($group.Name)'" -ErrorAction SilentlyContinue
            if (-not $exists) {
                $groupPath = if ($group.Path) { $group.Path } else { "DC=onepiece,DC=local" }
                New-ADGroup -Name $group.Name -GroupScope $group.Scope -GroupCategory Security -Path $groupPath -ErrorAction SilentlyContinue
                $createdCount++
            } else {
                $existingCount++
            }
        } catch {
            Write-Info "Error creating group $($group.Name): $_"
        }
    }
    
    Write-Good "Groups: $createdCount created, $existingCount existed"
    return $createdCount
}

function Add-UsersToGroups {
    Write-Info "Adding users to groups..."
    
    $groupMappings = @{
        "Straw Hat Crew" = @("luffy.m", "zoro.r", "nami.n", "sanji.v", "usopp.u", "franky.c", "brook.b")
        "Marine Admirals" = @("akainu", "aokiji", "kizaru")
        "Pirate Emperors" = @("shanks.r", "kaido.b", "bigmom", "blackbeard")
        "Warlords of the Sea" = @("doflamingo", "law.t")
        "Domain Admins" = @("luffy.m", "roger.g", "rayleigh.s")
        "Enterprise Admins" = @("luffy.m")
        "Schema Admins" = @("luffy.m")
        "DnsAdmins" = @("enel.g", "shirahoshi")
    }
    
    $addedTotal = 0
    
    foreach ($group in $groupMappings.Keys) {
        try {
            $groupExists = Get-ADGroup -Filter "Name -eq '$group'" -ErrorAction SilentlyContinue
            if (-not $groupExists) {
                Write-Info "Group does not exist: $group"
                continue
            }
            
            $usersToAdd = @()
            foreach ($user in $groupMappings[$group]) {
                $adUser = Get-ADUser -Filter "SamAccountName -eq '$user'" -ErrorAction SilentlyContinue
                if ($adUser) { $usersToAdd += $adUser.SamAccountName }
            }

            if ($usersToAdd.Count -gt 0) {
                Add-ADGroupMember -Identity $group -Members $usersToAdd -ErrorAction SilentlyContinue
                $addedTotal += $usersToAdd.Count
            }
        } catch {
            # FIXED LINE
            Write-Info "Error adding users to $($group): $($_)"
        }
    }
    
    Write-Good "Group memberships added: $addedTotal"
    return $addedTotal
}

# ============================================
# VULNERABILITY CONFIGURATION FUNCTIONS - FIXED
# ============================================

function Configure-DomainSettings {
    Write-Info "Configuring domain settings..."
    
    try {
        # Use net accounts command
        Write-Info "Setting password policy via net accounts..."
        net accounts /minpwlen:4 2>&1 | Out-Null
        net accounts /maxpwage:180 2>&1 | Out-Null
        net accounts /minpwage:0 2>&1 | Out-Null
        net accounts /uniquepw:0 2>&1 | Out-Null
        
        # Try PowerShell cmdlet
        Write-Info "Setting password policy via PowerShell..."
        try {
            Set-ADDefaultDomainPasswordPolicy -Identity $Global:Domain `
                -ComplexityEnabled $false `
                -MinPasswordLength 4 `
                -PasswordHistoryCount 0 `
                -ReversibleEncryptionEnabled $false `
                -ErrorAction SilentlyContinue
            Write-Info "Password policy set via PowerShell"
        } catch {
            Write-Info "Using net accounts only: $_"
        }
        
        Write-Info "Domain password policy configured (4 chars, no complexity)"
        return $true
    } catch {
        Write-Info "Error configuring domain settings: $_"
        return $false
    }
}

function Create-ServiceAccounts {
    Write-Info "Creating service accounts..."
    
    $services = @(
        @{Name="merry_svc";    Description="Going Merry Service"; SPN="merry_svc/goingmerry.onepiece.local"; Password="Password123!"},
        @{Name="cifs_svc";     Description="CIFS Service";        SPN="cifs/dc.onepiece.local";              Password="Password123!"},
        @{Name="http_svc";     Description="HTTP Service";        SPN="http/web.onepiece.local";             Password="Password123!"},
        @{Name="backup_svc";   Description="Backup Service";      SPN=$null;                                  Password="Backup123!"},
        @{Name="helpdesk_svc"; Description="Helpdesk Service";    SPN=$null;                                  Password="Helpdesk2024!"},
        @{Name="sql_svc";      Description="SQL Service";         SPN="MSSQLSvc/sql01.onepiece.local:1433";  Password="Sup3rS3cr3t!"}
    )
    
    $createdCount = 0
    
    foreach ($svc in $services) {
        try {
            $exists = Get-ADUser -Filter "SamAccountName -eq '$($svc.Name)'" -ErrorAction SilentlyContinue
            if (-not $exists) {
                $userParams = @{
                    Name = $svc.Description
                    DisplayName = $svc.Description
                    SamAccountName = $svc.Name
                    AccountPassword = (ConvertTo-SecureString $svc.Password -AsPlainText -Force)
                    Enabled = $true
                    PasswordNeverExpires = $true
                    Path = "OU=Services,DC=onepiece,DC=local"
                    ErrorAction = 'SilentlyContinue'
                }
                if ($svc.SPN) { $userParams['ServicePrincipalNames'] = $svc.SPN }
                
                New-ADUser @userParams
                $createdCount++
            }
        } catch {
            Write-Info "Error creating service account $($svc.Name): $_"
        }
    }
    
    Write-Good "Service accounts: $createdCount created"
    return $createdCount
}

function Configure-VulnerableAccounts {
    Write-Info "Configuring vulnerable account settings..."
    
    # Accounts with pre-auth disabled
    $noPreAuthUsers = @("enel.g", "shirahoshi", "bonclay.b")
    $configuredCount = 0
    
    foreach ($user in $noPreAuthUsers) {
        try {
            $adUser = Get-ADUser -Filter "SamAccountName -eq '$user'" -ErrorAction SilentlyContinue
            if ($adUser) {
                Set-ADAccountControl -Identity $adUser.SamAccountName -DoesNotRequirePreAuth $true -ErrorAction SilentlyContinue
                $configuredCount++
            }
        } catch { 
            # FIXED LINE
            Write-Info "Error configuring DoesNotRequirePreAuth for $($user): $($_)"
        }
    }
    
    # Accounts with unconstrained delegation
    $unconstrainedUsers = @("franky.c", "brook.b")
    foreach ($user in $unconstrainedUsers) {
        try {
            $adUser = Get-ADUser -Filter "SamAccountName -eq '$user'" -ErrorAction SilentlyContinue
            if ($adUser) {
                Set-ADAccountControl -Identity $adUser.SamAccountName -TrustedForDelegation $true -ErrorAction SilentlyContinue
                $configuredCount++
            }
        } catch { 
            # FIXED LINE
            Write-Info "Error configuring TrustedForDelegation for $($user): $($_)"
        }
    }
    
    Write-Good "Vulnerable accounts: $configuredCount configured (AS-REP + delegation)"
    return $configuredCount
}

function Configure-SMB {
    Write-Info "Configuring SMB settings..."
    
    try {
        Set-SmbClientConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Confirm:$false -ErrorAction SilentlyContinue
        Set-SmbServerConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Confirm:$false -ErrorAction SilentlyContinue
        Write-Info "SMB signing disabled"
        return $true
    } catch {
        Write-Info "Error configuring SMB settings: $_"
        return $false
    }
}

# ============================================
# AD CS INSTALLATION FUNCTIONS - COMPLETELY REWRITTEN
# ============================================

function Install-ADCS {
    Write-Info "Installing and configuring AD CS with vulnerabilities..."
    
    # Check AD CS status more carefully
    $caService = Get-Service -Name certsvc -ErrorAction SilentlyContinue
    $caInstalled = $caService -and ($caService.Status -eq 'Running')
    
    if ($caInstalled) {
        Write-Good "AD CS Certificate Authority is already running"
        Write-Info "Configuring vulnerable settings on existing CA..."

        Configure-ADCS-VulnerableSettings
        Create-VulnerableCertificateTemplates
        Disable-CertSrvRequireSSL
        Configure-ADCS-AdvancedVulns

        return $true
    }
    
    # If CA service exists but isn't running or is disabled
    if ($caService -and $caService.Status -ne 'Running') {
        Write-Info "CA service exists but not running. Attempting to configure..."
        
        try {
            # Try to start the service
            Start-Service -Name certsvc -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 10
            
            if ((Get-Service -Name certsvc).Status -eq 'Running') {
                Write-Good "CA service started successfully"
                Configure-ADCS-VulnerableSettings
                Create-VulnerableCertificateTemplates
                Disable-CertSrvRequireSSL
                Configure-ADCS-AdvancedVulns
                return $true
            }
        } catch {
            Write-Info "Could not start CA service: $_"
        }
    }
    
    # Fresh installation path
    Write-Info "Starting fresh AD CS installation..."
    
    try {
        # Uninstall any partially installed AD CS features
        Write-Info "Cleaning up any existing AD CS components..."
        $featuresToRemove = @(
            "ADCS-Cert-Authority",
            "ADCS-Web-Enrollment",
            "ADCS-Enroll-Web-Svc",
            "ADCS-Enroll-Web-Pol"
        )
        
        foreach ($feature in $featuresToRemove) {
            $featureState = Get-WindowsFeature -Name $feature -ErrorAction SilentlyContinue
            if ($featureState -and $featureState.InstallState -eq "Installed") {
                try {
                    Uninstall-WindowsFeature -Name $feature -Remove -Restart:$false -ErrorAction SilentlyContinue
                    Write-Info "Removed: $($feature)"
                } catch {
                    Write-Info "Could not remove $($feature): $_"
                }
            }
        }
        
        Start-Sleep -Seconds 5
        
        # Install AD CS features with proper syntax
        Write-Info "Installing AD CS features..."
        
        $featuresToInstall = @(
            "ADCS-Cert-Authority",
            "ADCS-Web-Enrollment",
            "ADCS-Enroll-Web-Svc"
        )
        
        $installSuccess = $true
        
        foreach ($feature in $featuresToInstall) {
            try {
                Write-Info "Installing $($feature)..."
                $result = Install-WindowsFeature -Name $feature -IncludeManagementTools -ErrorAction Stop
                
                if ($result.Success -or $result.ExitCode -eq 0 -or $result.RestartNeeded -eq "No") {
                    Write-Info "Successfully installed/verified: $($feature)"
                } else {
                    Write-Info "Warning: $($feature) installation may have issues"
                    $installSuccess = $false
                }
                
                Start-Sleep -Seconds 5
            } catch {
                Write-Info "Error installing $($feature): $_"
                $installSuccess = $false
            }
        }
        
        if (-not $installSuccess) {
            Write-Info "Some features failed to install. Attempting to continue with configuration..."
        }
        
        Write-Good "AD CS roles installation attempted"
        Start-Sleep -Seconds 10
        
        # Check if ADCSDeployment module is available
        Write-Info "Loading AD CS deployment module..."
        if (Get-Module -Name ADCSDeployment -ListAvailable) {
            Import-Module ADCSDeployment -ErrorAction Stop
            Write-Info "ADCSDeployment module loaded"
        } else {
            Write-Info "Installing RSAT-ADCS-Tools for module..."
            Install-WindowsFeature -Name RSAT-ADCS-Tools -IncludeManagementTools -ErrorAction SilentlyContinue
            Import-Module ADCSDeployment -ErrorAction SilentlyContinue
        }
        
        # Configure Certification Authority - ONLY if not already configured
        Write-Info "Checking if CA is already configured..."
        
        # Check if CA is already configured by looking for CA in AD
        $caExists = Get-ADObject -Filter "Name -eq 'OnePiece-CA'" -SearchBase "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=onepiece,DC=local" -ErrorAction SilentlyContinue
        
        if (-not $caExists) {
            Write-Info "Configuring Certificate Authority..."
            
            try {
                $caParams = @{
                    CAType = "EnterpriseRootCA"
                    CACommonName = "OnePiece-CA"
                    CADistinguishedName = "CN=OnePiece-CA,DC=onepiece,DC=local"
                    CryptoProviderName = "RSA#Microsoft Software Key Storage Provider"
                    KeyLength = 2048
                    HashAlgorithmName = "SHA256"
                    ValidityPeriod = "Years"
                    ValidityPeriodUnits = 5
                    Force = $true
                    Confirm = $false
                }
                
                Install-AdcsCertificationAuthority @caParams
                Write-Good "Certificate Authority configured"
                Start-Sleep -Seconds 30
            } catch {
                Write-Info "CA configuration error (may already exist): $_"
            }
        } else {
            Write-Good "Certificate Authority already exists in AD"
        }
        
        # Configure Web Enrollment (ESC8 - /certsrv NTLM relay target)
        Write-Info "Configuring Web Enrollment (ESC8)..."
        try {
            Install-AdcsWebEnrollment -Force -Confirm:$false -ErrorAction Stop
            Write-Good "Web Enrollment configured at http://$env:COMPUTERNAME/certsrv"
        } catch {
            Write-Info "Web Enrollment may already be configured: $_"
        }

        Disable-CertSrvRequireSSL
        
        # Configure all vulnerable settings
        Configure-ADCS-VulnerableSettings
        Create-VulnerableCertificateTemplates
        
        Write-Good "AD CS installation and vulnerability configuration completed"
        
        # Final test
        Write-Info "Testing Certificate Authority..."
        try {
            certutil -ping 2>&1 | Out-Null
            Write-Good "CA is responding"
        } catch {
            Write-Info "CA test may have issues: $_"
        }
        
        return $true
        
    } catch {
        Write-Info "Error during AD CS installation process: $_"
        Write-Info "Some components may need manual configuration"
        
        # Still try to configure vulnerabilities
        Configure-ADCS-VulnerableSettings
        Configure-ADCS-AdvancedVulns
        
        return $false
    }
}

function Disable-CertSrvRequireSSL {
    # IIS ships /certsrv with Require-SSL on, which returns 403.4 to plain HTTP
    # NTLM auth and breaks ntlmrelayx --adcs. The section is locked at the
    # applicationHost level, so Set-WebConfigurationProperty fails. appcmd with
    # /commit:apphost writes straight to applicationHost.config (bypasses lock).
    Write-Info "Disabling Require-SSL on /certsrv for ESC8..."
    $appcmd = "$env:windir\system32\inetsrv\appcmd.exe"
    if (-not (Test-Path $appcmd)) {
        Write-Info "appcmd not found -- IIS may not be installed yet, skipping"
        return
    }
    try {
        & $appcmd set config "Default Web Site/CertSrv" `
            -section:"system.webServer/security/access" `
            /sslFlags:"None" /commit:apphost 2>&1 | Out-Null
        iisreset 2>&1 | Out-Null
        Write-Good "/certsrv now accepts HTTP NTLM (ESC8 relay-ready)"
    } catch {
        Write-Info "Could not disable /certsrv SSL flag: $_"
    }
}

function Configure-ADCS-VulnerableSettings {
    Write-Info "Configuring vulnerable CA settings..."
    
    try {
        # ESC5/ESC6: Enable dangerous flags
        Write-Info "Setting vulnerable CA registry flags..."
        try {
            certutil -setreg CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags +EDITF_ATTRIBUTESUBJECT 2>&1 | Out-Null
            certutil -setreg CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags +EDITF_ENABLEAKIKEYID 2>&1 | Out-Null
            Write-Info "CA registry flags set"
        } catch {
            Write-Info "Could not set CA registry flags (may need admin rights): $_"
        }
        
        # MachineAccountQuota: enables RBCD / shadow-credentials attacks from any domain user
        Write-Info "Raising ms-DS-MachineAccountQuota for RBCD..."
        try {
            Set-ADDomain -Identity $Global:Domain -Replace @{"ms-DS-MachineAccountQuota" = "20"} -ErrorAction SilentlyContinue
            Write-Info "MachineAccountQuota = 20 (default 10) -- any user can join up to 20 machines"
        } catch {
            Write-Info "Could not set machine account quota: $_"
        }

        # PetitPotam: EFS RPC server enabled for coerced auth
        Write-Info "Ensuring EFS service is running (PetitPotam)..."
        try {
            Set-Service -Name EFS -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name EFS -ErrorAction SilentlyContinue
            Write-Info "EFS service configured"
        } catch { 
            Write-Info "EFS service configuration: $_"
        }
        
        # Restart CA service if it exists
        $caService = Get-Service -Name certsvc -ErrorAction SilentlyContinue
        if ($caService) {
            Write-Info "Restarting Certificate Services..."
            try {
                Restart-Service certsvc -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 10
                Write-Info "Certificate Services restarted"
            } catch {
                Write-Info "Could not restart Certificate Services: $_"
            }
        }
        
        Write-Info "Vulnerable CA settings configured"
    } catch {
        Write-Info "Error configuring vulnerable settings: $_"
    }
}

function New-VulnTemplateFromUser {
    param(
        [string]$NewName,
        [int]$NameFlag,        # msPKI-Certificate-Name-Flag
        [int]$EnrollmentFlag   # msPKI-Enrollment-Flag
    )

    $configNC = (Get-ADRootDSE).configurationNamingContext
    $templatesPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
    $newDN = "CN=$NewName,$templatesPath"

    if (Get-ADObject -Filter "Name -eq '$NewName'" -SearchBase $templatesPath -ErrorAction SilentlyContinue) {
        Write-Info "Template $NewName already exists"
        return
    }

    # Clone the built-in User template
    $src = Get-ADObject -Identity "CN=User,$templatesPath" -Properties *
    $attrs = @{
        'flags'                              = $src.flags
        'revision'                           = $src.revision
        'pKIDefaultKeySpec'                  = $src.pKIDefaultKeySpec
        'pKIMaxIssuingDepth'                 = $src.pKIMaxIssuingDepth
        'pKICriticalExtensions'              = $src.pKICriticalExtensions
        'pKIExpirationPeriod'                = $src.pKIExpirationPeriod
        'pKIOverlapPeriod'                   = $src.pKIOverlapPeriod
        'pKIExtendedKeyUsage'                = $src.pKIExtendedKeyUsage
        'pKIDefaultCSPs'                     = $src.pKIDefaultCSPs
        'msPKI-RA-Signature'                 = $src.'msPKI-RA-Signature'
        'msPKI-Minimal-Key-Size'             = $src.'msPKI-Minimal-Key-Size'
        'msPKI-Template-Schema-Version'      = 2
        'msPKI-Template-Minor-Revision'      = 1
        'msPKI-Cert-Template-OID'            = $src.'msPKI-Cert-Template-OID'
        'msPKI-Certificate-Name-Flag'        = $NameFlag
        'msPKI-Enrollment-Flag'              = $EnrollmentFlag
        'msPKI-Private-Key-Flag'             = 0x10  # exportable
        'msPKI-Certificate-Application-Policy' = '1.3.6.1.5.5.7.3.2'  # Client Auth
    }

    try {
        New-ADObject -Name $NewName -Type pKICertificateTemplate -Path $templatesPath -OtherAttributes $attrs -ErrorAction Stop
        Write-Good "Created template $NewName in AD"
    } catch {
        Write-Info "Could not create template $NewName : $_"
        return
    }

    # Grant Domain Users the Enroll right (extended right on the template object)
    try {
        $du = (Get-ADGroup "Domain Users").SID
        $enrollRightGuid = [GUID]'0e10c968-78fb-11d2-90d4-00c04f79dc55'  # Certificate-Enrollment
        $acl = Get-Acl "AD:$newDN"
        $ace = New-Object DirectoryServices.ActiveDirectoryAccessRule(
            $du, 'ExtendedRight', 'Allow', $enrollRightGuid
        )
        $acl.AddAccessRule($ace)
        Set-Acl -AclObject $acl -Path "AD:$newDN"
        Write-Info "Granted Domain Users Enroll on $NewName"
    } catch {
        Write-Info "ACL set failed on $NewName : $_"
    }

    # Publish template on the CA
    try {
        certutil -SetCATemplates "+$NewName" 2>&1 | Out-Null
        Write-Info "Published $NewName on CA"
    } catch {
        Write-Info "certutil publish failed for $NewName : $_"
    }
}

function Create-VulnerableCertificateTemplates {
    Write-Info "Publishing vulnerable certificate templates to AD..."

    # ESC1: ENROLLEE_SUPPLIES_SUBJECT (1) + Client Auth EKU + low-priv enroll
    # msPKI-Certificate-Name-Flag = 0x00000001 (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
    New-VulnTemplateFromUser -NewName "ESC1-VulnUser" -NameFlag 0x1 -EnrollmentFlag 0

    # ESC9: NO_SECURITY_EXTENSION on enrollment flag (0x80000)
    # Subject taken from AD = vulnerable to UPN-spoof + weak mapping
    New-VulnTemplateFromUser -NewName "ESC9-NoSecExt" -NameFlag 0x0 -EnrollmentFlag 0x80000

    # ESC15 / EKUwu: schema v1 template with ENROLLEE_SUPPLIES_SUBJECT (we
    # write schema v2 here but with editable subject -- gives a similar primitive)
    New-VulnTemplateFromUser -NewName "ESC15-Editable" -NameFlag 0x1 -EnrollmentFlag 0

    Write-Good "Vulnerable templates published: ESC1-VulnUser, ESC9-NoSecExt, ESC15-Editable"
}

function Configure-ADCS-AdvancedVulns {
    Write-Info "Configuring additional AD CS vulnerabilities..."

    # ESC10: Weak certificate mapping on the DC.
    # CertificateMappingMethods = 0x1F (all weak methods enabled, including UPN)
    # StrongCertificateBindingEnforcement = 0 (no enforcement)
    Write-Info "ESC10: weakening Kerberos cert mapping on DC..."
    try {
        $kdc = "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc"
        $schan = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
        New-Item -Path $kdc -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $kdc -Name "StrongCertificateBindingEnforcement" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $schan -Name "CertificateMappingMethods" -Value 0x1F -Type DWord -ErrorAction SilentlyContinue
        Write-Good "ESC10 weak mapping configured"
    } catch { Write-Info "ESC10 reg write failed: $_" }

    # ESC16: Disable szOID_NTDS_CA_SECURITY_EXT on the CA so all issued certs
    # lack the SID binding extension (domain-wide bypass).
    Write-Info "ESC16: disabling Security Extension on CA..."
    try {
        certutil -setreg policy\DisableExtensionList "+1.3.6.1.4.1.311.25.2" 2>&1 | Out-Null
        Restart-Service certsvc -Force -ErrorAction SilentlyContinue
        Write-Good "ESC16: szOID_NTDS_CA_SECURITY_EXT disabled CA-wide"
    } catch { Write-Info "ESC16 setreg failed: $_" }

    Show-ADCS-VulnerabilitySummary
    Write-Good "Advanced vulnerabilities configured"
}

function Create-VulnerableACLs {
    Write-Info "Creating vulnerable ACL attack paths (BloodHound bait)..."

    # Map: principal granted right -> (right, target object)
    # Picks scenarios that produce classic BloodHound edges.
    $paths = @(
        @{ Who='zoro.r';    Right='GenericAll';        Target='nami.n';     TargetType='User'  },
        @{ Who='sanji.v';   Right='ForceChangePassword'; Target='usopp.u';  TargetType='User'  },
        @{ Who='law.t';     Right='WriteDACL';         Target='Warlords of the Sea'; TargetType='Group' },
        @{ Who='kid.e';     Right='GenericWrite';      Target='Supernovas'; TargetType='Group' },
        @{ Who='doflamingo';Right='WriteOwner';        Target='shirahoshi'; TargetType='User'  }
    )

    foreach ($p in $paths) {
        try {
            $whoSid = (Get-ADUser -Identity $p.Who).SID
            if ($p.TargetType -eq 'User') {
                $targetDN = (Get-ADUser -Identity $p.Target).DistinguishedName
            } else {
                $targetDN = (Get-ADGroup -Identity $p.Target).DistinguishedName
            }

            $acl = Get-Acl -Path "AD:$targetDN"

            switch ($p.Right) {
                'GenericAll' {
                    $ace = New-Object DirectoryServices.ActiveDirectoryAccessRule(
                        $whoSid, 'GenericAll', 'Allow')
                }
                'GenericWrite' {
                    $ace = New-Object DirectoryServices.ActiveDirectoryAccessRule(
                        $whoSid, 'GenericWrite', 'Allow')
                }
                'WriteDACL' {
                    $ace = New-Object DirectoryServices.ActiveDirectoryAccessRule(
                        $whoSid, 'WriteDacl', 'Allow')
                }
                'WriteOwner' {
                    $ace = New-Object DirectoryServices.ActiveDirectoryAccessRule(
                        $whoSid, 'WriteOwner', 'Allow')
                }
                'ForceChangePassword' {
                    # Extended right: User-Force-Change-Password
                    $guid = [GUID]'00299570-246d-11d0-a768-00aa006e0529'
                    $ace = New-Object DirectoryServices.ActiveDirectoryAccessRule(
                        $whoSid, 'ExtendedRight', 'Allow', $guid)
                }
            }

            $acl.AddAccessRule($ace)
            Set-Acl -AclObject $acl -Path "AD:$targetDN"
            Write-Info "  $($p.Who) -[$($p.Right)]-> $($p.Target)"
        } catch {
            Write-Info "  Failed $($p.Who) -> $($p.Target) : $_"
        }
    }

    # DCSync rights for a non-DA user (classic BloodHound DCSync edge)
    try {
        $domainDN = (Get-ADDomain).DistinguishedName
        $acl = Get-Acl -Path "AD:$domainDN"
        $sid = (Get-ADUser bonclay.b).SID
        # DS-Replication-Get-Changes
        $g1 = [GUID]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        # DS-Replication-Get-Changes-All
        $g2 = [GUID]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
        foreach ($g in @($g1, $g2)) {
            $ace = New-Object DirectoryServices.ActiveDirectoryAccessRule(
                $sid, 'ExtendedRight', 'Allow', $g)
            $acl.AddAccessRule($ace)
        }
        Set-Acl -AclObject $acl -Path "AD:$domainDN"
        Write-Good "Granted DCSync rights to bonclay.b"
    } catch {
        Write-Info "DCSync ACL grant failed: $_"
    }
}

function Show-ADCS-VulnerabilitySummary {
    Write-Host ""
    Write-Host "AD CS VULNERABILITIES CONFIGURED" -ForegroundColor Green
    Write-Host "==============================================" -ForegroundColor Green
    Write-Host "ESC1 : Template 'ESC1-VulnUser' (ENROLLEE_SUPPLIES_SUBJECT + Client Auth, Domain Users can enroll)" -ForegroundColor Yellow
    Write-Host "ESC6 : EDITF_ATTRIBUTESUBJECT enabled on CA" -ForegroundColor Yellow
    Write-Host "ESC8 : Web Enrollment at http://$env:COMPUTERNAME/certsrv (NTLM relay target)" -ForegroundColor Yellow
    Write-Host "ESC9 : Template 'ESC9-NoSecExt' (CT_FLAG_NO_SECURITY_EXTENSION)" -ForegroundColor Yellow
    Write-Host "ESC10: Weak cert mapping on DC (StrongCertificateBindingEnforcement=0)" -ForegroundColor Yellow
    Write-Host "ESC15: Template 'ESC15-Editable' (editable subject)" -ForegroundColor Yellow
    Write-Host "ESC16: szOID_NTDS_CA_SECURITY_EXT disabled CA-wide" -ForegroundColor Yellow
    Write-Host "PetitPotam: EFS service running, SMB signing disabled" -ForegroundColor Yellow
    Write-Host ""
}

# ============================================
# V2: HIGH/MEDIUM VALUE VULN ADDITIONS
# ============================================

function Configure-ConstrainedDelegation {
    Write-Info "Configuring constrained delegation on nami.n..."
    try {
        Set-ADUser -Identity nami.n -Add @{
            'msDS-AllowedToDelegateTo' = @("CIFS/DC01.$Global:Domain","CIFS/DC01")
        } -ErrorAction Stop
        # protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION) -> S4U2Self abuse
        Set-ADAccountControl -Identity nami.n -TrustedToAuthForDelegation $true -ErrorAction SilentlyContinue
        Write-Good "nami.n: constrained delegation to CIFS/DC01 (with protocol transition)"
    } catch {
        Write-Info "Constrained delegation failed: $_"
    }
}

function Configure-RBCD {
    Write-Info "Pre-staging RBCD attack scenario..."
    try {
        $tgt = Get-ADComputer -Filter "Name -eq 'FILES01'" -ErrorAction SilentlyContinue
        if (-not $tgt) {
            New-ADComputer -Name "FILES01" -SamAccountName "FILES01`$" `
                -Path "OU=Servers,DC=onepiece,DC=local" -Enabled $true -ErrorAction Stop
            Write-Info "Created FILES01 computer object"
        }
        $usopp = Get-ADUser usopp.u
        Set-ADComputer -Identity FILES01 -PrincipalsAllowedToDelegateToAccount $usopp -ErrorAction Stop
        Write-Good "RBCD: usopp.u -> FILES01 (s4u2proxy abuse)"
    } catch {
        Write-Info "RBCD pre-stage failed: $_"
    }
}

function Install-LAPSOnDC {
    Write-Info "Installing Windows LAPS..."
    try {
        if (-not (Get-Command Update-LapsADSchema -ErrorAction SilentlyContinue)) {
            Write-Info "LAPS cmdlets unavailable. Install RSAT-AD-PowerShell + Windows LAPS module."
            return
        }
        Update-LapsADSchema -Confirm:$false -ErrorAction Stop
        Write-Good "LAPS schema extended"

        Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=onepiece,DC=local" -ErrorAction SilentlyContinue
        Set-LapsADReadPasswordPermission -Identity "OU=Workstations,DC=onepiece,DC=local" -AllowedPrincipals kid.e -ErrorAction SilentlyContinue
        Write-Good "kid.e granted ReadLAPSPassword on OU=Workstations"

        # Push policy so domain workstations rotate local admin via LAPS
        $polKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config"
        New-Item -Path $polKey -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $polKey -Name "BackupDirectory" -Value 2 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $polKey -Name "PasswordComplexity" -Value 4 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $polKey -Name "PasswordLength" -Value 14 -Type DWord -ErrorAction SilentlyContinue
    } catch {
        Write-Info "LAPS configure failed: $_"
    }
}

function Create-GMSA {
    Write-Info "Setting up gMSA with ReadGMSAPassword edge..."
    try {
        if (-not (Get-KdsRootKey -ErrorAction SilentlyContinue)) {
            Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null
            Write-Info "KDS root key created (effective immediately)"
        }
        if (-not (Get-ADServiceAccount -Filter "Name -eq 'gmsa_sql'" -ErrorAction SilentlyContinue)) {
            New-ADServiceAccount -Name "gmsa_sql" -DNSHostName "gmsa_sql.$Global:Domain" `
                -PrincipalsAllowedToRetrieveManagedPassword "kid.e" `
                -ServicePrincipalNames "MSSQLSvc/sql01.$Global:Domain:1433" `
                -ErrorAction Stop
            Write-Good "gMSA 'gmsa_sql' created -- kid.e can ReadGMSAPassword"
        }
    } catch {
        Write-Info "gMSA setup failed: $_"
    }
}

function Enable-LDAPAnonymousBind {
    Write-Info "Enabling LDAP anonymous bind + Pre-Win2000 compat..."
    try {
        $configNC = (Get-ADRootDSE).configurationNamingContext
        $dsh = "CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
        $current = (Get-ADObject -Identity $dsh -Properties dsHeuristics).dsHeuristics
        if (-not $current) { $current = "" }
        while ($current.Length -lt 7) { $current += "0" }
        $chars = $current.ToCharArray()
        $chars[6] = '2'
        Set-ADObject -Identity $dsh -Replace @{dsHeuristics = (-join $chars)}
        Write-Good "dsHeuristics: anonymous LDAP bind enabled"

        # "Authenticated Users" (S-1-5-11) is a well-known SID with no AD
        # object behind it, so Add-ADGroupMember can't resolve it.
        # Bind to the group via ADSI and add the binary SID directly.
        $domainDN = (Get-ADDomain).DistinguishedName
        $grpDN    = "CN=Pre-Windows 2000 Compatible Access,CN=Builtin,$domainDN"
        $grp      = [ADSI]"LDAP://$grpDN"

        $sid       = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-11'
        $sidBytes  = New-Object byte[] $sid.BinaryLength
        $sid.GetBinaryForm($sidBytes, 0)
        $sidHex    = ($sidBytes | ForEach-Object { $_.ToString("X2") }) -join ""

        try {
            $grp.Add("LDAP://<SID=$sidHex>")
            Write-Good "Authenticated Users (S-1-5-11) -> Pre-Windows 2000 Compatible Access"
        } catch {
            if ($_.Exception.Message -match "object already exists|attribute or value exists") {
                Write-Info "Authenticated Users already in Pre-Win2K group"
            } else { throw }
        }
    } catch {
        Write-Info "LDAP anon / Pre-Win2K failed: $_"
    }
}

function Create-ADIDNSWildcard {
    Write-Info "Creating ADIDNS wildcard record..."
    try {
        $dcIP = (Get-NetIPAddress -AddressFamily IPv4 |
                 Where-Object { $_.IPAddress -notlike '169.*' -and $_.IPAddress -ne '127.0.0.1' } |
                 Select-Object -First 1).IPAddress
        Add-DnsServerResourceRecordA -Name "*" -ZoneName $Global:Domain -IPv4Address $dcIP -ErrorAction SilentlyContinue
        Write-Good "Wildcard A record '*.$Global:Domain' -> $dcIP"
    } catch {
        Write-Info "ADIDNS wildcard failed: $_"
    }
}

function Create-CertifriedTemplate {
    Write-Info "Publishing Certifried (CVE-2022-26923) template..."
    # Subject from AD + missing SID extension on machine cert
    New-VulnTemplateFromUser -NewName "Certifried-Machine" -NameFlag 0x0 -EnrollmentFlag 0x80000

    try {
        $configNC = (Get-ADRootDSE).configurationNamingContext
        $dn = "CN=Certifried-Machine,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
        $sid = (Get-ADGroup "Domain Computers").SID
        $enrollGuid = [GUID]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
        $acl = Get-Acl "AD:$dn"
        $ace = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid, 'ExtendedRight', 'Allow', $enrollGuid)
        $acl.AddAccessRule($ace)
        Set-Acl -AclObject $acl -Path "AD:$dn"
        certutil -SetCATemplates "+Certifried-Machine" 2>&1 | Out-Null
        Write-Good "Certifried template published -- Domain Computers can enroll"
    } catch {
        Write-Info "Certifried ACL/publish failed: $_"
    }
}

function Enable-PrintSpoolerOnDC {
    Write-Info "Ensuring Print Spooler running on DC (PrinterBug / MS-RPRN)..."
    try {
        Set-Service -Name Spooler -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name Spooler -ErrorAction SilentlyContinue
        Write-Good "Spooler running on DC"
    } catch {
        Write-Info "Spooler start failed: $_"
    }
}

function Create-GPPCpassword {
    Write-Info "Planting GPP cpassword in SYSVOL..."
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        $gpoName = "OnePiece-Workstation-Policy"
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) {
            $gpo = New-GPO -Name $gpoName -ErrorAction Stop
            New-GPLink -Name $gpoName -Target "OU=Workstations,DC=onepiece,DC=local" -ErrorAction SilentlyContinue
            Write-Info "Created GPO $gpoName, linked to OU=Workstations"
        }

        $gpoGuid = $gpo.Id.ToString("B").ToUpper()
        $gppDir = "\\$env:COMPUTERNAME\SYSVOL\$Global:Domain\Policies\$gpoGuid\Machine\Preferences\Groups"
        if (-not (Test-Path $gppDir)) {
            New-Item -ItemType Directory -Path $gppDir -Force | Out-Null
        }

        # The infamous public AES key cpassword - decrypts to "Local*P4ss!"
        $cpassword = "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
        $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
        name="LocalAdmin" image="2" changed="2024-01-01 00:00:00"
        uid="{B5E5BF10-F0A0-4F2D-9F2A-9F1F2F3F4F5F}">
    <Properties action="C" fullName="" description="Local admin"
        cpassword="$cpassword" changeLogon="0" noChange="0"
        neverExpires="0" acctDisabled="0" subAuthority="" userName="LocalAdmin"/>
  </User>
</Groups>
"@
        $xml | Out-File -FilePath "$gppDir\Groups.xml" -Encoding UTF8 -Force
        Write-Good "GPP Groups.xml planted (cpassword decryptable -> Local*P4ss!)"
    } catch {
        Write-Info "GPP cpassword plant failed: $_"
    }
}

function Create-FileShareLoot {
    Write-Info "Creating loot SMB share..."
    try {
        $sharePath = "C:\Shares\Public"
        if (-not (Test-Path $sharePath)) {
            New-Item -ItemType Directory -Path $sharePath -Force | Out-Null
        }

        @"
:: Backup script - DO NOT DISTRIBUTE
@echo off
net use Z: \\dc01\backup /user:onepiece\backup_svc Backup123!
robocopy C:\Important Z:\ /MIR
"@ | Out-File -FilePath "$sharePath\backup.bat" -Encoding ASCII -Force

        @"
# Helpdesk remote-fix script
`$password = ConvertTo-SecureString 'Helpdesk2024!' -AsPlainText -Force
`$cred = New-Object PSCredential('onepiece\helpdesk_svc', `$password)
Invoke-Command -ComputerName WS01 -Credential `$cred -ScriptBlock { whoami }
"@ | Out-File -FilePath "$sharePath\fix-ws01.ps1" -Encoding UTF8 -Force

        @"
Database connection string:
Server=sql01.onepiece.local;Database=master;User Id=sa;Password=Sup3rS3cr3t!;

Linked server SQL01 -> DC01 (executes as onepiece\sql_svc)
"@ | Out-File -FilePath "$sharePath\db-conn.txt" -Encoding ASCII -Force

        if (-not (Get-SmbShare -Name "Public" -ErrorAction SilentlyContinue)) {
            New-SmbShare -Name "Public" -Path $sharePath -ReadAccess "Authenticated Users" | Out-Null
        }
        Write-Good "Share \\$env:COMPUTERNAME\Public created with loot files"
    } catch {
        Write-Info "Loot share failed: $_"
    }
}

# ============================================
# MAIN EXECUTION FUNCTION - FIXED
# ============================================

# Fix the main Invoke-OnePieceSetup function

function Invoke-OnePieceSetup {
    Write-Host "`n=== OnePiece AD Lab Setup ===" -ForegroundColor Cyan
    Write-Host "Target Domain: $Global:Domain" -ForegroundColor Cyan
    
    # Check if running as administrator
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Bad "This script must be run as Administrator!"
        Write-Host "Please right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Red
        return
    }
    
    # Ensure static IP + DNS=127.0.0.1 BEFORE rename/promotion.
    # Skips silently if already static.
    Configure-StaticIP | Out-Null

    # FORCE RENAME TO DC01 - Add this check at the very beginning
    if ($env:COMPUTERNAME -ne "DC01") {
        Write-Info "Current computer name is $($env:COMPUTERNAME). Renaming to DC01..."
        $renameResult = Rename-ComputerToDC01
        if ($renameResult) {
            Write-Host "`n=== RESTARTING NOW ===" -ForegroundColor Yellow
            Write-Host "Computer will restart in 5 seconds to apply name change..." -ForegroundColor Yellow
            Write-Host "Run the script again after restart to continue setup." -ForegroundColor Yellow
            Start-Sleep -Seconds 5
            Restart-Computer -Force
            return
        }
    }
    
    # Rest of the function remains the same...
    # Better check if already a DC - check domain membership
    $computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
    $isDC = $computerInfo.DomainRole -ge 4  # 4=Standalone DC, 5=DC with DNS
    $isDomainJoined = ($computerInfo.PartOfDomain) -and ($computerInfo.Domain -eq $Global:Domain)
    
    Write-Info "Computer name: $($env:COMPUTERNAME)"
    Write-Info "Domain: $($computerInfo.Domain)"
    Write-Info "DomainRole: $($computerInfo.DomainRole)"
    
    if ($isDC -and $isDomainJoined) {
        Write-Good "Domain Controller detected: $($env:COMPUTERNAME)"
        Write-Info "Proceeding with environment setup..."
        
        # Wait for AD services
        Write-Info "Checking AD services..."
        $adReady = Wait-ForADReady
        if (-not $adReady) {
            Write-Bad "AD services not ready!"
            Write-Info "Try restarting the server or checking AD services manually"
            return
        }
        
        # Execute setup steps
        Write-Host "`n=== Executing Setup Steps ===" -ForegroundColor Cyan
        
        $steps = @(
            @{Name="Creating OUs"; Action={Create-BasicOUs}},
            @{Name="Configuring Domain Settings"; Action={Configure-DomainSettings}},
            @{Name="Creating Users"; Action={Import-OnePieceUsers}},
            @{Name="Creating Groups"; Action={Create-EssentialGroups}},
            @{Name="Moving Users to OUs"; Action={Move-UsersToOUs}},
            @{Name="Adding Users to Groups"; Action={Add-UsersToGroups}},
            @{Name="Creating Service Accounts"; Action={Create-ServiceAccounts}},
            @{Name="Configuring Vulnerabilities"; Action={Configure-VulnerableAccounts}},
            @{Name="Configuring SMB Settings"; Action={Configure-SMB}},
            @{Name="Creating Vulnerable ACL Paths"; Action={Create-VulnerableACLs}},
            @{Name="Constrained Delegation (nami.n)"; Action={Configure-ConstrainedDelegation}},
            @{Name="RBCD Pre-stage (usopp.u -> FILES01)"; Action={Configure-RBCD}},
            @{Name="Installing LAPS"; Action={Install-LAPSOnDC}},
            @{Name="Creating gMSA"; Action={Create-GMSA}},
            @{Name="LDAP Anonymous Bind + Pre-Win2K"; Action={Enable-LDAPAnonymousBind}},
            @{Name="ADIDNS Wildcard"; Action={Create-ADIDNSWildcard}},
            @{Name="Print Spooler on DC"; Action={Enable-PrintSpoolerOnDC}},
            @{Name="GPP cpassword in SYSVOL"; Action={Create-GPPCpassword}},
            @{Name="File Share Loot"; Action={Create-FileShareLoot}},
            @{Name="Installing AD CS"; Action={Install-ADCS}},
            @{Name="Certifried Template"; Action={Create-CertifriedTemplate}}
            # Configure-ADCS-AdvancedVulns is called from inside Install-ADCS
        )
        
        $i = 0
        foreach ($step in $steps) {
            $i++
            Write-Host ("`n[{0,2}/{1}] {2}" -f $i, $steps.Count, $step.Name) -ForegroundColor Cyan
            & $step.Action | Out-Null
        }
        
        # Final Summary
        Show-SetupSummary
        
    } else {
        # First-time DC installation
        Write-Info "This is Phase 1: Installing Domain Controller"
        Write-Info "Current computer name: $($env:COMPUTERNAME)"
        
        # Check if we're in a domain already (different domain)
        if ($computerInfo.PartOfDomain -and $computerInfo.Domain -ne $Global:Domain) {
            Write-Bad "Computer is already joined to domain: $($computerInfo.Domain)"
            Write-Bad "Cannot install new domain. Please use a fresh Windows Server."
            return
        }
        
        # Check if AD DS is already installed
        $adDSInstalled = (Get-WindowsFeature -Name AD-Domain-Services).InstallState -eq "Installed"
        
        if ($adDSInstalled -and $computerInfo.DomainRole -eq 3) {
            # AD DS is installed but not promoted yet - promote now
            Write-Info "AD DS is installed but not promoted. Promoting now..."
            $promoted = Promote-ToDC
            if (-not $promoted) {
                Write-Bad "DC promotion failed!"
                return
            }
        } else {
            # Fresh install
            Write-Info "Step 1: Installing AD DS..."
            $featureInstalled = Install-SingleDC
            if (-not $featureInstalled) {
                Write-Bad "AD DS installation failed!"
                return
            }
            
            Write-Info "Step 2: Promoting to DC..."
            $promoted = Promote-ToDC
            if (-not $promoted) {
                Write-Bad "DC promotion failed!"
                return
            }
        }
        
        # The system will restart automatically
        Write-Host "`n" -ForegroundColor Green
        Write-Host "=== Server will restart automatically ===" -ForegroundColor Green
        Write-Host "After restart, run this script again to complete setup." -ForegroundColor Green
        Write-Host ""
    }
}

function Show-SetupSummary {
    Write-Host "`n" -ForegroundColor Green
    Write-Host "=== SETUP COMPLETE ===" -ForegroundColor Green
    Write-Host "=========================================" -ForegroundColor Green
    Write-Host "Domain: $Global:Domain" -ForegroundColor Yellow
    Write-Host "Domain Controller: $env:COMPUTERNAME" -ForegroundColor Yellow
    
    Write-Host "`n--- Created Objects ---" -ForegroundColor Cyan
    Write-Host "Users: 24 OnePiece character accounts" -ForegroundColor White
    Write-Host "Groups: 9 security groups" -ForegroundColor White
    Write-Host "OUs: 9 organizational units" -ForegroundColor White
    Write-Host "Service Accounts: 6 (merry_svc, cifs_svc, http_svc, sql_svc, backup_svc, helpdesk_svc)" -ForegroundColor White
    Write-Host "Computer: FILES01 (RBCD target)" -ForegroundColor White
    Write-Host "gMSA: gmsa_sql (kid.e can read password)" -ForegroundColor White

    Write-Host "`n--- Vulnerability Targets ---" -ForegroundColor Cyan
    Write-Host "AS-REP Roasting:           enel.g, shirahoshi, bonclay.b" -ForegroundColor Yellow
    Write-Host "Unconstrained Delegation:  franky.c, brook.b" -ForegroundColor Yellow
    Write-Host "Constrained Delegation:    nami.n -> CIFS/DC01 (protocol transition)" -ForegroundColor Yellow
    Write-Host "RBCD:                      usopp.u -> FILES01`$" -ForegroundColor Yellow
    Write-Host "Kerberoasting:             merry_svc, cifs_svc, http_svc, sql_svc" -ForegroundColor Yellow
    Write-Host "DCSync (non-DA):           bonclay.b" -ForegroundColor Yellow
    Write-Host "DnsAdmins:                 enel.g, shirahoshi" -ForegroundColor Yellow
    Write-Host "LAPS / gMSA Read:          kid.e" -ForegroundColor Yellow
    Write-Host "Weak/sprayable passwords:  roger.g, rayleigh.s, garp.m, smoker.c" -ForegroundColor Yellow

    Write-Host "`n--- AD CS Vulnerabilities ---" -ForegroundColor Cyan
    Write-Host "ESC1, ESC6, ESC8, ESC9, ESC10, ESC11, ESC15, ESC16 + Certifried" -ForegroundColor Yellow
    Write-Host "Web Enrollment: http://$env:COMPUTERNAME/certsrv" -ForegroundColor Yellow

    Write-Host "`n--- Domain-wide Misconfigs ---" -ForegroundColor Cyan
    Write-Host "SMB signing off, LDAP anonymous bind, Pre-Win2K compat" -ForegroundColor Yellow
    Write-Host "MachineAccountQuota = 20, Spooler on, EFS on (PetitPotam)" -ForegroundColor Yellow
    Write-Host "ADIDNS wildcard *.onepiece.local, GPP cpassword in SYSVOL" -ForegroundColor Yellow
    Write-Host "Loot share: \\$env:COMPUTERNAME\Public" -ForegroundColor Yellow

    Write-Host "`n--- Test Credentials ---" -ForegroundColor Cyan
    Write-Host "Domain Admin:   luffy.m / Password123!" -ForegroundColor White
    Write-Host "Weak pwd DA:    roger.g / Changeme123!" -ForegroundColor White
    Write-Host "DCSync user:    bonclay.b / Password777!" -ForegroundColor White
    Write-Host "LAPS/gMSA read: kid.e / Password222!" -ForegroundColor White
    Write-Host "Full list:      see README.md credentials table" -ForegroundColor White
    
    Write-Host "`n--- Verification Commands ---" -ForegroundColor Cyan
    Write-Host "Get-ADUser -Filter * | Select-Object SamAccountName" -ForegroundColor Gray
    Write-Host "Get-ADGroup -Filter * | Select-Object Name" -ForegroundColor Gray
    Write-Host "Get-SmbServerConfiguration | Select-Object *Signature*" -ForegroundColor Gray
    Write-Host "certutil -ping" -ForegroundColor Gray
    
    Write-Host "`n  IMPORTANT: Take a VM snapshot now for easy rollback!" -ForegroundColor Red
    Write-Host ""
}

# ============================================
# SCRIPT EXECUTION
# ============================================

if ($MyInvocation.InvocationName -ne '.') {
    Write-Host "Starting OnePiece AD Lab Setup..." -ForegroundColor Cyan
    Write-Host "Press Ctrl+C to cancel" -ForegroundColor Gray
    Start-Sleep -Seconds 2
    Invoke-OnePieceSetup
}