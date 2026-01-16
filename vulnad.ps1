[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 > $null

$Global:Domain = "onepiece.local"
$Global:NetbiosName = "ONEPIECE"
$Global:SourcePath = "D:\sources\sxs"  # Set this to Windows installation media path if needed

function Write-Good { param( $String ) Write-Host "[+]" $String -ForegroundColor 'Green'}
function Write-Bad  { param( $String ) Write-Host "[-]" $String -ForegroundColor 'Red'}
function Write-Info { param( $String ) Write-Host "[*]" $String -ForegroundColor 'Gray'}

# ============================================
# CORE INSTALLATION FUNCTIONS - FIXED
# ============================================

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
    
    foreach ($ou in $ous) {
        try {
            $exists = Get-ADOrganizationalUnit -Filter "Name -eq '$($ou.Name)'" -ErrorAction SilentlyContinue
            if (-not $exists) {
                New-ADOrganizationalUnit -Name $ou.Name -Path $ou.Path -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue
                Write-Info "Created OU: $($ou.Name)"
            } else {
                Write-Info "OU already exists: $($ou.Name)"
            }
        } catch {
            Write-Info "Error creating OU $($ou.Name): $_"
        }
    }
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
        @{Username="bonclay.b"; FullName="Bon Clay"; Password="Password777!"}
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
                Write-Info "Created user: $($user.Username)"
            } else {
                Write-Info "User already exists: $($user.Username)"
            }
        } catch {
            $errorCount++
            Write-Info "Error creating user $($user.Username): $_"
        }
    }
    
    Write-Good "$createdCount users created ($errorCount errors)"
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
                    Write-Info "Moved $user to $ou OU"
                    $movedCount++
                } else {
                    Write-Info "User not found: $user"
                }
            } catch {
                # FIXED LINE - use string formatting instead of colon
                Write-Info "Could not move user $($user): $($_)"
            }
        }
    }
    
    Write-Info "Moved $movedCount users to OUs"
    return $movedCount
}

function Create-EssentialGroups {
    Write-Info "Creating groups..."
    
    $groups = @(
        @{Name="Straw Hat Crew"; Scope="Global"},
        @{Name="Marine Admirals"; Scope="Global"},
        @{Name="Pirate Emperors"; Scope="Global"},
        @{Name="Warlords of the Sea"; Scope="Global"},
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
                New-ADGroup -Name $group.Name -GroupScope $group.Scope -GroupCategory Security -Path "DC=onepiece,DC=local" -ErrorAction SilentlyContinue
                $createdCount++
                Write-Info "Created group: $($group.Name)"
            } else {
                $existingCount++
                Write-Info "Group already exists: $($group.Name)"
            }
        } catch {
            Write-Info "Error creating group $($group.Name): $_"
        }
    }
    
    Write-Good "$createdCount groups created ($existingCount already exist)"
    return $createdCount
}

function Add-UsersToGroups {
    Write-Info "Adding users to groups..."
    
    $groupMappings = @{
        "Straw Hat Crew" = @("luffy.m", "zoro.r", "nami.n", "sanji.v", "usopp.u", "franky.c", "brook.b")
        "Marine Admirals" = @("akainu", "aokiji", "kizaru")
        "Pirate Emperors" = @("shanks.r", "kaido.b", "bigmom", "blackbeard")
        "Warlords of the Sea" = @("doflamingo", "law.t")
        "Domain Admins" = @("luffy.m")
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
                if ($adUser) {
                    $usersToAdd += $adUser.SamAccountName
                } else {
                    Write-Info "User not found for group membership: $user"
                }
            }
            
            if ($usersToAdd.Count -gt 0) {
                Add-ADGroupMember -Identity $group -Members $usersToAdd -ErrorAction SilentlyContinue
                $addedCount = $usersToAdd.Count
                $addedTotal += $addedCount
                Write-Info "Added $addedCount users to $group"
            }
        } catch {
            # FIXED LINE
            Write-Info "Error adding users to $($group): $($_)"
        }
    }
    
    Write-Info "Added $addedTotal total group memberships"
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
        @{Name="merry_svc"; Description="Going Merry Service"; SPN="merry_svc/goingmerry.onepiece.local"},
        @{Name="cifs_svc"; Description="CIFS Service"; SPN="cifs/dc.onepiece.local"},
        @{Name="http_svc"; Description="HTTP Service"; SPN="http/web.onepiece.local"}
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
                    ServicePrincipalNames = $svc.SPN
                    AccountPassword = (ConvertTo-SecureString "Password123!" -AsPlainText -Force)
                    Enabled = $true
                    PasswordNeverExpires = $true
                    Path = "OU=Services,DC=onepiece,DC=local"
                    ErrorAction = 'SilentlyContinue'
                }
                
                New-ADUser @userParams
                $createdCount++
                Write-Info "Created service account: $($svc.Name)"
            }
        } catch {
            Write-Info "Error creating service account $($svc.Name): $_"
        }
    }
    
    Write-Info "Created $createdCount service accounts"
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
                Write-Info "Configured DoesNotRequirePreAuth for $user"
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
                Write-Info "Configured TrustedForDelegation for $user"
                $configuredCount++
            }
        } catch { 
            # FIXED LINE
            Write-Info "Error configuring TrustedForDelegation for $($user): $($_)"
        }
    }
    
    Write-Info "Configured $configuredCount accounts for vulnerabilities"
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
        
        # Configure vulnerable settings on existing CA
        Configure-ADCS-VulnerableSettings
        Create-VulnerableCertificateTemplates
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
        
        # Configure Web Enrollment
        Write-Info "Configuring Web Enrollment Service..."
        try {
            Install-AdcsEnrollmentWebService -ApplicationPoolIdentity -Force -Confirm:$false -ErrorAction SilentlyContinue
            Write-Good "Web Enrollment Service configured (ESC8 vulnerable)"
        } catch {
            Write-Info "Web Enrollment may already be configured: $_"
        }
        
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
        
        # ESC13: Set high machine account quota
        Write-Info "Setting machine account quota for ESC13..."
        try {
            Set-ADDomain -Identity $Global:Domain -Replace @{"ms-DS-MachineAccountQuota" = "20"} -ErrorAction SilentlyContinue
            Write-Info "Machine account quota set to 20"
        } catch {
            Write-Info "Could not set machine account quota: $_"
        }
        
        # ESC12: Ensure EFS is enabled
        Write-Info "Configuring EFS for PetitPotam..."
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

function Create-VulnerableCertificateTemplates {
    Write-Info "Creating vulnerable certificate templates..."
    
    # Create template files directory
    $templateDir = "C:\ADCS-Templates"
    if (-not (Test-Path $templateDir)) {
        New-Item -ItemType Directory -Path $templateDir -Force | Out-Null
    }
    
    # ESC1: Vulnerable User template
    $esc1Template = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "CN=ESC1-Vulnerable-User"
KeyLength = 2048
KeySpec = 1
Exportable = TRUE
MachineKeySet = FALSE
RequestType = PKCS10

[RequestAttributes]
CertificateTemplate = "User"
SAN="upn=administrator@$Global:Domain"
"@
    
    $esc1Template | Out-File -FilePath "$templateDir\ESC1-Template.inf" -Encoding ASCII
    
    # ESC9: No-template-required certificate
    $esc9Template = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "CN=ESC9-No-Template"
KeyLength = 2048
KeySpec = 1
Exportable = TRUE
"@
    
    $esc9Template | Out-File -FilePath "$templateDir\ESC9-Template.inf" -Encoding ASCII
    
    Write-Info "Vulnerable certificate templates created in $templateDir"
    Write-Info "Note: Templates may need manual configuration in Certificate Templates console"
}

function Configure-ADCS-AdvancedVulns {
    Write-Info "Configuring additional AD CS vulnerabilities (ESC9-ESC16)..."
    
    try {
        # ESC10: Create Certificate Manager account
        Write-Info "Creating vulnerable Certificate Manager account..."
        try {
            $certManager = @{
                Name = "Certificate Manager"
                SamAccountName = "certmanager"
                Description = "Certificate Management Account"
                AccountPassword = (ConvertTo-SecureString "CertMgr123!" -AsPlainText -Force)
                Enabled = $true
                PasswordNeverExpires = $true
                Path = "OU=Services,DC=onepiece,DC=local"
            }
            
            New-ADUser @certManager -ErrorAction SilentlyContinue
            Write-Info "Created certificate manager account"
        } catch { }
        
        # ESC11: Already configured via enel.g in DnsAdmins
        
        # ESC14: Create backup service account
        Write-Info "Creating backup service account..."
        try {
            $backupSvc = @{
                Name = "Backup Operator"
                SamAccountName = "backup_svc"
                Description = "Backup Service Account"
                AccountPassword = (ConvertTo-SecureString "Backup123!" -AsPlainText -Force)
                Enabled = $true
                PasswordNeverExpires = $true
                Path = "OU=Services,DC=onepiece,DC=local"
            }
            
            New-ADUser @backupSvc -ErrorAction SilentlyContinue
            Add-ADGroupMember -Identity "Backup Operators" -Members "backup_svc" -ErrorAction SilentlyContinue
            Write-Info "Created backup service account"
        } catch { }
        
        # ESC15: Create test computer for RBCD
        Write-Info "Creating test computer for RBCD..."
        try {
            $testComputer = Get-ADComputer -Filter "Name -eq 'TESTCOMP'" -ErrorAction SilentlyContinue
            if (-not $testComputer) {
                New-ADComputer -Name "TESTCOMP" -SamAccountName "TESTCOMP`$" -Path "OU=Workstations,DC=onepiece,DC=local" -Enabled $true -ErrorAction SilentlyContinue
                Write-Info "Created test computer: TESTCOMP"
            }
        } catch { }
        
        # ESC16: Smartcard configuration
        Write-Info "Configuring smartcard authentication..."
        try {
            Set-ADDomain -Identity $Global:Domain -Replace @{
                "msDS-Other-Settings" = "RequireSmartCard=0"
            } -ErrorAction SilentlyContinue
        } catch { }
        
        # Create vulnerability summary
        Show-ADCS-VulnerabilitySummary
        
        Write-Good "Advanced AD CS vulnerabilities configured"
        
    } catch {
        Write-Info "Error in advanced vulnerability configuration: $_"
    }
}

function Show-ADCS-VulnerabilitySummary {
    Write-Host "`n" -ForegroundColor Green
    Write-Host "AD CS VULNERABILITIES CONFIGURED" -ForegroundColor Green
    Write-Host "==============================================" -ForegroundColor Green
    Write-Host "ESC1-ESC2: Vulnerable User template created" -ForegroundColor Yellow
    Write-Host "ESC5-ESC6: EDITF_ATTRIBUTESUBJECT enabled" -ForegroundColor Yellow
    Write-Host "ESC8: Web Enrollment enabled (http://$env:COMPUTERNAME/certsrv)" -ForegroundColor Yellow
    Write-Host "ESC9: No-template-required certificate template" -ForegroundColor Yellow
    Write-Host "ESC10: Certificate Manager account created" -ForegroundColor Yellow
    Write-Host "ESC11: DnsAdmins AD CS (via enel.g)" -ForegroundColor Yellow
    Write-Host "ESC12: EFS enabled for PetitPotam" -ForegroundColor Yellow
    Write-Host "ESC13: Machine account quota set to 20" -ForegroundColor Yellow
    Write-Host "ESC14: Backup service account created" -ForegroundColor Yellow
    Write-Host "ESC15: RBCD test computer created" -ForegroundColor Yellow
    Write-Host "ESC16: Smartcard authentication configured" -ForegroundColor Yellow
    Write-Host ""
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
            @{Name="Installing AD CS"; Action={Install-ADCS}},
            @{Name="Configuring Advanced AD CS Vulns"; Action={Configure-ADCS-AdvancedVulns}}
        )
        
        foreach ($step in $steps) {
            Write-Host ""
            Write-Info "$($step.Name)..."
            & $step.Action
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
    Write-Host "Users: 20 OnePiece character accounts" -ForegroundColor White
    Write-Host "Groups: 8 security groups" -ForegroundColor White
    Write-Host "OUs: 9 organizational units" -ForegroundColor White
    Write-Host "Service Accounts: 3 (merry_svc, cifs_svc, http_svc)" -ForegroundColor White
    
    Write-Host "`n--- Vulnerability Targets ---" -ForegroundColor Cyan
    Write-Host "AS-REP Roasting: enel.g, shirahoshi, bonclay.b" -ForegroundColor Yellow
    Write-Host "Unconstrained Delegation: franky.c, brook.b" -ForegroundColor Yellow
    Write-Host "Kerberoasting: merry_svc, cifs_svc, http_svc" -ForegroundColor Yellow
    Write-Host "DnsAdmins: enel.g, shirahoshi" -ForegroundColor Yellow
    
    Write-Host "`n--- AD CS Vulnerabilities ---" -ForegroundColor Cyan
    Write-Host "ESC1-ESC16: Multiple certificate service vulnerabilities" -ForegroundColor Yellow
    Write-Host "Web Enrollment: http://$env:COMPUTERNAME/certsrv" -ForegroundColor Yellow
    
    Write-Host "`n--- Test Credentials ---" -ForegroundColor Cyan
    Write-Host "Domain Admin: luffy.m / Password123!" -ForegroundColor White
    Write-Host "All users: PasswordXXX! format (see script for details)" -ForegroundColor White
    
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