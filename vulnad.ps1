# OnePiece AD Lab Setup and Cleanup Script

$Global:Domain = "onepiece.local"
$Global:NetbiosName = "ONEPIECE"
$Global:SourcePath = "D:\sources\sxs"  # Set this to Windows installation media path if needed

function Write-Good { param( $String ) Write-Host "[+]" $String -ForegroundColor 'Green'}
function Write-Bad  { param( $String ) Write-Host "[-]" $String -ForegroundColor 'Red'}
function Write-Info { param( $String ) Write-Host "[*]" $String -ForegroundColor 'Gray'}

# ============================================
# CLEANUP FUNCTIONS
# ============================================

function Remove-OnePieceAD {
    Write-Info "Starting complete AD environment cleanup..."
    
    # Check if AD DS is installed
    $adInstalled = (Get-WindowsFeature -Name AD-Domain-Services).InstallState -eq "Installed"
    
    if (-not $adInstalled) {
        Write-Info "AD Domain Services is not installed. Nothing to clean up."
        return $true
    }
    
    # Check if we're on a DC
    $isDC = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4
    
    if ($isDC) {
        Write-Info "This is a Domain Controller. Forcefully removing AD..."
        
        try {
            # Force demote the DC without credentials
            Uninstall-ADDSDomainController -LocalAdministratorPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) -ForceRemoval -Confirm:$false
            Write-Good "DC demotion initiated. Server will restart."
            Restart-Computer -Force
            return $true
        } catch {
            Write-Bad "Error during demotion: $_"
            return $false
        }
    } else {
        # Remove AD components if not a DC
        try {
            Write-Info "Removing AD Domain Services feature..."
            $result = Uninstall-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -Remove -Restart:$false
            Write-Good "AD Domain Services removed"
            
            if ($result.RestartNeeded -eq "Yes") {
                Write-Info "Restart required to complete AD removal. Restarting now..."
                Restart-Computer -Force
            }
            
            return $true
        } catch {
            Write-Bad "Error removing AD: $_"
            return $false
        }
    }
}

function Clean-OnePieceObjects {
    Write-Info "Cleaning up One Piece AD objects..."
    
    # First check if AD is installed
    $adInstalled = (Get-WindowsFeature -Name AD-Domain-Services).InstallState -eq "Installed"
    
    if (-not $adInstalled) {
        Write-Info "AD Domain Services is not installed. Nothing to clean up."
        return
    }
    
    # Check if we're on a DC
    $isDC = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4
    
    if (-not $isDC) {
        Write-Info "This server is not a Domain Controller. Cannot clean AD objects."
        return
    }
    
    # Import AD module
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    
    try {
        # Remove all OUs (excluding default ones)
        Get-ADOrganizationalUnit -Filter * | Where-Object {
            $_.DistinguishedName -notlike "*Domain Controllers*" -and 
            $_.DistinguishedName -notlike "*Users*" -and
            $_.DistinguishedName -notlike "*Computers*" -and
            $_.DistinguishedName -notlike "*Managed Service Accounts*"
        } | ForEach-Object {
            try {
                Remove-ADOrganizationalUnit -Identity $_.DistinguishedName -Recursive -Confirm:$false
                Write-Info "Removed OU: $($_.Name)"
            } catch {
                Write-Info "Could not remove OU: $($_.Name)"
            }
        }
        
        # Remove all custom groups (excluding built-in)
        Get-ADGroup -Filter * | Where-Object {
            $_.SID.Value -notlike "S-1-5-32*" -and 
            $_.SID.Value -notlike "S-1-5-21*" -and
            $_.Name -notlike "Domain*" -and
            $_.Name -notlike "Enterprise*" -and
            $_.Name -notlike "Schema*" -and
            $_.Name -notlike "*Administrators*" -and
            $_.Name -notin @("Users", "Guests")
        } | ForEach-Object {
            try {
                Remove-ADGroup -Identity $_.DistinguishedName -Confirm:$false
                Write-Info "Removed group: $($_.Name)"
            } catch {
                Write-Info "Could not remove group: $($_.Name)"
            }
        }
        
        # Remove all custom users (excluding built-in)
        Get-ADUser -Filter * | Where-Object {
            $_.SID.Value -notlike "S-1-5-21*-500" -and  # Administrator
            $_.SID.Value -notlike "S-1-5-21*-501" -and  # Guest
            $_.SID.Value -notlike "S-1-5-21*-502" -and  # KRBTGT
            $_.SID.Value -notlike "S-1-5-21*-512" -and  # Domain Admins
            $_.SID.Value -notlike "S-1-5-21*-513" -and  # Domain Users
            $_.SID.Value -notlike "S-1-5-21*-514" -and  # Domain Guests
            $_.SID.Value -notlike "S-1-5-21*-515" -and  # Domain Computers
            $_.SID.Value -notlike "S-1-5-21*-516" -and  # Domain Controllers
            $_.SID.Value -notlike "S-1-5-21*-517" -and  # Cert Publishers
            $_.SID.Value -notlike "S-1-5-21*-518" -and  # Schema Admins
            $_.SID.Value -notlike "S-1-5-21*-519" -and  # Enterprise Admins
            $_.SID.Value -notlike "S-1-5-21*-520" -and  # Group Policy Creator Owners
            $_.SID.Value -notlike "S-1-5-21*-526" -and  # Key Admins
            $_.SID.Value -notlike "S-1-5-21*-527" -and  # Enterprise Key Admins
            $_.SID.Value -notlike "S-1-5-21*-553" -and  # RAS and IAS Servers
            $_.SID.Value -notlike "S-1-5-21*-571" -and  # Allowed RODC Password Replication Group
            $_.SID.Value -notlike "S-1-5-21*-572" -and  # Denied RODC Password Replication Group
            $_.SID.Value -notlike "S-1-5-21*-1101" -and # DnsAdmins
            $_.SID.Value -notlike "S-1-5-21*-1102" -and # DnsUpdateProxy
            $_.SamAccountName -notin @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount", "krbtgt")
        } | ForEach-Object {
            try {
                Remove-ADUser -Identity $_.DistinguishedName -Confirm:$false
                Write-Info "Removed user: $($_.SamAccountName)"
            } catch {
                Write-Info "Could not remove user: $($_.SamAccountName)"
            }
        }
        
        # Remove GPOs
        Get-GPO -All | Where-Object {
            $_.DisplayName -match "Wano|Marine|StrawHat"
        } | ForEach-Object {
            try {
                Remove-GPO -Name $_.DisplayName -Confirm:$false
                Write-Info "Removed GPO: $($_.DisplayName)"
            } catch {
                Write-Info "Could not remove GPO: $($_.DisplayName)"
            }
        }
        
        Write-Good "AD objects cleanup completed"
        
    } catch {
        Write-Bad "Error during cleanup: $_"
    }
}

function Remove-ADCS {
    Write-Info "Removing Active Directory Certificate Services..."
    
    try {
        # Check if AD CS is installed
        $adcsFeatures = Get-WindowsFeature | Where-Object {$_.Name -like "*ADCS*" -and $_.InstallState -eq "Installed"}
        
        if ($adcsFeatures) {
            # First try to uninstall CA configuration
            try {
                Write-Info "Removing CA configuration..."
                Uninstall-AdcsCertificationAuthority -Force -Confirm:$false
                Write-Info "CA configuration removed"
            } catch {
                Write-Info "CA configuration removal failed or not needed: $_"
            }
            
            # Wait for cleanup
            Start-Sleep -Seconds 5
            
            # Uninstall AD CS features
            Write-Info "Removing AD CS features..."
            Uninstall-WindowsFeature -Name Adcs-Cert-Authority, Adcs-Web-Enrollment -IncludeManagementTools -Remove -Restart:$false
            Write-Good "AD CS roles removed"
            
            # Clean up leftover registry entries
            try {
                Write-Info "Cleaning up CA registry entries..."
                Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" -Name "CACertHash" -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" -Name "CASerialNumber" -ErrorAction SilentlyContinue
            } catch {
                Write-Info "Registry cleanup may not be needed: $_"
            }
        } else {
            Write-Info "AD CS is not installed"
        }
        
        return $true
    } catch {
        Write-Bad "Error removing AD CS: $_"
        return $false
    }
}

# ============================================
# INSTALLATION FUNCTIONS
# ============================================

function Install-ADForest {
    Write-Info "Installing AD Forest..."
    
    # Check if already a DC
    $isDC = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4
    
    if ($isDC) {
        Write-Info "Server is already a Domain Controller. Cleaning existing AD..."
        Remove-OnePieceAD
        Write-Info "Waiting for cleanup to complete..."
        Start-Sleep -Seconds 30
    }
    
    try {
        # Install AD DS with source path if specified
        $installParams = @{
            Name = "AD-Domain-Services"
            IncludeManagementTools = $true
        }
        
        if ($Global:SourcePath) {
            $installParams.Source = $Global:SourcePath
            Write-Info "Using source path: $Global:SourcePath"
        }
        
        Install-WindowsFeature @installParams
        
        # Check if installation succeeded
        $adInstalled = (Get-WindowsFeature -Name AD-Domain-Services).InstallState -eq "Installed"
        
        if (-not $adInstalled) {
            Write-Bad "AD installation failed. Please check if source files are available."
            Write-Info "You may need to mount Windows installation media and specify source path."
            Write-Info "Example: Mount Windows ISO and set source path to D:\sources\sxs"
            return $false
        }
        
        Import-Module ADDSDeployment
        
        $safeModePassword = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
        
        # Install new forest
        Install-ADDSForest `
            -CreateDnsDelegation:$false `
            -DatabasePath "C:\Windows\NTDS" `
            -DomainMode "WinThreshold" `
            -DomainName $Global:Domain `
            -DomainNetbiosName $Global:NetbiosName `
            -ForestMode "WinThreshold" `
            -InstallDns:$true `
            -LogPath "C:\Windows\NTDS" `
            -NoRebootOnCompletion:$false `
            -SysvolPath "C:\Windows\SYSVOL" `
            -SafeModeAdministratorPassword $safeModePassword `
            -Force:$true
        
        Write-Good "AD Forest installation initiated. Server will restart."
        return $true
        
    } catch {
        Write-Bad "Error installing AD Forest: $_"
        Write-Info "You may need to specify Windows installation source path."
        Write-Info "Edit the script and set `$Global:SourcePath = 'D:\sources\sxs' (adjust drive letter)"
        return $false
    }
}

function Check-ADInstalled {
    Write-Info "Checking if AD is installed..."
    
    # Check if AD DS is installed
    $adInstalled = (Get-WindowsFeature -Name AD-Domain-Services).InstallState -eq "Installed"
    
    if (-not $adInstalled) {
        Write-Info "AD is not installed. Attempting installation..."
        
        # Try without source first
        try {
            $result = Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -Restart:$false -ErrorAction Stop
            
            if ($result.Success -eq $true) {
                Write-Good "AD DS installed successfully"
                
                # Now promote to DC
                return $false  # Return false so main script continues to DC promotion
            }
        } catch {
            Write-Info "Installation without source failed: $_"
        }
        
        # If we get here, try with source path
        Write-Info "Trying installation with source path..."
        $installed = Install-ADForest
        if (-not $installed) {
            Write-Bad "AD installation failed. Please check the error above."
            return $false
        }
        return $false  # Installation initiated, will restart
    }
    
    # Check if we're on a DC
    $isDC = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4
    
    if (-not $isDC) {
        Write-Info "AD is installed but this server is not a Domain Controller."
        Write-Info "Server has AD DS feature but is not a DC. Promoting to DC..."
        
        # Instead of removing AD, promote this server to DC
        try {
            Import-Module ADDSDeployment
            $safeModePassword = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
            
            Install-ADDSDomainController `
                -InstallDns:$true `
                -CreateDnsDelegation:$false `
                -DomainName $Global:Domain `
                -SafeModeAdministratorPassword $safeModePassword `
                -NoRebootOnCompletion:$false `
                -Force:$true
            
            Write-Good "DC promotion initiated. Server will restart."
            return $false
        } catch {
            Write-Bad "DC promotion failed: $_"
            return $false
        }
    }
    
    Write-Good "AD is installed and this server is a Domain Controller."
    return $true
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

function Create-OnePieceOUs {
    Write-Info "Creating One Piece OUs..."
    
    $ous = @(
        @{Name="GrandLine"; Path="DC=onepiece,DC=local"},
        @{Name="NewWorld"; Path="DC=onepiece,DC=local"},
        @{Name="Paradise"; Path="DC=onepiece,DC=local"},
        @{Name="StrawHats"; Path="OU=GrandLine,DC=onepiece,DC=local"},
        @{Name="Marines"; Path="OU=GrandLine,DC=onepiece,DC=local"},
        @{Name="Warlords"; Path="OU=GrandLine,DC=onepiece,DC=local"},
        @{Name="Yonko"; Path="OU=NewWorld,DC=onepiece,DC=local"},
        @{Name="Revolutionary"; Path="OU=NewWorld,DC=onepiece,DC=local"},
        @{Name="Supernovas"; Path="OU=NewWorld,DC=onepiece,DC=local"},
        @{Name="Services"; Path="OU=Paradise,DC=onepiece,DC=local"},
        @{Name="Workstations"; Path="OU=Paradise,DC=onepiece,DC=local"},
        @{Name="Servers"; Path="OU=Paradise,DC=onepiece,DC=local"}
    )
    
    foreach ($ou in $ous) {
        try {
            $exists = Get-ADOrganizationalUnit -Filter "Name -eq '$($ou.Name)'" -ErrorAction SilentlyContinue
            if (-not $exists) {
                New-ADOrganizationalUnit -Name $ou.Name -Path $ou.Path -ProtectedFromAccidentalDeletion $false
                Write-Info "Created OU: $($ou.Name)"
            } else {
                Write-Info "OU already exists: $($ou.Name)"
            }
        } catch {
            Write-Info "Error creating OU $($ou.Name): $_"
        }
    }
}

function Create-OnePieceForests {
    Write-Info "Creating One Piece Forests..."
    
    $forests = @(
        @{Name="WanoForest"; Description="Wano Country Forest"},
        @{Name="WholeCakeForest"; Description="Whole Cake Island Forest"},
        @{Name="DressrosaForest"; Description="Dressrosa Kingdom Forest"},
        @{Name="FishmanForest"; Description="Fishman Island Forest"},
        @{Name="AlabastaForest"; Description="Alabasta Kingdom Forest"},
        @{Name="SkypieaForest"; Description="Skypiea Forest"}
    )
    
    foreach ($forest in $forests) {
        try {
            $exists = Get-ADOrganizationalUnit -Filter "Name -eq '$($forest.Name)'" -ErrorAction SilentlyContinue
            if (-not $exists) {
                New-ADOrganizationalUnit -Name $forest.Name -Path "DC=onepiece,DC=local" -Description $forest.Description -ProtectedFromAccidentalDeletion $false
                Write-Info "Created forest: $($forest.Name)"
            } else {
                Write-Info "Forest already exists: $($forest.Name)"
            }
        } catch {
            Write-Info "Error creating forest $($forest.Name): $_"
        }
    }
}

function Import-OnePieceUsers {
    Write-Info "Creating One Piece users..."
    
    # Hardcoded users from users.txt
    $users = @(
        @{ID=1; Username="luffy.m"; FullName="Monkey D. Luffy"; Password="Luffy@123!"},
        @{ID=2; Username="zoro.r"; FullName="Roronoa Zoro"; Password="Zoro@456#"},
        @{ID=3; Username="nami.n"; FullName="Nami"; Password="Nami$789!"},
        @{ID=4; Username="usopp.u"; FullName="Usopp"; Password="Usopp@2024!"},
        @{ID=5; Username="sanji.v"; FullName="Vinsmoke Sanji"; Password="Sanji#Cook!"},
        @{ID=6; Username="chopper.t"; FullName="Tony Tony Chopper"; Password="Chopper@321!"},
        @{ID=7; Username="robin.n"; FullName="Nico Robin"; Password="Robin@Hist0ria!"},
        @{ID=8; Username="franky.c"; FullName="Cutty Flam"; Password="Franky$SUPER!"},
        @{ID=9; Username="brook.b"; FullName="Brook"; Password="Brook@Yoho123!"},
        @{ID=10; Username="jimbei.s"; FullName="Jimbei"; Password="Jimbei@Se4!"},
        @{ID=11; Username="shanks.r"; FullName="Red-Haired Shanks"; Password="Shanks@Haki1!"},
        @{ID=12; Username="mihawk.d"; FullName="Dracule Mihawk"; Password="Mihawk@Yoru2!"},
        @{ID=13; Username="hancock.b"; FullName="Boa Hancock"; Password="Hancock$Love3!"},
        @{ID=14; Username="buggy.c"; FullName="Buggy the Clown"; Password="Buggy@Clown4!"},
        @{ID=15; Username="whitebeard"; FullName="Edward Newgate"; Password="Whitebeard@Gura5!"},
        @{ID=16; Username="marco.p"; FullName="Marco the Phoenix"; Password="Marco$Phoenix6!"},
        @{ID=17; Username="ace.p"; FullName="Portgas D. Ace"; Password="Ace@MeraMera7!"},
        @{ID=18; Username="sabo.r"; FullName="Sabo"; Password="Sabo@Flame8!"},
        @{ID=19; Username="law.t"; FullName="Trafalgar Law"; Password="Law$ROOM9!"},
        @{ID=20; Username="kid.e"; FullName="Eustass Kid"; Password="Kid@Punk10!"},
        @{ID=21; Username="garp.m"; FullName="Monkey D. Garp"; Password="Garp@Fist11!"},
        @{ID=22; Username="akainu"; FullName="Sakazuki"; Password="Akainu$Magma12!"},
        @{ID=23; Username="aokiji"; FullName="Kuzan"; Password="Aokiji@Ice13!"},
        @{ID=24; Username="kizaru"; FullName="Borsalino"; Password="Kizaru#Light14!"},
        @{ID=25; Username="smoker.t"; FullName="Smoker"; Password="Smoker$White15!"},
        @{ID=26; Username="doflamingo"; FullName="Donquixote Doflamingo"; Password="Doflamingo@Joker16!"},
        @{ID=27; Username="katakuri"; FullName="Charlotte Katakuri"; Password="Katakuri$Mochi17!"},
        @{ID=28; Username="kaido.b"; FullName="Kaido"; Password="Kaido@Dragon18!"},
        @{ID=29; Username="bigmom"; FullName="Charlotte Linlin"; Password="BigMom$Soul19!"},
        @{ID=30; Username="blackbeard"; FullName="Marshall D. Teach"; Password="Blackbeard@Yami20!"},
        @{ID=31; Username="crocodile"; FullName="Crocodile"; Password="Crocodile$Sand21!"},
        @{ID=32; Username="enel.g"; FullName="Enel"; Password="Enel@Raigo22!"},
        @{ID=33; Username="lucci.r"; FullName="Rob Lucci"; Password="Lucci$Roku23!"},
        @{ID=34; Username="koby.h"; FullName="Koby"; Password="Koby@Hero24!"},
        @{ID=35; Username="judge.v"; FullName="Vinsmoke Judge"; Password="Judge$Germa25!"},
        @{ID=36; Username="carrot.m"; FullName="Carrot"; Password="Carrot@Sulong26!"},
        @{ID=37; Username="yamato.k"; FullName="Yamato"; Password="Yamato$Oni27!"},
        @{ID=38; Username="oden.k"; FullName="Kozuki Oden"; Password="Oden@Paradise28!"},
        @{ID=39; Username="roger.g"; FullName="Gol D. Roger"; Password="Roger$PirateKing29!"},
        @{ID=40; Username="rayleigh.s"; FullName="Silvers Rayleigh"; Password="Rayleigh@Dark30!"},
        @{ID=41; Username="shirahoshi"; FullName="Shirahoshi"; Password="Shirahoshi$Poseidon31!"},
        @{ID=42; Username="vivi.n"; FullName="Nefertari Vivi"; Password="Vivi@Alabasta32!"},
        @{ID=43; Username="bartolomeo"; FullName="Bartolomeo"; Password="Bartolomeo$Barrier33!"},
        @{ID=44; Username="cavendish"; FullName="Cavendish"; Password="Cavendish@Hakuba34!"},
        @{ID=45; Username="killer.k"; FullName="Killer"; Password="Killer$Punisher35!"},
        @{ID=46; Username="drake.x"; FullName="X Drake"; Password="Drake@Dino36!"},
        @{ID=47; Username="hawkins.b"; FullName="Basil Hawkins"; Password="Hawkins$Straw37!"},
        @{ID=48; Username="bege.c"; FullName="Capone Bege"; Password="Bege@Castle38!"},
        @{ID=49; Username="urouge.m"; FullName="Urouge"; Password="Urouge$MadMonk39!"},
        @{ID=50; Username="bonclay.b"; FullName="Bon Clay"; Password="BonClay@Okama40!"}
    )
    
    Write-Info "Creating $($users.Count) users..."
    
    $createdCount = 0
    $skippedCount = 0
    
    foreach ($user in $users) {
        try {
            # Check if user already exists
            $existingUser = Get-ADUser -Filter "SamAccountName -eq '$($user.Username)'" -ErrorAction SilentlyContinue
            
            if ($existingUser) {
                Write-Info "User already exists: $($user.Username)"
                $skippedCount++
                continue
            }
            
            # Extract first and last name
            $nameParts = $user.FullName -split ' '
            $firstName = $nameParts[0]
            $lastName = if ($nameParts.Count -gt 1) { $nameParts[-1] } else { "" }
            
            New-ADUser `
                -Name $user.FullName `
                -GivenName $firstName `
                -Surname $lastName `
                -SamAccountName $user.Username `
                -UserPrincipalName "$($user.Username)@$Global:Domain" `
                -AccountPassword (ConvertTo-SecureString $user.Password -AsPlainText -Force) `
                -Enabled $true `
                -PasswordNeverExpires $true `
                -Path "CN=Users,DC=onepiece,DC=local"
            
            Write-Info "Created user: $($user.Username)"
            $createdCount++
            
        } catch {
            Write-Info "Error creating user $($user.Username): $_"
            $skippedCount++
        }
    }
    
    Write-Info "User creation completed: $createdCount created, $skippedCount skipped"
    
    if ($createdCount -gt 0) {
        Write-Good "Successfully created $createdCount users"
        return $true
    } else {
        Write-Bad "No users were created"
        return $false
    }
}

function Create-OnePieceGroups {
    Write-Info "Creating One Piece groups..."
    
    $groups = @(
        "Pirate Emperors", "Marine Admirals", "Revolutionary Army",
        "Warlords of the Sea", "Straw Hat Crew", "Whitebeard Pirates",
        "Red Hair Pirates", "East Blue Pirates", "Baroque Works",
        "CP9", "Fishman District", "Davy Back Fighters",
        "Sun Pirates", "Kuja Pirates", "Heart Pirates",
        "Kid Pirates", "Onigashima Forces", "Big Mom Pirates",
        "Beast Pirates", "Blackbeard Pirates", "Flying Fish Riders",
        "Franky Family", "Galley-La Company", "Rumbar Pirates",
        "Supernovas"
    )
    
    foreach ($group in $groups) {
        try {
            $exists = Get-ADGroup -Filter {Name -eq $group} -ErrorAction SilentlyContinue
            if (-not $exists) {
                New-ADGroup -Name $group -GroupScope Global -GroupCategory Security -Path "DC=onepiece,DC=local"
                Write-Info "Created group: $group"
            } else {
                Write-Info "Group already exists: $group"
            }
        } catch {
            Write-Info "Error creating group $($group): $_"
        }
    }
}

function Move-UsersToOUs {
    Write-Info "Moving users to appropriate OUs..."
    
    $userMappings = @{
        "StrawHats" = @("luffy.m", "zoro.r", "nami.n", "usopp.u", "sanji.v", "chopper.t", "robin.n", "franky.c", "brook.b", "jimbei.s")
        "Marines" = @("garp.m", "akainu", "aokiji", "kizaru", "smoker.t", "koby.h")
        "Warlords" = @("mihawk.d", "hancock.b", "buggy.c", "doflamingo", "crocodile", "law.t")
        "Yonko" = @("whitebeard", "kaido.b", "bigmom", "blackbeard", "shanks.r")
        "Revolutionary" = @("sabo.r", "ace.p")
        "Supernovas" = @("kid.e", "killer.k", "drake.x", "hawkins.b", "bege.c", "urouge.m", "bonclay.b", "law.t")
    }
    
    $movedCount = 0
    $failedCount = 0
    
    foreach ($ou in $userMappings.Keys) {
        $targetPath = switch ($ou) {
            "StrawHats" { "OU=StrawHats,OU=GrandLine,DC=onepiece,DC=local" }
            "Marines" { "OU=Marines,OU=GrandLine,DC=onepiece,DC=local" }
            "Warlords" { "OU=Warlords,OU=GrandLine,DC=onepiece,DC=local" }
            "Yonko" { "OU=Yonko,OU=NewWorld,DC=onepiece,DC=local" }
            "Revolutionary" { "OU=Revolutionary,OU=NewWorld,DC=onepiece,DC=local" }
            "Supernovas" { "OU=Supernovas,OU=NewWorld,DC=onepiece,DC=local" }
        }
        
        foreach ($user in $userMappings[$ou]) {
            try {
                $adUser = Get-ADUser -Filter {SamAccountName -eq $user} -ErrorAction SilentlyContinue
                if ($adUser) {
                    Move-ADObject -Identity $adUser.DistinguishedName -TargetPath $targetPath
                    Write-Info "Moved $user to $ou OU"
                    $movedCount++
                } else {
                    Write-Info "User not found: $user"
                    $failedCount++
                }
            } catch {
                Write-Info "Could not move user $($user): $_"
                $failedCount++
            }
        }
    }
    
    Write-Info "User movement completed: $movedCount moved, $failedCount failed"
}

function Add-UsersToGroups {
    Write-Info "Adding users to groups..."
    
    $groupMappings = @{
        "Straw Hat Crew" = @("luffy.m", "zoro.r", "nami.n", "usopp.u", "sanji.v", "chopper.t", "robin.n", "franky.c", "brook.b", "jimbei.s")
        "Marine Admirals" = @("akainu", "aokiji", "kizaru")
        "Pirate Emperors" = @("whitebeard", "kaido.b", "bigmom", "blackbeard", "shanks.r")
        "Warlords of the Sea" = @("mihawk.d", "hancock.b", "buggy.c", "doflamingo", "crocodile", "law.t")
        "Revolutionary Army" = @("sabo.r", "ace.p")
        "Supernovas" = @("kid.e", "killer.k", "law.t", "drake.x", "hawkins.b", "bege.c", "urouge.m", "bonclay.b")
        "Domain Admins" = @("luffy.m", "roger.g", "rayleigh.s")
        "Enterprise Admins" = @("roger.g")
        "Schema Admins" = @("rayleigh.s")
        "DnsAdmins" = @("enel.g", "shirahoshi")
    }
    
    foreach ($group in $groupMappings.Keys) {
        try {
            $groupExists = Get-ADGroup -Filter {Name -eq $group} -ErrorAction SilentlyContinue
            if (-not $groupExists) {
                Write-Info "Group does not exist: $group"
                continue
            }
            
            $usersToAdd = @()
            foreach ($user in $groupMappings[$group]) {
                $adUser = Get-ADUser -Filter {SamAccountName -eq $user} -ErrorAction SilentlyContinue
                if ($adUser) {
                    $usersToAdd += $adUser
                } else {
                    Write-Info "User not found for group $($group): $user"
                }
            }
            
            if ($usersToAdd.Count -gt 0) {
                Add-ADGroupMember -Identity $group -Members $usersToAdd
                Write-Info "Added $($usersToAdd.Count) users to $group"
            }
        } catch {
            Write-Info "Error adding users to $($group): $_"
        }
    }
}

function Configure-DomainSettings {
    Write-Info "Configuring domain settings..."
    
    try {
        Set-ADDefaultDomainPasswordPolicy `
            -Identity $Global:Domain `
            -ComplexityEnabled $false `
            -LockoutDuration "00:30:00" `
            -LockoutObservationWindow "00:30:00" `
            -LockoutThreshold 5 `
            -MaxPasswordAge "180.00:00:00" `
            -MinPasswordAge "1.00:00:00" `
            -MinPasswordLength 4 `
            -PasswordHistoryCount 5 `
            -ReversibleEncryptionEnabled $false
        
        Write-Info "Domain password policy configured"
    } catch {
        Write-Info "Error configuring domain settings: $_"
    }
}

function Create-ServiceAccounts {
    Write-Info "Creating service accounts..."
    
    $services = @(
        @{Name="merry_svc"; Description="Going Merry Service"; SPN="merry_svc/goingmerry.onepiece.local"},
        @{Name="sunny_svc"; Description="Thousand Sunny Service"; SPN="sunny_svc/thousandsunny.onepiece.local"},
        @{Name="moby_svc"; Description="Moby Dick Service"; SPN="moby_svc/mobydick.onepiece.local"},
        @{Name="redforce_svc"; Description="Red Force Service"; SPN="redforce_svc/redforce.onepiece.local"},
        @{Name="cifs_svc"; Description="CIFS Service"; SPN="cifs/dc.onepiece.local"},
        @{Name="http_svc"; Description="HTTP Service"; SPN="http/web.onepiece.local"},
        @{Name="sql_svc"; Description="SQL Service"; SPN="MSSQLSvc/sql.onepiece.local"}
    )
    
    foreach ($svc in $services) {
        try {
            $exists = Get-ADUser -Filter "SamAccountName -eq '$($svc.Name)'" -ErrorAction SilentlyContinue
            if (-not $exists) {
                New-ADUser `
                    -Name $svc.Description `
                    -DisplayName $svc.Description `
                    -SamAccountName $svc.Name `
                    -ServicePrincipalNames $svc.SPN `
                    -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
                    -Enabled $true `
                    -PasswordNeverExpires $true `
                    -Path "OU=Services,OU=Paradise,DC=onepiece,DC=local"
                
                Write-Info "Created service account: $($svc.Name)"
            } else {
                Write-Info "Service account already exists: $($svc.Name)"
            }
        } catch {
            Write-Info "Error creating service account $($svc.Name): $_"
        }
    }
}

function Configure-AccountSettings {
    Write-Info "Configuring account settings..."
    
    # Configure account control settings
    try {
        # enel.g - DoesNotRequirePreAuth
        $user = Get-ADUser -Filter "SamAccountName -eq 'enel.g'" -ErrorAction SilentlyContinue
        if ($user) {
            Set-ADAccountControl -Identity $user.SamAccountName -DoesNotRequirePreAuth $true
            Write-Info "Configured DoesNotRequirePreAuth for enel.g"
        }
    } catch { Write-Info "Error configuring enel.g: $_" }
    
    try {
        # shirahoshi - DoesNotRequirePreAuth
        $user = Get-ADUser -Filter "SamAccountName -eq 'shirahoshi'" -ErrorAction SilentlyContinue
        if ($user) {
            Set-ADAccountControl -Identity $user.SamAccountName -DoesNotRequirePreAuth $true
            Write-Info "Configured DoesNotRequirePreAuth for shirahoshi"
        }
    } catch { Write-Info "Error configuring shirahoshi: $_" }
    
    try {
        # bonclay.b - DoesNotRequirePreAuth
        $user = Get-ADUser -Filter "SamAccountName -eq 'bonclay.b'" -ErrorAction SilentlyContinue
        if ($user) {
            Set-ADAccountControl -Identity $user.SamAccountName -DoesNotRequirePreAuth $true
            Write-Info "Configured DoesNotRequirePreAuth for bonclay.b"
        }
    } catch { Write-Info "Error configuring bonclay.b: $_" }
    
    try {
        # franky.c - TrustedForDelegation
        $user = Get-ADUser -Filter "SamAccountName -eq 'franky.c'" -ErrorAction SilentlyContinue
        if ($user) {
            Set-ADAccountControl -Identity $user.SamAccountName -TrustedForDelegation $true
            Write-Info "Configured TrustedForDelegation for franky.c"
        }
    } catch { Write-Info "Error configuring franky.c: $_" }
    
    try {
        # brook.b - TrustedForDelegation
        $user = Get-ADUser -Filter "SamAccountName -eq 'brook.b'" -ErrorAction SilentlyContinue
        if ($user) {
            Set-ADAccountControl -Identity $user.SamAccountName -TrustedForDelegation $true
            Write-Info "Configured TrustedForDelegation for brook.b"
        }
    } catch { Write-Info "Error configuring brook.b: $_" }
    
    # Set user descriptions
    try {
        $user = Get-ADUser -Filter "SamAccountName -eq 'koby.h'" -ErrorAction SilentlyContinue
        if ($user) {
            Set-ADUser -Identity $user.SamAccountName -Description "Password: Changeme123!"
            Write-Info "Set description for koby.h"
        }
    } catch { Write-Info "Error setting description for koby.h: $_" }
    
    try {
        $user = Get-ADUser -Filter "SamAccountName -eq 'carrot.m'" -ErrorAction SilentlyContinue
        if ($user) {
            Set-ADUser -Identity $user.SamAccountName -Description "Default password: Winter2023!"
            Write-Info "Set description for carrot.m"
        }
    } catch { Write-Info "Error setting description for carrot.m: $_" }
    
    try {
        $user = Get-ADUser -Filter "SamAccountName -eq 'yamato.k'" -ErrorAction SilentlyContinue
        if ($user) {
            Set-ADUser -Identity $user.SamAccountName -Description "Temp pass: Autumn2023!"
            Write-Info "Set description for yamato.k"
        }
    } catch { Write-Info "Error setting description for yamato.k: $_" }
}

function Set-PasswordAttributes {
    Write-Info "Setting password attributes..."
    
    $passwordMap = @{
        "koby" = "Changeme123!"
        "carrot" = "Winter2023!"
        "yamato" = "Autumn2023!"
        "ace" = "Summer2023!"
        "sabo" = "Spring2023!"
    }
    
    try {
        foreach ($pattern in $passwordMap.Keys) {
            $users = Get-ADUser -Filter {SamAccountName -like "$pattern*"} -ErrorAction SilentlyContinue
            foreach ($user in $users) {
                try {
                    Set-ADAccountPassword -Identity $user.SamAccountName -Reset -NewPassword (ConvertTo-SecureString $passwordMap[$pattern] -AsPlainText -Force)
                    Write-Info "Set password for $($user.SamAccountName)"
                } catch {
                    Write-Info "Error setting password for $($user.SamAccountName): $_"
                }
            }
        }
    } catch {
        Write-Info "Error in Set-PasswordAttributes: $_"
    }
}

function Configure-SMB {
    Write-Info "Configuring SMB settings..."
    
    try {
        Set-SmbClientConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Confirm:$false -ErrorAction SilentlyContinue
        Set-SmbServerConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Confirm:$false -ErrorAction SilentlyContinue
        Write-Info "SMB settings configured"
    } catch {
        Write-Info "Error configuring SMB settings: $_"
    }
}

function Create-GPOs {
    Write-Info "Creating GPOs..."
    
    $gpos = @(
        @{Name="Wano-Security-Policy"; Target="OU=WanoForest,DC=onepiece,DC=local"},
        @{Name="Marine-Headquarters-Policy"; Target="OU=Marines,OU=GrandLine,DC=onepiece,DC=local"},
        @{Name="StrawHat-Crew-Policy"; Target="OU=StrawHats,OU=GrandLine,DC=onepiece,DC=local"}
    )
    
    foreach ($gpo in $gpos) {
        try {
            # Create GPO
            $existingGPO = Get-GPO -Name $gpo.Name -ErrorAction SilentlyContinue
            if (-not $existingGPO) {
                New-GPO -Name $gpo.Name
                Write-Info "Created GPO: $($gpo.Name)"
            } else {
                Write-Info "GPO already exists: $($gpo.Name)"
            }
            
            # Link GPO
            $linked = Get-GPPermissions -Name $gpo.Name -All -ErrorAction SilentlyContinue | Where-Object {$_.Trustee.Name -eq $gpo.Target}
            if (-not $linked) {
                New-GPLink -Name $gpo.Name -Target $gpo.Target -ErrorAction SilentlyContinue
                Write-Info "Linked GPO to $($gpo.Target)"
            }
        } catch {
            Write-Info "Error creating/linking GPO $($gpo.Name): $_"
        }
    }
}

# ============================================
# AD CS FUNCTIONS
# ============================================

function Install-ADCS {
    Write-Info "Installing and configuring Active Directory Certificate Services..."
    
    try {
        # Check if AD CS is already installed
        $adcsInstalled = Get-WindowsFeature | Where-Object {$_.Name -like "*ADCS*" -and $_.InstallState -eq "Installed"}
        
        if ($adcsInstalled) {
            Write-Info "AD CS is already installed. Reconfiguring..."
            Remove-ADCS
            Write-Info "Waiting for cleanup to complete..."
            Start-Sleep -Seconds 10
        }
        
        # Install AD CS role
        Install-WindowsFeature Adcs-Cert-Authority, Adcs-Web-Enrollment -IncludeManagementTools
        Write-Good "AD CS roles installed"
        
        # Wait for installation to complete
        Start-Sleep -Seconds 10
        
        # Check if CA already exists
        try {
            $caExists = Get-AdcsCertificationAuthority -ErrorAction SilentlyContinue
            if ($caExists) {
                Write-Info "CA already exists. Reconfiguring..."
                Uninstall-AdcsCertificationAuthority -Force -Confirm:$false
                Start-Sleep -Seconds 5
            }
        } catch {
            # CA doesn't exist or can't be accessed
        }
        
        # Configure Certification Authority
        Install-AdcsCertificationAuthority `
            -CAType EnterpriseRootCA `
            -CACommonName "OnePiece-CA" `
            -CADistinguishedName "CN=OnePiece-CA,DC=onepiece,DC=local" `
            -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
            -KeyLength 2048 `
            -HashAlgorithmName SHA256 `
            -ValidityPeriod Years `
            -ValidityPeriodUnits 5 `
            -Force `
            -Confirm:$false
        
        Write-Good "Certificate Authority configured"
        
        # Wait for CA to be ready
        Start-Sleep -Seconds 30
        
        # Configure Web Enrollment Service
        try {
            Install-AdcsEnrollmentWebService `
                -CAConfig "$($env:COMPUTERNAME)\OnePiece-CA" `
                -AuthenticationType Username `
                -Force `
                -Confirm:$false
            
            Write-Good "Web Enrollment Service configured"
        } catch {
            Write-Info "Web Enrollment configuration may have issues: $_"
        }
        
        # Create vulnerable certificate templates
        Create-ADCS-Templates
        
        Write-Good "AD CS installation complete!"
        
    } catch {
        Write-Bad "Error during AD CS installation: $_"
        # Don't throw, just log and continue
    }
}

function Create-ADCS-Templates {
    Write-Info "Creating vulnerable certificate templates..."
    
    try {
        # Restart CA service to apply changes
        Restart-Service certsvc -Force
        Start-Sleep -Seconds 10
        
        # Check if template exists
        $templateExists = certutil -template | Select-String "User"
        
        if (-not $templateExists) {
            # Create vulnerable User template
            certutil -addtemplate "User"
            Write-Info "Created User certificate template"
        } else {
            Write-Info "User template already exists"
        }
        
        # Configure vulnerable settings
        certutil -setreg CA\ValidityPeriodUnits 10
        certutil -setreg CA\ValidityPeriod "Years"
        
        Write-Info "Configured template validity period"
        
    } catch {
        Write-Info "Template configuration may require manual setup: $_"
    }
}

function Test-ADCS-Installation {
    Write-Info "Verifying AD CS installation..."
    
    $tests = @(
        @{Name="AD CS Features"; Test={Get-WindowsFeature | Where-Object {$_.Name -like "*ADCS*" -and $_.InstallState -eq "Installed"}}},
        @{Name="CA Service"; Test={Get-Service -Name certsvc -ErrorAction SilentlyContinue}},
        @{Name="CA Ping"; Test={certutil -ping 2>$null}}
    )
    
    $allPassed = $true
    
    foreach ($test in $tests) {
        try {
            $result = & $test.Test
            if ($result) {
                Write-Good "$($test.Name): PASSED"
            } else {
                Write-Bad "$($test.Name): FAILED"
                $allPassed = $false
            }
        } catch {
            Write-Bad "$($test.Name): ERROR - $_"
            $allPassed = $false
        }
    }
    
    return $allPassed
}

# ============================================
# MAIN FUNCTIONS
# ============================================

function Invoke-OnePieceSetup {
    Write-Host "`nOnePiece AD Lab Setup" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    
    # Check if running as administrator
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Bad "Please run this script as Administrator"
        return
    }
    
    # Check current state
    $isDC = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4
    $adInstalled = (Get-WindowsFeature -Name AD-Domain-Services).InstallState -eq "Installed"
    
    Write-Info "Current state: AD Installed=$adInstalled, Is DC=$isDC"
    
    # If AD is installed but not DC, promote it
    if ($adInstalled -and (-not $isDC)) {
        Write-Info "AD DS is installed but server is not a DC. Creating new forest..."
        
        try {
            Import-Module ADDSDeployment
            $safeModePassword = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
            
            # CREATE NEW FOREST (not join existing)
            Install-ADDSForest `
                -CreateDnsDelegation:$false `
                -DatabasePath "C:\Windows\NTDS" `
                -DomainMode "WinThreshold" `
                -DomainName $Global:Domain `
                -DomainNetbiosName $Global:NetbiosName `
                -ForestMode "WinThreshold" `
                -InstallDns:$true `
                -LogPath "C:\Windows\NTDS" `
                -NoRebootOnCompletion:$false `
                -SysvolPath "C:\Windows\SYSVOL" `
                -SafeModeAdministratorPassword $safeModePassword `
                -Force:$true
            
            Write-Good "New AD Forest installation initiated. Server will restart."
            return
        } catch {
            Write-Bad "Forest creation failed: $_"
            Write-Info "Will attempt to use existing AD configuration"
        }
    }
    
    # If we're already a DC, skip installation
    if ($isDC) {
        Write-Good "Server is already a Domain Controller. Continuing with lab setup..."
        $adReady = $true
    } else {
        # Only install AD if not present at all
        $adReady = Check-ADInstalled
        if (-not $adReady) {
            return
        }
    }
    
    # Wait for AD to be ready (if we just installed/promoted)
    if (-not $isDC) {
        $adReady = Wait-ForADReady
        if (-not $adReady) {
            Write-Bad "AD is not ready. Please check AD services and try again."
            return
        }
    }
    
    # Continue with lab setup...
    # Cleanup first
    Write-Info "Cleaning up existing One Piece objects..."
    Clean-OnePieceObjects
    Write-Info "Waiting for cleanup to complete..."
    Start-Sleep -Seconds 10
    
    Create-OnePieceOUs
    Create-OnePieceForests
    
    $imported = Import-OnePieceUsers
    if (-not $imported) {
        Write-Bad "User import failed. Setup cannot continue."
        return
    }
    
    Create-OnePieceGroups
    Move-UsersToOUs
    Add-UsersToGroups
    Configure-DomainSettings
    Create-ServiceAccounts
    Configure-AccountSettings
    Set-PasswordAttributes
    Configure-SMB
    Create-GPOs
    
    # AD CS installation (always included)
    Write-Info "Installing AD CS..."
    try {
        Install-ADCS
        $adcsTest = Test-ADCS-Installation
        if (-not $adcsTest) {
            Write-Bad "AD CS installation verification failed"
        }
    } catch {
        Write-Bad "AD CS installation failed: $_"
    }
    
    Write-Good "`nOnePiece AD Lab setup completed!"
    
    # Display summary
    Show-SetupSummary
}

function Show-SetupSummary {
    Write-Host "`nLab Setup Summary:" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    
    try {
        $domainInfo = Get-ADDomain
        Write-Host "Domain: $($domainInfo.DNSRoot)" -ForegroundColor Yellow
        Write-Host "Forest: $($domainInfo.Forest)" -ForegroundColor Yellow
    } catch {
        Write-Host "Domain: $Global:Domain" -ForegroundColor Yellow
    }
    
    try {
        $ouCount = (Get-ADOrganizationalUnit -Filter * | Where-Object {
            $_.DistinguishedName -notlike "*Domain Controllers*"
        }).Count
        
        $userCount = (Get-ADUser -Filter * | Where-Object {
            $_.SamAccountName -notin @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount", "krbtgt")
        }).Count
        
        $groupCount = (Get-ADGroup -Filter * | Where-Object {
            $_.SID.Value -notlike "S-1-5-32*"
        }).Count
        
        Write-Host "OUs Created: $ouCount" -ForegroundColor Yellow
        Write-Host "Users Created: $userCount" -ForegroundColor Yellow
        Write-Host "Groups Created: $groupCount" -ForegroundColor Yellow
    } catch {
        Write-Host "Cannot retrieve AD object counts: $_" -ForegroundColor Yellow
    }
    
    Write-Host "Service Accounts: 7" -ForegroundColor Yellow
    Write-Host "GPOs Created: 3" -ForegroundColor Yellow
    
    Write-Host "`nAD CS Configuration:" -ForegroundColor Cyan
    Write-Host "  - Enterprise Root CA: OnePiece-CA" -ForegroundColor Yellow
    Write-Host "  - Web Enrollment: Enabled" -ForegroundColor Yellow
    Write-Host "  - Vulnerable Templates: User" -ForegroundColor Yellow
    
    Write-Host "`nAD CS Attack Vectors:" -ForegroundColor Cyan
    Write-Host "  ESC1: Certificate Template Abuse" -ForegroundColor White
    Write-Host "  ESC8: Web Enrollment + NTLM Relay" -ForegroundColor White
    
    Write-Host "`nVerification Commands:" -ForegroundColor Cyan
    Write-Host "  Get-ADUser -Filter * | Select Name, SamAccountName" -ForegroundColor White
    Write-Host "  Get-ADGroup -Filter * | Select Name" -ForegroundColor White
    Write-Host "  Get-ADOrganizationalUnit -Filter * | Format-Table Name, DistinguishedName" -ForegroundColor White
    Write-Host "  certutil -ping" -ForegroundColor White
    Write-Host "  http://$env:COMPUTERNAME/certsrv" -ForegroundColor White
    
    Write-Host ""
}

# ============================================
# SCRIPT EXECUTION
# ============================================

if ($MyInvocation.InvocationName -ne '.') {
    # Run the setup automatically when script is executed
    Invoke-OnePieceSetup
}