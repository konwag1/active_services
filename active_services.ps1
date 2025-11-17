$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot }
elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
else { (Get-Location).Path }

$CsvPath = Join-Path $ScriptDir "active_services.csv"
$ChangesCsvPath = Join-Path $ScriptDir "service_changes.csv"

function Get-FileSignature {
    param([string]$FilePath)
    
    if (-not (Test-Path -LiteralPath $FilePath)) {
        return @{
            Status = "FileNotFound"
            Subject = ""
            Issuer = ""
            Thumbprint = ""
            TimeStamp = ""
            IsOSBinary = $false
        }
    }
    
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath
        
        # Jeśli certyfikat istnieje, ale status to UnknownError - traktuj jako Valid
        if ($sig -ne $null -and $sig.SignerCertificate -ne $null) {
            if ($sig.Status -eq "UnknownError") {
                $timeStamp = ""
                if ($sig.TimeStamperCertificate -ne $null) {
                    $timeStamp = $sig.TimeStamperCertificate.Subject
                }
                
                return @{
                    Status = "Valid"
                    Subject = $sig.SignerCertificate.Subject
                    Issuer = $sig.SignerCertificate.Issuer
                    Thumbprint = $sig.SignerCertificate.Thumbprint
                    TimeStamp = $timeStamp
                    IsOSBinary = $false
                    FilePath = $FilePath
                }
            }
            
           
            if ($sig.Status -eq "Valid") {
                $timeStamp = ""
                if ($sig.TimeStamperCertificate -ne $null) {
                    $timeStamp = $sig.TimeStamperCertificate.Subject
                }
                
                return @{
                    Status = $sig.Status.ToString()
                    Subject = $sig.SignerCertificate.Subject
                    Issuer = $sig.SignerCertificate.Issuer
                    Thumbprint = $sig.SignerCertificate.Thumbprint
                    TimeStamp = $timeStamp
                    IsOSBinary = $false
                    FilePath = $FilePath
                }
            }
        }
        
        if ($sig -eq $null) {
            return @{
                Status = "NotSigned"
                Subject = ""
                Issuer = ""
                Thumbprint = ""
                TimeStamp = ""
                IsOSBinary = $false
                FilePath = $FilePath
            }
        }
        
       
        return @{
            Status = $sig.Status.ToString()
            Subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }
            Issuer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Issuer } else { "" }
            Thumbprint = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { "" }
            TimeStamp = if ($sig.TimeStamperCertificate) { $sig.TimeStamperCertificate.Subject } else { "" }
            IsOSBinary = $false
            FilePath = $FilePath
        }
    }
    catch {
        return @{
            Status = "Error"
            Subject = ""
            Issuer = ""
            Thumbprint = ""
            TimeStamp = ""
            IsOSBinary = $false
            FilePath = $FilePath
            Error = $_.Exception.Message
        }
    }
}

function Test-SuspiciousSignature {
    param([hashtable]$Signature)
    
    $suspicious = $false
    $reasons = @()
    
    
    $whitelistedThumbprints = @(
        "9687B1EF175BBA4BDE33A05402134289B28B5BCB",  # Adobe ARM Service
        "A4341B9FD50FB9964283220A36A1EF6F6FAA7840",  # Inny przykładowy certyfikat Adobe
        "B1BC968BD4F9D0F4A7D6E2A7C6F7A8B5C8E9F0A1",  #  Google
        "C2CDE3F4G5H6I7J8K9L0M1N2O3P4Q5R6S7T8U9V0"  #  Intel
    )
   
    $suspiciousStatuses = @("NotSigned", "HashMismatch", "NotTrusted", "Error", "UnknownError", "FileNotFound")
    
    if ($suspiciousStatuses -contains $Signature.Status) {
        $suspicious = $true
        $reasons += "Signature status: $($Signature.Status)"
    }
    
  
    if ($Signature.FilePath -like "*\Downloads\*") {
        $suspicious = $true
        $reasons += "File in Downloads folder"
    }
    
   
    if ($Signature.Status -eq "Valid") {
        # SPRAWDŹ CZY THUMPBRINT JEST NA BIAŁEJ LIŚCIE - JEŚLI TAK, NIE OZNACZAJ JAKO PODEJRZANY
        if ($whitelistedThumbprints -contains $Signature.Thumbprint) {
            return @{
                IsSuspicious = $false
                Reasons = @()
            }
        }
        
       
        $suspiciousPatterns = @("Test Certificate", "Self Signed", "Unknown", "Test", "Suspicious", "localhost", "Development", "Temporary", "Custom", "Personal")
        foreach ($pattern in $suspiciousPatterns) {
            if ($Signature.Subject -like "*$pattern*") {
                $suspicious = $true
                $reasons += "Suspicious certificate subject: $pattern"
                break
            }
        }
        
        
        if ($Signature.Subject -eq $Signature.Issuer) {
            $suspicious = $true
            $reasons += "Self-signed certificate"
        }
        
       
        $trustedPublishers = @(
            "*Microsoft Windows*",
            "*Microsoft Corporation*", 
            "*O=Microsoft Corporation*",
            "*Adobe*",
            "*Google*", 
            "*Apple*",
            "*Intel*",
            "*AMD*",
            "*NVIDIA*",
            "*Oracle*",
            "*IBM*"
        )
        
        $isTrusted = $false
        foreach ($publisher in $trustedPublishers) {
            if ($Signature.Subject -like $publisher -or $Signature.Issuer -like $publisher) {
                $isTrusted = $true
                break
            }
        }
        
        if (-not $isTrusted) {
            $suspicious = $true
            $reasons += "Non-trusted publisher certificate"
        }
    }
    
    return @{
        IsSuspicious = $suspicious
        Reasons = $reasons
    }
}

$SuspiciousSubstrings = @(
    'downloads',
    'windows\fonts',
    'windows\temp',
    'users\public',
    'windows\debug',
    'users\administrator\music',
    'windows\servicing',
    'users\default recycle\bin',
    'users\default\recycle\bin',
    'windows\media',
    'windows\repair',
    'perflogs'
)
$SuspiciousListText = $SuspiciousSubstrings -join ', '
# Zbuforuj w lower-case, żeby szybciej porównywać
$SuspiciousLC = $SuspiciousSubstrings | ForEach-Object { $_.ToLowerInvariant() }

function Get-AllServices {
    $services = Get-CimInstance Win32_Service
    
    $result = foreach ($service in $services) {
        $pathName = $service.PathName
        $signatureInfo = @{
            Status = "NotChecked"
            Subject = ""
            Thumbprint = ""
            IsOSBinary = $false
        }
        $suspiciousCheck = @{
            IsSuspicious = $false
            Reasons = ""
        }
        
       
        if ($pathName -and $pathName -notlike "*.dll*") {
            $exePath = $pathName
            if ($exePath -match '^"([^"]+)"') {
                $exePath = $matches[1]
            } elseif ($exePath -match '^([^\s]+)') {
                $exePath = $matches[1]
            }
            
           
            if (Test-Path -LiteralPath $exePath -PathType Leaf) {
                $signatureInfo = Get-FileSignature -FilePath $exePath
                $signatureInfo.FilePath = $exePath
                $suspiciousCheck = Test-SuspiciousSignature -Signature $signatureInfo
            } else {
                $signatureInfo.Status = "FileNotFound"
                $suspiciousCheck = @{
                    IsSuspicious = $true
                    Reasons = "Executable file not found"
                }
            }
        }
        
        $service | Select-Object Name, DisplayName, State, StartMode, PathName,
            @{Name='IsRunning'; Expression = { if ($_.State -eq 'Running') { 1 } else { 0 } }},
            @{Name='SignatureStatus'; Expression = { $signatureInfo.Status }},
            @{Name='SignatureSubject'; Expression = { $signatureInfo.Subject }},
            @{Name='SignatureThumbprint'; Expression = { $signatureInfo.Thumbprint }},
            @{Name='IsOSBinary'; Expression = { $signatureInfo.IsOSBinary }},
            @{Name='IsSuspicious'; Expression = { $suspiciousCheck.IsSuspicious }},
            @{Name='SuspiciousReasons'; Expression = { $suspiciousCheck.Reasons -join "; " }}
    }
    
    return $result
}

function Normalize([string]$v) {
    if ($null -eq $v) { return "" }
    return $v.Trim()
}



function Convert-ToCanonicalPath([string]$path) {
    if ($null -eq $path) { return "" }
    $p = $path.Trim()

    $p = $p.Trim('"', "'") -replace '/', '\'

   
    $p = [Environment]::ExpandEnvironmentVariables($p)


    $p = $p -replace '^(\\\\\?\\|\\\?\?\\)', ''

    
    $p = $p -replace '^[\\]+(?=[A-Za-z]:)', ''

   
    if ($p -notmatch '^\\\\[^\\]') {
        $p = $p -replace '\\{2,}', '\'
    }

    return $p
}


function Get-SuspicionReason([string]$path, [ref]$canonicalOut) {
    $canon = Convert-ToCanonicalPath $path
    $canonicalOut.Value = $canon
    if (-not $canon) { return $null }

    $pLower = $canon.ToLowerInvariant()
    for ($i = 0; $i -lt $SuspiciousLC.Count; $i++) {
        if ($pLower.Contains($SuspiciousLC[$i])) { return $SuspiciousSubstrings[$i] }
    }
    return $null
}


Write-Host "Updating service baseline and checking for changes..."

try {
 
    $current = Get-AllServices | Sort-Object Name
    
   
    $hasBaseline = Test-Path -LiteralPath $CsvPath
    
    if ($hasBaseline) {
        
        try {
            $baselineRows = Import-Csv -Path $CsvPath
        } catch {
            Write-Error ("Cannot read baseline CSV: {0}" -f $_.Exception.Message)
            exit 1
        }

       
        $bl = @{}
        foreach ($row in $baselineRows) { $bl[$row.Name] = $row }

       
        $Changes = @()

        foreach ($cur in $current) {
            $name = $cur.Name
            if (-not $bl.ContainsKey($name)) {
                # NEW: add with the SAME columns as CSV
                $Changes += [pscustomobject]@{
                    Name               = $cur.Name
                    DisplayName        = $cur.DisplayName
                    State              = $cur.State
                    StartMode          = $cur.StartMode
                    PathName           = $cur.PathName
                    IsRunning          = $cur.IsRunning
                    SignatureStatus    = $cur.SignatureStatus
                    SignatureSubject   = $cur.SignatureSubject
                    SignatureThumbprint = $cur.SignatureThumbprint
                    IsOSBinary         = $cur.IsOSBinary
                    IsSuspicious       = $cur.IsSuspicious
                    SuspiciousReasons  = $cur.SuspiciousReasons
                }
                continue
            }

            $base = $bl[$name]
            $stateChanged        = (Normalize $base.State)            -ne (Normalize $cur.State)
            $pathNameChanged     = (Normalize $base.PathName)         -ne (Normalize $cur.PathName)
            $signatureChanged    = (Normalize $base.SignatureStatus)  -ne (Normalize $cur.SignatureStatus)

            if ($stateChanged -or $pathNameChanged -or $signatureChanged) {
                
                $Changes += [pscustomobject]@{
                    Name               = $cur.Name
                    DisplayName        = $cur.DisplayName
                    State              = $cur.State
                    StartMode          = $cur.StartMode
                    PathName           = $cur.PathName
                    IsRunning          = $cur.IsRunning
                    SignatureStatus    = $cur.SignatureStatus
                    SignatureSubject   = $cur.SignatureSubject
                    SignatureThumbprint = $cur.SignatureThumbprint
                    IsOSBinary         = $cur.IsOSBinary
                    IsSuspicious       = $cur.IsSuspicious
                    SuspiciousReasons  = $cur.SuspiciousReasons
                }
            }
        }

        
        if ($Changes.Count -gt 0) {
            Write-Host "`n*** NEW or CHANGED services (State/PathName/Signature) detected ***`n"
            
           
            $DisplayChanges = $Changes | ForEach-Object {
                [pscustomobject]@{
                    Name = $_.Name
                    DisplayName = if ($_.DisplayName.Length -gt 25) { 
                        $_.DisplayName.Substring(0, 25) + "..." 
                    } else { $_.DisplayName }
                    State = $_.State
                    StartMode = $_.StartMode
                    PathName = if ($_.PathName) { 
                        if ($_.PathName.Length -gt 30) {
                            $_.PathName.Substring(0, 30) + "..."
                        } else { $_.PathName }
                    } else { "" }
                    SignatureStatus = $_.SignatureStatus
                    SignatureThumbprint = if ($_.SignatureThumbprint) { 
                        $_.SignatureThumbprint.Substring(0, [Math]::Min(20, $_.SignatureThumbprint.Length)) + "..." 
                    } else { "" }
                    IsSuspicious = $_.IsSuspicious
                    SuspiciousReasons = if ($_.SuspiciousReasons.Length -gt 25) { 
                        $_.SuspiciousReasons.Substring(0, 25) + "..." 
                    } else { $_.SuspiciousReasons }
                }
            }
            
            $DisplayChanges | Sort-Object Name | Format-Table -AutoSize
        } else {
            Write-Host "No NEW or CHANGED services (State/PathName/Signature) detected."
        }
        
       
        $AllSuspiciousServices = $current | Where-Object { $_.IsSuspicious -eq $true }
        if ($AllSuspiciousServices.Count -gt 0) {
            Write-Host "`n*** SUSPICIOUS SERVICES DETECTED ***`n" -ForegroundColor Red
            $AllSuspiciousServices | Sort-Object Name | ForEach-Object {
                Write-Host "Service: $($_.DisplayName)" -ForegroundColor Yellow
                Write-Host "  Name: $($_.Name)"
                Write-Host "  State: $($_.State)"
                Write-Host "  Start Mode: $($_.StartMode)"
                Write-Host "  Path: $($_.PathName)"
                Write-Host "  Signature Status: $($_.SignatureStatus)"
                Write-Host "  Signature Subject: $($_.SignatureSubject)"
                Write-Host "  Signature Thumbprint: $($_.SignatureThumbprint)" -ForegroundColor Green
                Write-Host "  Is OS Binary: $($_.IsOSBinary)"
                Write-Host "  SUSPICIOUS REASONS: $($_.SuspiciousReasons)" -ForegroundColor Red
                Write-Host ""
            }
            Write-Host ("Total suspicious services: {0}" -f $AllSuspiciousServices.Count) -ForegroundColor Red
        } else {
            Write-Host "`nNo suspicious services detected." -ForegroundColor Green
        }
        
       
        if ($Changes.Count -gt 0) {
            try {
                $Changes | Export-Csv -Path $ChangesCsvPath -NoTypeInformation
                Write-Host ("Changes exported to: {0}" -f $ChangesCsvPath)
            } catch {
                Write-Error ("Error while saving changes: {0}" -f $_.Exception.Message)
            }
        } else {
            # Jeśli nie ma zmian, usuń plik service_changes.csv jeśli istnieje
            if (Test-Path -LiteralPath $ChangesCsvPath) {
                Remove-Item -Path $ChangesCsvPath
                Write-Host "service_changes.csv has been removed (no changes detected)."
            }
        }
        
    } else {
        Write-Host "No existing baseline found. This is the first run."
    }
    
  
    $current | Export-Csv -Path $CsvPath -NoTypeInformation
    Write-Host ("`nBaseline updated: {0} (count: {1})" -f $CsvPath, $current.Count)
    
} catch {
    Write-Error ("Error while collecting or saving data: {0}" -f $_.Exception.Message)
    exit 1
}
# === Force stop suspicious services ===
Write-Host "`nAttempting to stop all suspicious services..." -ForegroundColor Red
foreach ($svc in $AllSuspiciousServices) {
    try {
        Write-Host "Stopping service: $($svc.Name) ($($svc.DisplayName))..." -ForegroundColor Yellow
        Stop-Service -Name $svc.Name -Force -ErrorAction Stop
        Write-Host "Service $($svc.Name) stopped successfully." -ForegroundColor Green
    } catch {
        Write-Warning ("Failed to stop service {0}: {1}" -f $svc.Name, $_.Exception.Message)
    }
}
