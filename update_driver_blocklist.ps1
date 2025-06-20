<# Copyright 2025 UpSight Security Inc. All rights reserved
.SYNOPSIS
    Updates the Known Vulnerable Driver Block List policy.

.DESCRIPTION
    Updates T1211.100.KnownVulnerableDrivers.json from Microsoft Vulnerable Driver Block List & LOLDrivers verified.

.NOTES
    i hate powershell
#>

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue" # less slow

$MsDownloadUrl = "https://aka.ms/VulnerableDriverBlockList"

$TempDir = $env:TEMP
if (-not $TempDir) {
    $TempDir = "/tmp"
}

$ZipFilePath = Join-Path $TempDir "VulnerableDriverBlockList.zip"
$ExtractPath = Join-Path $TempDir "VulnerableDriverBlockList"
$JsonFilePath = "../../Outputs/T1211.100.KnownVulnerableDrivers.json"
$XmlFileName = "SiPolicy_Enforced.xml"
$LastRunFilePath = Join-Path $TempDir "upvulndriverlist.lastcheck"
$LogFilePath = Join-Path $TempDir "upvulndriverlist.log"
$ZipHashPattern = "ZipSha256Sum:\s*[A-Fa-f0-9]{64}"

enum LogLevel {
    INFO
    WARNING
    ERROR
    SUCCESS
    DEBUG
}
function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [LogLevel]$Level = [LogLevel]::INFO
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    $color = switch ($Level) {
        ([LogLevel]::INFO)    { [System.ConsoleColor]::Cyan }
        ([LogLevel]::WARNING) { [System.ConsoleColor]::Yellow }
        ([LogLevel]::ERROR)   { [System.ConsoleColor]::Red }
        ([LogLevel]::SUCCESS) { [System.ConsoleColor]::Green }
        ([LogLevel]::DEBUG)   { [System.ConsoleColor]::Gray }
        default               { [System.ConsoleColor]::White }
    }
    
    Write-Host $logMessage -ForegroundColor $color
    
    try {
        Add-Content -Path $LogFilePath -Value $logMessage -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "[$timestamp] [WARNING] Failed to write to log file: $_" -ForegroundColor Yellow
    }
}

function Write-Stage {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    Write-Log -Message $Message -Level ([LogLevel]::INFO)
}

function Write-LastRunTimestamp {
    try {
        $currentUtcTime = [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss")
        Set-Content -Path $LastRunFilePath -Value $currentUtcTime -Force
        Write-Stage "Updated last run timestamp at $LastRunFilePath"
    }
    catch {
        Write-Log "Failed to write last run timestamp: $_" -Level ([LogLevel]::WARNING)
    }
}

function Get-FileHash256 {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256
        return $hash.Hash.ToLower()
    }
    catch {
        throw "Failed to calculate hash for file '$FilePath': $_"
    }
}

function Find-JsonFilePath {
    param (
        [string]$DefaultPath,
        [int]$MaxSearchDepth = 5
    )
    
    if (Test-Path $DefaultPath) {
        Write-Stage "Found JSON file at default path: $((Resolve-Path $DefaultPath).Path)"
        return (Resolve-Path $DefaultPath).Path
    }
    
    Write-Stage "Default JSON path not found, searching alternatives..."
    
    $jsonFileName = Split-Path $DefaultPath -Leaf
    
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
    Write-Stage "Starting search from: $scriptDir"
    
    $relativePath = Join-Path $scriptDir $DefaultPath
    if (Test-Path $relativePath) {
        Write-Stage "Found JSON file relative to script: $((Resolve-Path $relativePath).Path)"
        return (Resolve-Path $relativePath).Path
    }
    
    $expectedPattern = ($DefaultPath -replace $jsonFileName, "").TrimEnd('/').TrimEnd('\')
    Write-Stage "Looking for pattern: $expectedPattern"
    
    $currentPath = $scriptDir
    $repoRootIndicator = '.git'
    $potentialProjectRoot = $null
    
    for ($i = 0; $i -lt $MaxSearchDepth; $i++) {
        if (Test-Path (Join-Path $currentPath $repoRootIndicator)) {
            $potentialProjectRoot = $currentPath
            Write-Stage "Found potential project root at: $potentialProjectRoot"
            break
        }
        
        if ($potentialProjectRoot) { break }
        
        $parentPath = Split-Path $currentPath -Parent
        if (!$parentPath -or $parentPath -eq $currentPath) { break }
        $currentPath = $parentPath
    }
    
    if ($potentialProjectRoot) {
        $matchingDirs = Get-ChildItem -Path $potentialProjectRoot -Recurse -Directory -ErrorAction SilentlyContinue | 
                       Where-Object { $_.FullName -like "*$expectedPattern" } | 
                       Select-Object -First 1
                       
        if ($matchingDirs) {
            $matchingPath = Join-Path $matchingDirs.FullName $jsonFileName
            if (Test-Path $matchingPath) {
                Write-Stage "Found JSON file at: $((Resolve-Path $matchingPath).Path)"
                return (Resolve-Path $matchingPath).Path
            }
        }
        
        Write-Stage "Searching for $jsonFileName in project..."
        $fileResults = Get-ChildItem -Path $potentialProjectRoot -Recurse -File -Filter $jsonFileName -ErrorAction SilentlyContinue | 
                      Select-Object -First 1
                      
        if ($fileResults) {
            Write-Stage "Found JSON file at: $($fileResults.FullName)"
            return $fileResults.FullName
        }
    }
    
    Write-Stage "Performing wider search for the JSON file..."
    $wideSearchResult = Get-ChildItem -Path $scriptDir -Recurse -Depth $MaxSearchDepth -File -Filter $jsonFileName -ErrorAction SilentlyContinue | 
                       Select-Object -First 1
    
    if ($wideSearchResult) {
        Write-Stage "Found JSON file at: $($wideSearchResult.FullName)"
        return $wideSearchResult.FullName
    }
    
    throw "Could not find $jsonFileName. Please ensure the file exists or place it at the expected path: $DefaultPath"
}

function Test-SHA256Format {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Hash
    )
    
    return $Hash -match "^[A-Fa-f0-9]{64}$"
}

function Invoke-RetryWebRequest {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        
        [Parameter(Mandatory = $false)]
        [string]$OutFile = $null,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec = 60
    )
    
    $retryCount = 0
    $success = $false
    $result = $null
    
    while (-not $success -and $retryCount -lt $MaxRetries) {
        try {
            if ($OutFile) {
                Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -TimeoutSec $TimeoutSec
                $result = $OutFile
            } else {
                $result = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec $TimeoutSec
            }
            $success = $true
        }
        catch {
            $retryCount++
            if ($retryCount -ge $MaxRetries) {
                throw
            }
            Write-Log "Retry ${retryCount}/${MaxRetries}: Failed to download from $Uri : $_" -Level ([LogLevel]::WARNING)
            Start-Sleep -Seconds (2 * $retryCount)
        }
    }
    
    return $result
}

function Get-SHA256HashesFromXml {
    param (
        [Parameter(Mandatory = $true)]
        [string]$XmlPath
    )
    
    try {
        [xml]$xmlContent = Get-Content -Path $XmlPath -ErrorAction Stop
        $hashList = @()
        
        $fileRules = $xmlContent.SiPolicy.FileRules.Deny
        foreach ($rule in $fileRules) {
            if ($rule.Hash -and $rule.FriendlyName -and ($rule.FriendlyName -match ' Hash Sha256$')) {
                $hash = $rule.Hash.ToUpper()
                if (Test-SHA256Format -Hash $hash) {
                    $friendlyName = ($rule.FriendlyName -replace ' Hash Sha256$', '') + " (ms)"
                    
                    $hashList += [PSCustomObject]@{
                        Hash = $rule.Hash.ToUpper()
                        FriendlyName = $friendlyName
                        EscapedFriendlyName = $friendlyName -replace '\\', '\\\\'
                    }
                } else {
                    Write-Log "Skipping invalid SHA256 hash: $hash" -Level ([LogLevel]::WARNING)
                }
            }
        }
        
        return $hashList
    }
    catch {
        throw "Failed to extract SHA256 hashes from XML: $_"
    }
}

function Get-SHA256HashesFromMicrosoftList {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DownloadUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$ZipFilePath,
        
        [Parameter(Mandatory = $true)]
        [string]$ExtractPath,
        
        [Parameter(Mandatory = $true)]
        [string]$XmlFileName
    )
    
    try {
        Write-Stage "Downloading Microsoft Vulnerable Driver Block List..."
        Invoke-RetryWebRequest -Uri $DownloadUrl -OutFile $ZipFilePath
        
        if (-not (Test-Path $ZipFilePath)) {
            throw "Downloaded zip file not found at expected path: $ZipFilePath"
        }
        
        Write-Stage "Calculating SHA256 for downloaded zip"
        $zipHash = Get-FileHash256 -FilePath $ZipFilePath
        
        Write-Stage "Extracting files from zip..."
        if (Test-Path $ExtractPath) {
            try {
                Remove-Item -Path $ExtractPath -Recurse -Force
            }
            catch {
                throw "Failed to clean up existing extract directory: $_"
            }
        }
        
        New-Item -Path $ExtractPath -ItemType Directory -Force | Out-Null
        
        $xmlPath = Find-XmlFileInZip -ZipPath $ZipFilePath -ExtractPath $ExtractPath -XmlFileName $XmlFileName
        
        if (-not $xmlPath -or -not (Test-Path $xmlPath)) {
            throw "Required XML file not found in the zip archive: $XmlFileName"
        }
        
        Write-Stage "Found XML file: $([System.IO.Path]::GetFileName($xmlPath))"
        
        try {
            [xml]$xmlContent = Get-Content -Path $xmlPath -ErrorAction Stop
            Write-Stage "XML file is well-formed, continuing with extraction"
        }
        catch {
            throw "Failed to parse XML file: $_"
        }
        
        Write-Stage "Extracting SHA256 hashes from XML..."
        $hashList = Get-SHA256HashesFromXml -XmlPath $xmlPath
        
        if ($hashList.Count -eq 0) {
            Write-Log "No SHA256 hashes found in the XML file" -Level ([LogLevel]::WARNING)
        } else {
            Write-Stage "Found $($hashList.Count) SHA256 hashes in the XML file"
        }
        
        return @{
            Hashes = $hashList
            ZipHash = $zipHash
        }
    }
    catch {
        throw "Failed to process Microsoft driver list: $_"
    }
}

function Get-SHA256HashesFromLolDrivers {
    param (
        [Parameter(Mandatory = $false)]
        [string]$LolDriversUrl = "https://www.loldrivers.io/api/drivers.json",
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3
    )

    try {
        Write-Stage "Downloading LOLDrivers data..."
        $response = Invoke-RetryWebRequest -Uri $LolDriversUrl -MaxRetries $MaxRetries
        $jsonContent = $response.Content

        #Add-Type -AssemblyName System.Web.Extensions
        #$jsonSerializer = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
        #$jsonSerializer.MaxJsonLength = [int]::MaxValue
        #$lolDriversData = $jsonSerializer.DeserializeObject($  jsonContent)
        $lolDriversData = $jsonContent | ConvertFrom-Json -AsHashtable
        Write-Stage "Processing LOLDrivers data..."
        $hashList = @()
        
        foreach ($driver in $lolDriversData) {
            if ($driver.Verified -ne "TRUE") { # unverified sounds risky
                continue
            }
            $category = $driver.Category
            
            foreach ($sample in $driver.KnownVulnerableSamples) {
                $sha256 = $sample.SHA256
                
                if ($sha256 -and (Test-SHA256Format -Hash $sha256)) {
                    $fileInfo = $sample.Filename
                    if ([string]::IsNullOrEmpty($fileInfo)) {
                        if (-not [string]::IsNullOrEmpty($sample.OriginalFilename)) {
                            $fileInfo = $sample.OriginalFilename
                        } elseif (-not [string]::IsNullOrEmpty($sample.InternalName)) {
                            $fileInfo = $sample.InternalName
                        }
                        
                        if ([string]::IsNullOrEmpty($fileInfo) -and $driver.Tags -and $driver.Tags.Count -gt 0) {
                            $fileInfo = $driver.Tags[0]
                        }
                    }

                    $fileInfo = ([System.Text.Encoding]::ASCII.GetString([System.Text.Encoding]::ASCII.GetBytes($fileInfo))).Trim() -replace '\s+', ' '

                    $productInfo = ""
                    if (-not [string]::IsNullOrEmpty($sample.Product)) {
                        $sanitizedProduct = ([System.Text.Encoding]::ASCII.GetString([System.Text.Encoding]::ASCII.GetBytes($sample.Product))).Trim() -replace '\s+', ' '
                        if (-not [string]::IsNullOrEmpty($sanitizedProduct)) {
                            $productInfo = " $sanitizedProduct"
                        }
                    }

                    $friendlyName = "$category - $fileInfo$productInfo (loldrv)"
                    
                    $hashList += [PSCustomObject]@{
                        Hash = $sha256.ToUpper()
                        FriendlyName = $friendlyName
                        EscapedFriendlyName = $friendlyName -replace '\\', '\\\\'
                    }
                } elseif ($sha256) {
                    Write-Log "Skipping invalid SHA256 hash: $sha256" -Level ([LogLevel]::WARNING)
                }
            }
        }
        
        Write-Stage "Found $($hashList.Count) SHA256 hashes from LOLDrivers"
        return $hashList
    }
    catch {
        Write-Log "Failed to retrieve or process LOLDrivers data: $_" -Level ([LogLevel]::WARNING)
        return @()
    }
}

function Get-ExistingHashes {
    param (
        [Parameter(Mandatory = $true)]
        [PSObject]$JsonObject
    )
    
    $existingHashes = @{}
    
    foreach ($rule in $JsonObject.Policies[0].Rules) {
        foreach ($target in $rule.Target) {
            if ($target.Attribute -eq "FileSha256" -and $target.Equals) {
                foreach ($hash in $target.Equals) {
                    if (-not [string]::IsNullOrWhiteSpace($hash)) {
                        $existingHashes[$hash.ToUpper()] = $true
                    }
                }
            }
        }
    }
    
    return $existingHashes
}

function Format-JsonOutput {
    param (
        [Parameter(Mandatory = $true)]
        [string]$JsonString
    )
    
    $sbUnicode = New-Object System.Text.StringBuilder
    $i = 0
    
    while ($i -lt $JsonString.Length) { # eval unicode escape sequences
        if (($i -le ($JsonString.Length - 6)) -and 
            ($JsonString[$i] -eq '\') -and 
            ($JsonString[$i+1] -eq 'u') -and
            ($i -eq 0 -or $JsonString[$i-1] -ne '\')) { # make sure it's unescaped
            
            $hexCode = $JsonString.Substring($i+2, 4)
            
            try {
                $unicodeChar = [char]([convert]::ToInt32($hexCode, 16))
                [void]$sbUnicode.Append($unicodeChar)
                $i += 6
            }
            catch {
                [void]$sbUnicode.Append('\u').Append($hexCode)
                $i += 6
            }
        }
        else {
            [void]$sbUnicode.Append($JsonString[$i])
            $i++
        }
    }
    
    $unescapedJson = $sbUnicode.ToString()
    
    $result = New-Object System.Text.StringBuilder
    $level = 0
    $inString = $false
    $isEscaped = $false
    
    $i = 0
    while ($i -lt $unescapedJson.Length) { # fix powershell's json indentation and compact single element arrays
        $char = $unescapedJson[$i]
        
        if ($inString) {
            [void]$result.Append($char)
            if ($char -eq '"' -and -not $isEscaped) {
                $inString = $false
            }
            $isEscaped = $char -eq '\' -and -not $isEscaped
            $i++
            continue
        }
        
        if ($char -eq ' ' -or $char -eq "`t" -or $char -eq "`n" -or $char -eq "`r") {
            $i++
            continue
        }
        
        switch ($char) {
            '{' {
                [void]$result.Append('{').AppendLine()
                $level++
                [void]$result.Append("`t" * $level)
                $i++
            }
            '}' {
                $level--
                [void]$result.AppendLine().Append("`t" * $level).Append('}')
                $i++
            }
            '[' {
                $isSimpleArray = $false
                $arrayEnd = -1
                $elementCount = 0
                $hasComplexElement = $false
                
                $lookAhead = $i + 1
                $inLookAheadString = $false
                $lookAheadEscaped = $false
                $depth = 1
                
                while ($lookAhead -lt $unescapedJson.Length) {
                    $nextChar = $unescapedJson[$lookAhead]
                    
                    if ($inLookAheadString) {
                        if ($nextChar -eq '"' -and -not $lookAheadEscaped) {
                            $inLookAheadString = $false
                        }
                        $lookAheadEscaped = $nextChar -eq '\' -and -not $lookAheadEscaped
                        $lookAhead++
                        continue
                    }
                    
                    if ($nextChar -eq '"') {
                        $inLookAheadString = $true
                        $lookAheadEscaped = $false
                    }
                    elseif ($nextChar -eq '[' -or $nextChar -eq '{') {
                        $depth++
                        $hasComplexElement = $true
                    }
                    elseif ($nextChar -eq ']') {
                        $depth--
                        if ($depth -eq 0) {
                            $arrayEnd = $lookAhead
                            break
                        }
                    }
                    elseif ($nextChar -eq ',') {
                        if ($depth -eq 1) {
                            $elementCount++
                        }
                    }
                    
                    $lookAhead++
                }
                
                if ($arrayEnd -ne -1 -and $elementCount -lt 3 -and -not $hasComplexElement) {
                    $arrayContent = $unescapedJson.Substring($i, $arrayEnd - $i + 1)
                    $compactArray = $arrayContent -replace '\s+', ' '
                    [void]$result.Append($compactArray)
                    $i = $arrayEnd + 1
                }
                else {
                    [void]$result.Append('[').AppendLine()
                    $level++
                    [void]$result.Append("`t" * $level)
                    $i++
                }
            }
            ']' {
                $level--
                [void]$result.AppendLine().Append("`t" * $level).Append(']')
                $i++
            }
            ',' {
                [void]$result.Append(',').AppendLine()
                [void]$result.Append("`t" * $level)
                $i++
            }
            ':' {
                [void]$result.Append(': ')
                $i++
            }
            '"' {
                $inString = $true
                $isEscaped = $false
                [void]$result.Append('"')
                $i++
            }
            default {
                [void]$result.Append($char)
                $i++
            }
        }
    }
    
    return $result.ToString()
}

function Update-JsonWithNewHashes {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$NewHashes,
        
        [Parameter(Mandatory = $true)]
        [PSObject]$JsonObject
    )

    try {
        $existingHashes = Get-ExistingHashes -JsonObject $JsonObject
        
        Write-Stage "Checking $($NewHashes.Count) hash entries..."
        
        $hashesToAdd = $NewHashes | 
        Where-Object { (Test-SHA256Format -Hash $_.Hash) -and (-not $existingHashes.ContainsKey($_.Hash.ToUpper())) } | 
        ForEach-Object { $_.Hash.ToUpper() } | 
        Select-Object -Unique
        
        Write-Stage "Found $($hashesToAdd.Count) new unique hash entries to add"
        return $hashesToAdd
    }
    catch {
        throw "Failed to identify new hashes to add: $_"
    }
}

function Update-TargetRules {
    param (
        [Parameter(Mandatory = $true)]
        [string]$JsonFilePath,
        
        [Parameter(Mandatory = $true)]
        [string[]]$NewHashes,
        
        [Parameter(Mandatory = $false)]
        [string]$NewZipHash = $null
    )
    
    try {
        if ($NewHashes.Count -eq 0 -and -not $NewZipHash) {
            Write-Stage "No changes detected. Skipping file update."
            return 0
        }
        
        $jsonContent = Get-Content -Path $JsonFilePath -Raw -ErrorAction Stop
        $jsonObject = $jsonContent | ConvertFrom-Json -ErrorAction Stop
        
        $dropRuleGuid = "{B4B6A87C-9937-4B21-95FD-F0C486122DF2}"
        $loadRuleGuid = "{99F8D7E1-CE6F-4367-8F3B-495ABA3877BC}"
        
        Write-Stage "Searching for rules with GUIDs: $dropRuleGuid and $loadRuleGuid"
        Write-Stage "Found $($jsonObject.Policies[0].Rules.Count) rules in the policy"
        
        foreach ($rule in $jsonObject.Policies[0].Rules) {
            Write-Stage "Found rule with GUID: $($rule.GUID)"
        }
        
        $dropRule = $null
        $loadRule = $null
        $loadRules = @()
        
        foreach ($rule in $jsonObject.Policies[0].Rules) {
            if ($rule.GUID -eq $dropRuleGuid) {
                $dropRule = $rule
            }
            
            if ($rule.GUID -eq $loadRuleGuid) {
                $loadRules += $rule
            }
        }
        
        if ($loadRules.Count -gt 0) {
            $loadRule = $loadRules[$loadRules.Count - 1]
        }
        
        if (-not $dropRule) {
            throw "Required drop rule with GUID $dropRuleGuid not found"
        }
        
        if (-not $loadRule) {
            throw "Required load rule with GUID $loadRuleGuid not found"
        }
        
        function Update-HashesInRule {
            param($Rule, $HashesToAdd)
            
            $fileSha256Target = $null
            foreach ($target in $Rule.Target) {
                if ($target.Attribute -eq "FileSha256") {
                    $fileSha256Target = $target
                    break
                }
            }
            
            $ruleDescription = $Rule.Description
            $ruleGuid = $Rule.GUID
            
            if ($fileSha256Target) {
                $validHashes = @()
                $emptyCount = 0
                
                if ($fileSha256Target.Equals -is [System.Array]) {
                    $originalCount = $fileSha256Target.Equals.Count
                    $validHashes = @($fileSha256Target.Equals | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                    $emptyCount = $originalCount - $validHashes.Count
                }
                elseif (-not [string]::IsNullOrWhiteSpace($fileSha256Target.Equals)) {
                    $validHashes = @($fileSha256Target.Equals)
                }
                
                Write-Stage "Rule '$ruleDescription' ($ruleGuid): Found $($validHashes.Count) existing hashes (removed $emptyCount empty entries)"
                
                $fileSha256Target.Equals = @($validHashes + $HashesToAdd | Select-Object -Unique)
                Write-Stage "Rule '$ruleDescription' ($ruleGuid): Updated to $($fileSha256Target.Equals.Count) hashes (added $($HashesToAdd.Count) new entries)"
            }
            else {
                Write-Stage "Rule '$ruleDescription' ($ruleGuid): No FileSha256 target found, adding new one with $($HashesToAdd.Count) hashes"
                $Rule.Target += [PSCustomObject]@{
                    Attribute = "FileSha256"
                    Equals = $HashesToAdd
                }
            }
        }
        
        
        Write-Stage "Updating drop rule $dropRuleGuid..."
        Update-HashesInRule -Rule $dropRule -HashesToAdd $NewHashes
        Write-Stage "Updating load rule $loadRuleGuid..."
        Update-HashesInRule -Rule $loadRule -HashesToAdd $NewHashes
        
        if ($NewZipHash) {
            $commentText = $jsonObject.Policies[0].Comment
            
            if ($commentText -match $ZipHashPattern) {
                $jsonObject.Policies[0].Comment = $commentText -replace $ZipHashPattern, "ZipSha256Sum: $NewZipHash"
            }
            else {
                $jsonObject.Policies[0].Comment += " ZipSha256Sum: $NewZipHash"
            }
        }

        $utf8NoBomEncoding = [System.Text.UTF8Encoding]::new($false)
        $updatedJsonContent = $jsonObject | ConvertTo-Json -Depth 100
        Write-Stage "Formatting json output..."
        $updatedJsonContent = Format-JsonOutput -JsonString $updatedJsonContent
        Write-Stage "Writing output to $JsonFilePath..."
        [System.IO.File]::WriteAllText($JsonFilePath, $updatedJsonContent, $utf8NoBomEncoding)
        
        return $NewHashes.Count
    }
    catch {
        throw "Failed to update target rules: $_"
    }
}

function Find-XmlFileInZip {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ZipPath,
        
        [Parameter(Mandatory = $true)]
        [string]$ExtractPath,
        
        [Parameter(Mandatory = $true)]
        [string]$XmlFileName
    )
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
        
        try {
            if (-not (Test-Path $ExtractPath)) {
                New-Item -Path $ExtractPath -ItemType Directory -Force | Out-Null
            }
            [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $ExtractPath)
            $xmlFile = Get-ChildItem -Path $ExtractPath -Recurse -File | Where-Object { $_.Name -eq $XmlFileName } | Select-Object -First 1
            
            return $xmlFile.FullName
        }
        finally {
            $zip.Dispose()
        }
    }
    catch {
        throw "Failed to extract or find files in zip: $_"
    }
}

function Test-ForDuplicateHashes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$JsonFilePath
    )
    
    try {
        $dropRuleGuid = "{B4B6A87C-9937-4B21-95FD-F0C486122DF2}"
        $loadRuleGuid = "{99F8D7E1-CE6F-4367-8F3B-495ABA3877BC}"
        
        if (-not (Test-Path -Path $JsonFilePath)) {
            Write-Log "Validation error: File not found at $JsonFilePath" -Level ([LogLevel]::ERROR)
            return $false
        }
        
        $json = Get-Content -Path $JsonFilePath -Raw | ConvertFrom-Json
        
        if (-not $json.Policies -or $json.Policies.Count -eq 0 -or -not $json.Policies[0].Rules) {
            Write-Log "Validation error: Invalid JSON structure" -Level ([LogLevel]::ERROR)
            return $false
        }
        
        $hashData = @{}
        $issues = $null
        
        foreach ($rule in $json.Policies[0].Rules) {
            $ruleGuid = $rule.GUID
            $hashesInRule = @{}
            
            foreach ($target in $rule.Target) {
                if ($target.Attribute -eq "FileSha256" -and $target.PSObject.Properties.Name -contains "Equals") {
                    foreach ($hash in $target.Equals) {
                        if ([string]::IsNullOrWhiteSpace($hash)) { continue }
                        
                        $hash = $hash.ToUpper()
                        
                        if ($hashesInRule.ContainsKey($hash)) {
                            if ($null -eq $issues) { $issues = @() }
                            $issues += "  Hash $hash appears multiple times in rule $ruleGuid (should appear only once)"
                        }
                        $hashesInRule[$hash] = $true
                        
                        if (-not $hashData.ContainsKey($hash)) {
                            $hashData[$hash] = @{
                                dropRule = $false
                                loadRule = $false
                                otherRules = @{}
                                totalRules = 0
                            }
                        }
                        
                        $info = $hashData[$hash]
                        if ($ruleGuid -eq $dropRuleGuid -and -not $info.dropRule) {
                            $info.dropRule = $true
                            $info.totalRules++
                        }
                        elseif ($ruleGuid -eq $loadRuleGuid -and -not $info.loadRule) {
                            $info.loadRule = $true
                            $info.totalRules++
                        }
                        elseif ($ruleGuid -ne $dropRuleGuid -and $ruleGuid -ne $loadRuleGuid -and -not $info.otherRules.ContainsKey($ruleGuid)) {
                            $info.otherRules[$ruleGuid] = $true
                            $info.totalRules++
                        }
                    }
                }
            }
        }
        
        foreach ($hash in $hashData.Keys) {
            $info = $hashData[$hash]
            
            if ($info.totalRules -ne 2) {
                if ($null -eq $issues) { $issues = @() }
                $rules = @()
                if ($info.dropRule) { $rules += $dropRuleGuid }
                if ($info.loadRule) { $rules += $loadRuleGuid }
                foreach ($rule in $info.otherRules.Keys) { $rules += $rule }
                $issues += "  Hash $hash appears in $($info.totalRules) rules: $($rules -join ', ') (should appear in exactly 2 rules)"
                continue
            }
            
            if (-not ($info.dropRule -and $info.loadRule)) {
                if ($null -eq $issues) { $issues = @() }
                $rules = @()
                if ($info.dropRule) { $rules += $dropRuleGuid }
                if ($info.loadRule) { $rules += $loadRuleGuid }
                foreach ($rule in $info.otherRules.Keys) { $rules += $rule }
                $issues += "  Hash $hash appears in wrong rules: $($rules -join ', ') (should be in drop rule $dropRuleGuid and load rule $loadRuleGuid)"
            }
        }
        
        if ($issues) {
            Write-Log "Validation issues:" -Level ([LogLevel]::WARNING)
            foreach ($issue in $issues) {
                Write-Log $issue -Level ([LogLevel]::WARNING)
            }
            return $false
        }
        
        Write-Log "Validation successful: all hashes are within expected rules." -Level ([LogLevel]::SUCCESS)
        return $true
    }
    catch {
        Write-Log "Validation error: $_" -Level ([LogLevel]::ERROR)
        return $false
    }
}

try {
    if (Test-Path $LastRunFilePath) {
        try {
            $lastRunTime = Get-Content -Path $LastRunFilePath -ErrorAction Stop
            $lastRunDate = $null
            try {
                $lastRunDate = [DateTime]::Parse($lastRunTime).Date
                $todayUtc = [DateTime]::UtcNow.Date
                
                if ($lastRunDate -eq $todayUtc) {
                    Write-Log "Vulnerable Driver Block List was already checked today. Skipping." -Level ([LogLevel]::SUCCESS)
                    return 0
                }
            }
            catch {
                Write-Log "Invalid timestamp format in last run file, continuing with check" -Level ([LogLevel]::WARNING)
            }
        }
        catch {
            Write-Log "Failed to read last run timestamp, continuing with check: $_" -Level ([LogLevel]::WARNING)
        }
    }

    Write-Stage "Starting Vulnerable Driver Block List update process"
        
    $resolvedJsonPath = Find-JsonFilePath -DefaultPath $JsonFilePath
    Write-Stage "Using JSON file: $resolvedJsonPath"
        
    $JsonFilePath = $resolvedJsonPath

    $jsonContent = Get-Content -Path $JsonFilePath -Raw -ErrorAction Stop
    if ([string]::IsNullOrEmpty($jsonContent)) {
        throw "JSON file is empty: $JsonFilePath"
    }
        
    try {
        $jsonObject = $jsonContent | ConvertFrom-Json
    }
    catch {
        throw "Failed to parse JSON file: $_"
    }
        
    if (-not $jsonObject.Policies) {
        throw "Invalid JSON format: Policies block expected"
    }
        
    if (-not $jsonObject.Policies[0].Comment) {
        throw "Invalid JSON format: Comment field expected (should contain ZipSha256Sum)"
    }
        
    $commentText = [string]$jsonObject.Policies[0].Comment
    if ($commentText -notmatch "ZipSha256Sum") {
        throw "Invalid JSON format: Comment field does not contain ZipSha256Sum"
    }
        
    $sha256Pattern = "ZipSha256Sum:?\s*([A-Fa-f0-9]{64})(\s|$)"
    if ($commentText -notmatch $sha256Pattern) {
        throw "Invalid JSON format: Comment field does not contain a valid SHA256 hash"
    }
        
    $hashMatch = [regex]::Match($commentText, $sha256Pattern)
    $expectedZipHash = $hashMatch.Groups[1].Value
    $msHashList = @()
    $newZipHash = $null

    $msResult = Get-SHA256HashesFromMicrosoftList -DownloadUrl $MsDownloadUrl -ZipFilePath $ZipFilePath -ExtractPath $ExtractPath -XmlFileName $XmlFileName
    $zipHash = $msResult.ZipHash

    if ($zipHash -eq $expectedZipHash) {
        Write-Stage "Zip file hash matches the existing database. No update required."
    } else {
        $msHashList = $msResult.Hashes
        $newZipHash = $zipHash
    }    
    Write-Stage "Getting SHA256 hashes from LOLDrivers..."
    $lolDriversHashes = Get-SHA256HashesFromLolDrivers

    $hashList = $msHashList + $lolDriversHashes
    Write-Stage "Combined hash list contains $($hashList.Count) entries"

    if ($hashList.Count -eq 0) {
        Write-Stage "No hashes available from any source. No update required."
        Write-LastRunTimestamp
        return 0
    }

    Write-Stage "Identifying new hashes to add..."
    $newHashes = Update-JsonWithNewHashes -NewHashes $hashList -JsonObject $jsonObject

    $hasChanges = $newHashes.Count -gt 0 -or $newZipHash
    if ($hasChanges) {
        Write-Stage "Updating target rules with new hashes..."
        Update-TargetRules -JsonFilePath $JsonFilePath -NewHashes $newHashes -NewZipHash $newZipHash
        $msCount = $msHashList.Count
        $lolCount = $lolDriversHashes.Count
        $msNew = @($newHashes | Where-Object { $msHashList.Hash -contains $_ }).Count
        $lolNew = @($newHashes | Where-Object { $lolDriversHashes.Hash -contains $_ }).Count
        
        Write-Log "Update summary:" -Level ([LogLevel]::INFO)
        Write-Log "  - Microsoft Vulnerable Driver List: $msCount hashes" -Level ([LogLevel]::INFO)
        Write-Log "  - LOLDrivers list: $lolCount hashes" -Level ([LogLevel]::INFO)
        Write-Log "  - Total new hashes added: $($newHashes.Count)" -Level ([LogLevel]::INFO)
        Write-Log "  - New from Microsoft list: $msNew" -Level ([LogLevel]::INFO)
        Write-Log "  - New from LOLDrivers: $lolNew" -Level ([LogLevel]::INFO)
        
        if ($newZipHash) {
            Write-Log "  - Updated ZIP hash: $newZipHash" -Level ([LogLevel]::INFO)
        }
    } else {
        Write-Stage "No changes detected. Skipping file save."
    }
    
    Write-Stage "Validating no duplicate hashes..."
    Test-ForDuplicateHashes -JsonFilePath $JsonFilePath
    
    Write-Log "Vulnerable Driver Block List update completed successfully" -Level ([LogLevel]::SUCCESS)
    Write-LastRunTimestamp
    return 0
}
catch {
    Write-Log "$_" -Level ([LogLevel]::ERROR)
    return 1
}
finally {
    Write-Stage "Cleaning up temporary files..."
    
    if (Test-Path $ZipFilePath) {
        try {
            Remove-Item -Path $ZipFilePath -Force -ErrorAction Stop
            Write-Stage "Removed zip file: $ZipFilePath"
        }
        catch {
            Write-Log "Failed to remove zip file: $_" -Level ([LogLevel]::WARNING)
        }
    }
    
    if (Test-Path $ExtractPath) {
        try {
            Remove-Item -Path $ExtractPath -Recurse -Force -ErrorAction Stop
            Write-Stage "Removed extract directory: $ExtractPath"
        }
        catch {
            Write-Log "Failed to remove extract directory: $_" -Level ([LogLevel]::WARNING)
        }
    }
}