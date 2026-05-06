#Requires -Version 5.1

<#PSScriptInfo
.VERSION 1.0
.AUTHOR LUKASZ BODZIONY
.COPYRIGHT Copyright (c) LUKASZ BODZIONY
.TAGS Windows PowerShell Multiple RDP
.PROJECTURI https://netcloud24.com
#>

<#
.SYNOPSIS
    Patch termsrv.dll to allow multiple simultaneous RDP sessions on non-Windows Server computers.
.DESCRIPTION
    This script patches the termsrv.dll file to enable multiple RDP sessions on Windows 7, 10, 11, Server 2016, 2019, 2022, and potentially Windows 2025.
.LINK
    http://woshub.com/how-to-allow-multiple-rdp-sessions-in-windows-10
    https://www.mysysadmintips.com/windows/clients/545-multiple-rdp-remote-desktop-sessions-in-windows-10
#>

# Self-elevate the script
if (-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host 'You didn''t run this script as an Administrator. Elevating...' -ForegroundColor Green
    Start-Sleep -Milliseconds 2500
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

$OSArchitecture = (Get-CimInstance -ClassName Win32_OperatingSystem).OSArchitecture

$termsrvDllFile = "$env:SystemRoot\System32\termsrv.dll"
$termsrvDllCopy = "$env:SystemRoot\System32\termsrv.dll.copy"
$termsrvPatched = "$env:SystemRoot\System32\termsrv.dll.patched"

$patterns = @{
    Pattern = [regex]'39 81 3C 06 00 00 0F (?:[0-9A-F]{2} ){4}00'
    Win24H2 = [regex]'8B 81 38 06 00 00 39 81 3C 06 00 00 75'
}

function Get-OSInfo {
    $OSInfo = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    [PSCustomObject]@{
        CurrentBuild = $OSInfo.CurrentBuild
        BuildRevision = $OSInfo.UBR
        FullOSBuild = "$($OSInfo.CurrentBuild).$($OSInfo.UBR)"
        DisplayVersion = $OSInfo.DisplayVersion
        InstallationType = $OSInfo.InstallationType
    }
}

function Get-OSVersion {
    [version]$OSVersion = [System.Environment]::OSVersion.Version
    $installationType = (Get-OSInfo).InstallationType

    if ($OSVersion.Major -eq 6 -and $OSVersion.Minor -eq 1) {
        return 'Windows 7'
    } elseif ($OSVersion.Major -eq 10 -and $OSVersion.Build -lt 22000 -and $installationType -eq 'Client') {
        return 'Windows 10'
    } elseif ($OSVersion.Major -eq 10 -and $OSVersion.Build -gt 22000) {
        return 'Windows 11'
    } elseif ($OSVersion.Major -eq 10 -and $OSVersion.Build -lt 22000 -and $installationType -eq 'Server') {
        return 'Windows Server 2016'
    } elseif ($OSVersion.Major -eq 10 -and $OSVersion.Build -eq 20348) {
        return 'Windows Server 2022'
    } else {
        return 'Unsupported OS'
    }
}

function Update-Dll {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [regex]$InputPattern,

        [Parameter(Mandatory)]
        [string]$Replacement,

        [Parameter(Mandatory)]
        [string]$TermsrvDllAsText,

        [Parameter(Mandatory)]
        [string]$TermsrvDllAsFile,

        [Parameter(Mandatory)]
        [string]$TermsrvDllAsPatch,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSecurity]$TermsrvAclObject
    )

    begin {
        $match = $TermsrvDllAsText -match $InputPattern
        $patch = $TermsrvDllAsText -match $Replacement
    }

    process {
        if ($match) {
            Write-Host "`nPattern matching!`n" -ForegroundColor Green
            $dllAsTextReplaced = $TermsrvDllAsText -replace $InputPattern, $Replacement
            [byte[]] $dllAsBytesReplaced = -split $dllAsTextReplaced -replace '^', '0x'
            [System.IO.File]::WriteAllBytes($TermsrvDllAsPatch, $dllAsBytesReplaced)
            fc.exe /b $TermsrvDllAsPatch $TermsrvDllAsFile
            Start-Sleep -Milliseconds 1500
            Copy-Item -Path $TermsrvDllAsPatch -Destination $TermsrvDllAsFile -Force
        } elseif ($patch) {
            Write-Host "The file is already patched. No changes needed.`n" -ForegroundColor Green
        } else {
            Write-Host "Pattern not found. No changes made.`n" -ForegroundColor Yellow
        }
        Set-Acl -Path $TermsrvDllAsFile -AclObject $TermsrvAclObject
        Start-Service TermService -PassThru
    }
}

function Stop-TermService {
    try {
        Stop-Service -Name TermService -Force -ErrorAction Stop
    } catch {
        Write-Warning -Message $_.Exception.Message
        return
    }
    while ((Get-Service -Name TermService).Status -ne 'Stopped') {
        Start-Sleep -Milliseconds 500
    }
    Write-Host "`nRemote Desktop Services (TermService) stopped successfully`n" -ForegroundColor Green
}

Stop-TermService

$termsrvDllAcl = Get-Acl -Path $termsrvDllFile
Write-Host "Owner of termsrv.dll: $($termsrvDllAcl.Owner)"
Copy-Item -Path $termsrvDllFile -Destination $termsrvDllCopy -Force
takeown.exe /F $termsrvDllFile
$currentUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls.exe $termsrvDllFile /grant "$($currentUserName):F"
$dllAsByte = [System.IO.File]::ReadAllBytes($termsrvDllFile)
$dllAsText = ($dllAsByte | ForEach-Object { $_.ToString('X2') }) -join ' '

$commonParams = @{
    TermsrvDllAsText = $dllAsText
    TermsrvDllAsFile = $termsrvDllFile
    TermsrvDllAsPatch = $termsrvPatched
    TermsrvAclObject = $termsrvDllAcl
}

switch (Get-OSVersion) {
    'Windows 7' {
        if ($OSArchitecture -eq '64-bit') {
            switch ((Get-OSInfo).FullOSBuild) {
                '7601.23964' {
                    $dllAsTextReplaced = $dllAsText -replace '8B 87 38 06 00 00 39 87 3C 06 00 00 0F 84 2F C3 00 00', 'B8 00 01 00 00 90 89 87 38 06 00 00 90 90 90 90 90 90' `
                    -replace '4C 24 60 BB 01 00 00 00', '4C 24 60 BB 00 00 00 00' `
                    -replace '83 7C 24 50 00 74 18 48 8D', '83 7C 24 50 00 EB 18 48 8D'
                }
                '7601.24546' {
                    $dllAsTextReplaced = $dllAsText -replace '8B 87 38 06 00 00 39 87 3C 06 00 00 0F 84 3E C4 00 00', 'B8 00 01 00 00 90 89 87 38 06 00 00 90 90 90 90 90 90' `
                    -replace '4C 24 60 BB 01 00 00 00', '4C 24 60 BB 00 00 00 00' `
                    -replace '83 7C 24 50 00 74 43 48 8D', '83 7C 24 50 00 EB 18 48 8D'
                }
                Default {
                    $dllAsTextReplaced = $dllAsText -replace '8B 87 38 06 00 00 39 87 3C 06 00 00 0F 84 3E C4 00 00', 'B8 00 01 00 00 90 89 87 38 06 00 00 90 90 90 90 90 90' `
                    -replace '4C 24 60 BB 01 00 00 00', '4C 24 60 BB 00 00 00 00' `
                    -replace '83 7C 24 50 00 74 43 48 8D', '83 7C 24 50 00 EB 18 48 8D'
                }
            }
            [byte[]] $dllAsBytesReplaced = -split $dllAsTextReplaced -replace '^', '0x'
            [System.IO.File]::WriteAllBytes($termsrvPatched, $dllAsBytesReplaced)
            fc.exe /B $termsrvPatched $termsrvDllFile
            Start-Sleep -Milliseconds 1500
            Copy-Item -Path $termsrvPatched -Destination $termsrvDllFile -Force
            Set-Acl -Path $termsrvDllFile -AclObject $termsrvDllAcl
            Start-Sleep -Milliseconds 2500
            Start-Service TermService -PassThru
        }
    }
    'Windows 10' {
        Update-Dll @commonParams -InputPattern $patterns.Pattern -Replacement 'B8 00 01 00 00 89 81 38 06 00 00 90'
    }
    'Windows 11' {
        if ((Get-OSInfo).DisplayVersion -eq '23H2') {
            Update-Dll @commonParams -InputPattern $patterns.Pattern -Replacement 'B8 00 01 00 00 89 81 38 06 00 00 90'
        } elseif ((Get-OSInfo).DisplayVersion -eq '24H2') {
            Update-Dll @commonParams -InputPattern $patterns.Win24H2 -Replacement 'B8 00 01 00 00 89 81 38 06 00 00 90 EB'
        }
    }
    'Windows Server 2016' {
        Update-Dll @commonParams -InputPattern $patterns.Pattern -Replacement 'B8 00 01 00 00 89 81 38 06 00 00 90'
    }
    'Windows Server 2022' {
        Update-Dll @commonParams -InputPattern $patterns.Pattern -Replacement 'B8 00 01 00 00 89 81 38 06 00 00 90'
    }
    'Unsupported OS' {
        Write-Host 'Unable to get OS Version'
    }
}