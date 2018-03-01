function Get-GPOUsedDrives
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$Domain = ""
    )
    PROCESS {
        if ($Domain -eq "")
        {
            $Domain = (Get-WmiObject Win32_ComputerSystem).Domain
        }

        if (!$Domain.Contains("."))
        {
            Write-Host "The specified domain looks like a workgroup. Make sure you're using the FQDN and not the NetBIOS name. Exiting."
            return
        }

        $Path = "\\$Domain\SYSVOL\$Domain\Policies\"
        $Policies = Get-ChildItem -Path $Path

        $UsedDrives = New-Object System.Collections.ArrayList

        ForEach ($Policy in $Policies)
        {
            if ($Policy.Mode -NotLike "d*") { continue }
            if ($Policy.Name -NotLike "{*}") { continue }

            $GUID = $Policy.Name

            $GPO = (Get-GPO -Guid $GUID -ErrorAction SilentlyContinue)
            if (!$?)
            {
                Write-Host "Ignoring invalid policy: ${Policy.Name}"
                continue
            }

            $DisplayName = $GPO.DisplayName
            $Drives = "$Path\$GUID\User\Preferences\Drives\Drives.xml"

            if (Test-Path $Drives)
            {
                $UsedDrives = $UsedDrives + (ParseUsedDrives $DisplayName $Drives)
            }
        }

        return ($UsedDrives | Sort-Object Policy,Letter)
    }
}

function ParseUsedDrives([string]$Policy, [string]$XMLPath)
{
    $Out = New-Object System.Collections.ArrayList

    try
    {
        [xml]$DriveFile = Get-Content -Path $XMLPath

        ForEach($Drive in $DriveFile.Drives.Drive)
        {
            $Item = New-Object System.Object
            $Item | Add-Member -Type NoteProperty -Name Policy -Value $Policy
            $Item | Add-Member -Type NoteProperty -Name Letter -Value $Drive.Properties.letter
            $Item | Add-Member -Type NoteProperty -Name Path -Value $Drive.Properties.path
            $Out.Add($Item) | Out-Null
        }
    }
    catch {}

    return $Out
}

Export-ModuleMember *-*