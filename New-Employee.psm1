[string]$ExchangeConnectionURL = "http://exchange.corp.domain.com/PowerShell/"
[string]$OfflineAddressBook = "\Default Offline Address Book"

[string]$DrivePathPrefix = "\\fileserver.corp.domain.com\Users$\" # End with a backslash
[string]$HomeDrive = "U:"

$UPNMap = @{ "Company"="@corp.domain.com" } # Separated by semi-colon
$OUMap = @{ "Company"="OU=Users,OU=Company,DC=corp,DC=domain,DC=com" } # Separated by semi-colon
$GroupMap = @{ "Company"=@("Company Staff", "CompanyAll") } # Separated by semi-colon, use shown format to have multiple groups per company
$DepartmentGroupMap = @{
    "Company"=@{
        "accounts"="Accounts Staff";
        "purchasing"="Purchasing Staff";
        "returns"="Returns Staff";
        "sales"="Sales Staff"
    }
}
$DepartmentMailboxMap = @{
    "Company"=@{
        "accounts"="Accounts";
        "purchasing"="Purchasing";
        "returns"="Returns";
        "sales"="Sales"
    }
}

[string]$AllStaffGroup = "All Staff"
[string]$VPNGroup = "VPN Users"

function New-Employee
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$FirstName,

        [Parameter(Mandatory=$true)]
        [string]$LastName,

        [Parameter(Mandatory=$true)]
        [string]$Company,

        [Parameter(Mandatory=$true)]
        [string]$Department,

        [Parameter(Mandatory=$true)]
        [ValidateRange(0,1)] 
        [int]$IsRemote,

        [Parameter(Mandatory=$true)]
        [string]$Domain
    )
    PROCESS {
        $DomainDNS = (Get-ADDomain -Server $DOMAIN).DNSRoot
        $Username = ("{0}.{1}" -f $FirstName.Substring(0,1), $LastName).ToLower( );

        try
        {
            Get-ADUser -Identity $Username -Server $Domain
            Write-Warning "User already exists, aborting.";
            return;
        }
        catch { }

        $DisplayName = "$FirstName $LastName";
        $DrivePath = $DrivePathPrefix + $Username;

        $ofs = '';
        $PasswordRaw = [string]("abcdefghijklmnopqrstuvwxyz0123456789".ToCharArray() | Get-Random -Count 12)
        $Password = ConvertTo-SecureString -String $PasswordRaw -AsPlainText -Force

        $UPN = $Username + (&{If($UPNMap.$Company) {$UPNMap.$Company} Else { "@$($DomainDNS)"}});

        $ResultUser = New-ADUser -Server $Domain -Name $DisplayName -SAMAccountName $Username -DisplayName $DisplayName -GivenName $FirstName -Surname $LastName `
            -Company $Company -Department $Department -Description $Department -Office $Department `
            -AccountPassword $Password -ChangePasswordAtLogon $true `
            -HomeDrive $HomeDrive -HomeDirectory $DrivePath `
            -Enabled $true -UserPrincipalName $UPN -Passthru

        if ($ResultUser -eq $null)
        {
            Write-Warning "Failed to add user, aborting.";
            return;
        }

        If ($OUMap.$Company)
        {
            $ResultUser | Move-ADObject -TargetPath $OUMap.$Company
        }

        CreateDrivePath $Username $DrivePath

        ###

        Write-Host "Adding to groups..."

        $Groups = New-Object System.Collections.Generic.List[System.Object]

        $Groups.Add($AllStaffGroup);

        If ($GroupMap.$Company)
        {
            ForEach($Group in $GroupMap.$Company)
            {
                $Groups.Add($Group);
            }
        }

        if ($DepartmentGroupMap.$Company.$Department)
        {
            ForEach ($Group in $DepartmentGroupMap.$Company.$Department)
            {
                $Groups.Add($Group);
            }
        }

        if ($IsRemote -eq 1)
        {
            $Groups.Add($VPNGroup);
        }

        ForEach($Group in $Groups)
        {
            Add-ADGroupMember -Server $Domain -Identity $Group -Members $Username
        }

        Write-Host "Added user to the following groups: " (($groups | Sort-Object) -Join ", ")

        ###

        Write-Host "Adding Exchange Mailbox..."

        AddExchangeUser $Username

        ###

        Write-Host "User successfully created.";
        Write-Host "Username: $Username";
        Write-Host "Password: $PasswordRaw";
    }
}

function CreateDrivePath($Username, $DrivePath)
{
    New-Item -Path $DrivePath -Type Directory -Force

    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        [string]"$Domain\$Username",
        [System.Security.AccessControl.FileSystemRights]"FullControl",
        [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit",
        [System.Security.AccessControl.PropagationFlags]"None",
        [System.Security.AccessControl.AccessControlType]"Allow"
    )

    $DrivePathACL = Get-ACL $DrivePath
    $DrivePathACL.AddAccessRule($AccessRule)

    Set-ACL -Path $DrivePath -AclObject $DrivePathACL
}

function AddExchangeUser($Username)
{
    # $UserCredential = Get-Credential -Message "Exchange Login"
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ExchangeConnectionURL `
        -Authentication Kerberos # -Credential $UserCredential

    $null = Import-PSSession $Session -DisableNameChecking

    $null = Enable-Mailbox -Identity $Username -Alias $Username # Setting to $null limits the spammy output

    if ($DepartmentMailboxMap.$Company.$Department)
    {
        ForEach ($Mailbox in $DepartmentMailboxMap.$Company.$Department)
        {
            $null = Add-MailboxPermission -Identity $Mailbox -User $Username -AccessRights FullAccess -InheritanceType All -AutoMapping $True
        }

        Write-Host "Added user to the following exchange mailboxes: " (($DepartmentMailboxMap.$Company.$Department | Sort-Object) -Join ", ")
    }

    Update-OfflineAddressBook $OfflineAddressBook

    Remove-PSSession $Session
}

Export-ModuleMember *-*