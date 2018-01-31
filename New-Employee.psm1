[string]$Departments = @("accounts", "purchasing", "returns", "sales")
[string]$DrivePathPrefix = "" # End with a backslash
[string]$ExchangeConnectionURL = "http://exchange.corp.domain.com/PowerShell/"
[string]$HomeDrive = "U:"
[string]$UPNMap = @{ "Company"="@corp.domain.com" } # Separated by semi-colon

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
        [string]$IsRemote,

        [Parameter(Mandatory=$true)]
        [string]$Domain
    )
    PROCESS {
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

        $UPN = $Username + (&{If($UPNMap -Contains $Company) {$UPNMap.$Company} Else { "@$($Domain)"}});

        $result = New-ADUser -Server $Domain -Name $DisplayName -SAMAccountName $Username -DisplayName $DisplayName -GivenName $FirstName -Surname $LastName `
            -Company $Company -Department $Department `
            -AccountPassword $Password -ChangePasswordAtLogon $true `
            -HomeDrive $HomeDrive -HomeDirectory $DrivePath `
            -Enabled $true -UserPrincipalName $UPN -Passthru

        if ($result -eq $null)
        {
            Write-Warning "Failed to add user, aborting.";
            return;
        }

        CreateDrivePath $Username $DrivePath

        ###

        Write-Host "Adding to groups..."

        $Groups = New-Object System.Collections.Generic.List[System.Object]

        $Groups.Add("All Staff");

        if ($Departments -Contains $Department.ToLower())
        {
            $Groups.Add("$Department Staff");
        }

        if ($IsRemote -eq 1)
        {
            $Groups.Add("VPN Users");
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

    Import-PSSession $Session

    $null = Enable-Mailbox -Identity $Username -Alias $Username # Setting to $null limits the spammy output

    Remove-PSSession $Session
}