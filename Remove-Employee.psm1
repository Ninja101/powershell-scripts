[string]$ExchangeConnectionURL = "http://exchange.corp.domain.com/PowerShell/"
[string]$NewOUPath = "OU=Past Staff,OU=Staff,DC=corp,DC=domain,DC=com"

function Remove-Employee
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Username,

        [Parameter(Mandatory=$true)]
        [string]$Domain,

        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$EmailAccess
    )
    PROCESS {

        $User = Get-ADUser -Identity $Username -Server $Domain

        if ($User -eq $null)
        {
            Write-Warning "User account does not exist, aborting."
            return;
        }

        if ($User.Enabled -eq $false)
        {
            Write-Warning "User account already disabled, aborting."
            return;
        }

        Disable-ADAccount -Identity $Username -Server $Domain
        Write-Host "User account has been disabled"

        ###

        $GroupList = @()
        $Groups = Get-ADUser -Identity $Username -Server $Domain -Properties * | select -ExpandProperty memberof
        foreach($i in $Groups)
        {
            $i = ($i -split ',')[0]
            $GroupList += ($i -creplace 'CN=|}', '')
        }

        (Get-ADUser -Identity $Username -Server $Domain -properties memberof).memberof | Remove-ADGroupMember -Server $Domain -member $Username -Confirm:$false
        Write-Host "Removed user to the following groups: " (($GroupList | Sort-Object) -Join ", ")

        ###

        Get-ADUser -Identity $Username -Server $Domain | Move-ADObject -Server $Domain -TargetPath $NewOUPath
        Write-Host "User account moved to NLE OU"

        ### Exchange

        DoExchangeStuff $Username $EmailAccess

        ###

        Write-Host "User account successfully disabled."
    }
}

function DoExchangeStuff($Username, $EmailAccess)
{
    # $UserCredential = Get-Credential -Message "Exchange Login"
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ExchangeConnectionURL `
        -Authentication Kerberos

    Import-PSSession $Session

    Set-Mailbox -Identity $Username -Type Shared -HiddenFromAddressListsEnabled:$true
    Write-Host "User mailbox set to shared and removed from address lists"

    if ($EmailAccess.length -gt 0)
    {
        Add-MailboxPermission -Identity $Username -User $EmailAccess -AccessRights FullAccess -InheritanceType All -AutoMapping:$true
        Write-Host "User mailbox permissions added for $EmailAccess"
    }

    Remove-PSSession $Session
}