<#
.SYNOPSIS
    Set config settings, run as a scheduled task daily and your users will be emailed when passwords are about to expire.

.PARAMETER Test
    Sends the email to a specified test email instead of the user.
#>
param(
    [Parameter(Position=0)]
    [switch]$Test
)

$ErrorActionPreference = "Stop"

### CONFIG ###
[int[]]$NotifyDays = @(1, 3)

[string]$EmailHost = "mailserver.corp.domain.com"
[int]$EmailPort = 25

[string]$EmailFrom = "changeme@corp.domain.com"
[string]$EmailTestAddress = "changeme@corp.domain.com"
[string]$EmailSubject = "Notice: Your password will expire %TIME%"
[string]$EmailBody = "<p>Your password is about to expire %TIME%. If you wish to change your password now, press CTRL+ALT+DELETE and choose Change Password.</p>
<br />
<b>Password Policy:</b>
<ul>
<li></li>
<li></li>
<li></li>
<li></li>
<li></li>
</ul>
<br />
<br />
<font size=""2"">
Details:<br />
Username: %USERNAME%<br />
Domain: %DOMAIN%<br />
Expiry Date: %FULLTIME%
</font>"
[string]$LogDirectory = "E:\Logs\PasswordExpiry"
### END CONFIG ###

if ( ( Test-Path -Path $LogDirectory ) -eq $False )
{
    New-Item -ItemType Directory -Path $LogDirectory
}

Start-Transcript -Path "$LogDirectory\$(Get-Date -UFormat "%Y-%m-%d").log"

$Domains = (Get-ADForest).Domains

foreach ( $Domain in $Domains )
{
    $Users = Get-ADUser -Server $Domain -Filter {(Enabled -eq $True) -and (PasswordNeverExpires -eq $False)} `
        -Properties Name, SamAccountName, PasswordExpired, PasswordLastSet, EmailAddress | `
        Where { $_.PasswordExpired -eq $False -And ( [string]::IsNullOrEmpty( $_.EmailAddress ) -eq $False ) }

    $ADPasswordPolicy = Get-ADDefaultDomainPasswordPolicy -Server $Domain
    $Today = (Get-Date -Hour 0 -Minute 0 -Second 0)
    $Encoding = [System.Text.Encoding]::UTF8

    foreach ( $User in $Users )
    {
        $UserPolicy = Get-ADUserResultantPasswordPolicy -Identity $User -Server $Domain
        $ExpiryDays = $ADPasswordPolicy.MaxPasswordAge.Days

        if ( $UserPolicy -ne $Null )
        {
            $ExpiryDays = $UserPolicy.MaxPasswordAge.Days
        }

        $PasswordLastSet = $User.PasswordLastSet
        $PasswordExpiry = $PasswordLastSet.AddDays( $ExpiryDays )

        $TimeUntilExpiry = New-TimeSpan -Start $Today -End $PasswordExpiry

        if ( ( $NotifyDays -Contains $TimeUntilExpiry.Days ) -eq $False )
        {
            continue
        }

        $TimeDiffString = "in $($TimeUntilExpiry.Days) days"

        if ( $TimeUntilExpiry.Days -eq 1 )
        {
            $TimeDiffString = "tomorrow"
        }
        elseif ( ( $TimeUntilExpiry.Days -gt 1 ) -And ( $TimeUntilExpiry.Days -lt 7 ) )
        {
            $TimeDiffString = "on $($PasswordExpiry.DayOfWeek)"
        }

        Write-Host "Sending password expiry notice to $($User.Name) [Expires $TimeDiffString]"

        $EmailAddr = $User.EmailAddress

        if ( $Test )
        {
            $EmailAddr = $EmailTestAddress
        }

        $UserEmailSubject = $EmailSubject.Replace( "%TIME%", $TimeDiffString )
        $UserEmailBody = $EmailBody.Replace( "%TIME%", $TimeDiffString ).Replace( "%USERNAME%", $User.SamAccountName ).Replace( "%DOMAIN%", $Domain ).Replace( "%FULLTIME%", $PasswordExpiry.ToString( ) )

        Send-MailMessage -SmtpServer $EmailHost -Port $EmailPort -From $EmailFrom `
            -To $EmailAddr -Subject $UserEmailSubject -Body $UserEmailBody -BodyAsHTML `
            -Priority High -Encoding $Encoding

        Write-Host "Password expiry email sent to $EmailAddr"
    }
}

Stop-Transcript