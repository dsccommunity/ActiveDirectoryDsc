configuration JoinDomain {
    param(
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds
    )

    Import-DscResource -ModuleName xActiveDirectory,PSDesiredStateConfiguration;

    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)

    node localhost {

        xADDomainMember MemberServer {
            DomainName = $DomainName
            ADAdmin = $DomainCreds
            AllowReboot = $true
        }

    }

}

$cd = @{
    AllNodes = @(
        @{
            NodeName = 'localhost'
            PSDscAllowPlainTextPassword = $true
        }
    )
}

$cred = Get-Credential -Message "Domain Credentials:"
$domain = Read-Host -Message "Domain to join:"
JoinDomain -DomainName $domain -Admincreds $cred -ConfigurationData $cd