function Get-TargetResource
{
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [PSCredential]$DomainUserCredential,

        [UInt64]$RetryIntervalSec = 10,

        [UInt32]$RetryCount = 5
    )
    $cimInstanceParams = @{
        ClassName = 'MSFT_Credential'
        Property = @{Username=[string]$DomainUserCredential.UserName; Password=[string]$null}
        Namespace = 'root/microsoft/windows/desiredstateconfiguration'
        ClientOnly = $true
    }
    $convertToCimCredential = New-CimInstance @cimInstanceParams
    $domain = Get-Domain @PSBoundParameters
    $returnValue = @{
        DomainName = $domain.name
        DomainUserCredential = $convertToCimCredential
        RetryIntervalSec = $RetryIntervalSec
        RetryCount = $RetryCount
    }
    $returnValue
}


function Set-TargetResource
{
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [PSCredential]$DomainUserCredential,

        [UInt64]$RetryIntervalSec = 10,

        [UInt32]$RetryCount = 5
    )

    $domainFound = $false
    
    for($count = 0; $count -lt $RetryCount; $count++)
    {
        $domain = Get-Domain @PSBoundParameters
        if ($domain.name)
        {
            Write-Verbose -Message "Found domain $DomainName"
            $domainFound = $true
            break
        }
        else
        {
            Write-Verbose -Message "Domain $DomainName not found. Will retry again after $RetryIntervalSec sec"
            Start-Sleep -Seconds $RetryIntervalSec
            Clear-DnsClientCache
        }
    }

    if(! $domainFound) {throw "Domain $DomainName not found after $count attempts with $RetryIntervalSec sec interval"}
}

function Test-TargetResource
{
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [PSCredential]$DomainUserCredential,

        [UInt64]$RetryIntervalSec = 10,

        [UInt32]$RetryCount = 5
    )

    $domain = Get-Domain @PSBoundParameters
    if ($domain.name)
    {
        Write-Verbose -Message "Found domain $DomainName"
        $true
    }
    else
    {
        Write-Verbose -Message "Domain $DomainName not found"
        $false
    }
}

function Get-Domain
{
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [PSCredential]$DomainUserCredential,

        [UInt64]$RetryIntervalSec = 10,

        [UInt32]$RetryCount = 5
    )
    Write-Verbose -Message "Checking for domain $DomainName ..."
    New-Object DirectoryServices.DirectoryEntry(
        "LDAP://$DomainName",
        $DomainUserCredential.UserName,
        $DomainUserCredential.GetNetworkCredential().Password
    )
}
