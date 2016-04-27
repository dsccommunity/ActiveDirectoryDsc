function Get-TargetResource
{
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [PSCredential]$DomainUserCredential,

        [UInt64]$RetryIntervalSec = 60,

        [UInt32]$RetryCount = 10,
        
        [UInt32]$RebootRetryCount = 0

    )

    if($DomainUserCredential)
    {
        $convertToCimCredential = New-CimInstance -ClassName MSFT_Credential -Property @{Username=[string]$DomainUserCredential.UserName; Password=[string]$null} -Namespace root/microsoft/windows/desiredstateconfiguration -ClientOnly
    }
    else
    {
        $convertToCimCredential = $null
    }
    
    $domain = Get-Domain -DomainName $DomainName -DomainUserCredential $DomainUserCredential
         
   
    $returnValue = @{
        DomainName = $domain.Name
        DomainUserCredential = $convertToCimCredential
        RetryIntervalSec = $RetryIntervalSec
        RetryCount = $RetryCount
        RebootRetryCount = $RebootRetryCount
    }
    
    $returnValue
}


function Set-TargetResource
{
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [PSCredential]$DomainUserCredential,

        [UInt64]$RetryIntervalSec = 60,

        [UInt32]$RetryCount = 10,
        
        [UInt32]$RebootRetryCount = 0

    )

    $rebootLogFile = "$env:temp\xWaitForADDomain_Reboot.tmp"
    
    for($count = 0; $count -lt $RetryCount; $count++)
    {
        $domain = Get-Domain -DomainName $DomainName -DomainUserCredential $DomainUserCredential
         
        if($domain)
        {
            if($RebootRetryCount -gt 0)
            {
                Remove-Item $rebootLogFile -ErrorAction SilentlyContinue
            }
            
            break;
        }
        else 
        {
            Write-Verbose -Message "Domain $DomainName not found. Will retry again after $RetryIntervalSec sec"
            Start-Sleep -Seconds $RetryIntervalSec
            Clear-DnsClientCache
        }    
    }

    if(-not $domain) 
    {
        if($RebootRetryCount -gt 0)
        {
            [UInt32]$rebootCount = Get-Content $RebootLogFile -ErrorAction SilentlyContinue
            
            if($rebootCount -lt $RebootRetryCount)
            {
                $rebootCount = $rebootCount + 1
                Write-Verbose -Message  "Domain $DomainName not found after $count attempts with $RetryIntervalSec sec interval. Rebooting.  Reboot attempt number $rebootCount of $RebootRetryCount."
                Set-Content -Path $RebootLogFile -Value $rebootCount
                $global:DSCMachineStatus = 1
            }
            else 
            {
                throw "Domain '$($DomainName)' NOT found after $RebootRetryCount Reboot attempts."     
            }

            
        }
        else
        {
            throw "Domain '$($DomainName)' NOT found after $RetryCount attempts."
        }
    }
}

function Test-TargetResource
{
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [PSCredential]$DomainUserCredential,

        [UInt64]$RetryIntervalSec = 60,

        [UInt32]$RetryCount = 10,
        
        [UInt32]$RebootRetryCount = 0

    )
    
    $rebootLogFile = "$env:temp\xWaitForADDomain_Reboot.tmp"
    
    $domain = Get-Domain -DomainName $DomainName -DomainUserCredential $DomainUserCredential
   
    if($domain)
    {
        if($RebootRetryCount -gt 0)
        {
            Remove-Item $rebootLogFile -ErrorAction SilentlyContinue
        }
            
        $true
    }
    else 
    {
        $false
    }    
}



function Get-Domain
{
    [OutputType([PSObject])]
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [PSCredential]$DomainUserCredential

    )
    Write-Verbose -Message "Checking for domain $DomainName ..."
  
    if($DomainUserCredential)
    {
        $context = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $DomainName, $DomainUserCredential.UserName, $DomainUserCredential.GetNetworkCredential().Password)
    }
    else
    {
        $context = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain',$DomainName)
    }
    
    try 
    {
        $domain = ([System.DirectoryServices.ActiveDirectory.DomainController]::FindOne($context)).domain.ToString()
        Write-Verbose -Message "Found domain $DomainName"
        $returnValue = @{
            Name = $domain
        }
    
       $returnValue
    }
    catch
    {
        Write-Verbose -Message "Domain $DomainName not found"
    }
}
