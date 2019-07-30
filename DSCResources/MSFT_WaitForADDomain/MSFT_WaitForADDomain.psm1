$script:resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$script:modulesFolderPath = Join-Path -Path $script:resourceModulePath -ChildPath 'Modules'

$script:localizationModulePath = Join-Path -Path $script:modulesFolderPath -ChildPath 'ActiveDirectoryDsc.Common'
Import-Module -Name (Join-Path -Path $script:localizationModulePath -ChildPath 'ActiveDirectoryDsc.Common.psm1')

$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_WaitForADDomain'

# This file is used to remember the number of times the node has been rebooted.
$script:rebootLogFile = Join-Path $env:temp -ChildPath 'WaitForADDomain_Reboot.tmp'

<#
    .SYNOPSIS
        Returns the current state of the specified Active Directory domain.

    .PARAMETER DomainName
        Specifies the fully qualified domain name to wait for.

    .PARAMETER SiteName
        Specifies the site in the domain where to look for a domain controller.

    .PARAMETER Credential
        Specifies the credentials that are used when accessing the domain,
        unless the built-in PsDscRunAsCredential is used.

    .PARAMETER WaitTimeout
        Specifies the timeout in seconds that the resource will wait for the
        domain to be accessible. Default value is 300 seconds.

    .PARAMETER RebootCount
        Specifies the number of times the node will be reboot in an effort to
        connect to the domain.
#>
function Get-TargetResource
{
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $DomainName,

        [Parameter()]
        [System.String]
        $SiteName,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.UInt64]
        $WaitTimeout = 300,

        [Parameter()]
        [System.UInt32]
        $RebootCount
    )

    $findDomainControllerParameters = @{
        DomainName = $DomainName
    }

    Write-Verbose -Message ($script:localizedData.SearchDomainController -f $DomainName)

    if ($PSBoundParameters.ContainsKey('SiteName'))
    {
        $findDomainControllerParameters['SiteName'] = $SiteName

        Write-Verbose -Message ($script:localizedData.SearchInSiteOnly -f $SiteName)
    }

    if ($PSBoundParameters.ContainsKey('Credential'))
    {
        $cimCredentialInstance = New-CimCredentialInstance -Credential $Credential

        $findDomainControllerParameters['Credential'] = $Credential

        Write-Verbose -Message ($script:localizedData.ImpersonatingCredentials -f $Credential.UserName)
    }
    else
    {
        if ($null -ne $PsDscContext.RunAsUser)
        {
            # Running using PsDscRunAsCredential
            Write-Verbose -Message ($script:localizedData.ImpersonatingCredentials -f $PsDscContext.RunAsUser)
        }
        else
        {
            # Running as SYSTEM or current user.
            Write-Verbose -Message ($script:localizedData.ImpersonatingCredentials -f (Get-CurrentUser).Name)
        }

        $cimCredentialInstance = $null
    }

    $currentDomainController = Find-DomainController @findDomainControllerParameters

    if ($currentDomainController)
    {
        $domainFound = $true
        $domainControllerSiteName = $currentDomainController.SiteName

        Write-Verbose -Message $script:localizedData.FoundDomainController

    }
    else
    {
        $domainFound = $false
        $domainControllerSiteName = $null

        Write-Verbose -Message $script:localizedData.NoFoundDomainController
    }

    return @{
        DomainName  = $DomainName
        SiteName    = $domainControllerSiteName
        Credential  = $cimCredentialInstance
        WaitTimeout = $WaitTimeout
        RebootCount = $RebootCount
        IsAvailable = $domainFound
    }
}

<#
    .SYNOPSIS
        Waits for the specified Active Directory domain to have a domain
        controller that can serve connections.

    .PARAMETER DomainName
        Specifies the fully qualified domain name to wait for.

    .PARAMETER SiteName
        Specifies the site in the domain where to look for a domain controller.

    .PARAMETER Credential
        Specifies the credentials that are used when accessing the domain,
        unless the built-in PsDscRunAsCredential is used.

    .PARAMETER WaitTimeout
        Specifies the timeout in seconds that the resource will wait for the
        domain to be accessible. Default value is 300 seconds.

    .PARAMETER RebootCount
        Specifies the number of times the node will be reboot in an effort to
        connect to the domain.
#>
function Set-TargetResource
{
    <#
        Suppressing this rule because $global:DSCMachineStatus is used to trigger
        a reboot if the domain name cannot be found withing the timeout period.
    #>
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
    <#
        Suppressing this rule because $global:DSCMachineStatus is only set,
        never used (by design of Desired State Configuration).
    #>
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Scope='Function', Target='DSCMachineStatus')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $DomainName,

        [Parameter()]
        [System.String]
        $SiteName,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.UInt64]
        $WaitTimeout = 300,

        [Parameter()]
        [System.UInt32]
        $RebootCount
    )

    for ($count = 0; $count -lt $RetryCount; $count++)
    {
        $domain = Get-Domain -DomainName $DomainName -DomainUserCredential $DomainUserCredential

        if ($domain)
        {
            if ($RebootRetryCount -gt 0)
            {
                Remove-Item $rebootLogFile -ErrorAction SilentlyContinue
            }

            break
        }
        else
        {
            Write-Verbose -Message ($script:localizedData.DomainNotFoundRetrying -f $DomainName, $RetryIntervalSec)

            Start-Sleep -Seconds $RetryIntervalSec

            Clear-DnsClientCache
        }
    }

    if (-not $domain)
    {
        if ($RebootRetryCount -gt 0)
        {
            [System.UInt32] $rebootCount = Get-Content $RebootLogFile -ErrorAction SilentlyContinue

            if ($rebootCount -lt $RebootRetryCount)
            {
                $rebootCount = $rebootCount + 1

                Write-Verbose -Message  ($script:localizedData.DomainNotFoundRebooting -f $DomainName, $count, $RetryIntervalSec, $rebootCount, $RebootRetryCount)

                Set-Content -Path $RebootLogFile -Value $rebootCount

                $global:DSCMachineStatus = 1
            }
            else
            {
                throw ($script:localizedData.DomainNotFoundAfterReboot -f $DomainName, $RebootRetryCount)
            }
        }
        else
        {
            throw ($script:localizedData.DomainNotFoundAfterRetry -f $DomainName, $RetryCount)
        }
    }
}

<#
    .SYNOPSIS
        Determines if the specified Active Directory domain have a domain controller
        that can serve connections.

    .PARAMETER DomainName
        Specifies the fully qualified domain name to wait for.

    .PARAMETER SiteName
        Specifies the site in the domain where to look for a domain controller.

    .PARAMETER Credential
        Specifies the credentials that are used when accessing the domain,
        unless the built-in PsDscRunAsCredential is used.

    .PARAMETER WaitTimeout
        Specifies the timeout in seconds that the resource will wait for the
        domain to be accessible. Default value is 300 seconds.

    .PARAMETER RebootCount
        Specifies the number of times the node will be reboot in an effort to
        connect to the domain.
#>
function Test-TargetResource
{
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $DomainName,

        [Parameter()]
        [System.String]
        $SiteName,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.UInt64]
        $WaitTimeout = 300,

        [Parameter()]
        [System.UInt32]
        $RebootCount
    )

    Write-Verbose -Message (
        $script:localizedData.TestConfiguration -f $DomainName
    )

    # Only pass properties that could be used when fetching the domain controller.
    $compareTargetResourceStateParameters = @{
        DomainName = $DomainName
        SiteName = $SiteName
        Credential = $Credential
    }

    <#
        This returns array of hashtables which contain the properties ParameterName,
        Expected, Actual, and InDesiredState. In this case only the property
        'IsAvailable' will be returned.
    #>
    $compareTargetResourceStateResult = Compare-TargetResourceState @compareTargetResourceStateParameters

    if ($false -in $compareTargetResourceStateResult.InDesiredState)
    {
        $testTargetResourceReturnValue = $false

        Write-Verbose -Message ($script:localizedData.DomainNotInDesiredState -f $DomainName)
    }
    else
    {
        $testTargetResourceReturnValue = $true

        if ($PSBoundParameters.ContainsKey('RebootCount') -and $RebootCount -gt 0 )
        {
            if (Test-Path -Path $script:rebootLogFile)
            {
                Remove-Item $script:rebootLogFile -Force -ErrorAction SilentlyContinue
            }
        }

        Write-Verbose -Message ($script:localizedData.DomainInDesiredState -f $DomainName)
    }

    return $testTargetResourceReturnValue
}

<#
    .SYNOPSIS
        Compares the properties in the current state with the properties of the
        desired state and returns a hashtable with the comparison result.

    .PARAMETER DomainName
        Specifies the fully qualified domain name to wait for.

    .PARAMETER SiteName
        Specifies the site in the domain where to look for a domain controller.

    .PARAMETER Credential
        Specifies the credentials that are used when accessing the domain,
        unless the built-in PsDscRunAsCredential is used.
#>
function Compare-TargetResourceState
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $DomainName,

        [Parameter()]
        [System.String]
        $SiteName,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    $getTargetResourceParameters = @{
        DomainName  = $DomainName
        SiteName    = $SiteName
        Credential  = $Credential
    }

    <#
        Removes any keys not bound to $PSBoundParameters.
        Need the @() around this to get a new array to enumerate.
    #>
    @($getTargetResourceParameters.Keys) | ForEach-Object {
        if (-not $PSBoundParameters.ContainsKey($_))
        {
            $getTargetResourceParameters.Remove($_)
        }
    }

    $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters

    <#
        Only interested in the read-only property IsAvailable, which
        should always be compared to the value $true.
    #>
    $compareResourcePropertyStateParameters = @{
        CurrentValues = $getTargetResourceResult
        DesiredValues = @{
            IsAvailable = $true
        }
        Properties    = 'IsAvailable'
    }

    return Compare-ResourcePropertyState @compareResourcePropertyStateParameters
}
