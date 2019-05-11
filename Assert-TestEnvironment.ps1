<#
    .SYNOPSIS
        Assert that the test environment is properly setup and loaded into the
        PowerShell session.

    .DESCRIPTION
        Assert that the test environment is properly setup and loaded into the
        PowerShell session.

    .EXAMPLE
        .\Assert-testEnvironment.ps1

        Will assert that the current PowerShell session is ready to run tests.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param
(
)

#region Verify prerequisites Pester
$pesterModuleName = 'Pester'

# This is the minimum version that can be used with the tests in this repo.
$pesterModuleMinimumVersion = '4.0.2'

<#
    Pester v4.4.0 has a fix for '-Not -Throw' so it shows the actual error
    message if an unexpected exception does occur. It will help when debugging
    tests.
    If no Pester module exist, then use this as the minimum version.
#>
$pesterModuleRecommendedMinimumVersion = '4.4.0'

$pesterModule = Get-Module $pesterModuleName -ListAvailable -Verbose:$false |
    Where-Object -Property 'Version' -GE -Value $pesterModuleMinimumVersion |
    Sort-Object -Property 'Version' -Descending |
    Select-Object -First 1

if (-not $pesterModule)
{
    <#
        Not installing the module here because it's not known what scope the
        user want (can) to install the module in.
    #>
    $message = 'Missing a compatible version of the {0} module. Minimum version of {0} module can be ''{2}'', but the recommended minimum version is ''{1}''.' -f $pesterModuleName, $pesterModuleRecommendedMinimumVersion, $pesterModuleMinimumVersion
    Write-Warning -Message $message
    $dependencyMissing = $true
}
else
{
    Write-Verbose -Message ('A compatible {0} module is already installed (v{1}). If you want to use a newer version of {0} module, please install it manually.' -f $pesterModule.Name, $pesterModule.Version)
}
#endregion Verify prerequisites Pester

#region Verify prerequisites PSDepend
$psDependModuleName = 'PSDepend'

# This is the minimum version that can be used with the tests in this repo.
$psDependModuleMinimumVersion = '0.3.0'
$psDependModuleRecommendedMinimumVersion = 'latest'

$psDependModule = Get-Module $psDependModuleName -ListAvailable -Verbose:$false |
    Where-Object -Property 'Version' -GE -Value $psDependModuleMinimumVersion |
    Sort-Object -Property 'Version' -Descending |
    Select-Object -First 1

if (-not $psDependModule)
{
    <#
        Not installing the module here because it's not known what scope the
        user want (can) to install the module in.
    #>
    $message = 'Missing a compatible version of the {0} module. Minimum version of {0} module can be ''{2}'', but the recommended minimum version is ''{1}''. Please install {0} module manually, then run this script again.' -f $psDependModuleName, $psDependModuleRecommendedMinimumVersion, $psDependModuleMinimumVersion
    Write-Warning -Message $message
    $dependencyMissing = $true
}
else
{
    Write-Verbose -Message ('A compatible {0} module is already installed (v{1}). If you want to use a newer version of {0} module, please install it manually.' -f $psDependModule.Name, $psDependModule.Version)
}
#endregion Verify prerequisites PSDepend

if ($dependencyMissing)
{
    Write-Output -InputObject 'Please install the necessary dependencies manually, then run this script again.'
    return
}

$dependenciesPath = Join-Path $PSScriptRoot -ChildPath 'Tests'

Write-Verbose -Message ('Running Invoke-PSDepend using dependencies found under the path ''{0}''.' -f $dependenciesPath)

if ($PSBoundParameters.ContainsKey('Confirm'))
{
    $invokePSDependConfirmation = $ConfirmPreference
}
else
{
    $invokePSDependConfirmation = $false
}

Invoke-PSDepend -Path $dependenciesPath -Confirm:$invokePSDependConfirmation
