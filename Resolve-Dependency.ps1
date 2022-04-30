<#
    .DESCRIPTION
        Bootstrap script for PSDepend.

    .PARAMETER DependencyFile
        Specifies the configuration file for the this script. The default value is
        'RequiredModules.psd1' relative to this script's path.

    .PARAMETER PSDependTarget
        Path for PSDepend to be bootstrapped and save other dependencies.
        Can also be CurrentUser or AllUsers if you wish to install the modules in
        such scope. The default value is './output/RequiredModules' relative to
        this script's path.

    .PARAMETER Proxy
        Specifies the URI to use for Proxy when attempting to bootstrap
        PackageProvider and PowerShellGet.

    .PARAMETER ProxyCredential
        Specifies the credential to contact the Proxy when provided.

    .PARAMETER Scope
        Specifies the scope to bootstrap the PackageProvider and PSGet if not available.
        THe default value is 'CurrentUser'.

    .PARAMETER Gallery
        Specifies the gallery to use when bootstrapping PackageProvider, PSGet and
        when calling PSDepend (can be overridden in Dependency files). The default
        value is 'PSGallery'.

    .PARAMETER GalleryCredential
        Specifies the credentials to use with the Gallery specified above.

    .PARAMETER AllowOldPowerShellGetModule
        Allow you to use a locally installed version of PowerShellGet older than
        1.6.0 (not recommended). Default it will install the latest PowerShellGet
        if an older version than 2.0 is detected.

    .PARAMETER MinimumPSDependVersion
        Allow you to specify a minimum version fo PSDepend, if you're after specific
        features.

    .PARAMETER AllowPrerelease
        Not yet written.

    .PARAMETER WithYAML
        Not yet written.

    .NOTES
        Load defaults for parameters values from Resolve-Dependency.psd1 if not
        provided as parameter.
#>
[CmdletBinding()]
param
(
    [Parameter()]
    [System.String]
    $DependencyFile = 'RequiredModules.psd1',

    [Parameter()]
    [System.String]
    $PSDependTarget = (Join-Path -Path $PSScriptRoot -ChildPath './output/RequiredModules'),

    [Parameter()]
    [System.Uri]
    $Proxy,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $ProxyCredential,

    [Parameter()]
    [ValidateSet('CurrentUser', 'AllUsers')]
    [System.String]
    $Scope = 'CurrentUser',

    [Parameter()]
    [System.String]
    $Gallery = 'PSGallery',

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $GalleryCredential,

    [Parameter()]
    [System.Management.Automation.SwitchParameter]
    $AllowOldPowerShellGetModule,

    [Parameter()]
    [System.String]
    $MinimumPSDependVersion,

    [Parameter()]
    [System.Management.Automation.SwitchParameter]
    $AllowPrerelease,

    [Parameter()]
    [System.Management.Automation.SwitchParameter]
    $WithYAML
)

try
{
    if ($PSVersionTable.PSVersion.Major -le 5)
    {
        if (-not (Get-Command -Name 'Import-PowerShellDataFile' -ErrorAction 'SilentlyContinue'))
        {
            Import-Module -Name Microsoft.PowerShell.Utility -RequiredVersion '3.1.0.0'
        }

        <#
            Making sure the imported PackageManagement module is not from PS7 module
            path. The VSCode PS extension is changing the $env:PSModulePath and
            prioritize the PS7 path. This is an issue with PowerShellGet because
            it loads an old version if available (or fail to load latest).
        #>
        Get-Module -ListAvailable PackageManagement |
            Where-Object -Property 'ModuleBase' -NotMatch 'powershell.7' |
            Select-Object -First 1 |
            Import-Module -Force
    }

    Write-Verbose -Message 'Importing Bootstrap default parameters from ''$PSScriptRoot/Resolve-Dependency.psd1''.'

    $resolveDependencyConfigPath = Join-Path -Path $PSScriptRoot -ChildPath '.\Resolve-Dependency.psd1' -Resolve -ErrorAction 'Stop'

    $resolveDependencyDefaults = Import-PowerShellDataFile -Path $resolveDependencyConfigPath

    $parameterToDefault = $MyInvocation.MyCommand.ParameterSets.Where{ $_.Name -eq $PSCmdlet.ParameterSetName }.Parameters.Keys

    if ($parameterToDefault.Count -eq 0)
    {
        $parameterToDefault = $MyInvocation.MyCommand.Parameters.Keys
    }

    # Set the parameters available in the Parameter Set, or it's not possible to choose yet, so all parameters are an option.
    foreach ($parameterName in $parameterToDefault)
    {
        if (-not $PSBoundParameters.Keys.Contains($parameterName) -and $resolveDependencyDefaults.ContainsKey($parameterName))
        {
            Write-Verbose -Message "Setting $parameterName with $($resolveDependencyDefaults[$parameterName])."

            try
            {
                $variableValue = $resolveDependencyDefaults[$parameterName]

                if ($variableValue -is [System.String])
                {
                    $variableValue = $ExecutionContext.InvokeCommand.ExpandString($variableValue)
                }

                $PSBoundParameters.Add($parameterName, $variableValue)

                Set-Variable -Name $parameterName -value $variableValue -Force -ErrorAction 'SilentlyContinue'
            }
            catch
            {
                Write-Verbose -Message "Error adding default for $parameterName : $($_.Exception.Message)."
            }
        }
    }
}
catch
{
    Write-Warning -Message "Error attempting to import Bootstrap's default parameters from '$resolveDependencyConfigPath': $($_.Exception.Message)."
}

Write-Progress -Activity 'Bootstrap:' -PercentComplete 0 -CurrentOperation 'NuGet Bootstrap'

# TODO: This should handle the parameter $AllowOldPowerShellGetModule.
$powerShellGetModule = Import-Module -Name 'PowerShellGet' -MinimumVersion '2.0' -ErrorAction 'SilentlyContinue' -PassThru

# Install the package provider if it is not available.
$nuGetProvider = Get-PackageProvider -Name 'NuGet' -ListAvailable | Select-Object -First 1

if (-not $powerShellGetModule -and -not $nuGetProvider)
{
    $providerBootstrapParameters = @{
        Name           = 'nuget'
        Force          = $true
        ForceBootstrap = $true
        ErrorAction    = 'Stop'
    }

    switch ($PSBoundParameters.Keys)
    {
        'Proxy'
        {
            $providerBootstrapParameters.Add('Proxy', $Proxy)
        }

        'ProxyCredential'
        {
            $providerBootstrapParameters.Add('ProxyCredential', $ProxyCredential)
        }

        'Scope'
        {
            $providerBootstrapParameters.Add('Scope', $Scope)
        }
    }

    if ($AllowPrerelease)
    {
        $providerBootstrapParameters.Add('AllowPrerelease', $true)
    }

    Write-Information -MessageData 'Bootstrap: Installing NuGet Package Provider from the web (Make sure Microsoft addresses/ranges are allowed).'

    $null = Install-PackageProvider @providerBootstrapParams

    $nuGetProvider = Get-PackageProvider -Name 'NuGet' -ListAvailable | Select-Object -First 1

    $nuGetProviderVersion = $nuGetProvider.Version.ToString()

    Write-Information -MessageData "Bootstrap: Importing NuGet Package Provider version $nuGetProviderVersion to current session."

    $Null = Import-PackageProvider -Name 'NuGet' -RequiredVersion $nuGetProviderVersion -Force
}

Write-Progress -Activity 'Bootstrap:' -PercentComplete 10 -CurrentOperation "Ensuring Gallery $Gallery is trusted"

# Fail if the given PSGallery is not registered.
$previousGalleryInstallationPolicy = (Get-PSRepository -Name $Gallery -ErrorAction 'Stop').InstallationPolicy

Set-PSRepository -Name $Gallery -InstallationPolicy 'Trusted' -ErrorAction 'Ignore'

try
{
    Write-Progress -Activity 'Bootstrap:' -PercentComplete 25 -CurrentOperation 'Checking PowerShellGet'

    # Ensure the module is loaded and retrieve the version you have.
    $powerShellGetVersion = (Import-Module -Name 'PowerShellGet' -PassThru -ErrorAction 'SilentlyContinue').Version

    Write-Verbose -Message "Bootstrap: The PowerShellGet version is $powerShellGetVersion"

    # Versions below 2.0 are considered old, unreliable & not recommended
    if (-not $powerShellGetVersion -or ($powerShellGetVersion -lt [System.Version] '2.0' -and -not $AllowOldPowerShellGetModule))
    {
        Write-Progress -Activity 'Bootstrap:' -PercentComplete 40 -CurrentOperation 'Installing newer version of PowerShellGet'

        $installPowerShellGetParameters = @{
            Name               = 'PowerShellGet'
            Force              = $True
            SkipPublisherCheck = $true
            AllowClobber       = $true
            Scope              = $Scope
            Repository         = $Gallery
        }

        switch ($PSBoundParameters.Keys)
        {
            'Proxy'
            {
                $installPowerShellGetParameters.Add('Proxy', $Proxy)
            }

            'ProxyCredential'
            {
                $installPowerShellGetParameters.Add('ProxyCredential', $ProxyCredential)
            }

            'GalleryCredential'
            {
                $installPowerShellGetParameters.Add('Credential', $GalleryCredential)
            }
        }

        Write-Progress -Activity 'Bootstrap:' -PercentComplete 60 -CurrentOperation 'Installing newer version of PowerShellGet'

        Install-Module @installPowerShellGetParameters

        Remove-Module -Name 'PowerShellGet' -Force -ErrorAction 'SilentlyContinue'
        Remove-Module -Name 'PackageManagement' -Force

        $powerShellGetModule = Import-Module PowerShellGet -Force -PassThru

        $powerShellGetVersion = $powerShellGetModule.Version.ToString()

        Write-Information -MessageData "Bootstrap: PowerShellGet version loaded is $powerShellGetVersion"
    }

    # Try to import the PSDepend module from the available modules.
    $getModuleParameters = @{
        Name          = 'PSDepend'
        ListAvailable = $true
    }

    $psDependModule = Get-Module @getModuleParameters

    if ($PSBoundParameters.ContainsKey('MinimumPSDependVersion'))
    {
        try
        {
            $psDependModule = $psDependModule | Where-Object -FilterScript { $_.Version -ge $MinimumPSDependVersion }
        }
        catch
        {
            throw ('There was a problem finding the minimum version of PSDepend. Error: {0}' -f $_)
        }
    }

    if (-not $psDependModule)
    {
        # PSDepend module not found, installing or saving it.
        if ($PSDependTarget -in 'CurrentUser', 'AllUsers')
        {
            Write-Debug -Message "PSDepend module not found. Attempting to install from Gallery $Gallery."

            Write-Warning -Message "Installing PSDepend in $PSDependTarget Scope."

            $installPSDependParameters = @{
                Name               = 'PSDepend'
                Repository         = $Gallery
                Force              = $true
                Scope              = $PSDependTarget
                SkipPublisherCheck = $true
                AllowClobber       = $true
            }

            if ($MinimumPSDependVersion)
            {
                $installPSDependParameters.Add('MinimumVersion', $MinimumPSDependVersion)
            }

            Write-Progress -Activity 'Bootstrap:' -PercentComplete 75 -CurrentOperation "Installing PSDepend from $Gallery"

            Install-Module @installPSDependParameters
        }
        else
        {
            Write-Debug -Message "PSDepend module not found. Attempting to Save from Gallery $Gallery to $PSDependTarget"

            $saveModuleParameters = @{
                Name       = 'PSDepend'
                Repository = $Gallery
                Path       = $PSDependTarget
                Force      = $true
            }

            if ($MinimumPSDependVersion)
            {
                $saveModuleParameters.add('MinimumVersion', $MinimumPSDependVersion)
            }

            Write-Progress -Activity 'Bootstrap:' -PercentComplete 75 -CurrentOperation "Saving & Importing PSDepend from $Gallery to $Scope"

            Save-Module @saveModuleParameters
        }
    }

    Write-Progress -Activity 'Bootstrap:' -PercentComplete 80 -CurrentOperation 'Loading PSDepend'

    $importModulePSDependParameters = @{
        Name        = 'PSDepend'
        ErrorAction = 'Stop'
        Force       = $true
    }

    if ($PSBoundParameters.ContainsKey('MinimumPSDependVersion'))
    {
        $importModulePSDependParameters.Add('MinimumVersion', $MinimumPSDependVersion)
    }

    # We should have successfully bootstrapped PSDepend. Fail if not available.
    $null = Import-Module @importModulePSDependParameters

    if ($WithYAML)
    {
        Write-Progress -Activity 'Bootstrap:' -PercentComplete 82 -CurrentOperation 'Verifying PowerShell module PowerShell-Yaml'

        if (-not (Get-Module -ListAvailable -Name 'PowerShell-Yaml'))
        {
            Write-Progress -Activity 'Bootstrap:' -PercentComplete 85 -CurrentOperation 'Installing PowerShell module PowerShell-Yaml'

            Write-Verbose -Message "PowerShell-Yaml module not found. Attempting to Save from Gallery $Gallery to $PSDependTarget"

            $SaveModuleParam = @{
                Name       = 'PowerShell-Yaml'
                Repository = $Gallery
                Path       = $PSDependTarget
                Force      = $true
            }

            Save-Module @SaveModuleParam
        }
        else
        {
            Write-Verbose "PowerShell-Yaml is already available"
        }
    }

    Write-Progress -Activity 'Bootstrap:' -PercentComplete 90 -CurrentOperation 'Invoke PSDepend'

    Write-Progress -Activity "PSDepend:" -PercentComplete 0 -CurrentOperation "Restoring Build Dependencies"

    if (Test-Path -Path $DependencyFile)
    {
        $psDependParameters = @{
            Force = $true
            Path  = $DependencyFile
        }

        # TODO: Handle when the Dependency file is in YAML, and -WithYAML is specified.
        Invoke-PSDepend @psDependParameters
    }

    Write-Progress -Activity "PSDepend:" -PercentComplete 100 -CurrentOperation "Dependencies restored" -Completed

    Write-Progress -Activity 'Bootstrap:' -PercentComplete 100 -CurrentOperation "Bootstrap complete" -Completed
}
finally
{
    # Reverting the Installation Policy for the given gallery
    Set-PSRepository -Name $Gallery -InstallationPolicy $previousGalleryInstallationPolicy
    Write-Verbose -Message "Project Bootstrapped, returning to Invoke-Build"
}
