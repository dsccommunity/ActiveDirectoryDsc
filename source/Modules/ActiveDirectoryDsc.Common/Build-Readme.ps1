[CmdletBinding()]
param
(
    [Parameter()]
    [System.String]
    $Path = 'docs',

    [Parameter()]
    [System.String]
    $ModulePagePath = 'README.md',

    [Parameter()]
    [System.String]
    $HelpVersion = '1.0.0',

    [Parameter()]
    [System.String]
    $ModuleName = 'ActiveDirectoryDsc',

    [Parameter()]
    [System.String]
    $CommonModuleName = "$($ModuleName).Common",

    [Parameter()]
    [System.String]
    $ModuleRootPath = '..\..\..',

    [Parameter()]
    [System.String]
    $StubModulePath = "$ModuleRootPath\tests\Unit\Stubs"
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1.0

$descriptionMarker = '{{ Fill in the Description }}'
$description = "The $CommonModuleName module is a PowerShell module that contains a set of functions that are common across the $ModuleName Module"

Write-Verbose -Message "Building the resource module"
& "$ModuleRootPath\build.ps1" -Tasks build -Verbose:$false


Write-Verbose -Message "Importing the test Stub Modules"
$stubModules = Get-ChildItem -Path $StubModulePath -Filter '*.psm1'
Import-Module -Name $stubModules.FullName -Verbose:$false -Force

Write-Verbose -Message "Force importing the $CommonModuleName module"
$moduleVersion = (Get-ChildItem -Path "$ModuleRootPath\output\$ModuleName")[0].Name
Import-Module $ModuleRootPath\output\$ModuleName\$moduleVersion\Modules\$CommonModuleName -Verbose:$false -Force

Write-Verbose "Adding the PrincipalContext Type"
Add-TypeAssembly -AssemblyName 'System.DirectoryServices.AccountManagement' `
    -TypeName 'System.DirectoryServices.AccountManagement.PrincipalContext'


If (Test-Path -Path $Path)
{
    Write-Verbose -Message "Removing the current $Path directory"
    Remove-Item -Path $Path -Recurse
}

Write-Verbose -Message "Creating the new module markdown help files in $Path"
New-MarkdownHelp -Module $CommonModuleName -OutputFolder $Path -UseFullTypeName -AlphabeticParamsOrder `
    -WithModulePage -ModulePagePath $modulePagePath -HelpVersion $HelpVersion -Force
Update-MarkdownHelpModule -path $Path -RefreshModulePage -ModulePagePath $modulePagePath -AlphabeticParamsOrder `
     -UseFullTypeName | Out-Null

$modulePageContent = Get-Content -Path $ModulePagePath

Write-Verbose 'Fixing README Markdown link paths'
$modulePageContent = $modulePageContent.Replace('(','(docs/')

Write-Verbose 'Updating module description'
$modulePageContent = $modulePageContent.Replace($descriptionMarker,$description)

$modulePageContent | Out-File $ModulePagePath -Encoding ascii
