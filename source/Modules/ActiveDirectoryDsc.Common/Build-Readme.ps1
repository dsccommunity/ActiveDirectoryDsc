<#
    .SYNOPSIS
        Builds the markdown documentation for the common module.

    .DESCRIPTION
        The Build-ReadMe script is used to build the markdown documentation for the common module. this uses functions
        from the PlatyPS PowerShell Module to build the markdown from the PowerShell comment based help in the module.

    .EXAMPLE
        Build-ReadMe

    .PARAMETER Path
        Specifies the output path for the function markdown files.

    .PARAMETER ModulePagePath
        Specifies the output path for the main module markdown file.

    .PARAMETER HelpVersion
        Specifies the version of the help files.

    .PARAMETER ModuleName
        Specifies the name of the main module.

    .PARAMETER CommonModuleName
        Specifies the name of the common module.

    .PARAMETER ModuleRootPath
        Specifies the path of the root of the main module.

    .PARAMETER StubModulePath
        Specifies the path of the stub modules.

    .PARAMETER Description
        Specifies the description for the common module.

    .INPUTS
        None

    .OUTPUTS
        System.IO.FileInfo[]
#>
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
    $StubModulePath = "$ModuleRootPath\tests\Unit\Stubs",

    [Parameter()]
    [System.String]
    $Description = "The $CommonModuleName module is a PowerShell module that contains a set of functions that are " + `
        "common across the $ModuleName Module"
)

Function Remove-MetaData
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.String[]]
        $Content
    )

    $inMetadataBlock = $false
    $newContent = @()
    foreach ($line in $Content)
    {
        if ($line -eq '---')
        {
            if ($inMetadataBlock)
            {
                $inMetadataBlock = $false
            }
            else
            {
                $inMetadataBlock = $true
            }
        }
        else
        {
            if (!$inMetadataBlock)
            {
                $newContent += $line
            }
        }
    }

    return $newContent
}

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1.0

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
    -WithModulePage -ModulePagePath $modulePagePath -HelpVersion $HelpVersion -Force -FwLink 'N/A'
Update-MarkdownHelpModule -Path $Path -RefreshModulePage -ModulePagePath $modulePagePath -AlphabeticParamsOrder `
    -UseFullTypeName | Out-Null

Write-Verbose -Message "Getting contents of $ModulePagePath file"
$modulePageContent = Get-Content -Path $ModulePagePath

Write-Verbose -Message 'Fixing README Markdown link paths'
$modulePageContent = $modulePageContent.Replace('(', '(docs/')

Write-Verbose -Message 'Updating README module description'
$descriptionMarker = '{{ Fill in the Description }}'
$modulePageContent = $modulePageContent.Replace($descriptionMarker, $description)

Write-Verbose -Message 'Removing README Metadata'
$newModulePageContent = Remove-MetaData -Content $modulePageContent

Write-Verbose -Message "Writing updated $ModulePagePath file"
$newModulePageContent | Out-File -FilePath $ModulePagePath -Encoding ascii

Write-Verbose -Message 'Removing Metadata from function markdown files'
$functionMdFiles = Get-ChildItem -Path $Path -Filter '*.md'
foreach ($functionMdFile in $functionMdFiles)
{
    $functionMdFileContent = Get-Content -Path $functionMdFile.FullName
    $newFunctionMdFileContent = Remove-MetaData -Content $functionMdFileContent

    $newFunctionMdFileContent | Out-File -FilePath $functionMdFile.FullName -Encoding ascii
}
