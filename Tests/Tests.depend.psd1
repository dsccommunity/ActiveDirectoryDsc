<#
    .DESCRIPTION
        This is the dependency file for use with Assert-TestEnvironment.ps1 and/or
        Invoke-PSDepend (PSSDepend).
#>
@{
    RemoveTestFramework = @{
        DependencyType = 'Command'
        Source = '
            $testFrameWorkPath = Join-Path -Path $PWD -ChildPath ''DscResource.Tests''
            if (Test-Path -Path $testFrameWorkPath)
            {
                Write-Verbose -Message ''Removing local test framework repository.''
                Remove-Item -Path (Join-Path -Path $PWD -ChildPath ''DscResource.Tests'') -Recurse -Force
            }
        '
    }

    'CloneTestFramework' = @{
        DependencyType = 'Git'
        Name = 'https://github.com/PowerShell/DscResource.Tests'
        Version = 'dev'
        DependsOn = 'RemoveTestFramework'
    }

    LoadDscResourceKitTypes = @{
        DependencyType = 'Command'
        Source = '
            if (-not (''Microsoft.DscResourceKit.Test'' -as [Type]))
            {
                Write-Verbose -Message ''Loading the Microsoft.DscResourceKit types into the current session.''
                $typesSourceFile = Join-Path -Path ''$PWD\DscResource.Tests'' -ChildPath ''Microsoft.DscResourceKit.cs''
                Add-Type -Path $typesSourceFile -WarningAction SilentlyContinue
            }
            else
            {
                Write-Verbose -Message ''The Microsoft.DscResourceKit types was already loaded into the current session.''
            }
        '
        DependsOn = 'CloneTestFramework'
    }
}
