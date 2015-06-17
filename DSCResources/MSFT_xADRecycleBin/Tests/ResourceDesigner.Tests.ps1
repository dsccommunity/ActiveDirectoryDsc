Describe 'xADRecycleBin' {
    Context 'xDscResouceDesigner' {
        It 'Pass Test-xDscResource' {
            $rootDirectory = $pwd.Path + "\..\"
            $oldPSModulePath = $env:PSModulePath
            $env:PSModulePath = $env:PSModulePath + ";" + $rootDirectory

            Write-Host "psmodulepath: $env:PSModulePath"
            Test-xDscResource xADRecycleBin -Verbose | Should Be $True
            $env:PSModulePath = $oldPSModulePath
        }

        It 'Pass Test-xDscSchema' {
            Test-xDscSchema -Path ".\DSCResources\MSFT_xADRecycleBin\MSFT_xADRecycleBin.schema.mof" -Verbose | Should Be $True
        }
    }
}
