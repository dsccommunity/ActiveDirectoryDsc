Describe 'xADRecycleBin' {
    Context 'xDscResouceDesigner' {
        It 'Pass Test-xDscResource' {
            $rootDirectory = Split-Path $pwd.Path -Parent
            $oldPSModulePath = $env:PSModulePath
            $env:PSModulePath = $env:PSModulePath + ";" + $rootDirectory
            Test-xDscResource xADRecycleBin -Verbose | Should Be $True
            $env:PSModulePath = $oldPSModulePath
        }

        It 'Pass Test-xDscSchema' {
            Test-xDscSchema -Path ".\DSCResources\MSFT_xADRecycleBin\MSFT_xADRecycleBin.schema.mof" -Verbose | Should Be $True
        }
    }
}
