Describe 'xADRecycleBin' {
    Context 'xDscResouceDesigner' {
        It 'Pass Test-xDscResource' {
            Test-xDscResource xADRecycleBin -Verbose | Should Be $True
        }

        It 'Pass Test-xDscSchema' {
            Test-xDscSchema -Path ".\DSCResources\MSFT_xADRecycleBin\MSFT_xADRecycleBin.schema.mof" -Verbose | Should Be $True
        }
    }
}
