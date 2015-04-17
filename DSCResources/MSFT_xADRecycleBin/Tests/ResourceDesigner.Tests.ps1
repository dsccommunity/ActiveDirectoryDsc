Describe 'xADRecycleBin' {
  Context 'xDscResouceDesigner' {
    Test-xDscResource xADRecycleBin -Verbose | Should Be $True
  }
}

Describe 'xADRecycleBin' {
  Context 'xDscResouceDesigner' {
    Test-xDscSchema -Path "$Env:ProgramFiles\WindowsPowerShell\Modules\xActiveDirectory\DSCResources\MSFT_xADRecycleBin\MSFT_xADRecycleBin.schema.mof" -Verbose | Should Be $True
  }
}
