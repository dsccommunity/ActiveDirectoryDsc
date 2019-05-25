# Running tests

## Run integration tests in Hyper-V (PowerShell Direct)

The below steps assumes the virtual machines does not have access to the
Internet.

This requires at least one working domain controller.

### Create Hyper-V base image template

There are many blog articles explaining this, just search for
create a hyper-v template" in your favorite search engine.

The basic steps are

1. Create VM with Windows Server 2016 or later (Desktop Experience or
   Server Core).
1. Export the VM.

This can be done with these steps.

>**Note:** All these steps are expected to be run in the same elevated
>PowerShell prompt.

1. Create a Hyper-VM (Generation 2). In an elevated PowerShell prompt run
   this.
   ```powershell
   $virtualHardDiskPath = Get-VMHost | Select-Object -ExpandProperty 'VirtualHardDiskPath'
   $pathWindowsServerIso = 'C:\_images\en_windows_server_2019_x64_dvd_4cb967d8.iso'

   $newVmParameters = @{
        Name = 'DscAD-template'
        BootDevice = 'CD'
        MemoryStartupBytes = 4GB
        NoVHD = $true
        Generation = 2
        SwitchName = 'Default Switch'
    }

    $vm = New-VM @newVmParameters
    Set-VM -VM $vm -AutomaticCheckpointsEnabled $false -DynamicMemory
    $vmDiskPath = Join-Path -Path $virtualHardDiskPath -ChildPath 'DscAD-template.vhdx'
    $vhd = New-VHD -Path $vmDiskPath -SizeBytes 40GB -Dynamic
    Add-VMHardDiskDrive -VM $vm -Path $vhd.Path
    Get-VMDvdDrive -VM $vm | Set-VMDvdDrive -Path $pathWindowsServerIso
    Start-VM -VM $vm
    ```
1. Continue the installation as normal in the Hyper-V Virtual Machine
   Connection.
   1. You don't need to provide a product key.
1. (Optional) Install any updates.
1. (Optional) Make any personal modifications, if they will stick after
   a SysPrep.
1. In an elevated PowerShell prompt run this to
  [Sysprep generalize](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/sysprep--generalize--a-windows-installation)
  and return the VM (image) to the out-of-the-box-experience.
   ```powershell
   C:\Windows\System32\SysPrep\sysprep.exe /quiet /generalize /oobe /shutdown
   ```
1. Create the folder where we store the exported image. _This folder can_
   _be located anywhere._
   ```powershell
   $templatePath = 'C:\Hyper-V\Templates'
   New-Item -Path $templatePath -ItemType 'Directory' -Force
   ```
1. Export the VM base image template.
   ```powershell
   Export-VM -VM $vm -Path $templatePath
   ```
1. (Optional) This VM can be deleted once we exported the image.
   ```powershell
   Remove-VM -VM $vm -Force
   Remove-Item -Path $vmDiskPath -Force
   ```

<!--
1. Install [`git`](https://git-scm.com/download/win) using the default
   configuration. _This is used later to clone the test framework._
1. NOT NECESSARY: Copy any dependent modules to Modules-folder.
// -->

1. Copy Pester to a path in `$env:PSModulePath`.
1. Copy PSDepend to a path in `$env:PSModulePath`.
1. Copy resource module code to a local folder, e.g. `C:\source\xActiveDirectory`.
   _**NOTE:** Do not copy the resource being tested to a path that exist_
   _in `$env:PSModulePath`, that will generate an error that multiple_
   _modules exist on the node._
1. Copy the repository [DscResource.Tests](https://github.com/PowerShell/DscResource.Tests)
   to the root of the folder where the resource module code was copied,
   e.g. `C:\source\xActiveDirectory`.
1. Start a PowerShell prompt with elevated permissions.
1. Run
   ```powershell
   cd 'c:\source\xActiveDirectory'
   .\Assert-TestEnvironment.ps1 -Confirm
   ```
1. **IMPORTANT!** Answer 'No' on the first two questions, and answer
   'Yes' on the third question.
   ```plaintext
   Processing dependency
   Process the dependency 'RemoveTestFramework'?
   [Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): n

   Processing dependency
   Process the dependency 'CloneTestFramework'?
   [Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): n

   Processing dependency
   Process the dependency 'LoadDscResourceKitTypes'?
   [Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): y
   ```
1. Run
   ```powershell
   Invoke-Pester .\Tests\Integration\MSFT_xADComputer.Integration.Tests.ps1
   ```
