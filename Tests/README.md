# Running tests

## Run integration tests in Hyper-V (PowerShell Direct)

### Create Hyper-V base image template

There are many blog articles explaining this, just search for
"create a hyper-v template" in your favorite search engine.

The basic steps to create a base image template for the PC that should
host the Hyper-V virtual machines are.

1. Create VM with Windows Server 2016 or later (Desktop Experience or
   Server Core).
1. Export the VM.

The below steps will help to create a base image template that will be
used to create the one or more servers to run tests on.

>**Note:** All these steps are expected to be run in the same elevated
>PowerShell prompt. It also expect that you have downloaded the appropriate
>installation media, for example from [Windows Server Evaluations](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019).

<!-- markdownlint-disable MD031 - Fenced code blocks should be surrounded by blank lines -->
1. Create a Hyper-VM (Generation 2). In an elevated PowerShell prompt run
   this.
   ```powershell
   $pathWindowsServerIso = 'C:\_images\17763.379.190312-0539.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso'
   $virtualHardDiskPath = Get-VMHost | Select-Object -ExpandProperty 'VirtualHardDiskPath'

   $newVmParameters = @{
        Name = 'DSCAD-template'
        BootDevice = 'CD'
        MemoryStartupBytes = 4GB
        NoVHD = $true
        Generation = 2
        SwitchName = 'Default Switch'
    }

    $vm = New-VM @newVmParameters
    Set-VM -VM $vm -AutomaticCheckpointsEnabled $false -DynamicMemory
    $vmDiskPath = Join-Path -Path $virtualHardDiskPath -ChildPath 'DSCAD-template.vhdx'
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
   $templatesPath = 'C:\Hyper-V\Templates'
   New-Item -Path $templatesPath -ItemType 'Directory' -Force
   ```
1. Export the VM base image template.
   ```powershell
   Export-VM -VM $vm -Path $templatesPath
   ```
1. (Optional) The exported VM can be deleted once the export is finished.
   ```powershell
   Remove-VM -VM $vm -Force
   Remove-Item -Path $vmDiskPath -Force
   ```
<!-- markdownlint-enable MD031 -->

### Deploy Hyper-V virtual machines

This will deploy three virtual machines using the virtual machine template
exported in the previous step. These steps assume you have a PC with enough
memory (~32GB) and disk (~60GB) on the PC that will host the virtual machines.

>You can make changes to memory before starting the virtual machines, or
>change the default memory in the template above before exporting the base
>image template.

<!-- markdownlint-disable MD031 - Fenced code blocks should be surrounded by blank lines -->
1. Create a Hyper-V virtual switch to use for the private network between
   the virtual machines. _**Note:** Running the cmdlet `New-VMSwitch` more_
   _than once will create more than one virtual switch with the same name._
   ```powershell
   $virtualSwitchName = 'DSCADLabPrivate'
   if (-not (Get-VMSwitch -Name $virtualSwitchName))
   {
       New-VMSwitch -Name $virtualSwitchName -SwitchType 'Private'
   }
   ```
1. Deploy three virtual machines that will be used to configure three
   domain controllers.
   ```powershell
   $templateName = 'DSCAD-template'
   $templatesPath = 'C:\Hyper-V\Templates'
   $virtualMachinesPath = 'C:\Hyper-V\Virtual Machines'

   $vmTemplatePath = (Get-ChildItem -Path (Join-Path -Path $templatesPath -ChildPath $templateName) -Recurse -Filter '*.vmcx').FullName

   $vmNames = @(
       'dc01'
       'dc02'
       'dc03'
   )

   foreach ($vmName in $vmNames)
   {
       $vmPath = Join-Path -Path $virtualMachinesPath -ChildPath $vmName
       $vm = Import-VM -Path $vmTemplatePath -Copy -GenerateNewId -VirtualMachinePath $vmPath -VhdDestinationPath  $vmPath -SnapshotFilePath $vmPath -SmartPagingFilePath $vmPath
       Set-VM -VM $vm -NewVMName $vmName -DynamicMemory
       Set-VM -VM $vm -AutomaticCheckpointsEnabled $false
       Get-VMNetworkAdapter -VM $vm | Connect-VMNetworkAdapter -SwitchName $virtualSwitchName
   }

   Get-VM -Name $vmnames | Start-VM -Verbose
   ```
1. On each started VM finish the installation by configure the following
   in the Hyper-V Virtual Machine Connection.
   - Localization
   - (Optional) Product key
   - Accept license terms
   - Set local administrator password to `adminP@ssw0rd1`. _**Note:** This_
     _password must be the same as the one used in the integration test._
<!-- markdownlint-enable MD031 -->

### Test prerequisites

The below steps assumes the virtual machines does not have access to the
Internet.

<!-- markdownlint-disable MD031 - Fenced code blocks should be surrounded by blank lines -->
1. Install the dependent DSC resource modules on the node that hosts your
   virtual machines, the same as from where the integration tests will be run.
   ```powershell
   $dependentModules = @(
       'Pester',
       'PSDepend',
       'PSDscResources',
       'ComputerManagementDsc',
       'NetworkingDsc'
   )

   Install-Module -Name $dependentModules
   ```
1. Open a PowerShell Direct session to each virtual machine.
   ```powershell
   $localAdminPassword = ConvertTo-SecureString 'adminP@ssw0rd1' -AsPlainText -Force
   $localAdminUsername = 'Administrator'

   $newObjectParameters = @{
       TypeName = 'System.Management.Automation.PSCredential'
       ArgumentList = @(
           $localAdminUsername,
           $localAdminPassword
       )
   }

   $localAdminCredential = New-Object @newObjectParameters

   $dc01Session = New-PSSession -VMName 'dc01' -Credential $localAdminCredential
   $dc02Session = New-PSSession -VMName 'dc02' -Credential $localAdminCredential
   $dc03Session = New-PSSession -VMName 'dc03' -Credential $localAdminCredential
   ```
1. Copy the dependent modules to each of the virtual machines.
   ```powershell
   $dependentModule = Get-Module -ListAvailable -Name $dependentModules |
    Sort-Object -Property 'Version' |
    Sort-Object -Unique

   foreach ($module in $dependentModule)
   {
       $sourceModulePath = $module.ModuleBase
       $moduleVersionFolder = Split-Path -Path $module.ModuleBase -Leaf
       $destinationModulePath = Join-Path -Path (Join-Path -Path 'C:\Program Files\WindowsPowerShell\Modules' -ChildPath $module.Name) -ChildPath $moduleVersionFolder

       Copy-Item -ToSession $dc01Session -Path $sourceModulePath -Destination $destinationModulePath -Recurse -Force
       Copy-Item -ToSession $dc02Session -Path $sourceModulePath -Destination $destinationModulePath -Recurse -Force
       Copy-Item -ToSession $dc03Session -Path $sourceModulePath -Destination $destinationModulePath -Recurse -Force
   }
   ```
1. **Important!** Change to folder to root of your local working repository
   folder, e.g. cd 'c:\source\xActiveDirectory'.
1. Create the configuration .mof and the metadata .mof file on the respective
   nodes.
   ```powershell
   Invoke-Command -Session $dc01Session -FilePath '.\Tests\TestHelpers\Prepare-DscLab-dc01.ps1'
   Invoke-Command -Session $dc02Session -FilePath '.\Tests\TestHelpers\Prepare-DscLab-dc02.ps1'
   Invoke-Command -Session $dc03Session -FilePath '.\Tests\TestHelpers\Prepare-DscLab-dc03.ps1'
   ```
1. Configure the DSC Local Configuration Manager (LCM) on each virtual
   machine using the metadata .mof created in previous step.
   ```powershell
   Invoke-Command -Session $dc01Session,$dc02Session,$dc03Session -ScriptBlock {
       Set-DscLocalConfigurationManager -Path 'C:\DSC\Configuration' -ComputerName 'localhost' -Verbose -Force
   }
   ```
1. Run the configuration on each virtual machine to set up all the
   prerequisites. **The virtual machine will reboot during this.**
   ```powershell
   Invoke-Command -Session $dc01Session,$dc02Session,$dc03Session -ScriptBlock {
       Start-DscConfiguration -Path "C:\DSC\Configuration\" -ComputerName 'localhost' -Wait -Force -Verbose
   }
   ```
1. Wait until the node has been restarted and the rest of the configuration
   has been applied. This should report the status *Success* once the
   configuration is finished. _**Note:** Since the virtual machines rebooted_
   _we need to reconnect to the sessions._
   ```powershell
   $dc01Session = New-PSSession -VMName 'dc01' -Credential $localAdminCredential
   $dc02Session = New-PSSession -VMName 'dc02' -Credential $localAdminCredential
   $dc03Session = New-PSSession -VMName 'dc03' -Credential $localAdminCredential

   Invoke-Command -Session $dc01Session,$dc02Session,$dc03Session -ScriptBlock {
       Get-DscConfigurationStatus
   }
   ```
1. Clone the latest test framework into the local repository folder. _**Note:**_
   _This requires `git`. The test framework will also be cloned when running_
   _a unit test._
   ```powershell
   .\Assert-TestEnvironment.ps1
   ```
1. At this point it would be good to checkpoint the servers.
   ```powershell
   Checkpoint-VM -Name 'dc01','dc02','dc03' -SnapshotName 'WithPreReq'
   ```

### Running the integration tests

By reverting to the checkpoint created before, these tests can be run
several times. The integration tests that depend on an already existing
domain can be run several times without reverting to the checkpoint. The
resources that need a clean environment are the resources that configures
the domain, e.g. `xADDomain` and `xADDomainController`.

1. **Important!** Change to folder to root of your local working repository
   folder, e.g. cd 'c:\source\xActiveDirectory'.
1. Copy resource module code to a local folder on each virtual machine,
   e.g. `C:\source\xActiveDirectory`.
   _**NOTE:** Do not copy the resource being tested to a path that exist_
   _in `$env:PSModulePath`, that will generate an error that multiple_
   _modules exist on the node when running the integration tests._
   ```powershell
   $sourceRepositoryPath = '.'
   $destinationRepositoryPath = 'C:\Source\xActiveDirectory'

    # This way we skip the hidden folder '.git'.
   Get-ChildItem -Path $sourceRepositoryPath | Copy-Item -ToSession $dc01Session -Destination $destinationRepositoryPath -Recurse -Force
   Get-ChildItem -Path $sourceRepositoryPath | Copy-Item -ToSession $dc02Session -Destination $destinationRepositoryPath -Recurse -Force
   Get-ChildItem -Path $sourceRepositoryPath | Copy-Item -ToSession $dc03Session -Destination $destinationRepositoryPath -Recurse -Force
   ```
1. This runs the actual integration tests.
   ```powershell
   Invoke-Command -Session $dc01Session -ScriptBlock {
        cd 'c:\source\xActiveDirectory'
        .\Assert-TestEnvironment.ps1 -Tags 'LoadDscResourceKitTypes'

       Invoke-Pester -Path '.\Tests\Integration\MSFT_xADComputer.Integration.Tests.ps1'
   }
   ```
<!-- markdownlint-enable MD031 -->
