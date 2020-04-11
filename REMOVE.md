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
