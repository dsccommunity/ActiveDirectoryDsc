Configuration xADRecycleBin {
    Param(
        [Parameter(Mandatory = $true)]
        [System.String]
        $ForestFQDN,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $EnterpriseAdministratorCredential
    )

    Import-DscResource -ModuleName xActiveDirectory

    xADOptionalFeature RecycleBin
    {
        FeatureName = "Recycle Bin Feature"
        EnterpriseAdministratorCredential = $EnterpriseAdministratorCredential
        ForestFQDN = $ForestFQDN
    }
}
