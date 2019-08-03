Configuration Example_xADOptionalFeature
{
Param(
    [Parameter(Mandatory = $true)]
    [System.String]
    $ForestFQDN,

    [Parameter(Mandatory = $true)]
    [System.Management.Automation.PSCredential]
    $EACredential
)

    Import-DscResource -Module xActiveDirectory

    Node $AllNodes.NodeName
    {
        xADOptionalFeature RecycleBin
        {
           FeatureName = "Recycle Bin Feature"
           EnterpriseAdministratorCredential = $EACredential
           ForestFQDN = $ForestFQDN
        }
    }
}

$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName = '2012r2-dc'
            PSDscAllowPlainTextPassword = $true
        }
    )
}

Example_xADOptionalFeature -EACredential (Get-Credential contoso\administrator) -ForestFQDN 'contoso.com' -ConfigurationData $ConfigurationData

Start-DscConfiguration -Path .\Example_xADOptionalFeature -Wait -Verbose -WhatIf

Start-DscConfiguration -Path .\Example_xADOptionalFeature -Wait -Verbose
