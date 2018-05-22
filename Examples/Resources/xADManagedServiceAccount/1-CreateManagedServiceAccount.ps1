<#
    .EXAMPLE
        In this example we will create a managed service account.
#>

configuration Example
{
    Import-DscResource -Module xActiveDirectory

    Node $AllNodes.NodeName
    {
        xADManagedServiceAccount ExampleMSA
        {
            Ensure             = 'Present'
            ServiceAccountName = 'ExampleMSA'
        }
    }
}
