<#
    .EXAMPLE
        In this example we will create a managed service account.
#>

configuration Example
{
    Import-DscResource -Module xActiveDirectory

    Node localhost
    {
        xADManagedServiceAccount ExampleMSA
        {
            Ensure             = 'Present'
            ServiceAccountName = 'Service01'
        }
    }
}
