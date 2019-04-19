<#
    .EXAMPLE
        In this example we will create a managed service account.
#>

configuration Example
{
    Import-DscResource -Module xActiveDirectory

    Node localhost
    {
        xADManagedServiceAccount ExampleSingleMSA
        {
            Ensure             = 'Present'
            ServiceAccountName = 'Service01'
        }
    }
}
