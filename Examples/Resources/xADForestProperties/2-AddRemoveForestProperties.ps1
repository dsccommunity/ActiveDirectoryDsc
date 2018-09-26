<#
.EXAMPLE
    This example manages the Service and User Principal name suffixes in the Consto.com
    forest by adding and removing the desired suffixes.  This will not overwrite existing
    suffixes in the forest.
#>
configuration Example
{
    Import-DscResource -ModuleName xActiveDirectory

    node localhost
    {
        xADForestProperties ContosoProperties
        {
            ForestName                          = 'contoso.com'
            ServicePrincipalNameSuffixToRemove  = 'test.com'
            ServicePrincipalNameSuffixToInclude = 'test.net'
            UserPrincipalNameSuffixToRemove     = 'pester.net'
            UserPrincipalNameSuffixToInclude    = 'cloudapp.net', 'fabrikam.com'
        }
    }
}