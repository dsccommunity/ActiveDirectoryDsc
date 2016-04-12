configuration Example_xADRequestODJ
{
Param(
    [parameter(Mandatory = $true)]
    [System.String]
    $CompterName,
    
    [parameter(Mandatory = $true)]
    [System.String]
    $DomainName,
    
    [parameter(Mandatory = $true)]
    [System.String]
    $Path,

    [ValidateNotNull()]
    [System.String]
    $OU
)

    Import-DscResource -Module xActiveDirectory

    Node $AllNodes.NodeName
    {
        xADRequestODJ ExampleRequestODJ
        {
           ComputerName = $ComputerName
           DomainName = $DomainName
           Path = $Path
           OU = $OU
        }
    }
}

Example_xADRequestODJ -ComputerName 'NANOSERVER1' -DomainName 'CONTOSO.COM' -OU 'cn=Servers' -Path 'c:\NANOSERVER1-ODJ.txt' -ConfigurationData $ConfigurationData

Start-DscConfiguration -Path .\Example_xADRequestODJ -Wait -Verbose
