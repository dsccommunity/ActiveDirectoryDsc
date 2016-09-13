<#
  Author: David McWee (MSFT Sr. Consultant)
  Create the MOF, PS1, PSD1 and other necessary module files for this DSC Resource
#>

New-xDscResource -Name MSFT_xADDomainMember -FriendlyName xADDomainMember -ModuleName xActiveDirectory -Path . -Force -Property @(
    New-xDscResourceProperty -Name DomainName -Type String -Attribute Key
    New-xDscResourceProperty -Name ADAdmin -Type PSCredential -Attribute Required
    New-xDscResourceProperty -Name AllowReboot -Type Boolean -Attribute Write
)