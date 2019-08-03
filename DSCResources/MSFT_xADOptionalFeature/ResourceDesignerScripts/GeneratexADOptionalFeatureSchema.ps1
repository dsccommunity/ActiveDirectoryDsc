New-xDscResource -Name MSFT_xADOptionalFeature -FriendlyName xADOptionalFeature -ModuleName xActiveDirectory -Path . -Force -Property @(
    New-xDscResourceProperty -Name ForestFQDN -Type String -Attribute Key -Description "Specifies the target Active Directory forest for the change."
    New-xDscResourceProperty -Name FeatureName -Type String -Attribute Key -Description "Specifies the feature to be activated"
    New-xDscResourceProperty -Name EnterpriseAdministratorCredential -Type PSCredential -Attribute Required -Description "Specifies the user account credentials to use to perform this task."
    New-xDscResourceProperty -Name Enabled -Type Boolean -Attribute Read -Description "Shows the current state of the feature i.e. enabled or not"
)
