# culture="en-US"
ConvertFrom-StringData @'
MissingRoleMessage        = Please ensure that the {0} role is installed
CheckingTrustMessage      = Checking if Trust between {0} and {1} exists ...
TestTrustMessage          = Trust is {0} between source and target domains and it should be {1}
RemovingTrustMessage      = Removing trust between {0} and {1} domains ...
DeleteTrustMessage        = Trust between specified domains is now absent
AddingTrustMessage        = Adding domain trust between {0} and {1}  ...
SetTrustMessage           = Trust between specified domains is now present
CheckPropertyMessage      = Checking for {0} between domains ...
DesiredPropertyMessage    = {0} between domains is set correctly
NotDesiredPropertyMessage = {0} between domains is not correct. Expected {1}, actual {2}
SetPropertyMessage        = {0} between domains is set
TrustPresentMessage       = Trust between domains {0} and {1} is present
TrustAbsentMessage        = Trust between domains {0} and {1} is absent
'@
