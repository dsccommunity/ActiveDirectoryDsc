# culture='en-US'
ConvertFrom-StringData @'
    GetServicePrincipalName               = Getting service principal name '{0}'.
    ServicePrincipalNameAbsent            = Service principal name '{0}' is absent.
    ServicePrincipalNamePresent           = Service principal name '{0}' is present on account(s) '{1}'
    AccountNotFound                       = AD object with SamAccountName '{0}' not found!
    RemoveServicePrincipalName            = Removing service principal name '{0}' from account '{1}'.
    AddServicePrincipalName               = Adding service principal name '{0}' to account '{1}.
    ServicePrincipalNameInDesiredState    = Service principal name '{0}' is in the desired state.
    ServicePrincipalNameNotInDesiredState = Service principal name '{0}' is not in the desired state.
'@
