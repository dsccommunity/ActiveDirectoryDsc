# culture="en-US"
ConvertFrom-StringData @'
    QueryingDomainPasswordPolicy   = Querying Active Directory domain '{0}' default password policy.
    UpdatingDomainPasswordPolicy   = Updating Active Directory domain '{0}' default password policy.
    SettingPasswordPolicyValue     = Setting password policy '{0}' property to '{1}'.
    ResourcePropertyValueIncorrect = Property '{0}' value is incorrect; expected '{1}', actual '{2}'.
    ResourceInDesiredState         = Resource '{0}' is in the desired state.
    ResourceNotInDesiredState      = Resource '{0}' is NOT in the desired state.
'@
