# culture="en-US"
ConvertFrom-StringData @'
    QueryingFineGrainedPasswordPolicy               = Querying Active Directory domain '{0}' fine grained password policy. (ADFGPP0001)
    UpdatingFineGrainedPasswordPolicy               = Updating Active Directory domain '{0}' fine grained password policy. (ADFGPP0002)
    CreatingFineGrainedPasswordPolicy               = Creating Active Directory domain '{0}' fine grained password policy. (ADFGPP0003)
    RemovingFineGrainedPasswordPolicy               = Removing Active Directory domain '{0}' fine grained password policy. (ADFGPP0004)
    SettingPasswordPolicyValue                      = Setting fine grained password policy '{0}' property to '{1}'. (ADFGPP0005)
    ResourceInDesiredState                          = Resource '{0}' is in the desired state. (ADFGPP0006)
    ResourceNotInDesiredState                       = Resource '{0}' is NOT in the desired state. (ADFGPP0007)
    ResourceConfiguration                           = Resource '{0}' configuration: {1}. (ADFGPP0008)
    ResourceConfigurationError                      = Error setting resource '{0}'. (ADFGPP0009)
    FineGrainedPasswordPolicySubjectNotFoundMessage = Subject '{0}' was not found. (ADFGPP0010)
    RetrieveFineGrainedPasswordPolicyError          = Error retrieving fine grained password policy '{0}'. (ADFGPP0011)
    RetrieveFineGrainedPasswordPolicySubjectError   = Error retrieving fine grained password policy subject '{0}'. (ADFGPP0012)
    ResourceExistsButShouldNotMessage               = Fine grained password policy '{0}' exists but should not. (ADFGPP0013)
    ResourceDoesNotExistButShouldMessage            = Fine grained password policy '{0}' does not exist but should. (ADFGPP0014)
'@
