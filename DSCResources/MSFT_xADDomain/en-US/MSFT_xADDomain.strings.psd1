# culture="en-US"
ConvertFrom-StringData @'
    ExistingDomainMemberError            = Computer is already a domain member. Cannot create a new '{0}' domain?
    InvalidCredentialError               = Domain '{0}' is available, but invalid credentials were supplied.
    QueryDomainWithLocalCredential       = Computer is a domain member; querying domain '{0}' using local credential ...
    QueryDomainWithCredential            = Computer is a workgroup member; querying for domain '{0}' using supplied credential ...
    DomainFound                          = Active Directory domain '{0}' found.
    DomainNotFound                       = Active Directory domain '{0}' cannot be found.
    CreatingChildDomain                  = Creating domain '{0}' as a child of domain '{1}' ...
    CreatedChildDomain                   = Child domain '{0}' created.
    CreatingForest                       = Creating AD forest '{0}' ...
    CreatedForest                        = AD forest '{0}' created.
    ResourcePropertyValueIncorrect       = Property '{0}' value is incorrect; expected '{1}', actual '{2}'.
    ResourceInDesiredState               = Resource '{0}' is in the desired state.
    ResourceNotInDesiredState            = Resource '{0}' is NOT in the desired state.
    RetryingGetADDomain                  = Attempt {0} of {1} to call Get-ADDomain failed, retrying in {2} seconds.
    UnhandledError                       = Unhandled error occured, detail here: {0}
    FaultExceptionAndDomainShouldExist   = ServiceModel FaultException detected and domain should exist, performing retry...
'@
