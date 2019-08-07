# culture="en-US"
ConvertFrom-StringData @'
    ExistingDomainMemberError            = Computer is already a domain member. Cannot create a new '{0}' domain. (ADD0001)
    InvalidCredentialError               = Domain '{0}' is available, but invalid credentials were supplied. (ADD0002)
    QueryDomainWithLocalCredential       = Computer is a domain member; querying domain '{0}' using local credential. (ADD0003)
    QueryDomainWithCredential            = Computer is a workgroup member; querying for domain '{0}' using supplied credential. (ADD0004)
    DomainFound                          = Active Directory domain '{0}' found. (ADD0005)
    DomainNotFound                       = Active Directory domain '{0}' cannot be found. (ADD0006)
    CreatingChildDomain                  = Creating domain '{0}' as a child of domain '{1}'. (ADD0007)
    CreatedChildDomain                   = Child domain '{0}' created. (ADD0008)
    CreatingForest                       = Creating AD forest '{0}'. (ADD0009)
    CreatedForest                        = AD forest '{0}' created. (ADD0010)
    ResourcePropertyValueIncorrect       = Property '{0}' value is incorrect; expected '{1}', actual '{2}'. (ADD0011)
    ResourceInDesiredState               = Resource '{0}' is in the desired state. (ADD0012)
    ResourceNotInDesiredState            = Resource '{0}' is NOT in the desired state. (ADD0013)
    RetryingGetADDomain                  = Attempt {0} of {1} to call Get-ADDomain failed, retrying in {2} seconds. (ADD0014)
    UnhandledError                       = Unhandled error occured, detail here: {0} (ADD0015)
    FaultExceptionAndDomainShouldExist   = ServiceModel FaultException detected and domain should exist, performing retry. (ADD0016)
'@
