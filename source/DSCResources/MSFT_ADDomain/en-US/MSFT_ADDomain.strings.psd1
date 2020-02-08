# culture="en-US"
ConvertFrom-StringData @'
    QueryDomain                        = Querying for domain '{0}'. (ADD0001)
    ADServerDown                       = The AD Server for domain '{0}' is currently down. (ADD0002)
    DomainFound                        = Active Directory domain '{0}' found. (ADD0003)
    DomainNotFound                     = Active Directory domain '{0}' cannot be found. (ADD0004)
    CreatingChildDomain                = Creating domain '{0}' as a child of domain '{1}'. (ADD0005)
    CreatedChildDomain                 = Child domain '{0}' created. (ADD0006)
    CreatingForest                     = Creating AD forest '{0}'. (ADD0007)
    CreatedForest                      = AD forest '{0}' created. (ADD0008)
    DomainInDesiredState               = The domain '{0}' is in the desired state. (ADD0009)
    DomainNotInDesiredState            = The domain '{0}' is NOT in the desired state. (ADD0010)
    RetryingGetADDomain                = Attempt {0} of {1} to call Get-ADDomain failed, retrying in {2} seconds. (ADD0011)
    ExpectedDomain                     = Expected to find the domain '{0}', but it was not found. (ADD0012)
    SysVolPathDoesNotExistError        = The expected SysVol Path '{0}' does not exist. (ADD0013)
    MaxDomainRetriesReachedError       = Maximum Get-ADDomain retries reached and the domain did not respond. (ADD0014)
    GetAdDomainUnexpectedError         = Error getting AD domain '{0}'. (ADD0015)
    GetAdForestUnexpectedError         = Error getting AD forest '{0}'. (ADD0016)
'@
