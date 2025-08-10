# culture="en-US"
ConvertFrom-StringData @'
    QueryDomain                        = Querying for domain '{0}'. (ADD0001)
    DomainFound                        = Active Directory domain '{0}' found. (ADD0003)
    CreatingChildDomain                = Creating domain '{0}' as a child of domain '{1}'. (ADD0004)
    CreatedChildDomain                 = Child domain '{0}' created. (ADD0005)
    CreatingForest                     = Creating AD forest '{0}'. (ADD0006)
    CreatedForest                      = AD forest '{0}' created. (ADD0007)
    DomainInDesiredState               = The domain '{0}' is in the desired state. (ADD0008)
    DomainNotInDesiredState            = The domain '{0}' is NOT in the desired state. (ADD0009)
    SysVolPathDoesNotExistError        = The expected SysVol Path '{0}' does not exist. (ADD0011)
    GetAdForestUnexpectedError         = Error getting AD forest '{0}'. (ADD0014)
    PendingReboot                      = Promotion pending reboot. (ADD0015)
    SuppressReboot                     = No reboot will be signaled to the LCM. (ADD0016)
'@
