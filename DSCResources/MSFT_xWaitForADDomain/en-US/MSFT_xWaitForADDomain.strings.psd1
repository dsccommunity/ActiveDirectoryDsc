# culture='en-US'
ConvertFrom-StringData @'
    GetDomain                 = Getting Domain '{0}'. (WFADD0001)
    DomainNotFoundRetrying    = Domain '{0}' not found. Will retry again after {1} seconds. (WFADD0002)
    DomainNotFoundRebooting   = Domain '{0}' not found after {1} attempts with {2} sec interval. Rebooting.  Reboot attempt number {3} of {4}. (WFADD0003)
    DomainNotFoundAfterReboot = Domain '{0}' NOT found after {1} Reboot attempts. (WFADD0004)
    DomainNotFoundAfterRetry  = Domain '{0}' NOT found after {1} attempts. (WFADD0005)
    DomainInDesiredState      = Domain '{0}' is in the desired state. (WFADD0006)
    DomainNotInDesiredState   = Domain '{0}' is not in the desired state. (WFADD0007)
    CheckDomain               = Checking for domain '{0}'. (WFADD0008)
    FoundDomain               = Found domain '{0}'. (WFADD0009)
    DomainNotFound            = Domain '{0}' not found. (WFADD0010)
'@
