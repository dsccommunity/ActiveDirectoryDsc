# culture='en-US'
ConvertFrom-StringData @'
    GetDomain                 = Getting Domain '{0}'.
    DomainNotFoundRetrying    = Domain '{0}' not found. Will retry again after {1} seconds.
    DomainNotFoundRebooting   = Domain '{0}' not found after {1} attempts with {2} sec interval. Rebooting.  Reboot attempt number {3} of {4}.
    DomainNotFoundAfterReboot = Domain '{0}' NOT found after {1} Reboot attempts.
    DomainNotFoundAfterRetry  = Domain '{0}' NOT found after {1} attempts.
    DomainInDesiredState      = Domain '{0}' is in the desired state.
    DomainNotInDesiredState   = Domain '{0}' is not in the desired state.
    CheckDomain               = Checking for domain '{0}' ...
    FoundDomain               = Found domain '{0}'.
    DomainNotFound            = Domain '{0}' not found.
'@
