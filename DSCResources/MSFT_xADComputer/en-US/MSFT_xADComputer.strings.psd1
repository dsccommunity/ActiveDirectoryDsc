# culture="en-US"
ConvertFrom-StringData @'
    EnabledDeprecatedMessage = DEPRECATED parameter Enabled is being used in this configuration. The parameter Enabled no longer sets nor enforce the Enabled property. Please see more information at https://github.com/PowerShell/xActiveDirectory/blob/master/README.md#xadcomputer. (ADC0001)
    RetrievingComputerAccount = Retrieving the information about the computer account '{0}' from Active Directory. (ADC0002)
    ComputerAccountIsPresent = The computer account '{0}' is present in Active Directory. (ADC0003)
    ComputerAccountIsAbsent = The computer account '{0}' is absent from Active Directory. (ADC0004)
    FailedToRetrieveComputerAccount = Failed to retrieve the computer account '{0}' from Active Directory. (ADC0005)
    TestConfiguration = Determining the current state of the computer account '{0}'.
    ComputerAccountShouldBeAbsent = The computer account '{0}' is present in Active Directory, but expected it to be absent.
    ComputerAccountShouldBePresent = The computer account '{0}' is absent in Active Directory, but expected it to be present.
    ServicePrincipalNamesInDesiredState = The service principal names was in desired state.
    ServicePrincipalNamesNotInDesiredState = The service principal names was '{0}', but expected them to be '{1}'.
    ComputerAccountInDesiredState = The computer account '{0}' is in the desired state.
    ComputerAccountNotInDesiredState = The computer account '{0}' is not in the desired state.

    AddingADComputer                  = Adding Active Directory computer '{0}'.
    AddingADComputerAsDisabled        = Adding a disabled Active Directory computer account '{0}'.
    RemovingADComputer                = Removing Active Directory computer '{0}'.
    UpdatingADComputer                = Updating Active Directory computer '{0}'.
    UpdatingADComputerProperty        = Updating computer property '{0}' with/to '{1}'.
    RemovingADComputerProperty        = Removing computer property '{0}' with '{1}'.
    MovingADComputer                  = Moving computer from '{0}' to '{1}'.
    RenamingADComputer                = Renaming computer from '{0}' to '{1}'.
    RestoringADComputer               = Attempting to restore the computer object {0} from recycle bin.

    ODJRequestStartMessage = Attempting to create the ODJ request file '{2}' for computer '{1}' in Domain '{0}'.
    ODJRequestCompleteMessage = The ODJ request file '{2}' for computer '{1}' in Domain '{0}' has been provisioned successfully.
    ODJRequestError = Error {0} occurred provisioning the computer using ODJ- {1}.

'@
