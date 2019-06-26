# culture="en-US"
ConvertFrom-StringData @'
    RetrievingADUserError                = Error looking up Active Directory user '{0}' ({0}@{1}).
    PasswordParameterConflictError       = Parameter '{0}' cannot be set to '{1}' when the '{2}' parameter is specified.
    ChangePasswordParameterConflictError = Parameter 'ChangePasswordAtLogon' cannot be set to 'true' when Parameter 'PasswordNeverExpires' is also set to 'true'.
    RetrievingADUser                     = Retrieving Active Directory user '{0}' ({0}@{1}) ...
    CreatingADDomainConnection           = Creating connection to Active Directory domain '{0}' ...
    CheckingADUserPassword               = Checking Active Directory user '{0}' password ...
    ADUserIsPresent                      = Active Directory user '{0}' ({0}@{1}) is present.
    ADUserNotPresent                     = Active Directory user '{0}' ({0}@{1}) was NOT present.
    ADUserNotDesiredPropertyState        = User '{0}' property is NOT in the desired state. Expected '{1}', actual '{2}'.
    AddingADUser                         = Adding Active Directory user '{0}'.
    RemovingADUser                       = Removing Active Directory user '{0}'.
    UpdatingADUser                       = Updating Active Directory user '{0}'.
    SettingADUserPassword                = Setting Active Directory user password.
    UpdatingADUserProperty               = Updating user property '{0}' with/to '{1}'.
    ClearingADUserProperty               = Clearing user property '{0}'.
    MovingADUser                         = Moving user from '{0}' to '{1}'.
    RenamingADUser                       = Renaming user from '{0}' to '{1}'.
    RestoringUser                        = Attempting to restore the user object {0} from the recycle bin.
'@
