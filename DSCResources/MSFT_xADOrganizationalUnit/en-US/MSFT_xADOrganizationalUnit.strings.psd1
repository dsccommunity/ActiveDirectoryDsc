# culture="en-US"
ConvertFrom-StringData @'
    RetrievingOU               = Retrieving OU '{0}'.
    UpdatingOU                 = Updating OU '{0}'.
    DeletingOU                 = Deleting OU '{0}'.
    CreatingOU                 = Creating OU '{0}'.
    RestoringOU                = Attempting to restore the organizational unit object {0} from the recycle bin.
    OUInDesiredState           = OU '{0}' exists and is in the desired state.
    OUNotInDesiredState        = OU '{0}' exists but is not in the desired state.
    OUExistsButShouldNot       = OU '{0}' exists when it should not exist.
    OUDoesNotExistButShould    = OU '{0}' does not exist when it should exist.
    OUDoesNotExistAndShouldNot = OU '{0}' does not exist and is in the desired state.
'@
