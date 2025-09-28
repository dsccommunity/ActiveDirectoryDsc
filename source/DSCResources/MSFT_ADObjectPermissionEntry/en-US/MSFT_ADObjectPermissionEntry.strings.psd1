
# culture='en-US'
ConvertFrom-StringData @'
    ObjectPermissionEntryFound             = Object permission entry found on object '{0}'. (OPE0001)
    ObjectPermissionEntryNotFound          = Object permission entry not found on object '{0}'. (OPE0002)
    AddingObjectPermissionEntry            = Adding object permission entry to object '{0}'. (OPE0003)
    RemovingObjectPermissionEntry          = Removing object permission entry from object '{0}'. (OPE0004)
    ObjectPermissionEntryInDesiredState    = Object permission entry on object '{0}' is in the desired state. (OPE0005)
    ObjectPermissionEntryNotInDesiredState = Object permission entry on object '{0}' is not in the desired state. (OPE0006)
    ObjectPathIsAbsent                     = Object Path '{0}' is absent from Active Directory. (OPE0007)
    RetrievedADDrivePSPath                 = Retrieved the AD Drive full PSPath of '{0}'. (OPE0008)
    FailedToRetrieveRootDSE                = Failed to retrieve the Active Directory RootDSE (OPE0009): {0}
    ErrorSearchingSchema                   = Error searching the Active Directory schema for an object matching lDAPDisplayName = '{0}'. (OPE0010): {1}
    ErrorMultipleSchemaObjectsFound        = Error: Multiple objects found in Active Directory schema matching lDAPDisplayName = '{0}'. (OPE0011)
    ErrorSearchingExtendedRights           = Error searching the Extended Rights container for an object matching displayName = '{0}' (OPE0012): {1}
    ErrorMultipleExtendedRightsFound       = Error: Multiple objects found in Extended Rights container matching displayName = '{0}'. (OPE0013)
    NoMatchingGuidFound                    = No matching GUID found for DisplayName = '{0}'. (OPE0014)
'@
