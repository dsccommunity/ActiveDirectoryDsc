# culture="en-US"
ConvertFrom-StringData @'
    GetForest                          = Getting properties for forest '{0}'. (ADFP0001)
    ForestUpnSuffixNotInDesiredState   = User Principal Name Suffix for forest '{0}' not in the desired state. (ADFP0002)
    ForestSpnSuffixNotInDesiredState   = Service Principal Name Suffix for forest '{0}' not in the desired state. (ADFP0003)
    AddSpnSuffix                       = Adding Service Principal Name Suffix: '{0}' for forest '{1}'. (ADFP0004)
    RemoveSpnSuffix                    = Removing Service Principal Name Suffix: '{0}' for forest '{1}'. (ADFP0005)
    ReplaceSpnSuffix                   = Replacing Service Principal Name Suffix with: '{0}' for forest '{1}'. (ADFP0006)
    ClearSpnSuffix                     = Clearing Service Principal Name Suffix for forest '{0}'. (ADFP0007)
    AddUpnSuffix                       = Adding User Principal Name Suffix: '{0}' for forest '{1}'. (ADFP0008)
    RemoveUpnSuffix                    = Removing User Principal Name Suffix: '{0}' for forest '{1}'. (ADFP0009)
    ReplaceUpnSuffix                   = Replacing User Principal Name Suffix with: '{0}' for forest '{1}'. (ADFP0010)
    ClearUpnSuffix                     = Clearing User Principal Name Suffix for forest '{0}'. (ADFP0011)
    TombstoneLifetimeNotInDesiredState = Tombstone lifetime for forest '{0}' not in the desired state. Current: '{1}', Expected: '{2}'. (ADFP0012)
    SetTombstoneLifetime               = Setting tombstone lifetime to '{0}' for forest '{1}. (ADFP0013)
    SetTombstoneLifetimeError          = Error setting tombstone lifetime to '{0}' for forest '{1}. (ADFP0014)
'@
