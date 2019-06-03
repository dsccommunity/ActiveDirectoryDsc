# culture="en-US"
ConvertFrom-StringData @'
    RetrievingGroupMembers         = Retrieving group membership based on '{0}' property.
    GroupMembershipNotDesiredState = Group membership is NOT in the desired state.
    AddingGroupMembers             = Adding '{0}' member(s) to AD group '{1}'.
    RemovingGroupMembers           = Removing '{0}' member(s) from AD group '{1}'.
    AddingGroup                    = Adding AD Group '{0}'
    UpdatingGroup                  = Updating AD Group '{0}'
    RemovingGroup                  = Removing AD Group '{0}'
    MovingGroup                    = Moving AD Group '{0}' to '{1}'
    RestoringGroup                 = Attempting to restore the group {0} from recycle bin.
    GroupNotFound                  = AD Group '{0}' was not found
    NotDesiredPropertyState        = AD Group '{0}' is not correct. Expected '{1}', actual '{2}'
    UpdatingGroupProperty          = Updating AD Group property '{0}' to '{1}'
    GroupMembershipMultipleDomains = Group membership objects are in '{0}' different AD Domains.
'@
