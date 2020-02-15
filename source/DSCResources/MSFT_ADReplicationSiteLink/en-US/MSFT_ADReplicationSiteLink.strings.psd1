ConvertFrom-StringData @'
    SiteNotFound               = Site: '{0}' not found in SitesIncluded. Current SitesIncluded: '{1}'. (ADRSL0001)
    SiteFoundInExcluded        = Excluded '{0}' site found in SitesIncluded. Current SitesIncluded: '{1}'. (ADRSL0002)
    PropertyNotInDesiredState  = '{0}' is not in desired state Current: '{1}' Desired: '{2}'. (ADRSL0003)
    SettingProperty            = Setting property '{0}' to '{1}' on site link '{2}'. (ADRSL0004)
    RemovingSites              = Removing sites '{0}' from site link '{1}'. (ADRSL0005)
    AddingSites                = Adding sites '{0}' to site link '{1}'. (ADRSL0006)
    NewSiteLink                = Creating AD Site Link '{0}'. (ADRSL0007)
    RemoveSiteLink             = Removing AD Site Link '{0}'. (ADRSL0008)
    SiteLinkNotFound           = Could not find '{0}' site link. (ADRSL0009)
    GetSiteLinkUnexpectedError = Unexpected error getting site link '{0}'. (ADRSL0010)
'@
