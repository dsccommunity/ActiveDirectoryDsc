namespace Microsoft.ActiveDirectory.Management
{
    public enum ADDomainMode
    {
        Windows2000Domain,
        Windows2003InterimDomain,
        Windows2003Domain,
        Windows2008Domain,
        Windows2008R2Domain,
        Windows2012Domain,
        Windows2012R2Domain,
        Windows2016Domain,
        UnknownDomain
    }

    public enum ADForestMode
    {
        Windows2000Forest,
        Windows2003InterimForest,
        Windows2003Forest,
        Windows2008Forest,
        Windows2008R2Forest,
        Windows2012Forest,
        Windows2012R2Forest,
        Windows2016Forest,
        UnknownForest
    }
}
