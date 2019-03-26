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

    public class ADAuthType
    {
        public ADAuthType():base(){}
    }

    public class ADDomain
    {
        public ADDomain():base(){}
        public ADDomain(System.String Identity):base(){}
    }

    public class ADDomainController
    {
        public ADDomainController():base(){}
        public ADDomainController(System.String Identity):base(){}
    }

    public class ADDirectoryServer
    {
        public ADDirectoryServer():base(){}
        public ADDirectoryServer(System.String Identity):base(){}
    }

    public class ADReplicationSite
    {
        string site;
        public ADReplicationSite(System.String s){ site = s; }
    }
}

namespace Microsoft.ActiveDirectory.Management.Commands
{
    public class ADCurrentDomainType
    {
        public ADCurrentDomainType():base(){}
    }

    public class ADMinimumDirectoryServiceVersion
    {
        public ADMinimumDirectoryServiceVersion():base(){}
    }

    public class ADDiscoverableService
    {
        public ADDiscoverableService():base(){}
    }
}
