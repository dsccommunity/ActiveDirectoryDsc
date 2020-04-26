
# Get-CurrentUser

## SYNOPSIS
Gets the current user identity.

## SYNTAX

```
Get-CurrentUser [<CommonParameters>]
```

## DESCRIPTION
The Get-CurrentUser function is used to get the current user identity.
A WindowsIdentity object is returned
that represents the current user.

## EXAMPLES

### EXAMPLE 1
```
Get-CurrentUser
```

## PARAMETERS

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### System.Security.Principal.WindowsIdentity
## NOTES
This is a wrapper to allow test mocking of the calling function.

## RELATED LINKS
