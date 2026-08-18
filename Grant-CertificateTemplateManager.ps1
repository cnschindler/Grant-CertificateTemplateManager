[cmdletbinding()]
Param
(
    [Parameter(Mandatory=$true)]
    [string]$GroupName
)

function Grant-ADObjectPermissions {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [System.DirectoryServices.ActiveDirectoryAccessRule]$Rule,
        [Parameter(Mandatory=$true)]
        [System.Security.Principal.NTAccount]$Principal,
        [switch]$SetOwner
    )

    # Assign Full Control permissions to the delegated group for the specified template
    $Acl = Get-Acl $Path

    if ($SetOwner)
    {
        # Set Owner of the object to the delegated group
        [void]$Acl.SetOwner($Principal)
        # Write back modified ACL
        Set-Acl -Path $Path -AclObject $Acl
    }

    else
    {
        # Add access rule to current ACL
        [void]$Acl.AddAccessRule($Rule)
        # Write back modified ACL
        Set-Acl -Path $Path -AclObject $Acl
    }
}

# Retrive domain controllers
$DomainController = (Get-ADDomainController -Filter * | Select-Object -First 1).Hostname
# Retrieve the delegated group
$Group = Get-ADGroup $GroupName -server $DomainController
# Check if the group is a Universal group, otherwise exit with an error message
if ($Group.GroupScope -ne 'Universal') {
    Write-Error "The group '$GroupName' is not a Universal group. Please use a Universal group for delegation."
    exit
}
# Retrieve the current domain
$Domain = Get-ADDomain -server $DomainController
# Retrieve AD Root DSE info
$RootDse = Get-ADRootDSE -server $DomainController
# Retrieve the schema NC
$schemaNC = $RootDse.schemaNamingContext
# Retrieve Config NC
$ConfigNC = $RootDse.configurationNamingContext
# Retrieve 'schemaGUID' property of 'pKICertificateTemplate' objectclass
$pkiTempl = Get-ADObject -LDAPFilter '(&(objectClass=classSchema)(lDAPDisplayName=pKICertificateTemplate))' -SearchBase $schemaNC -Properties schemaIDGUID -server $DomainController
# Build a formatted GUID from 'pKICertificateTemplate' for later use in ACL rules
$pkiTemplGuid = New-Object Guid (,$pkiTempl.schemaIDGUID)
# Retrieve 'schemaGUID' property of 'msPKI-Enterprise-Oid' objectclass
$pkiEntOID = Get-ADObject -LDAPFilter '(&(objectClass=classSchema)(lDAPDisplayName=msPKI-Enterprise-Oid))' -SearchBase $schemaNC -Properties schemaIDGUID -Server $DomainController
# Build a formatted GUID of the schemaGUID from 'msPKI-Enterprise-Oid' for later use in ACL rules
$pkiEntOidGuid = New-Object Guid (,$pkiEntOID.schemaIDGUID)
# Define path to 'certificate templates' container in current forest
$PkiTemplPath = "AD:\CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
# Retrieve current ACL of 'certificte templates' container
$PkiTemplAcl = Get-Acl $PkiTemplPath
# Define path to 'OID' container in current forest
$PkiEntOidPath = "AD:\CN=OID,CN=Public Key Services,CN=Services,$ConfigNC"
# Retrieve current ACL of 'OID' container
$PkiEntOidAcl = Get-Acl $PkiEntOidPath
# Retrieve all Templates from the 'Certificate Templates' container
$pkiTemplates = Get-AdObject -LDAPFilter '(objectClass=pKICertificateTemplate)' -SearchBase $PkiTemplPath -Server $DomainController
# Retrieve all OIDs from the 'OID' container
$pkiOids = Get-AdObject -LDAPFilter '(objectClass=msPKI-Enterprise-Oid)' -SearchBase $PkiEntOidPath -Server $DomainController
# Create the ACL Security Principal for the delegated group
$ACLSEcurityPrincipal = [System.Security.Principal.NTAccount]::new($($Domain.NetBIOSName), $($Group.SamAccountName))

# Create generic Full Control ACL Rule for AD objects
$GenericFCRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $ACLSEcurityPrincipal,
    [System.DirectoryServices.ActiveDirectoryRights]::FullControl,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
)

# Create ACL Rules for 'pkiCertificateTemplate' object creation/deletion
$PkiTemplCreateDeleteRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $ACLSEcurityPrincipal,
    ([System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild),
    [System.Security.AccessControl.AccessControlType]::Allow,
    $pkiTemplGuid,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)

# Add access rules to existing 'pkiCertificateTemplate' ACL
Grant-ADObjectPermissions -Path $PkiTemplPath -Rule $PkiTemplCreateDeleteRule -Principal $ACLSEecurityPrincipal
Grant-ADObjectPermissions -Path $PkiTemplPath -Rule $GenericFCRule -Principal $ACLSEecurityPrincipal

# Create ACL Rules for 'msPKI-Enterprise-Oid' object creation/deletion
$PkiEntOIDCreateDeleteRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $ACLSEcurityPrincipal,
    ([System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild),
    [System.Security.AccessControl.AccessControlType]::Allow,
    $pkiEntOidGuid,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)

# Add access rules to existing 'msPKI-Enterprise-Oid' ACL
Grant-ADObjectPermissions -Path $PkiEntOidPath -Rule $PkiEntOIDCreateDeleteRule -Principal $ACLSEecurityPrincipal
Grant-ADObjectPermissions -Path $PkiEntOidPath -Rule $GenericFCRule -Principal $ACLSEecurityPrincipal

# Assign Full Control and owner permissions to the delegated group for all existing 'pkiCertificateTemplate' objects
foreach ($object in $pkiTemplates)
{
    Grant-ADObjectPermissions -Path $object.DistinguishedName -Rule $GenericFCRule -Principal $ACLSEcurityPrincipal
    Grant-ADObjectPermissions -Path $object.DistinguishedName -Principal $ACLSEcurityPrincipal -SetOwner
}

# Assign Full Control and owner permissions to the delegated group for all existing 'msPKI-Enterprise-Oid' objects
foreach ($object in $pkiEntOids)
{
    Grant-ADObjectPermissions -Path $object.DistinguishedName -Rule $GenericFCRule -Principal $ACLSEcurityPrincipal
    Grant-ADObjectPermissions -Path $object.DistinguishedName -Principal $ACLSEcurityPrincipal -SetOwner
}
