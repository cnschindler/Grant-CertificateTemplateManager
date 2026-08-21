# Requires -Version 5.1
# Requires -Modules ActiveDirectory
# Requires -RunAsAdministrator

[cmdletbinding()]
Param
(
    [Parameter(Mandatory=$true)]
    [string]$GroupName,
    [switch]$ModifySchemaDefaultPermission
)

#
# Logging Configuration
#
# Use the script name as the base for the logfile name, add a timestamp to it.
[System.IO.FileInfo]$ScriptName = $MyInvocation.MyCommand.Name
[System.IO.FileInfo]$LogfileName = ($ScriptName.BaseName + "_{0:yyyyMMdd-HHmmss}.log" -f [DateTime]::Now)

# Combine the script directory and logfile name to create the full path of the logfile
[System.IO.FileInfo]$script:LogFileFullPath = Join-Path -Path $PSScriptRoot -ChildPath $LogfileName

# Set start and stop messages for the logfile
[string]$Script:LogFileStart = "{0:dd.MM.yyyy H:mm:ss} : {1}" -f [DateTime]::Now, "Logging started"
[string]$Script:LogFileStop = "Logging stopped"

# Set logging variables to control the initial logging behavior
$Script:LoggingEnabled = $true
$Script:FileLoggingEnabled = $true
$Script:ConsoleLoggingEnabled = $true

function Write-LogFile
{
    # Logging function, used for progress and error logging
    # Uses the globally (script scoped) configured variables 'LogFileFullPath' to identify the logfile, 'LoggingEnabled' to enable/disable logging
    # 'FileLoggingEnabled' to enable/disable file based logging
    # 'ConsoleLoggingEnabled' to enable/disable console based logging
    [CmdLetBinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [System.Management.Automation.ErrorRecord]$ErrorInfo = $null
    )

    # Prefix the string to write with the current Date and Time, add error message if present...
    if ($ErrorInfo)
    {
        $logLine = "{0:dd.MM.yyyy H:mm:ss} : ERROR : {1} The error is: {2}" -f [DateTime]::Now, $Message, $ErrorInfo.Exception.Message
    }

    Else
    {
        $logLine = "{0:dd.MM.yyyy H:mm:ss} : INFO : {1}" -f [DateTime]::Now, $Message
    }

    function Write-LogToConsole
    {
        # If an errorinfo was given, format the output in red
        If ($ErrorInfo)
        {
            Write-Host -ForegroundColor Red -Object $logLine
        }

        Else
        {
            Write-Host -Object $logLine
        }
    }

    function Write-LogToFile
    {
        # Create the Script:LogfileFullPath and folder structure if it doesn't exist
        if (-not (Test-Path $script:LogFileFullPath -PathType Leaf))
        {
            New-Item -ItemType File -Path $script:LogFileFullPath -Force -Confirm:$false -WhatIf:$false | Out-Null
            Add-Content -Value $Script:LogFileStart -Path $script:LogFileFullPath -Encoding UTF8 -WhatIf:$false -Confirm:$false
        }

        # Write to Script:LogfileFullPath
        Add-Content -Value $logLine -Path $script:LogFileFullPath -Encoding UTF8 -WhatIf:$false -Confirm:$false
    }

    # If logging is enabled...
    if ($Script:LoggingEnabled)
    {
        # If file based and console based logging is enabled, write to the logfile and to the console
        if ($Script:FileLoggingEnabled -and $Script:ConsoleLoggingEnabled)
        {
            Write-LogToFile
            Write-LogToConsole
        }

        # If file based logging is not enabled, but console based logging is enabled, output the log line to the console
        elseif ($Script:ConsoleLoggingEnabled)
        {
            Write-LogToConsole
        }
    }
}

# Import the Active Directory module if not already imported
if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue))
{
    Try
    {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-LogFile -Message "Successfully imported the Active Directory module."
    }

    Catch
    {
        Write-LogFile -Message "Failed to import the Active Directory module." -ErrorInfo $_
        Exit
    }
}

Get-PSDrive
Get-Module
function Grant-ADObjectPermissions
{
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [System.DirectoryServices.ActiveDirectoryAccessRule]$Rule,
        [Parameter(Mandatory=$true)]
        [System.Security.Principal.NTAccount]$Principal,
        [switch]$SetOwner,
        [Parameter(Mandatory=$true)]
        [string]$AccessType,
        [Parameter(Mandatory=$true)]
        [string]$ObjectType
    )

    # Retrieve the current ACL of the specified AD object
    Try
    {
        $Acl = Get-Acl $Path -ErrorAction Stop
        Write-LogFile -Message "Successfully retrieved ACL for '$Path'."
    }

    Catch
    {
        Write-LogFile -Message "Failed to retrieve ACL for '$Path'." -ErrorInfo $_
        Exit

    }

    if ($SetOwner)
    {
        # Set Owner of the object to the delegated group
        Write-LogFile -Message "Setting owner of '$Path' to '$($Principal.Value)'."
        [void]$Acl.SetOwner($Principal)
        # Write back modified ACL
        Try
        {
            Set-Acl -Path $Path -AclObject $Acl -ErrorAction Stop
            Write-LogFile -Message "Successfully set owner of '$Path' to '$($Principal.Value)'."
        }

        Catch
        {
            Write-LogFile -Message "Failed to set owner of '$Path' to '$($Principal.Value)'." -ErrorInfo $_
            Exit
        }
    }

    else
    {
        # Add access rule to current ACL
        Write-LogFile -Message "Adding $($AccessType) to $($ObjectType) objects access rule for '$($Principal.Value)' to '$Path'."
        [void]$Acl.AddAccessRule($Rule)
        # Write back modified ACL
        Try
        {
            Set-Acl -Path $Path -AclObject $Acl -ErrorAction Stop
            Write-LogFile -Message "Successfully added $($AccessType) to $($ObjectType) objects access rule for '$($Principal.Value)' to '$Path'."
        }

        Catch
        {
            Write-LogFile -Message "Failed to add $($AccessType) to $($ObjectType) objects access rule for '$($Principal.Value)' to '$Path'." -ErrorInfo $_
            Exit
        }
    }
}

# Retrive domain controllers
$DomainController = (Get-ADDomainController -Filter * | Select-Object -First 1).Hostname
Write-LogFile -Message "Using domain controller '$DomainController' for Active Directory operations."
# Retrieve the current domain
$Domain = Get-ADDomain -server $DomainController
Write-LogFile -Message "Current domain is '$($Domain.DNSRoot)'."

function Test-IsActiveDirectoryAdmin
{
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [ValidateSet("EnterpriseAdmin", "SchemaAdmin", "DomainAdmin")]
        [string]$Role
    )

    switch ($Role)
    {
        "EnterpriseAdmin" {
            $SID = $Domain.DomainSID.Value + "-519"
            Write-LogFile -Message "Enterprise Admins SID is '$SID'."
        }
        "SchemaAdmin" {
            $SID = $Domain.DomainSID.Value + "-518"
            Write-LogFile -Message "Schema Admins SID is '$SID'."
        }
        "DomainAdmin" {
            $SID = $Domain.DomainSID.Value + "-512"
            Write-LogFile -Message "Domain Admins SID is '$SID'."
        }
    }

    # Get current user principal
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    Write-LogFile -Message "Current user is '$($principal.Identity.Name)'."

    if ($principal.Identities.Groups -notcontains $SID)
    {
        Write-LogFile -Message "Current user is not a member of the '$Role' group."
        Write-LogFile -Message "This script must be run with a user account that is a member in the '$Role' group."
        Exit
    }

    Else
    {
        Write-LogFile -Message "Current user is a member of the '$Role' group. Continuing with script execution."
    }

}

# Check if the current user is a member of the Enterprise Admins group
Test-IsActiveDirectoryAdmin -Role "EnterpriseAdmin"

# Retrieve the delegated group
$Group = Get-ADGroup $GroupName -server $DomainController
Write-LogFile -Message "Retrieved group '$GroupName' with distinguished name '$($Group.DistinguishedName)'."

# Check if the group is a Universal group, otherwise exit with an error message
if ($Group.GroupScope -ne 'Universal') {
    Write-LogFile -Message "The group '$GroupName' is not a Universal group. Please use a Universal group for delegation."
    Exit
}

# Retrieve AD Root DSE info
$RootDse = Get-ADRootDSE -server $DomainController
Write-LogFile -Message "Retrieved RootDSE information from domain controller '$DomainController'."
# Retrieve the schema NC
$schemaNC = $RootDse.schemaNamingContext
Write-LogFile -Message "Schema Naming Context is '$schemaNC'."
# Retrieve Config NC
$ConfigNC = $RootDse.configurationNamingContext
Write-LogFile -Message "Configuration Naming Context is '$ConfigNC'."
# Retrieve 'schemaGUID' property of 'pKICertificateTemplate' objectclass
$pkiTempl = Get-ADObject -LDAPFilter '(&(objectClass=classSchema)(lDAPDisplayName=pKICertificateTemplate))' -SearchBase $schemaNC -Properties schemaIDGUID -server $DomainController
Write-LogFile -Message "Retrieved 'pKICertificateTemplate' schemaGUID: '$($pkiTempl.schemaIDGUID)'."
# Build a formatted GUID from 'pKICertificateTemplate' for later use in ACL rules
$pkiTemplGuid = New-Object Guid (,$pkiTempl.schemaIDGUID)
Write-LogFile -Message "Formatted 'pKICertificateTemplate' schemaGUID: '$pkiTemplGuid'."
# Retrieve 'schemaGUID' property of 'msPKI-Enterprise-Oid' objectclass
$pkiEntOID = Get-ADObject -LDAPFilter '(&(objectClass=classSchema)(lDAPDisplayName=msPKI-Enterprise-Oid))' -SearchBase $schemaNC -Properties schemaIDGUID -Server $DomainController
Write-LogFile -Message "Retrieved 'msPKI-Enterprise-Oid' schemaGUID: '$($pkiEntOID.schemaIDGUID)'."
# Build a formatted GUID of the schemaGUID from 'msPKI-Enterprise-Oid' for later use in ACL rules
$pkiEntOidGuid = New-Object Guid (,$pkiEntOID.schemaIDGUID)
Write-LogFile -Message "Formatted 'msPKI-Enterprise-Oid' schemaGUID: '$pkiEntOidGuid'."
# Define path to 'certificate templates' container in current forest
$PkiTemplPath = "AD:\CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
Write-LogFile -Message "Certificate Templates container path is '$PkiTemplPath'."
# Retrieve current ACL of 'certificte templates' container
# $PkiTemplAcl = Get-Acl $PkiTemplPath
# Write-LogFile -Message "Retrieved current ACL of 'Certificate Templates' container."
# Define path to 'OID' container in current forest
$PkiEntOidPath = "AD:\CN=OID,CN=Public Key Services,CN=Services,$ConfigNC"
Write-LogFile -Message "OID container path is '$PkiEntOidPath'."
# Retrieve current ACL of 'OID' container
# $PkiEntOidAcl = Get-Acl $PkiEntOidPath
# Write-LogFile -Message "Retrieved current ACL of 'OID' container."
# Retrieve all Templates from the 'Certificate Templates' container
$pkiTemplates = Get-ChildItem $($PkiTemplPath)
Write-LogFile -Message "Retrieved $($pkiTemplates.Count) certificate templates from 'Certificate Templates' container."
# Retrieve all OIDs from the 'OID' container
$pkiOids = Get-ChildItem $($PkiEntOidPath)
Write-LogFile -Message "Retrieved $($pkiOids.Count) OIDs from 'OID' container."
# Create the ACL Security Principal for the delegated group
$ACLSecurityPrincipal = [System.Security.Principal.NTAccount]::new($($Domain.NetBIOSName), $($Group.SamAccountName))
Write-LogFile -Message "Created ACL Security Principal for group '$($Group.SamAccountName)' in domain '$($Domain.NetBIOSName)'."

# Create generic Full Control ACL Rule for AD objects
$GenericFCRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $ACLSecurityPrincipal,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
)

# Create ACL Rules for 'pkiCertificateTemplate' object creation/deletion
$PkiTemplCreateDeleteRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $ACLSecurityPrincipal,
    ([System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild),
    [System.Security.AccessControl.AccessControlType]::Allow,
    $pkiTemplGuid,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)

# Add access rules to existing 'pkiCertificateTemplate' ACL
Grant-ADObjectPermissions -Path $PkiTemplPath -Rule $PkiTemplCreateDeleteRule -Principal $ACLSecurityPrincipal -AccessType "Create/Delete" -ObjectType "pkiCertificateTemplate"
Grant-ADObjectPermissions -Path $PkiTemplPath -Rule $GenericFCRule -Principal $ACLSecurityPrincipal -AccessType "Full Control" -ObjectType "pkiCertificateTemplate"

# Create ACL Rules for 'msPKI-Enterprise-Oid' object creation/deletion
$PkiEntOIDCreateDeleteRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $ACLSecurityPrincipal,
    ([System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild),
    [System.Security.AccessControl.AccessControlType]::Allow,
    $pkiEntOidGuid,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)

# Add access rules to existing 'msPKI-Enterprise-Oid' ACL
Grant-ADObjectPermissions -Path $PkiEntOidPath -Rule $PkiEntOIDCreateDeleteRule -Principal $ACLSecurityPrincipal -AccessType "Create/Delete" -ObjectType "msPKI-Enterprise-Oid"
Grant-ADObjectPermissions -Path $PkiEntOidPath -Rule $GenericFCRule -Principal $ACLSecurityPrincipal -AccessType "Full Control" -ObjectType "msPKI-Enterprise-Oid"

# Assign Full Control and owner permissions to the delegated group for all existing 'pkiCertificateTemplate' objects
foreach ($object in $pkiTemplates)
{
    $path = "AD:\" + $object.DistinguishedName
    Grant-ADObjectPermissions -Path $path -Rule $GenericFCRule -Principal $ACLSecurityPrincipal -AccessType "Full Control" -ObjectType "pkiCertificateTemplate"
    Grant-ADObjectPermissions -Path $path -Principal $ACLSecurityPrincipal -SetOwner -AccessType "Owner" -ObjectType "pkiCertificateTemplate"
}

# Assign Full Control and owner permissions to the delegated group for all existing 'msPKI-Enterprise-Oid' objects
foreach ($object in $pkiEntOids)
{
    $path = "AD:\" + $object.DistinguishedName
    Grant-ADObjectPermissions -Path $path -Rule $GenericFCRule -Principal $ACLSecurityPrincipal -AccessType "Full Control" -ObjectType "msPKI-Enterprise-Oid"
}

if ($ModifySchemaDefaultPermission)
{
    # Check if the current user is a member of the Schema Admins group
    Test-IsActiveDirectoryAdmin -Role "SchemaAdmin"

    # Modify default permissions in the AD schema for the 'pkiCertificateTemplate' object class to automatically grant the delegated group Full Control and owner permissions for all future 'pkiCertificateTemplate' objects
    # Retrieve the current default security descriptor for the 'pkiCertificateTemplate' object class
    $CurrentSDDL = (Get-ADObject $pkiTempl -Properties defaultSecurityDescriptor).defaultSecurityDescriptor
    # Create a new security descriptor object with the current SDDL
    $NewSDDL = New-Object -TypeName Security.AccessControl.CommonSecurityDescriptor -ArgumentList $False,$true,$CurrentSDDL
    # Build ACE parameters for the new access rule to be added to the security descriptor
    $AccessType = [System.Security.AccessControl.AccessControlType]::Allow
    $AccessMask = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    $PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None
    $Sid = $Group.SID.Value
    # Add a new access rule to the security descriptor for the delegated group with Full Control permissions for all future 'pkiCertificateTemplate' objects
    $NewSDDL.DiscretionaryAcl.AddAccess($AccessType, $SID, $AccessMask, $InheritanceType, $PropagationFlags)
    #Convert back to SDDL string
    $NewSDDLString = $NewSDDL.GetSddlForm('All')

    # Update the default security descriptor for the 'pkiCertificateTemplate' object class with the new SDDL string
    try
    {
        Set-ADObject -Identity $pkiTempl -Replace @{defaultSecurityDescriptor=$NewSDDLString} -Server $DomainController
        Write-LogFile -Message "Added full access permissions for group '$($Group.SamAccountName)' to default security descriptor for 'pkiCertificateTemplate' object class."
    }

    catch
    {
        Write-LogFile -Message "Failed to add full access permissions for group '$($Group.SamAccountName)' to default security descriptor for 'pkiCertificateTemplate' object class:." -errorInfo $_
        Exit
    }
}