Add-Type -AssemblyName System.DirectoryServices.Protocols

# ========================================================
# Paramètres
# ========================================================

$baseDN     = "DC=kbaz,DC=corp"
$ldapServer = "kbaz.corp:389"
$computerName = $env:COMPUTERNAME

# ========================================================
# Connexion LDAP
# ========================================================

try {
    $ldapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($ldapServer)
    $ldapConnection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate

    Write-Host "Connexion initialisée sur $ldapServer"

    $ldapConnection.Bind()

    Write-Host "Bind réussi"
}
catch [System.DirectoryServices.Protocols.LdapException] {
    Write-Error "Échec du bind LDAP : $($_.Exception.Message) (code: $($_.Exception.ErrorCode))"
}
catch {
    Write-Error "Erreur inattendue : $($_.Exception.Message)"
}


# ========================================================
# Recherche du compte ordinateur
# ========================================================


$searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
    $baseDN,
    "(&(objectClass=computer)(sAMAccountName=$computerName`$))",
    [System.DirectoryServices.Protocols.SearchScope]::Subtree
)

$response = $ldapConnection.SendRequest($searchRequest)


foreach ($entry in $response.Entries) {

    Write-Host "`n========================================"
    Write-Host "DN : $($entry.DistinguishedName)"
    Write-Host "========================================"


    # ========================================================
    # msDS-KeyCredentialLink
    # ========================================================

    if ($entry.Attributes["msDS-KeyCredentialLink"]) {

        Write-Host "`nmsDS-KeyCredentialLink :"

        foreach ($val in $entry.Attributes["msDS-KeyCredentialLink"].GetValues([string])) {
            Write-Host "  $val"
        }

    }
    else {
        Write-Host "`nmsDS-KeyCredentialLink : (vide / non defini)"
    }


    # ========================================================
    # msDS-AllowedToActOnBehalfOfOtherIdentity
    # ========================================================

    if ($entry.Attributes["msDS-AllowedToActOnBehalfOfOtherIdentity"]) {

        Write-Host "`nmsDS-AllowedToActOnBehalfOfOtherIdentity :"

        try {

            # Récupération des octets du security descriptor
            $rawValue = $entry.Attributes[
                "msDS-AllowedToActOnBehalfOfOtherIdentity"
            ].GetValues([byte[]])[0]

            # Conversion binaire -> RawSecurityDescriptor
            $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor(
                $rawValue,
                0
            )

            # Conversion du security descriptor -> SDDL
            $sddl = $sd.GetSddlForm(
                [System.Security.AccessControl.AccessControlSections]::All
            )

            Write-Host "SDDL :"
            Write-Host "  $sddl"


            # ========================================================
            # Affichage des ACE
            # ========================================================

            Write-Host "`nACE :"

            foreach ($ace in $sd.DiscretionaryAcl) {

                Write-Host ""
                Write-Host "  Type              : $($ace.AceType)"
                Write-Host "  SID               : $($ace.SecurityIdentifier.Value)"


                # ====================================================
                # Résolution SID -> sAMAccountName
                # ====================================================

                try {

                    $sidBytes = New-Object byte[] $ace.SecurityIdentifier.BinaryLength

                    $ace.SecurityIdentifier.GetBinaryForm(
                        $sidBytes,
                        0
                    )

                    $sidFilter = -join ($sidBytes | ForEach-Object {
                        '\' + $_.ToString("X2")
                    })


                    $sidSearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
                        $baseDN,
                        "(objectSid=$sidFilter)",
                        [System.DirectoryServices.Protocols.SearchScope]::Subtree,
                        "sAMAccountName"
                    )

                    $sidResponse = $ldapConnection.SendRequest(
                        $sidSearchRequest
                    )


                    if ($sidResponse.Entries.Count -gt 0) {

                        $samAccountName = $sidResponse.Entries[0].Attributes[
                            "sAMAccountName"
                        ][0]

                        Write-Host "  sAMAccountName    : $samAccountName"
                    }
                    else {
                        Write-Host "  sAMAccountName    : introuvable"
                    }

                }
                catch {
                    Write-Host "  sAMAccountName    : erreur de résolution - $($_.Exception.Message)"
                }


                Write-Host "  Access Mask       : 0x$('{0:X8}' -f $ace.AccessMask)"
                Write-Host "  Inheritance Flags : $($ace.InheritanceFlags)"
                Write-Host "  Propagation Flags : $($ace.PropagationFlags)"
            }

        }
        catch {
            Write-Error "Impossible de parser le security descriptor RBCD : $($_.Exception.Message)"
        }

    }
    else {
        Write-Host "`nmsDS-AllowedToActOnBehalfOfOtherIdentity : (vide / non defini)"
    }
}

$ldapConnection.Dispose()

