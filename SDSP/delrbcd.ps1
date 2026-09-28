Add-Type -AssemblyName System.DirectoryServices.Protocols

# --- Paramètres ---

$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domainName = $domain.Name
$serveur = $domainName
$baseDN = ($domainName -split '\.' | ForEach-Object { "DC=$_" }) -join ','
$computerName = $env:COMPUTERNAME

$compteCible   = "CN=$($computerName),CN=Computers,DC=kbaz,DC=corp"

# --- Construire la modification LDAP ---
$modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
$modification.Name = "msDS-AllowedToActOnBehalfOfOtherIdentity"
$modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Remove

# --- Envoyer la requête de modification ---
$requeteModif = New-Object System.DirectoryServices.Protocols.ModifyRequest
$requeteModif.DistinguishedName = $compteCible
$requeteModif.Modifications.Add($modification) | Out-Null

$connexion.SendRequest($requeteModif) | Out-Null

Write-Host "Attribut msDS-AllowedToActOnBehalfOfOtherIdentity supprime"
