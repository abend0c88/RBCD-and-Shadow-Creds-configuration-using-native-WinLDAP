Add-Type -AssemblyName System.DirectoryServices.Protocols

# --- Paramètres ---

$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domainName = $domain.Name
$serveur = $domainName
$baseDN = ($domainName -split '\.' | ForEach-Object { "DC=$_" }) -join ','
$computerName = $env:COMPUTERNAME
$compteCible   = "CN=$($computerName),CN=Computers,$($baseDN)"

Write-Host $compteCible 
Write-Host $env:COMPUTERNAME

try {
    $connexion = New-Object System.DirectoryServices.Protocols.LdapConnection($serveur)
    $connexion.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate

    Write-Host "Connexion initialisée sur $serveur"

    $connexion.Bind()

    Write-Host "Bind réussi"
}
catch [System.DirectoryServices.Protocols.LdapException] {
    Write-Error "Échec du bind LDAP : $($_.Exception.Message) (code: $($_.Exception.ErrorCode))"
}
catch {
    Write-Error "Erreur inattendue : $($_.Exception.Message)"
}


# --- Construire la modification LDAP ---
$modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
$modification.Name = "msDS-AllowedToActOnBehalfOfOtherIdentity"
$modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete

# --- Envoyer la requête de modification ---
$requeteModif = New-Object System.DirectoryServices.Protocols.ModifyRequest
$requeteModif.DistinguishedName = $compteCible
$requeteModif.Modifications.Add($modification) | Out-Null

$connexion.SendRequest($requeteModif)

Write-Host "Attribut msDS-AllowedToActOnBehalfOfOtherIdentity supprime"

