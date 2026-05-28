# winCheck-compagnon
# Diagnostic de la posture de securite Windows
# Famille "Outils Compagnon"

# ===== ELEVATION AUTOMATIQUE EN ADMINISTRATEUR =====
$estAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $estAdmin) {
    Write-Host "Elevation des droits administrateur necessaire..." -ForegroundColor Yellow
    Start-Process -FilePath powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Host "[OK] Droits administrateur confirmes." -ForegroundColor Green

# ===== ENCODAGE DE LA CONSOLE (pour afficher les accents) =====
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ===== EN-TETE =====
Write-Host ""
Write-Host "===== winCheck-compagnon =====" -ForegroundColor Cyan
Write-Host "Diagnostic de la posture de sécurité Windows" -ForegroundColor Cyan
Write-Host ""

# ===== LES CONTROLES =====

function Test-InfosSysteme {
    # On interroge Windows sur son systeme d'exploitation
    $os = Get-CimInstance -ClassName Win32_OperatingSystem

    $edition      = $os.Caption
    $version      = $os.Version
    $build        = $os.BuildNumber
    $architecture = $os.OSArchitecture

    return @{
        Nom       = "Informations système"
        Categorie = "Identité du poste"
        Etat      = "Information"
        Valeur    = "$edition - version $version (build $build) - $architecture"
        Constat   = "Système d'exploitation détecté."
        Risque    = ""
        Action    = ""
        Poids     = 0
    }
}

function Test-AntivirusTempsReel {
    try {
        # On tente de lire l'etat de Windows Defender
        $defender = Get-MpComputerStatus -ErrorAction Stop
        $actif = $defender.RealTimeProtectionEnabled

        if ($actif) {
            $etat   = "Conforme"
            $valeur = "La protection en temps réel est active."
            $risque = ""
            $action = ""
        } else {
            $etat   = "Critique"
            $valeur = "La protection en temps réel est désactivée."
            $risque = "Sans protection en temps réel, les menaces ne sont pas bloquées dès leur exécution."
            $action = "Réactiver la protection en temps réel de Windows Defender."
        }
    }
    catch {
        # Plan B : si la commande echoue (Defender absent ou AV tiers)
        $etat   = "Attention"
        $valeur = "Impossible de lire l'état de Windows Defender."
        $risque = "Defender est peut-être désactivé, ou remplacé par un antivirus tiers."
        $action = "Vérifier manuellement quel antivirus protège le poste."
    }

    return @{
        Nom       = "Protection antivirus en temps réel"
        Categorie = "Protection"
        Etat      = $etat
        Valeur    = $valeur
        Constat   = $valeur
        Risque    = $risque
        Action    = $action
        Poids     = 3
    }
}

function Test-PareFeu {
    try {
        $profils = Get-NetFirewallProfile -ErrorAction Stop
        # On garde uniquement les profils desactives
        $desactives = @($profils | Where-Object { -not $_.Enabled })

        if ($desactives.Count -eq 0) {
            $etat   = "Conforme"
            $valeur = "Le pare-feu est actif sur les trois profils (Domaine, Privé, Public)."
            $risque = ""
            $action = ""
        } else {
            $noms   = ($desactives.Name) -join ", "
            $etat   = "Critique"
            $valeur = "Le pare-feu est désactivé sur : $noms."
            $risque = "Un pare-feu désactivé expose le poste aux connexions entrantes non sollicitées."
            $action = "Réactiver le pare-feu Windows sur tous les profils."
        }
    }
    catch {
        $etat   = "Attention"
        $valeur = "Impossible de lire l'état du pare-feu."
        $risque = "L'état du pare-feu n'a pas pu être déterminé."
        $action = "Vérifier manuellement le pare-feu Windows."
    }

    return @{
        Nom       = "Pare-feu Windows"
        Categorie = "Protection"
        Etat      = $etat
        Valeur    = $valeur
        Constat   = $valeur
        Risque    = $risque
        Action    = $action
        Poids     = 3
    }
}

function Test-SignaturesAntivirus {
    try {
        $defender = Get-MpComputerStatus -ErrorAction Stop
        $age = $defender.AntivirusSignatureAge   # age en jours

        if ($age -le 3) {
            $etat   = "Conforme"
            $valeur = "Signatures antivirus à jour (mises à jour il y a $age jour(s))."
            $risque = ""
            $action = ""
        } elseif ($age -le 7) {
            $etat   = "Attention"
            $valeur = "Signatures antivirus datant de $age jours."
            $risque = "Des signatures un peu anciennes détectent moins bien les menaces récentes."
            $action = "Lancer une mise à jour des définitions Windows Defender."
        } else {
            $etat   = "Critique"
            $valeur = "Signatures antivirus obsolètes ($age jours)."
            $risque = "Des signatures obsolètes laissent passer les menaces récentes."
            $action = "Mettre à jour immédiatement les définitions Windows Defender."
        }
    }
    catch {
        $etat   = "Attention"
        $valeur = "Impossible de lire l'âge des signatures antivirus."
        $risque = "L'état des signatures n'a pas pu être déterminé."
        $action = "Vérifier manuellement les mises à jour de l'antivirus."
    }

    return @{
        Nom       = "Signatures antivirus"
        Categorie = "Protection"
        Etat      = $etat
        Valeur    = $valeur
        Constat   = $valeur
        Risque    = $risque
        Action    = $action
        Poids     = 2
    }
}

function Test-MisesAJour {
    try {
        # On ouvre l'historique de Windows Update (composant COM de Windows)
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $count    = $searcher.GetTotalHistoryCount()

        if ($count -eq 0) { throw "Historique des mises à jour vide." }

        # On garde la mise a jour REUSSIE (ResultCode 2) la plus recente
        $derniere = $searcher.QueryHistory(0, $count) |
                    Where-Object { $_.ResultCode -eq 2 } |
                    Sort-Object Date -Descending |
                    Select-Object -First 1

        if ($null -eq $derniere) { throw "Aucune mise à jour réussie trouvée." }

        $dateDerniere = $derniere.Date
        $jours        = (New-TimeSpan -Start $dateDerniere -End (Get-Date)).Days
        $dateLisible  = $dateDerniere.ToString("dd/MM/yyyy")

        if ($jours -le 35) {
            $etat   = "Conforme"
            $valeur = "Dernière mise à jour le $dateLisible (il y a $jours jours)."
            $risque = ""
            $action = ""
        } elseif ($jours -le 60) {
            $etat   = "Attention"
            $valeur = "Dernière mise à jour le $dateLisible (il y a $jours jours)."
            $risque = "Le poste a probablement manqué un cycle de mises à jour mensuel."
            $action = "Lancer Windows Update et installer les correctifs en attente."
        } else {
            $etat   = "Critique"
            $valeur = "Dernière mise à jour le $dateLisible (il y a $jours jours)."
            $risque = "Un poste non mis à jour de longue date cumule des vulnérabilités connues."
            $action = "Mettre à jour le poste sans tarder via Windows Update."
        }
    }
    catch {
        $etat   = "Attention"
        $valeur = "Impossible de lire l'historique des mises à jour."
        $risque = "L'état des mises à jour n'a pas pu être déterminé."
        $action = "Vérifier manuellement Windows Update."
    }

    return @{
        Nom       = "Mises à jour Windows"
        Categorie = "Mises à jour"
        Etat      = $etat
        Valeur    = $valeur
        Constat   = $valeur
        Risque    = $risque
        Action    = $action
        Poids     = 3
    }
}

function Test-AdminsLocaux {
    try {
        # Groupe Administrateurs identifie par son SID universel (S-1-5-32-544)
        $membres = @(Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop)
        $nombre  = $membres.Count
        $noms    = ($membres.Name) -join ", "

        if ($nombre -le 2) {
            $etat   = "Conforme"
            $valeur = "$nombre compte(s) administrateur : $noms."
            $risque = ""
            $action = ""
        } else {
            $etat   = "Attention"
            $valeur = "$nombre comptes administrateurs : $noms."
            $risque = "Plus il y a de comptes administrateurs, plus la surface d'attaque est large."
            $action = "Vérifier que chaque compte administrateur est légitime et nécessaire."
        }
    }
    catch {
        $etat   = "Attention"
        $valeur = "Impossible de lire les comptes administrateurs."
        $risque = "La composition du groupe Administrateurs n'a pas pu être déterminée."
        $action = "Vérifier manuellement les membres du groupe Administrateurs."
    }

    return @{
        Nom       = "Comptes administrateurs locaux"
        Categorie = "Comptes"
        Etat      = $etat
        Valeur    = $valeur
        Constat   = $valeur
        Risque    = $risque
        Action    = $action
        Poids     = 2
    }
}

function Test-CompteInvite {
    try {
        # Compte Invite identifie par son SID se terminant par -501
        $invite = Get-LocalUser | Where-Object { $_.SID.Value -like "*-501" }

        if ($null -ne $invite -and $invite.Enabled) {
            $etat   = "Critique"
            $valeur = "Le compte Invité est activé."
            $risque = "Un compte Invité actif offre un accès potentiel non authentifié au poste."
            $action = "Désactiver le compte Invité."
        } else {
            $etat   = "Conforme"
            $valeur = "Le compte Invité est désactivé ou absent."
            $risque = ""
            $action = ""
        }
    }
    catch {
        $etat   = "Attention"
        $valeur = "Impossible de lire l'état du compte Invité."
        $risque = "L'état du compte Invité n'a pas pu être déterminé."
        $action = "Vérifier manuellement le compte Invité."
    }

    return @{
        Nom       = "Compte Invité"
        Categorie = "Comptes"
        Etat      = $etat
        Valeur    = $valeur
        Constat   = $valeur
        Risque    = $risque
        Action    = $action
        Poids     = 2
    }
}

function Test-DemarrageAuto {
    # Les deux emplacements classiques de demarrage automatique
    $chemins = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    )

    $details   = @()
    $suspectes = 0

    foreach ($chemin in $chemins) {
        if (Test-Path $chemin) {
            $item    = Get-ItemProperty -Path $chemin
            # On ne garde que les vraies valeurs (on exclut les proprietes techniques PS*)
            $valeurs = $item.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }

            foreach ($v in $valeurs) {
                $details += "$($v.Name) -> $($v.Value)"

                # Indice : une cible dans un dossier temporaire ou Telechargements
                if ($v.Value -match "\\Temp\\" -or $v.Value -match "\\Downloads\\") {
                    $suspectes++
                }
            }
        }
    }

    $nombre = $details.Count

    if ($suspectes -gt 0) {
        $etat   = "Attention"
        $valeur = "$nombre programme(s) au démarrage, dont $suspectes dans un dossier inhabituel."
        $risque = "Un programme lancé depuis Temp ou Téléchargements est un indice possible de logiciel indésirable."
        $action = "Examiner les entrées de démarrage situées dans des dossiers temporaires."
    } else {
        $etat   = "Information"
        $valeur = "$nombre programme(s) au démarrage détecté(s)."
        $risque = ""
        $action = ""
    }

    return @{
        Nom       = "Programmes au démarrage"
        Categorie = "Persistance"
        Etat      = $etat
        Valeur    = $valeur
        Constat   = $valeur
        Risque    = $risque
        Action    = $action
        Poids     = 1
        Details   = $details
    }
}

function Test-TachesPlanifiees {
    try {
        # On ecarte les taches systeme Microsoft, on garde les taches tierces actives
        $taches = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
            $_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled"
        })

        $details = @()
        foreach ($t in $taches) {
            $details += "$($t.TaskName)  [$($t.TaskPath)]"
        }

        if ($taches.Count -eq 0) {
            $valeur = "Aucune tâche planifiée tierce active."
        } else {
            $valeur = "$($taches.Count) tâche(s) planifiée(s) tierce(s) active(s)."
        }

        $etat   = "Information"
        $risque = ""
        $action = ""
    }
    catch {
        $etat    = "Attention"
        $valeur  = "Impossible de lire les tâches planifiées."
        $risque  = "La liste des tâches planifiées n'a pas pu être déterminée."
        $action  = "Vérifier manuellement le Planificateur de tâches."
        $details = @()
    }

    return @{
        Nom       = "Tâches planifiées tierces"
        Categorie = "Persistance"
        Etat      = $etat
        Valeur    = $valeur
        Constat   = $valeur
        Risque    = $risque
        Action    = $action
        Poids     = 0
        Details   = $details
    }
}

function Test-SecureBoot {
    try {
        $actif = Confirm-SecureBootUEFI -ErrorAction Stop

        if ($actif) {
            $etat   = "Conforme"
            $valeur = "Secure Boot est activé."
            $risque = ""
            $action = ""
        } else {
            $etat   = "Attention"
            $valeur = "Secure Boot est désactivé."
            $risque = "Sans Secure Boot, un code non signé peut s'exécuter au démarrage (bootkit)."
            $action = "Activer Secure Boot dans le firmware UEFI du poste."
        }
    }
    catch {
        # Confirm-SecureBootUEFI echoue si le poste n'est pas en UEFI
        $etat   = "Attention"
        $valeur = "Secure Boot indisponible (poste probablement en BIOS hérité)."
        $risque = "Un poste en BIOS hérité ne bénéficie pas de Secure Boot."
        $action = "Vérifier si le poste peut passer en UEFI avec Secure Boot."
    }

    return @{
        Nom       = "Secure Boot"
        Categorie = "Identité du poste"
        Etat      = $etat
        Valeur    = $valeur
        Constat   = $valeur
        Risque    = $risque
        Action    = $action
        Poids     = 2
    }
}

function Test-BitLocker {
    try {
        # On regarde le volume systeme (la ou Windows est installe)
        $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop

        if ($volume.ProtectionStatus -eq "On") {
            $etat   = "Conforme"
            $valeur = "Le disque système ($env:SystemDrive) est chiffré par BitLocker."
            $risque = ""
            $action = ""
        } else {
            $etat   = "Attention"
            $valeur = "Le disque système ($env:SystemDrive) n'est pas chiffré."
            $risque = "Sans chiffrement, les données sont lisibles si le disque est retiré ou le poste volé."
            $action = "Activer BitLocker sur le disque système."
        }
    }
    catch {
        $etat   = "Attention"
        $valeur = "État de BitLocker illisible (édition de Windows sans BitLocker ?)."
        $risque = "L'état du chiffrement de disque n'a pas pu être déterminé."
        $action = "Vérifier manuellement le chiffrement du disque."
    }

    return @{
        Nom       = "Chiffrement du disque (BitLocker)"
        Categorie = "Identité du poste"
        Etat      = $etat
        Valeur    = $valeur
        Constat   = $valeur
        Risque    = $risque
        Action    = $action
        Poids     = 2
    }
}

function Test-UAC {
    try {
        $chemin    = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $valeurUAC = (Get-ItemProperty -Path $chemin -Name EnableLUA -ErrorAction Stop).EnableLUA

        if ($valeurUAC -eq 1) {
            $etat   = "Conforme"
            $valeur = "Le contrôle de compte d'utilisateur (UAC) est activé."
            $risque = ""
            $action = ""
        } else {
            $etat   = "Critique"
            $valeur = "Le contrôle de compte d'utilisateur (UAC) est désactivé."
            $risque = "UAC désactivé permet aux programmes d'obtenir les droits administrateur sans confirmation."
            $action = "Réactiver l'UAC (EnableLUA = 1) puis redémarrer le poste."
        }
    }
    catch {
        $etat   = "Attention"
        $valeur = "Impossible de lire l'état de l'UAC."
        $risque = "L'état de l'UAC n'a pas pu être déterminé."
        $action = "Vérifier manuellement les paramètres de contrôle de compte d'utilisateur."
    }

    return @{
        Nom       = "Contrôle de compte d'utilisateur (UAC)"
        Categorie = "Identité du poste"
        Etat      = $etat
        Valeur    = $valeur
        Constat   = $valeur
        Risque    = $risque
        Action    = $action
        Poids     = 2
    }
}

function Test-TamperProtection {
    try {
        $defender = Get-MpComputerStatus -ErrorAction Stop
        if ($defender.IsTamperProtected) {
            $etat   = "Conforme"
            $valeur = "La protection contre la falsification (Tamper Protection) est active."
            $risque = ""
            $action = ""
        } else {
            $etat   = "Attention"
            $valeur = "La protection contre la falsification est désactivée."
            $risque = "Sans elle, un logiciel malveillant peut désactiver l'antivirus avant d'agir."
            $action = "Activer la protection contre la falsification dans Sécurité Windows."
        }
    }
    catch {
        $etat   = "Attention"
        $valeur = "Impossible de lire la protection contre la falsification."
        $risque = "Son état n'a pas pu être déterminé."
        $action = "Vérifier manuellement dans Sécurité Windows."
    }

    return @{
        Nom       = "Protection contre la falsification"
        Categorie = "Protection"
        Etat      = $etat
        Valeur    = $valeur
        Constat   = $valeur
        Risque    = $risque
        Action    = $action
        Poids     = 2
    }
}

function Test-ProtectionPUA {
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $pua  = $pref.PUAProtection   # 0 = desactive, 1 = bloque, 2 = audit

        if ($pua -eq 1) {
            $etat   = "Conforme"
            $valeur = "La protection contre les applications indésirables (PUA) est active (blocage)."
            $risque = ""
            $action = ""
        } elseif ($pua -eq 2) {
            $etat   = "Attention"
            $valeur = "La protection PUA est en mode audit (détecte sans bloquer)."
            $risque = "Les applications indésirables sont signalées mais pas bloquées."
            $action = "Passer la protection PUA en mode blocage."
        } else {
            $etat   = "Attention"
            $valeur = "La protection contre les applications indésirables (PUA) est désactivée."
            $risque = "Les adwares et logiciels indésirables ne sont pas bloqués."
            $action = "Activer la protection PUA (Set-MpPreference -PUAProtection Enabled)."
        }
    }
    catch {
        $etat   = "Attention"
        $valeur = "Impossible de lire la protection PUA."
        $risque = "Son état n'a pas pu être déterminé."
        $action = "Vérifier manuellement la configuration de Windows Defender."
    }

    return @{
        Nom       = "Protection contre les applications indésirables (PUA)"
        Categorie = "Protection"
        Etat      = $etat
        Valeur    = $valeur
        Constat   = $valeur
        Risque    = $risque
        Action    = $action
        Poids     = 1
    }
}

function Test-SMBv1 {
    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop

        if ($smb.EnableSMB1Protocol) {
            $etat   = "Critique"
            $valeur = "Le protocole SMBv1 est activé."
            $risque = "SMBv1 est obsolète et vulnérable (faille exploitée par WannaCry / EternalBlue)."
            $action = "Désactiver SMBv1 (Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol)."
        } else {
            $etat   = "Conforme"
            $valeur = "Le protocole SMBv1 est désactivé."
            $risque = ""
            $action = ""
        }
    }
    catch {
        $etat   = "Attention"
        $valeur = "Impossible de lire l'état de SMBv1."
        $risque = "L'état du protocole SMBv1 n'a pas pu être déterminé."
        $action = "Vérifier manuellement la configuration SMB."
    }

    return @{
        Nom       = "Protocole SMBv1"
        Categorie = "Durcissement"
        Etat      = $etat
        Valeur    = $valeur
        Constat   = $valeur
        Risque    = $risque
        Action    = $action
        Poids     = 3
    }
}

function Test-LLMNR {
    # 0 = LLMNR desactive (bon) ; 1 ou absent = actif (defaut Windows)
    $chemin = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    $llmnr  = (Get-ItemProperty -Path $chemin -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast

    if ($llmnr -eq 0) {
        $etat   = "Conforme"
        $valeur = "LLMNR est désactivé."
        $risque = ""
        $action = ""
    } else {
        $etat   = "Attention"
        $valeur = "LLMNR est activé (configuration par défaut de Windows)."
        $risque = "LLMNR permet l'empoisonnement de résolution de noms et le vol d'authentifiants sur le réseau local."
        $action = "Désactiver LLMNR par stratégie de groupe (EnableMulticast = 0)."
    }

    return @{
        Nom       = "LLMNR (résolution de noms multicast)"
        Categorie = "Durcissement"
        Etat      = $etat
        Valeur    = $valeur
        Constat   = $valeur
        Risque    = $risque
        Action    = $action
        Poids     = 2
    }
}

function Test-WDigest {
    # 1 = mots de passe en clair en memoire (mauvais) ; 0 ou absent = securise
    $chemin  = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    $wdigest = (Get-ItemProperty -Path $chemin -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential

    if ($wdigest -eq 1) {
        $etat   = "Critique"
        $valeur = "WDigest stocke les mots de passe en clair en mémoire."
        $risque = "Un attaquant disposant de droits peut extraire les mots de passe en clair de la mémoire (Mimikatz)."
        $action = "Mettre UseLogonCredential = 0 dans le registre, puis redémarrer."
    } else {
        $etat   = "Conforme"
        $valeur = "WDigest ne stocke pas les mots de passe en clair (configuration sécurisée)."
        $risque = ""
        $action = ""
    }

    return @{
        Nom       = "WDigest (mots de passe en mémoire)"
        Categorie = "Durcissement"
        Etat      = $etat
        Valeur    = $valeur
        Constat   = $valeur
        Risque    = $risque
        Action    = $action
        Poids     = 3
    }
}

function Test-TPM {
    try {
        $tpm = Get-Tpm -ErrorAction Stop

        if ($tpm.TpmPresent -and $tpm.TpmReady) {
            $etat   = "Conforme"
            $valeur = "Une puce TPM est présente et prête à l'emploi."
            $risque = ""
            $action = ""
        } elseif ($tpm.TpmPresent) {
            $etat   = "Attention"
            $valeur = "Une puce TPM est présente mais n'est pas prête."
            $risque = "Un TPM non initialisé ne peut pas protéger les clés de chiffrement (BitLocker)."
            $action = "Initialiser le TPM via la console tpm.msc ou le firmware."
        } else {
            $etat   = "Attention"
            $valeur = "Aucune puce TPM détectée."
            $risque = "Sans TPM, le chiffrement et l'intégrité du démarrage sont moins protégés."
            $action = "Vérifier la présence et l'activation du TPM dans le firmware."
        }
    }
    catch {
        $etat   = "Attention"
        $valeur = "Impossible de lire l'état du TPM."
        $risque = "L'état du TPM n'a pas pu être déterminé."
        $action = "Vérifier manuellement dans tpm.msc."
    }

    return @{
        Nom       = "Module TPM"
        Categorie = "Identité du poste"
        Etat      = $etat
        Valeur    = $valeur
        Constat   = $valeur
        Risque    = $risque
        Action    = $action
        Poids     = 2
    }
}

function Test-SmartScreen {
    # "Off" = desactive ; "Warn"/"RequireAdmin"/absent = actif
    $chemin = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    $ss = (Get-ItemProperty -Path $chemin -Name SmartScreenEnabled -ErrorAction SilentlyContinue).SmartScreenEnabled

    if ($ss -eq "Off") {
        $etat   = "Attention"
        $valeur = "SmartScreen (filtre de réputation) est désactivé."
        $risque = "Sans SmartScreen, les applications et fichiers malveillants connus ne sont pas filtrés."
        $action = "Réactiver SmartScreen dans Sécurité Windows."
    } else {
        $etat   = "Conforme"
        $valeur = "SmartScreen (filtre de réputation des applications) est actif."
        $risque = ""
        $action = ""
    }

    return @{
        Nom       = "SmartScreen"
        Categorie = "Protection"
        Etat      = $etat
        Valeur    = $valeur
        Constat   = $valeur
        Risque    = $risque
        Action    = $action
        Poids     = 2
    }
}

# ===== AFFICHAGE D'UN RESULTAT =====

function Show-Resultat($resultat) {
    switch ($resultat.Etat) {
        "Conforme"  { $couleur = "Green" }
        "Attention" { $couleur = "Yellow" }
        "Critique"  { $couleur = "Red" }
        default     { $couleur = "Cyan" }   # Information
    }

    Write-Host "[$($resultat.Etat)] " -ForegroundColor $couleur -NoNewline
    Write-Host $resultat.Nom -ForegroundColor White
    Write-Host "   $($resultat.Valeur)" -ForegroundColor Gray

    # Affichage du detail (liste) si le controle en fournit
    if ($resultat.Details) {
        foreach ($ligne in $resultat.Details) {
            Write-Host "      $ligne" -ForegroundColor DarkGray
        }
    }
    if ($resultat.Risque) { Write-Host "   Risque : $($resultat.Risque)" -ForegroundColor DarkYellow }
    if ($resultat.Action) { Write-Host "   Action : $($resultat.Action)" -ForegroundColor DarkCyan }
    Write-Host ""
}

# ===== CALCUL DU SCORE =====

function Get-Score($resultats) {
    $pointsPossibles = 0
    $pointsGagnes    = 0

    foreach ($r in $resultats) {
        # On ignore les controles d'information (poids 0)
        if ($r.Poids -eq 0) { continue }# On ignore les controles de poids 0 ET ceux purement informatifs
        if ($r.Poids -eq 0 -or $r.Etat -eq "Information") { continue }
        $pointsPossibles += $r.Poids

        switch ($r.Etat) {
            "Conforme"  { $pointsGagnes += $r.Poids }
            "Attention" { $pointsGagnes += ($r.Poids / 2) }
            "Critique"  { $pointsGagnes += 0 }
        }
    }

    # Garde-fou : on evite la division par zero
    if ($pointsPossibles -eq 0) { return 0 }

    $score = [math]::Round(($pointsGagnes / $pointsPossibles) * 100)
    return $score
}

function Get-ScoreParCategorie($resultats) {
    $scores = [ordered]@{}
    $categories = $resultats.Categorie | Select-Object -Unique

    foreach ($cat in $categories) {
        $controles = $resultats | Where-Object { $_.Categorie -eq $cat }

        $possibles = 0
        $gagnes    = 0
        foreach ($r in $controles) {
            if ($r.Poids -eq 0 -or $r.Etat -eq "Information") { continue }
            $possibles += $r.Poids
            switch ($r.Etat) {
                "Conforme"  { $gagnes += $r.Poids }
                "Attention" { $gagnes += ($r.Poids / 2) }
                "Critique"  { $gagnes += 0 }
            }
        }

        if ($possibles -eq 0) {
            $scores[$cat] = $null   # categorie purement informative : pas de score
        } else {
            $scores[$cat] = [math]::Round(($gagnes / $possibles) * 100)
        }
    }

    return $scores
}

function Show-Score($score) {
    if ($score -ge 80) {
        $couleur      = "Green"
        $appreciation = "Bonne posture de sécurité"
    } elseif ($score -ge 50) {
        $couleur      = "Yellow"
        $appreciation = "Posture à renforcer"
    } else {
        $couleur      = "Red"
        $appreciation = "Posture critique"
    }

    Write-Host ""
    Write-Host "===== SCORE DE CONFORMITÉ =====" -ForegroundColor White
    Write-Host "   $score % - $appreciation" -ForegroundColor $couleur
    Write-Host ""
}

function ConvertTo-HtmlSafe($texte) {
    # Neutralise les caracteres speciaux pour ne pas casser le HTML
    if ($null -eq $texte) { return "" }
    return ([string]$texte).Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
}

function New-RadarSVG($scoresParCat) {
    # On ne garde que les categories qui ont un score
    $cats = @()
    foreach ($cle in $scoresParCat.Keys) {
        if ($null -ne $scoresParCat[$cle]) { $cats += $cle }
    }

    $n = $cats.Count
    if ($n -lt 3) { return "" }   # un radar a besoin d'au moins 3 axes

    $cx = 240; $cy = 210; $rayon = 140
    $svg = "<svg viewBox='0 0 480 440' xmlns='http://www.w3.org/2000/svg' class='radar'>"

    # Grille concentrique (25 / 50 / 75 / 100 %)
    foreach ($niveau in 25, 50, 75, 100) {
        $pts = ""
        for ($i = 0; $i -lt $n; $i++) {
            $a = (-90 + $i * (360 / $n)) * [math]::PI / 180
            $r = $rayon * ($niveau / 100)
            $x = [math]::Round($cx + $r * [math]::Cos($a), 1)
            $y = [math]::Round($cy + $r * [math]::Sin($a), 1)
            $pts += "$x,$y "
        }
        $svg += "<polygon points='$($pts.Trim())' fill='none' stroke='#E5E0D8' stroke-width='1' />"
    }

    # Axes
    for ($i = 0; $i -lt $n; $i++) {
        $a = (-90 + $i * (360 / $n)) * [math]::PI / 180
        $x = [math]::Round($cx + $rayon * [math]::Cos($a), 1)
        $y = [math]::Round($cy + $rayon * [math]::Sin($a), 1)
        $svg += "<line x1='$cx' y1='$cy' x2='$x' y2='$y' stroke='#E5E0D8' stroke-width='1' />"
    }

    # Polygone des scores
    $ptsScore = ""
    for ($i = 0; $i -lt $n; $i++) {
        $a = (-90 + $i * (360 / $n)) * [math]::PI / 180
        $r = $rayon * ($scoresParCat[$cats[$i]] / 100)
        $x = [math]::Round($cx + $r * [math]::Cos($a), 1)
        $y = [math]::Round($cy + $r * [math]::Sin($a), 1)
        $ptsScore += "$x,$y "
    }
    $svg += "<polygon points='$($ptsScore.Trim())' fill='#1E3A5F' fill-opacity='0.22' stroke='#1E3A5F' stroke-width='2' />"

    # Points + etiquettes
    for ($i = 0; $i -lt $n; $i++) {
        $a = (-90 + $i * (360 / $n)) * [math]::PI / 180
        $score = $scoresParCat[$cats[$i]]
        $r = $rayon * ($score / 100)
        $x = [math]::Round($cx + $r * [math]::Cos($a), 1)
        $y = [math]::Round($cy + $r * [math]::Sin($a), 1)
        $svg += "<circle cx='$x' cy='$y' r='4' fill='#1E3A5F' />"

        $rl = $rayon + 26
        $lx = [math]::Round($cx + $rl * [math]::Cos($a), 1)
        $ly = [math]::Round($cy + $rl * [math]::Sin($a), 1)
        $ancre = "middle"
        if ($lx -gt $cx + 5) { $ancre = "start" } elseif ($lx -lt $cx - 5) { $ancre = "end" }

        $nom = $cats[$i]
        if ($nom -eq "Identité du poste") { $nom = "Identité" }

        $svg += "<text x='$lx' y='$ly' text-anchor='$ancre' class='radar-label'>$nom</text>"
        $svg += "<text x='$lx' y='$([math]::Round($ly + 15, 1))' text-anchor='$ancre' class='radar-score'>$score %</text>"
    }

    $svg += "</svg>"
    return $svg
}

function New-AnneauScore($score) {
    if ($score -ge 80)     { $couleur = "#2F5D3F" }
    elseif ($score -ge 50) { $couleur = "#C97B4A" }
    else                   { $couleur = "#B83A26" }

    $circonf = 534
    $offset  = [math]::Round($circonf - ($circonf * $score / 100), 1)

    $svg = @"
<svg viewBox="0 0 200 200" class="anneau">
  <circle cx="100" cy="100" r="85" fill="none" stroke="#EBE6DD" stroke-width="18" />
  <circle cx="100" cy="100" r="85" fill="none" stroke="$couleur" stroke-width="18"
          stroke-linecap="round" stroke-dasharray="$circonf" stroke-dashoffset="$offset"
          transform="rotate(-90 100 100)" class="anneau-arc" />
  <text x="100" y="100" text-anchor="middle" dominant-baseline="central" class="anneau-valeur" fill="$couleur">$score%</text>
</svg>
"@
    return $svg
}

function New-RapportHtml($resultats, $score) {
    # Couleur et appreciation du score global
    if ($score -ge 80) {
        $scoreClasse  = "score-bon"
        $appreciation = "Bonne posture de sécurité"
    } elseif ($score -ge 50) {
        $scoreClasse  = "score-moyen"
        $appreciation = "Posture à renforcer"
    } else {
        $scoreClasse  = "score-faible"
        $appreciation = "Posture critique"
    }

    $nomPoste     = $env:COMPUTERNAME
    $dateGen      = Get-Date -Format "dd/MM/yyyy à HH:mm"
    $scoresParCat = Get-ScoreParCategorie $resultats
    $radarSvg     = New-RadarSVG $scoresParCat
    $anneauSvg = New-AnneauScore $score

    # Compteurs par etat
    $nbConforme  = @($resultats | Where-Object { $_.Etat -eq "Conforme" }).Count
    $nbAttention = @($resultats | Where-Object { $_.Etat -eq "Attention" }).Count
    $nbCritique  = @($resultats | Where-Object { $_.Etat -eq "Critique" }).Count

    # Corps : une section par categorie, cartes en grille
    $corps = ""
    $categories = $resultats.Categorie | Select-Object -Unique

    foreach ($cat in $categories) {
        $scoreCat   = $scoresParCat[$cat]
        $scoreTexte = if ($null -ne $scoreCat) { " — $scoreCat %" } else { "" }
        $corps += "<div class='categorie'><div class='categorie-titre'>$cat$scoreTexte</div><div class='cartes'>"

        $controles = $resultats | Where-Object { $_.Categorie -eq $cat }
        foreach ($r in $controles) {
            $classe = $r.Etat.ToLower()
            # Pleine largeur si la carte porte un risque, une action ou une liste
            $pleine = if ($r.Risque -or $r.Action -or ($r.Details -and $r.Details.Count -gt 0)) { " pleine" } else { "" }

            $corps += "<div class='carte $classe$pleine'>"
            $corps += "<div class='carte-tete'><span class='badge $classe'>$($r.Etat)</span><span class='carte-nom'>$($r.Nom)</span></div>"
            $corps += "<div class='carte-valeur'>$(ConvertTo-HtmlSafe $r.Valeur)</div>"

            if ($r.Risque) { $corps += "<div class='carte-risque'><strong>Risque :</strong> $($r.Risque)</div>" }
            if ($r.Action) { $corps += "<div class='carte-action'><strong>À faire :</strong> $($r.Action)</div>" }

            if ($r.Details -and $r.Details.Count -gt 0) {
                $corps += "<div class='details'>"
                foreach ($ligne in $r.Details) { $corps += "<div>$(ConvertTo-HtmlSafe $ligne)</div>" }
                $corps += "</div>"
            }

            $corps += "</div>"
        }

        $corps += "</div></div>"
    }

    $radarBloc = if ($radarSvg) { "<div class='radar-bloc'><h2>Conformité par catégorie</h2>$radarSvg</div>" } else { "" }

    # Gabarit HTML
    $html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport winCheck-compagnon</title>
<link rel="stylesheet" href="rapport.css">
</head>
<body>
<div class="conteneur">
 <div class="entete">
        <div class="mascotte"></div>
        <div class="entete-texte">
            <h1>winCheck-compagnon</h1>
            <div class="sous-titre">Diagnostic de la posture de sécurité Windows</div>
            <div class="date">Poste : $nomPoste — Généré le $dateGen</div>
        </div>
    </div>
    <div class="synthese">
        <div class="synthese-gauche">
          <div class="score-bloc">
                $anneauSvg
                <div class="score-libelle">$appreciation</div>
            </div>
            <div class="compteurs">
                <div class="compteur conforme"><div class="compteur-valeur">$nbConforme</div><div class="compteur-libelle">Conformes</div></div>
                <div class="compteur attention"><div class="compteur-valeur">$nbAttention</div><div class="compteur-libelle">Attention</div></div>
                <div class="compteur critique"><div class="compteur-valeur">$nbCritique</div><div class="compteur-libelle">Critiques</div></div>
            </div>
        </div>
        <div class="synthese-droite">
            $radarBloc
        </div>
    </div>
    $corps
    <div class="pied">winCheck-compagnon — Famille « Outils Compagnon »<br>DOUKAKAS Yeni</div>
</div>
</body>
</html>
"@

    $chemin = Join-Path $PSScriptRoot "rapport.html"
    Set-Content -Path $chemin -Value $html -Encoding UTF8
    return $chemin
}

# ===== PROGRAMME PRINCIPAL =====

$resultats = @()
$resultats += Test-InfosSysteme
$resultats += Test-SecureBoot
$resultats += Test-BitLocker
$resultats += Test-UAC
$resultats += Test-TPM
$resultats += Test-AntivirusTempsReel
$resultats += Test-PareFeu
$resultats += Test-SignaturesAntivirus
$resultats += Test-TamperProtection
$resultats += Test-ProtectionPUA
$resultats += Test-SmartScreen
$resultats += Test-MisesAJour
$resultats += Test-AdminsLocaux
$resultats += Test-CompteInvite
$resultats += Test-SMBv1
$resultats += Test-LLMNR
$resultats += Test-WDigest
$resultats += Test-DemarrageAuto
$resultats += Test-TachesPlanifiees

foreach ($r in $resultats) {
    Show-Resultat $r
}

# Calcul et affichage du score global
$score = Get-Score $resultats
Show-Score $score

# ===== GENERATION ET OUVERTURE DU RAPPORT HTML =====
$cheminRapport = New-RapportHtml $resultats $score
Write-Host "Rapport HTML généré : $cheminRapport" -ForegroundColor Cyan
Invoke-Item $cheminRapport

# ===== TEMPORAIRE : garde la fenetre ouverte pour ce test =====
Write-Host ""
Write-Host "[OK] Rapport genere : $cheminRapport" -ForegroundColor Green
Write-Host "Il vient de s'ouvrir dans votre navigateur." -ForegroundColor Gray
Write-Host ""
$null = Read-Host "Appuyez sur Entree pour fermer cette fenetre"