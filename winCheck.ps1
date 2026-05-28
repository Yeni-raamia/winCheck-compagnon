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

function Test-BureauADistance {
    # On lit l'etat du Bureau a distance dans le registre.
    # fDenyTSConnections = 1 : RDP refuse (desactive). = 0 : RDP autorise (active).
    $cle = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
    $valeur = (Get-ItemProperty -Path $cle -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections

    if ($valeur -eq 0) {
        $etat    = "Attention"
        $constat = "Le Bureau à distance (RDP) est activé sur ce poste."
        $risque  = "Le RDP est l'un des vecteurs les plus exploités par les rançongiciels. Activé sans protection, il expose le poste aux attaques par force brute et au vol d'identifiants."
        $action  = "S'il n'est pas indispensable, désactivez-le (Paramètres > Système > Bureau à distance). S'il est nécessaire, exigez l'authentification NLA, restreignez l'accès par pare-feu et passez par un VPN."
    }
    else {
        $etat    = "Conforme"
        $constat = "Le Bureau à distance (RDP) est désactivé."
        $risque  = ""
        $action  = ""
    }

    return @{
        Nom       = "Bureau à distance (RDP)"
        Categorie = "Réseau"
        Etat      = $etat
        Valeur    = $constat
        Risque    = $risque
        Action    = $action
        Poids     = 2
    }
}

function Test-PartagesReseau {
   # Get-SmbShare liste tous les partages. On ecarte :
    #  - les partages systeme/admin marques .Special ($true) : C$, ADMIN$, IPC$...
    #  - les partages dont le nom finit par "$" (caches par convention), comme
    #    print$ (pilotes d'imprimante) qui est legitime, pas un partage de donnees.
    # On ne garde que les partages personnalises reellement exposes.
    $partages = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object {
        -not $_.Special -and $_.Name -notlike '*$'
    })

    if (-not $partages) {
        return @{
            Nom       = "Partages réseau"
            Categorie = "Réseau"
            Etat      = "Conforme"
            Valeur    = "Aucun partage réseau personnalisé. Seuls les partages administratifs par défaut sont présents."
            Risque    = ""
            Action    = ""
            Poids     = 2
        }
    }

    $details = foreach ($p in $partages) {
        "$($p.Name) -> $($p.Path)"
    }

    return @{
        Nom       = "Partages réseau"
        Categorie = "Réseau"
        Etat      = "Attention"
        Valeur    = "$($partages.Count) partage(s) réseau exposé(s) sur ce poste."
        Risque    = "Un dossier partagé mal protégé peut exposer des fichiers sensibles aux autres utilisateurs du réseau, voire servir de point de propagation à un rançongiciel."
        Action    = "Vérifiez que chaque partage est légitime et que ses permissions sont restreintes aux seules personnes concernées. Supprimez les partages inutiles."
        Poids     = 2
        Details   = @($details)
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
function Test-PortsEnEcoute {
    # On liste les ports TCP en ECOUTE accessibles depuis le reseau.
    # LocalAddress 0.0.0.0 (IPv4) ou :: (IPv6) = ecoute sur TOUTES les interfaces.
    # On ignore 127.0.0.1 / ::1 (ecoute locale uniquement, non exposee).
    $ecoutes = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -eq "0.0.0.0" -or $_.LocalAddress -eq "::" } |
        Sort-Object LocalPort -Unique)

    # Pour chaque port, on retrouve le programme qui l'a ouvert (via son PID).
    $details = foreach ($e in $ecoutes) {
        $proc = (Get-Process -Id $e.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        if (-not $proc) { $proc = "?" }
        "Port $($e.LocalPort) <- $proc (PID $($e.OwningProcess))"
    }

    return @{
        Nom       = "Ports en écoute"
        Categorie = "Surveillance"
        Etat      = "Information"
        Valeur    = "$($ecoutes.Count) service(s) en écoute accessibles depuis le réseau. Vérifiez que vous reconnaissez les programmes associés."
        Risque    = ""
        Action    = ""
        Poids     = 0
        Details   = @($details)
    }
}

function Test-Processus {
    # On recherche les processus qui s'executent depuis un dossier temporaire
    # ou de telechargement : un logiciel legitime y tourne tres rarement,
    # alors que les programmes malveillants s'y installent souvent.
    # Get-CimInstance Win32_Process donne le chemin complet de chaque executable.
    $suspects = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.ExecutablePath -and (
                $_.ExecutablePath -match '\\Temp\\' -or
                $_.ExecutablePath -match '\\Downloads\\'
            )
        })

    if (-not $suspects) {
        return @{
            Nom       = "Processus en cours"
            Categorie = "Surveillance"
            Etat      = "Conforme"
            Valeur    = "Aucun processus ne s'exécute depuis un dossier temporaire ou de téléchargement."
            Risque    = ""
            Action    = ""
            Poids     = 0
        }
    }

    $details = foreach ($p in $suspects) {
        "$($p.Name) -> $($p.ExecutablePath)"
    }

    return @{
        Nom       = "Processus en cours"
        Categorie = "Surveillance"
        Etat      = "Attention"
        Valeur    = "$($suspects.Count) processus s'exécute(nt) depuis un emplacement inhabituel (dossier temporaire ou téléchargements)."
        Risque    = "Les programmes malveillants s'exécutent fréquemment depuis ces dossiers, où un logiciel légitime ne tourne que très rarement."
        Action    = "Identifiez chaque programme listé. Si vous ne le reconnaissez pas, lancez une analyse antivirus complète et, en cas de doute, isolez le poste du réseau."
        Poids     = 0
        Details   = @($details)
    }
}

function Test-ConnexionsActives {
    # Connexions TCP etablies vers des adresses distantes (reseau local + Internet).
    # On exclut le loopback 127.0.0.1 / ::1 : ce sont des communications internes au poste.
    $cnx = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object {
            $_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -ne "::1"
        } |
        Sort-Object RemoteAddress)

    if (-not $cnx) {
        return @{
            Nom       = "Connexions actives"
            Categorie = "Surveillance"
            Etat      = "Information"
            Valeur    = "Aucune connexion sortante établie pour le moment."
            Risque    = ""
            Action    = ""
            Poids     = 0
        }
    }

    # Pour chaque connexion : adresse distante, port, et programme responsable.
    $details = foreach ($c in $cnx) {
        $proc = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        if (-not $proc) { $proc = "?" }
        "$($c.RemoteAddress):$($c.RemotePort) <- $proc (PID $($c.OwningProcess))"
    }

    return @{
        Nom       = "Connexions actives"
        Categorie = "Surveillance"
        Etat      = "Information"
        Valeur    = "$($cnx.Count) connexion(s) établie(s) avec des adresses distantes. Vérifiez que les programmes et destinations vous semblent légitimes."
        Risque    = ""
        Action    = ""
        Poids     = 0
        Details   = @($details)
    }
}

function Test-Applications {
    # --- 1. Inventaire des logiciels installes (registre "Uninstall") ---
    $chemins = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $apps = foreach ($chemin in $chemins) {
        Get-ItemProperty -Path $chemin -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 } |
            Select-Object -ExpandProperty DisplayName
    }
    $apps = @($apps | Sort-Object -Unique)

    # --- 2. Liste noire : categories d'applications a proscrire sur un poste sensible ---
    # Tu peux completer librement chaque categorie, ou en ajouter d'autres.
    $listeNoire = [ordered]@{
        "Accès distant non maîtrisé"        = @("TeamViewer", "AnyDesk", "UltraViewer", "RustDesk", "VNC", "LogMeIn", "Ammyy", "Splashtop", "ToDesk", "Supremo", "Chrome Remote Desktop")
        "Partage de fichiers P2P / torrent" = @("uTorrent", "BitTorrent", "qBittorrent", "Vuze", "Deluge", "eMule", "LimeWire", "FrostWire")
        "Jeux et plateformes de jeu"        = @("Steam", "Epic Games", "Battle.net", "Ubisoft Connect", "EA app", "GOG Galaxy", "Riot", "Roblox", "Minecraft")
        "Minage de cryptomonnaie"           = @("NiceHash", "XMRig", "MinerGate", "Cudo Miner")
        "Stockage cloud personnel"          = @("Dropbox", "Google Drive", "MEGAsync", "pCloud", "iCloud", "MediaFire", "Sync.com")
        "Messageries personnelles"          = @("WhatsApp", "Telegram", "Signal", "Viber", "WeChat", "Discord")
        "VPN et outils de contournement"    = @("NordVPN", "ExpressVPN", "ProtonVPN", "CyberGhost", "Surfshark", "Hotspot Shield", "Psiphon", "Ultrasurf", "Windscribe", "TunnelBear", "Tor Browser")
        "Activateurs et cracks (piratage)"  = @("KMSpico", "KMSAuto", "AutoKMS", "Re-Loader", "Microsoft Toolkit")
        # "Outils de securite offensive"    = @("Mimikatz", "Metasploit", "Cain", "Hashcat", "John the Ripper", "Aircrack", "Cobalt Strike")   # a decommenter pour les postes NON techniques uniquement
    }

    # --- 3. Decompte par categorie + liste des applications detectees ---
    $details = @()
    $totalInterdites = 0
    foreach ($cat in $listeNoire.Keys) {
        # Logiciels installes correspondant a un motif de CETTE categorie.
        $appsDeCat = foreach ($app in $apps) {
            foreach ($motif in $listeNoire[$cat]) {
                if ($app -like "*$motif*") { $app; break }
            }
        }
        $appsDeCat = @($appsDeCat)

        $totalInterdites += $appsDeCat.Count
        $details += "$cat : $($appsDeCat.Count)"
        foreach ($a in $appsDeCat) { $details += "    - $a" }
    }

    # Cas conforme : rien d'interdit.
    if ($totalInterdites -eq 0) {
        return @{
            Nom       = "Applications interdites"
            Categorie = "Applications"
            Etat      = "Conforme"
            Valeur    = "Aucune application interdite parmi les $($apps.Count) logiciels installés. Décompte par catégorie surveillée :"
            Risque    = ""
            Action    = ""
            Poids     = 3
            Details   = @($details)
        }
    }

    # Cas critique : des applications proscrites sont presentes.
    return @{
        Nom       = "Applications interdites"
        Categorie = "Applications"
        Etat      = "Critique"
        Valeur    = "$totalInterdites application(s) interdite(s) détectée(s) sur ce poste. Décompte par catégorie :"
        Risque    = "Ces logiciels n'ont pas leur place sur un poste professionnel sensible : ils élargissent la surface d'attaque, peuvent servir de canal d'exfiltration ou de prise de contrôle à distance, et enfreignent la politique de sécurité."
        Action    = "Désinstallez-les, ou documentez et justifiez formellement leur présence si elle est exceptionnellement autorisée."
        Poids     = 3
        Details   = @($details)
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
    $sommaire = ""
    $categories = $resultats.Categorie | Select-Object -Unique
    $index = 0

    foreach ($cat in $categories) {
        $index++
        $ancre      = "cat-$index"
        $scoreCat   = $scoresParCat[$cat]
        $scoreTexte = if ($null -ne $scoreCat) { " — $scoreCat %" } else { "" }

        # Entree du sommaire (score colore selon le niveau)
        if ($null -eq $scoreCat)  { $scoreSom = "";            $classeSom = "som-info" }
        elseif ($scoreCat -ge 80) { $scoreSom = "$scoreCat %"; $classeSom = "som-bon" }
        elseif ($scoreCat -ge 50) { $scoreSom = "$scoreCat %"; $classeSom = "som-moyen" }
        else                      { $scoreSom = "$scoreCat %"; $classeSom = "som-faible" }
        $sommaire += "<a class='sommaire-item' href='#$ancre'><span class='sommaire-nom'>$cat</span><span class='sommaire-score $classeSom'>$scoreSom</span></a>"

        $corps += "<div class='categorie' id='$ancre'><div class='categorie-titre'>$cat$scoreTexte</div><div class='cartes'>"

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
    <div class="sommaire">
        <h2>Sommaire</h2>
        <div class="sommaire-liste">$sommaire</div>
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

# Liste ordonnee de tous les controles a executer.
$controles = @(
    'Test-InfosSysteme', 'Test-SecureBoot', 'Test-BitLocker', 'Test-UAC', 'Test-TPM',
    'Test-AntivirusTempsReel', 'Test-PareFeu', 'Test-SignaturesAntivirus',
    'Test-TamperProtection', 'Test-ProtectionPUA', 'Test-SmartScreen',
    'Test-MisesAJour',
    'Test-AdminsLocaux', 'Test-CompteInvite',
    'Test-SMBv1', 'Test-LLMNR', 'Test-WDigest',
    'Test-BureauADistance', 'Test-PartagesReseau',
    'Test-DemarrageAuto', 'Test-TachesPlanifiees',
    'Test-PortsEnEcoute', 'Test-ConnexionsActives', 'Test-Processus',
    'Test-Applications'
)

# Execution de chaque controle avec une barre de progression (rassure l'utilisateur).
$total = $controles.Count
for ($i = 0; $i -lt $total; $i++) {
    $pct = [math]::Round((($i + 1) / $total) * 100)
    Write-Progress -Activity "Analyse de la securite du poste" -Status "$pct %" -PercentComplete $pct
    $resultats += & $controles[$i]
}
Write-Progress -Activity "Analyse de la securite du poste" -Completed


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