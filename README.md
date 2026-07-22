# Coffre

[![Dernière version](https://img.shields.io/github/v/release/yoshines62000-alt/Coffre?label=derni%C3%A8re%20version)](https://github.com/yoshines62000-alt/Coffre/releases/latest)
[![Téléchargements](https://img.shields.io/github/downloads/yoshines62000-alt/Coffre/total?label=t%C3%A9l%C3%A9chargements)](https://github.com/yoshines62000-alt/Coffre/releases/latest)

**[⬇️ Télécharger l'exécutable (.exe) — aucune installation requise](https://github.com/yoshines62000-alt/Coffre/releases/latest)**

Gestionnaire de mots de passe chiffré et 100 % local — gratuit, open
source, sans compte, sans cloud, sans synchronisation. Alternative libre à
1Password/Bitwarden Premium/LastPass : vos identifiants ne quittent jamais
votre machine.

## Sécurité — comment ça marche

- Un seul **mot de passe maître** protège tout le coffre. Il n'est **jamais
  stocké**, ni en clair ni sous forme de hash direct : il sert uniquement à
  dériver, via [scrypt](https://en.wikipedia.org/wiki/Scrypt) (résistant aux
  attaques par GPU/ASIC), une clé de chiffrement AES-256.
- Chaque entrée (titre, identifiant, mot de passe, URL, notes) est chiffrée
  individuellement avec **AES-256-GCM** (chiffrement authentifié) : toute
  donnée altérée, même d'un seul octet, est détectée au déchiffrement plutôt
  que silencieusement corrompue.
- Toute la cryptographie s'appuie sur la bibliothèque
  [`cryptography`](https://cryptography.io/) (implémentations auditées) —
  aucune primitive cryptographique maison.
- **Aucun moyen de récupération** du mot de passe maître : c'est la
  contrepartie inévitable d'un chiffrement réel. S'il est oublié, le coffre
  est définitivement inaccessible.
- Le mot de passe maître doit contenir **au moins 8 caractères** (indicateur
  de solidité affiché à la création et au changement de mot de passe).
- Les paramètres de dérivation (scrypt) sont stockés avec chaque coffre et
  mis à niveau automatiquement, sans action de votre part, si une nouvelle
  version de Coffre en recommande de plus robustes.

## Fonctionnalités

- **Coffre chiffré local** : un seul fichier SQLite, entièrement chiffré,
  stocké sur votre machine.
- **Recherche instantanée** parmi vos entrées (titre, identifiant, URL).
- **Générateur de mots de passe** : longueur configurable, majuscules,
  minuscules, chiffres, symboles, option pour éviter les caractères
  ambigus (0/O, 1/l/I).
- **Copie presse-papier auto-effaçable** : un mot de passe copié est
  automatiquement effacé du presse-papier après 20 secondes (sauf si vous
  avez déjà copié autre chose entre-temps), et exclu de l'historique du
  presse-papier Windows (Win+V) ainsi que du Cloud Clipboard.
- **Verrouillage automatique** après 5 minutes d'inactivité.
- **Changement de mot de passe maître** : re-chiffre l'intégralité du
  coffre de façon atomique (jamais d'état intermédiaire corrompu, même en
  cas d'interruption).
- **100 % local, zéro cloud** : aucune connexion réseau, aucun compte,
  aucune télémétrie.
- **Gratuit et open source, pour toujours**.

## Démarrage rapide

1. [**Téléchargez `Coffre.exe`**](https://github.com/yoshines62000-alt/Coffre/releases/latest)
   depuis la dernière release.
2. Double-cliquez dessus : la fenêtre de l'application s'ouvre directement,
   sans installation, sans Python.
3. Au premier lancement, choisissez un mot de passe maître **dont vous êtes
   certain de vous souvenir** (voir l'avertissement ci-dessus).

L'exécutable n'étant pas signé numériquement, Windows SmartScreen peut
afficher un avertissement au premier lancement : cliquez sur **Informations
complémentaires** puis **Exécuter quand même**.

### Vérifier l'intégrité du fichier téléchargé (optionnel)

Chaque release GitHub publie, dans ses notes de version, l'empreinte
**SHA-256** de `Coffre.exe`. Vous pouvez vérifier que le fichier téléchargé
correspond exactement à celui publié par le développeur (protection contre
une altération en transit, une compromission du dépôt, ou une confusion
entre plusieurs versions) avec PowerShell :

```powershell
Get-FileHash .\Coffre.exe -Algorithm SHA256
```

Comparez la valeur `Hash` affichée avec celle indiquée dans les notes de la
[release correspondante](https://github.com/yoshines62000-alt/Coffre/releases).
Si les deux empreintes ne correspondent pas exactement, ne lancez pas le
fichier et retéléchargez-le depuis la page officielle des releases.

## Lancer depuis le code source

Alternative à l'exécutable, pour les développeurs ou par souci de
transparence : double-cliquez sur **[`Lancer.vbs`](Lancer.vbs)** — la
fenêtre s'ouvre directement, sans console.

Une dépendance tierce est necessaire (la bibliothèque `cryptography`) :

```bash
python -m pip install -r requirements.txt
```

## Utilisation

1. Au premier lancement, créez votre mot de passe maître.
2. Bouton **Ajouter...** : enregistrez un identifiant (titre, identifiant,
   mot de passe, site/URL, notes).
3. Utilisez **Générateur...** pour créer un mot de passe fort, avant ou
   pendant l'ajout/modification d'une entrée.
4. **Copier l'identifiant** / **Copier le mot de passe** place la valeur
   dans le presse-papier (effacé automatiquement après 20 secondes).
5. **Verrouiller maintenant** ferme le coffre immédiatement ; il se
   verrouille aussi automatiquement après 5 minutes d'inactivité.

## Confidentialité

- Aucune donnée ne quitte votre machine : pas de compte, pas de serveur, pas
  de télémétrie, aucune synchronisation.
- Les données sont stockées, entièrement chiffrées, dans
  `%APPDATA%\Coffre\coffre.sqlite` (résolu depuis la variable d'environnement
  `%APPDATA%` elle-même, y compris si elle est redirigée par une politique
  d'entreprise).
- Sur un profil itinérant (roaming profile) où `%APPDATA%` est un partage
  réseau, Coffre détecte automatiquement ce cas et désactive le mode WAL de
  SQLite (dont la documentation officielle déconseille l'usage sur certains
  systèmes de fichiers réseau) au profit du mode journal par défaut, plus
  lent mais dont le verrouillage est mieux supporté sur ce type de stockage.

## Limites connues

Par honnêteté envers les utilisateurs, plutôt que de laisser ces limites se
découvrir à l'usage :

- **Accessibilité (lecteur d'écran)** : l'interface est construite avec
  Tkinter/ttk, dont le support des technologies d'assistance (Narrator,
  NVDA, JAWS) est historiquement faible sur toutes les plateformes et tous
  les thèmes, indépendamment de tout choix propre à Coffre. Une personne
  dépendante d'un lecteur d'écran risque donc une expérience dégradée ou
  inutilisable. Il n'existe pas de correctif de code réaliste à court terme
  compte tenu du choix technologique déjà fait pour l'ensemble de l'outil ;
  cette limite est documentée ici plutôt que passée sous silence.

## Créer un exécutable autonome (.exe)

Pour distribuer l'outil sans que le destinataire ait besoin d'installer
Python, un exécutable Windows autonome peut être généré avec
[PyInstaller](https://pyinstaller.org/) :

```bash
python -m pip install pyinstaller
python -m PyInstaller Coffre.spec
```

L'exécutable est produit dans `dist/Coffre.exe` (fichier unique, sans
console). Le fichier `.spec` du dépôt fixe la configuration de build pour un
résultat reproductible. Les dossiers `build/` et `dist/` ne sont pas suivis
par Git.

Pour un build de **release** parfaitement reproductible (même version exacte
de `cryptography` et de sa chaîne de dépendances qu'au build précédent),
utiliser `requirements-lock.txt` plutôt que `requirements.txt` (qui ne fixe
volontairement qu'un plancher de version, `cryptography>=42.0`, pour les
contributeurs) :

```bash
python -m pip install -r requirements-lock.txt
python -m PyInstaller Coffre.spec
```

`requirements-lock.txt` doit être régénéré et commité avant chaque nouvelle
release (voir le commentaire en tête de ce fichier pour la procédure).

### Processus de publication d'une release

Avant de rendre une release GitHub publique, calculer l'empreinte SHA-256
de l'exécutable fraîchement généré :

```powershell
Get-FileHash dist\Coffre.exe -Algorithm SHA256 | Format-List
```

Coller la valeur `Hash` obtenue dans les notes de la release GitHub (ou
l'attacher en tant qu'asset séparé `Coffre.exe.sha256`), afin que tout
utilisateur puisse vérifier hors bande l'intégrité du fichier téléchargé
(voir « Vérifier l'intégrité du fichier téléchargé » plus haut).

## Tests

Une suite de tests automatisés couvre en priorité la cryptographie
(dérivation de clé, chiffrement/déchiffrement, détection d'altération, de
mot de passe incorrect) ainsi que toute la logique du coffre (création,
verrouillage, CRUD des entrées, changement de mot de passe maître) sur de
vrais fichiers SQLite temporaires.

```bash
python -m unittest discover tests -v
```

## Structure du projet

```
crypto.py             # primitives cryptographiques pures : derivation de cle (scrypt), AES-256-GCM
db.py                  # couche donnees SQLite : stocke des blobs chiffres opaques
vault.py               # logique metier : creation/deverrouillage/verrouillage, CRUD, generateur
gui.py                  # interface graphique Tkinter
tests/                  # tests automatises
requirements.txt       # cryptography (plancher de version, pour les contributeurs)
requirements-lock.txt  # versions exactes figees pour un build de release reproductible
Lancer.vbs             # raccourci de lancement double-clic (sans console)
Lancer.bat             # raccourci de lancement double-clic (avec console, pour debug)
Coffre.spec            # configuration de build PyInstaller (.exe autonome)
icon.ico               # icone de l'application et de l'executable
.gitignore
LICENSE                # licence MIT
README.md
```

## Licence

Ce projet est publié sous licence [MIT](LICENSE) : gratuit, open source, et
libre de réutilisation, modification et redistribution.

## Soutenir le projet

<div align="center">

**Cet outil est gratuit, open source, et le restera toujours.**
Pas de version payante, pas de fonctionnalité cachée derrière un paywall.

Si Coffre vous aide à garder vos mots de passe en sécurité sans
abonnement, un petit café est toujours très apprécié. 🙌

[![Offrez-moi un café sur Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/yoshines62000)

</div>
