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
  `%APPDATA%\Coffre\coffre.sqlite`.

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
requirements.txt       # cryptography
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
