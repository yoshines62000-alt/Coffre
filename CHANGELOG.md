# Changelog

Historique des changements notables de Coffre, par version. Format inspiré de
[Keep a Changelog](https://keepachangelog.com/fr/1.0.0/) ; versionnage inspiré
de [SemVer](https://semver.org/lang/fr/).

## [1.2.0] - 2026-08-27

### Ajouté

- Le coffre peut vivre sur une **clé USB** plutôt que dans le profil Windows.
  La clé est reconnue à son **contenu**, jamais à sa lettre — Windows les
  réattribue à chaque branchement.
- **Secours** : un script lit le coffre sans l'application, avec Python seul.
- **Menu Aide** dans la colonne de navigation : fiche du logiciel, glossaire,
  communauté, et « Signaler un problème… » qui ouvre la fenêtre de contact.
- **États vides** : une liste vide explique pourquoi elle l'est et propose
  l'action qui la remplit, au lieu de rester muette.
- **Erreurs de saisie en ligne** : le message s'affiche sous le champ fautif,
  marque ce champ, et disparaît dès qu'on le retouche. Plus de fenêtre à
  fermer avant de pouvoir corriger.
- **Barre d'état** : ce qui n'appelle aucune décision (« Termine », « Rien à
  faire », « Sélectionnez d'abord… ») s'y affiche et s'efface tout seul.

### Modifié

- **Refonte visuelle complète**, aux couleurs du site Open Projects Lab :
  thème clair par défaut, accent cyan, thème sombre toujours commutable.
- **Navigation en colonne verticale** à gauche, avec le logo Open Projects Lab,
  à la place du bandeau horizontal.
- **Plus une seule boîte de dialogue dessinée par Windows.** Les 275 boîtes de
  la suite ont été triées une par une sur la question « mérite-t-elle
  d'arrêter l'utilisateur ? », puis réparties sur quatre médias : message
  thémé, barre d'état, erreur en ligne, confirmation thémée.
- **Une confirmation destructrice n'est jamais l'action par défaut** : sur ces
  dialogues, la touche Entrée annule.

### Corrigé

- La fenêtre de contact ne gèle plus l'interface pendant l'envoi : le réseau
  a quitté le fil graphique.
- `journal_mode` est réellement converti sur support amovible, au lieu d'être
  seulement évité — une base créée en WAL le restait après copie.

### Sécurité

- Mise à jour : le flux d'Open Projects Lab d'abord, l'API GitHub en repli, et
  le téléchargement est vérifié par sa taille et son empreinte SHA-256.
- La liste blanche de téléchargement est restreinte aux publications **du
  dépôt**, plus au seul hôte github.com.

