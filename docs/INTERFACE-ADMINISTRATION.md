# Administrer une installation depuis le terminal

Le gestionnaire d’administration propose des menus dans le terminal du serveur
SIEM. Il rassemble les paramètres du site, le plan d’installation, la reprise,
les mises à jour de code, la publication de la console et les intégrations.
La console d’exploitation des événements reste accessible séparément sous `/soc/`.

## Démarrer depuis SSH

Se connecter au serveur qui possède le dépôt et les services à administrer,
puis lancer depuis ce dépôt :

```bash
ssh administrateur@serveur-siem
cd /chemin/du/depot/omnitech-siem-setup
sudo python3 tools/omni-manager.py --state-dir /var/lib/omni-siem-manager
```

Le dépôt courant est celui associé au gestionnaire lancé ; le répertoire d’état
est fixé par la ligne de commande. Il reste hors du dépôt et réservé à son
propriétaire. Les menus ne permettent pas de choisir une commande shell arbitraire
ou de modifier le serveur cible. Les opérations qui installent des paquets ou
modifient nginx exigent les droits correspondants sur cet hôte.

L'état historique des mises à jour reste dans `/var/lib/omni-siem-updater` par
défaut, afin de retrouver les transactions de l'outil existant. Si l'opérateur
utilisait un autre chemin, démarrer avec `--updater-state-dir /chemin/existant`.
Le gestionnaire n'importe pas arbitrairement d'autres états à la volée.

Le gestionnaire utilise le terminal SSH et ne démarre pas de serveur web. Aucun
port d’administration supplémentaire, code d’accès web ou tunnel HTTP n’est
nécessaire. Les secrets saisis interactivement ne s’affichent pas à l’écran.
Quitter le menu à la fin de la maintenance et consulter le résultat de chaque
opération lancée avant de fermer la session.

## Paramètres du site

Le menu de configuration présente les paramètres pris en charge par l’assistant :
identité du serveur, réseau, stockage, dimensionnement, SMTP et secrets de la pile.
Les valeurs sont contrôlées avant l’écriture de `00-vars.env`, fichier privé
exclu de Git. Les secrets existants ne sont pas relus à l’écran ; seul leur état
configuré ou absent est indiqué. Laisser un secret vide conserve sa valeur.

Une modification partielle conserve les autres paramètres du site. Une sauvegarde
privée de la configuration précédente est conservée dans le répertoire d’état
avant le remplacement atomique du fichier. Les noms de paramètres inconnus et
les valeurs contenant un retour à la ligne ou un caractère de contrôle interdit
sont refusés. Les valeurs écrites sont protégées pour leur utilisation dans les
scripts shell : une adresse, un nom ou un secret n’est pas exécuté comme une
commande par le gestionnaire.

Un fichier `00-vars.env` hérité peut contenir des expressions shell complexes.
Le gestionnaire ne le source pas pour afficher sa configuration. Seules les
références simples prises en charge entre paramètres non secrets sont interprétées
pour l’affichage ; les lignes non reconnues restent conservées. Examiner ces
personnalisations avant une installation et les adapter manuellement si nécessaire.
Ne pas supposer qu’une commande shell stockée comme texte produira le même résultat.

Choisir les plages autorisées pour SSH et HTTPS, les sources de temps, le stockage
et le dimensionnement selon le site. Un exemple de réseau ou de disque n’est pas
une détection automatique de l’infrastructure. Les outils ne peuvent pas inventer
les droits AD, les identifiants d’un tenant Microsoft365 ou les accès SQL SEAL.

## Installer ou reprendre une instance neuve

1. Enregistrer les paramètres nécessaires puis afficher le plan d’installation.
2. Lire les blocages, les phases et les composants qui attendent une configuration
   externe. Corriger les prérequis avant d’appliquer.
3. Appliquer le profil proposé sur une machine neuve. Suivre la sortie de la
   commande et attendre son résultat.
4. En cas d’échec, examiner la phase en erreur, corriger sa cause puis demander une
   reprise avec le même commit, la même configuration et les mêmes options.
5. Exécuter les contrôles de réception de [INSTALLATION.md](INSTALLATION.md).

Le profil `core-soc` installe la pile de base, les enrichissements, les détections
et dashboards de base, la console et sa sauvegarde applicative. L’option de triage
des mails se configure séparément. L’installateur refuse de traiter une instance
existante comme une machine vierge. Une liste explicite de phases remplace toute
boucle sur les scripts numérotés, dont certains réalisent des purges ou des actions
de maintenance.

## Mettre à jour le code

Le parcours reprend [UPDATES.md](UPDATES.md) :

1. Télécharger la référence souhaitée dans le cache isolé de mise à jour.
2. Retenir le SHA complet retourné et afficher son plan. La révision à appliquer
   est figée, même si la branche distante évolue ensuite.
3. Préparer le candidat puis examiner les conflits et les changements qui exigent
   une revue de migration.
4. Appliquer les fichiers de code pris en charge et vérifier la transaction.
5. Publier les composants d’exécution concernés et vérifier leur santé.

Les secrets, configurations de site et bases sont conservés. Une personnalisation
locale d’un fichier de code géré bloque la copie avant son écrasement. Le gestionnaire
ne fusionne pas automatiquement une personnalisation métier et n’exécute pas les
scripts de provisioning pour forcer un alignement. Les versions Graylog, MongoDB
et OpenSearch se migrent selon une procédure distincte.

Après une mise à jour du code du gestionnaire lui-même, quitter le menu et le
relancer : un processus Python déjà ouvert conserve les modules qu'il a chargés.
Ne pas considérer le menu courant comme la version nouvellement copiée.

Le retour arrière porte sur la transaction de code sauvegardée. Il ne restaure
pas des bases modifiées par une autre intervention. Pour une console déjà
publiée, republier explicitement la version restaurée et vérifier ses services.

## Publier ou réparer `/soc/`

La publication copie tous les fichiers statiques de la console et vérifie les
routes nginx. Elle conserve les restrictions d’accès locales et valide nginx
avant son rechargement. Un backend déjà installé est traité selon ses marqueurs
de propriété et la procédure de publication correspondante ; une ancienne
installation personnalisée ne doit pas être remplacée silencieusement.

Ouvrir `https://<nom-du-siem>/soc/` sur le port443. Le port9000 est l’interface
locale Graylog et n’héberge pas la console SOC. Vérifier aussi `/soc/app-boot.js`,
la connexion au backend et l’arrivée de données. Un HTTP200 de la page HTML ne
prouve pas que chaque source ou extension est opérationnelle.

## Intégrations et catalogue des outils

Le catalogue distingue les composants disponibles dans le projet, leurs prérequis
et les opérations automatisées par le gestionnaire. Un composant présenté dans
la liste ne devient pas automatiquement opérationnel. Les collecteurs externes,
ML/XDR/graphe, politiques SOAR et scans conservent leurs procédures et leur recette.

Pour un module WatchGuard, UniFi ou Palo Alto, examiner le format couvert, son
niveau de validation et l’aperçu du pack. Afficher le plan, puis appliquer
l’installation souhaitée. Configurer ensuite l’émission des journaux sur
l’équipement, le transport et les règles réseau du site. Vérifier des événements
réels, le statut de parsing et les widgets attendus. Les modules de préversion
restent identifiés comme tels.

La désinstallation concerne l’installation du Content Pack sélectionnée. Examiner
ses entités et dépendances avant de l’appliquer ; ce n’est pas une commande de
purge des journaux. Une mise à jour des fichiers d’un module dans Git et
l’installation d’une nouvelle révision du pack dans Graylog sont deux opérations
distinctes. Voir [INTEGRATIONS-MODULAIRES.md](INTEGRATIONS-MODULAIRES.md).

Les packs communautaires du projet et les packs propriétaires Graylog Illuminate
n’ont pas les mêmes conditions de licence. Un catalogue local n’active pas une
licence Enterprise, Security ou Illuminate et ne promet pas la compatibilité avec
tous les formats personnalisés d’un constructeur.

## Vérifier le résultat et terminer

Les opérations exécutées utilisent des outils et arguments prédéfinis. Examiner
leur résultat et leurs erreurs avant de poursuivre. Conserver les sauvegardes et
l’état nécessaires au retour arrière, vérifier les services et les flux concernés,
puis quitter le gestionnaire. Une session SSH fermée pendant un travail ne
constitue pas une preuve de réussite de l’opération.

Un verrou local empêche une seconde opération du gestionnaire ou une modification
de configuration pendant un travail. Les journaux JSON restent privés et les
secrets connus, jetons, autorisations et identifiants dans les URL sont masqués.
Le jeton Graylog est demandé pour l'opération en cours et transmis au seul processus
du module par l'environnement, jamais dans ses arguments ou dans le journal.

Après une interruption, examiner le journal et les services avant la reprise.
Si un verrou subsiste après un arrêt brutal, vérifier l'absence de processus actif
avant de retirer ce seul verrou. Une reprise de l'installation exige sa révision,
sa configuration et ses options d'origine ; une récupération de mise à jour
utilise l'identifiant exact de transaction décrit dans [UPDATES.md](UPDATES.md).

## Inventaire sans interface interactive

```bash
python3 tools/omni-manager.py --inventory
```

Cette commande ne nécessite pas de terminal interactif, ne crée pas de répertoire
d'état et classe chaque fichier suivi par Git dans un seul composant. Le menu
catalogue affiche les mêmes catégories et permet de consulter la liste détaillée
des fichiers ou des scripts historiques. Les purges restent hors des commandes
exécutables du gestionnaire. L'inventaire complète l'audit de portabilité ; il
ne prétend pas certifier toutes les lignes de code ni les flux d'un site réel.
