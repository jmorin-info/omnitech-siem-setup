/* ============================================================================
   03_vw_SealZone_SIEM.sql - Vue de resolution ZONE physique
   OMNITECH SECURITY - MISSION_SEAL_GRAYLOG

   >>> CE SCRIPT NE CONTIENT PLUS AUCUNE INSTRUCTION. Le lancer ne fait RIEN. <<<

   POURQUOI
   --------
   La version precedente supposait une hierarchie "parent -> enfant" classique :
       NodeId / ParentNodeId / NodeLabel / NodeClass
   L'extraction du modele reel (05_recon_fonctionnel.sql, joue sur OMEGA le
   16/07/2026) montre que Hypervision.ObjectsHierarchicalCatalog n'a que QUATRE
   colonnes, et pas celles-la :

       NodeHierarchyId   hierarchyid   -- cle primaire : LE CHEMIN dans l'arbre
       NodeId            bigint
       NodeObjectId      numeric       -- l'objet porte par le noeud
       NodeObjectType    varchar(50)   -- son type

   Ni ParentNodeId, ni NodeLabel, ni NodeClass. La parente est portee par le type
   hierarchyid de SQL Server (.GetAncestor(), .IsDescendantOf(), .GetLevel()),
   pas par une jointure sur un identifiant parent. La vue precedente ne pouvait
   donc pas fonctionner : elle est retiree plutot que laissee en commentaire (un
   commentaire SQL imbrique se referme trop tot et le code redevient actif -
   piege rencontre en la neutralisant).

   L'original reste consultable au depot : seal/sql/07_vw_SealZone_SIEM.sql
   (et dans l'historique git). Le garde-fou de Run-SealFix.ps1 a fait son travail :
   il a empeche le deploiement d'une vue de zones fausse.

   LA SUITE
   --------
   Jouer 06_recon_complements.sql (questions Q2 et Q2b). Son resultat designera
   la bonne piste parmi :

     1. dbo.POS_OBJECTS_IN_ZONES_CACHE (54 lignes)
        Le cache objet -> zone que SEAL utilise deja pour ses plans. La piste la
        plus simple SI elle couvre le parc (a comparer aux 165 portes deployees).

     2. Hypervision.fn_GetObjectsCatalogPath
        La fonction de l'editeur qui rend le chemin d'un noeud : exactement le
        ZONE_PATH recherche. A privilegier sur toute remontee d'arbre maison.

     3. dbo.T_PASSAGES (45 623 lignes)  <-- probablement la meilleure
        Porte deja FICH_ID (le porteur), ZONE_OBFI_ID (la zone) et ZONE_IN_OUT
        (le sens), et fait le lien avec l'evenement via EVEN_ID. Elle resout d'un
        coup les DEUX manques du SIEM : l'identite ET la zone.

   La vue definitive sera ecrite sur la piste retenue, puis livree ici meme.
   ============================================================================ */
