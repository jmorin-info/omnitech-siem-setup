/* ============================================================================
   03_vw_SealZone_SIEM.sql - Physical ZONE resolution view
   OMNITECH SECURITY - MISSION_SEAL_GRAYLOG

   >>> THIS SCRIPT NO LONGER CONTAINS ANY STATEMENT. Running it does NOTHING. <<<

   WHY
   ---
   The previous version assumed a classic "parent -> child" hierarchy:
       NodeId / ParentNodeId / NodeLabel / NodeClass
   Extracting the real model (05_recon_fonctionnel.sql, run on OMEGA on
   07/16/2026) shows that Hypervision.ObjectsHierarchicalCatalog has only FOUR
   columns, and not those:

       NodeHierarchyId   hierarchyid   -- primary key: THE PATH in the tree
       NodeId            bigint
       NodeObjectId      numeric       -- the object carried by the node
       NodeObjectType    varchar(50)   -- its type

   Neither ParentNodeId, nor NodeLabel, nor NodeClass. Parenthood is carried by the
   SQL Server hierarchyid type (.GetAncestor(), .IsDescendantOf(), .GetLevel()),
   not by a join on a parent identifier. The previous view therefore could
   not work: it is removed rather than left commented out (a nested SQL
   comment closes too early and the code becomes active again -
   pitfall encountered while neutralizing it).

   The original remains available in the repo: seal/sql/07_vw_SealZone_SIEM.sql
   (and in the git history). The Run-SealFix.ps1 guardrail did its job:
   it prevented the deployment of an incorrect zones view.

   NEXT STEPS
   ----------
   Run 06_recon_complements.sql (questions Q2 and Q2b). Its result will point to
   the right track among:

     1. dbo.POS_OBJECTS_IN_ZONES_CACHE (54 rows)
        The object -> zone cache that SEAL already uses for its plans. The
        simplest track IF it covers the estate (to compare against the 165 doors
        deployed).

     2. Hypervision.fn_GetObjectsCatalogPath
        The vendor function that returns a node's path: exactly the
        ZONE_PATH we are looking for. To be preferred over any homemade tree
        walk.

     3. dbo.T_PASSAGES (45,623 rows)  <-- probably the best
        Already carries FICH_ID (the holder), ZONE_OBFI_ID (the zone) and ZONE_IN_OUT
        (the direction), and links to the event via EVEN_ID. It resolves in one
        go BOTH of the SIEM's gaps: identity AND zone.

   The final view will be written on the selected track, then delivered right here.
   ============================================================================ */
