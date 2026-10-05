# Scripts remplacés — ne pas utiliser

Ces scripts sont conservés pour l'historique uniquement. Ils sont **entièrement
couverts** par `../Install-OmniSiem-NinjaOne.ps1`, qui est le script unique à
déployer depuis NinjaOne.

| Script archivé | Remplacé par |
|---|---|
| `Deploy-SiemAgents-NinjaOne.ps1` | `Install-OmniSiem-NinjaOne.ps1` (étapes Sysmon + Winlogbeat) |
| `Set-OmniAudit-NinjaOne.ps1` | `Install-OmniSiem-NinjaOne.ps1` (étape politique d'audit) |

Les lancer en plus du script unique ne casse rien (ils sont idempotents et
appliquent la même configuration), mais c'est inutile et cela double le temps
d'exécution sur chaque machine.

Le kit publié par `95-kit-deploy.sh` ne distribue déjà que le script unique :
ces fichiers ne sont pas servis aux machines.
