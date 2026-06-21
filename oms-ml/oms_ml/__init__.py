"""OMS-ML — couche d'apprentissage (scoring ML) au-dessus du SIEM OMNITECH.

Complète l'UEBA statistique (40-ueba-ndr) et oms-xdr (corrélation/LLM) par :
  - anomalie NON-SUPERVISÉE par entité (IsolationForest) — entraînable sans label ;
  - réduction de FAUX POSITIFS SUPERVISÉE — labels = issue analyste des cas SOC.
Tout est local (sklearn, CPU). Le résultat est réinjecté en GELF (champ ml_score).
"""
__version__ = "1.0.0"
