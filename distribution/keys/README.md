# Clé publique de publication OMNI SIEM

Identité : **Julien Morin (OMNI SIEM releases)**.

Empreinte primaire : `2668CC327A9ADCB1AE585187AE984C65217DB120`.

La clé publique est dans [omni-siem-release.asc](omni-siem-release.asc). La clé
primaire RSA 4096 sert à certifier une sous-clé RSA 4096 de signature. La partie
privée de la clé primaire reste hors du dépôt et des machines clientes ; le
certificat public contient la clé primaire et la sous-clé publique. Les clients vérifient cette empreinte avant
de faire confiance au dépôt. Les durées de validité et les sous-clés sont
consultables avec `gpg --show-keys --with-fingerprint omni-siem-release.asc`.

Aucune clé privée ni phrase secrète n'est versionnée. Le stockage de publication
et la mise en service des dépôts signés sont distincts de la distribution de cette
clé publique. La présence de ce fichier ne rend pas rétroactivement signées les
préversions déjà publiées.
