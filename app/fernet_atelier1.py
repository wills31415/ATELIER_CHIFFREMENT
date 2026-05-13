#!/usr/bin/env python3
"""
fernet_atelier1.py

Chiffre / dechiffre un fichier avec une cle Fernet lue depuis la variable
d'environnement FERNET_KEY, qui est alimentee par un GitHub Repository Secret
(via un workflow GitHub Actions).

Usage:
    python app/fernet_atelier1.py encrypt <fichier_entree> <fichier_sortie>
    python app/fernet_atelier1.py decrypt <fichier_entree> <fichier_sortie>

La cle n'est JAMAIS ecrite dans le code ni dans le repo : elle vit uniquement
dans le Secret GitHub (cote Actions) ou dans ton environnement local (cote dev).
"""

import os
import sys
from cryptography.fernet import Fernet, InvalidToken


KEY_ENV_VAR = "FERNET_KEY"


def load_key() -> bytes:
    """Recupere la cle Fernet depuis l'environnement, avec validation."""
    key = os.environ.get(KEY_ENV_VAR)
    if not key:
        sys.exit(
            f"Erreur : variable d'environnement {KEY_ENV_VAR} absente.\n"
            "  - En GitHub Actions : ajoutez un Repository Secret nomme "
            f"{KEY_ENV_VAR} et exposez-le via 'env:' dans le workflow.\n"
            "  - En local : exportez la variable, par exemple :\n"
            f"      export {KEY_ENV_VAR}=\"$(python -c "
            "'from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())')\""
        )

    key_bytes = key.encode("utf-8")
    # Fernet leve ValueError si la cle n'est pas un base64 valide de 32 octets.
    try:
        Fernet(key_bytes)
    except (ValueError, TypeError) as exc:
        sys.exit(f"Erreur : cle Fernet invalide ({exc}).")
    return key_bytes


def encrypt_file(fernet: Fernet, src: str, dst: str) -> None:
    with open(src, "rb") as f:
        data = f.read()
    token = fernet.encrypt(data)
    with open(dst, "wb") as f:
        f.write(token)
    print(f"Chiffre : {src} -> {dst} ({len(token)} octets)")


def decrypt_file(fernet: Fernet, src: str, dst: str) -> None:
    with open(src, "rb") as f:
        token = f.read()
    try:
        data = fernet.decrypt(token)
    except InvalidToken:
        # Couvre les deux cas : mauvaise cle, ou fichier altere (HMAC KO).
        sys.exit(
            "Erreur : token Fernet invalide. "
            "Cle incorrecte ou fichier modifie/corrompu."
        )
    with open(dst, "wb") as f:
        f.write(data)
    print(f"Dechiffre : {src} -> {dst} ({len(data)} octets)")


def main() -> None:
    if len(sys.argv) != 4 or sys.argv[1] not in ("encrypt", "decrypt"):
        sys.exit(
            "Usage:\n"
            "  python app/fernet_atelier1.py encrypt <entree> <sortie>\n"
            "  python app/fernet_atelier1.py decrypt <entree> <sortie>"
        )

    action, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
    if not os.path.isfile(src):
        sys.exit(f"Erreur : fichier introuvable : {src}")

    fernet = Fernet(load_key())

    if action == "encrypt":
        encrypt_file(fernet, src, dst)
    else:
        decrypt_file(fernet, src, dst)


if __name__ == "__main__":
    main()
