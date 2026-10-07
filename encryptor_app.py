#!/usr/bin/env python3
import argparse
import logging
import os
import sys

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication, QFileDialog, QLabel, QMainWindow, QMessageBox,
    QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)

import crypto_utils

logger = logging.getLogger(__name__)

# Set to a PEM public key string to embed a key for distribution.
# When set, the key input field is hidden — users only need to drop their file.
# Example:
#   EMBEDDED_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
#   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
#   -----END PUBLIC KEY-----"""
EMBEDDED_PUBLIC_KEY = None


class DropLabel(QLabel):
    def __init__(self, text: str, callback, parent=None):
        super().__init__(parent)
        self.callback = callback
        self.setAcceptDrops(True)
        self.setText(text)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(
            "border: 2px dashed #888; padding: 30px; font-size: 12pt;"
        )
        self.setFixedHeight(160)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            self.callback(urls[0].toLocalFile())


class EncryptorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Anonymizator — Chiffrement")
        self.setGeometry(400, 400, 600, 240)

        self.encrypted_data = None
        self.source_path = None
        self.key_input = None  # only set in developer mode
        self.key = None

        layout = QVBoxLayout()

        if EMBEDDED_PUBLIC_KEY:
            layout.addWidget(QLabel("Prêt — glissez le fichier à chiffrer ci-dessous."))
        else:
            layout.addWidget(QLabel("Clé publique du chercheur (PEM ou SSH) :"))
            self.key_input = QPlainTextEdit()
            self.key_input.setPlaceholderText(
                "Coller ou faire glisser ici la clé publique reçue du chercheur…"
            )
            self.key_input.setFixedHeight(100)
            layout.addWidget(self.key_input)
            self.key_input.textChanged.connect(self._try_load_key)

        self.drop_label = DropLabel(
            "Glisser ici un fichier pour le chiffrer", self.encrypt_file
        )
        layout.addWidget(self.drop_label)
        central = QWidget()
        central.setLayout(layout)
        self.setCentralWidget(central)

    def _try_load_key(self):
        self.key_input.textChanged.disconnect(self._try_load_key)
        p_key = self.key_input.toPlainText().strip()
        try:
            if os.path.exists(p_key):
                with open(p_key, "r") as key_file:
                    p_key = key_file.read()
            self.key = crypto_utils.load_public_key(p_key)
            self.key_input.clear()
            self.key_input.insertPlainText(p_key)
            self.key_input.setStyleSheet("background-color: #777777;")
        except Exception as e:
            self.key = None
            print('not loaded', p_key, e)
        self.key_input.textChanged.connect(self._try_load_key)
        return self.key


    def _get_public_key(self):
        # the key has been loaded by _try_load_key, unless it is embedded
        if EMBEDDED_PUBLIC_KEY:
            self.key = crypto_utils.load_public_key(EMBEDDED_PUBLIC_KEY)
        elif self.key == None:
            QMessageBox.warning(
                self, "Clé Manquante",
                "Veuillez saisir la clé publique avant de chiffrer.",
            )
        elif getattr(self.key, "key_size", 0) < 4096:
                #On n'annule plus le chiffrement : c'est la responsabilité du chercheur
                #pas de l'expérimentateur
                QMessageBox.warning(
                    self, "Clé faible",
                    f"La clé RSA fait {getattr(self.key, 'key_size', '?')} bits.\n"
                    "Une clé d'au moins 4096 bits est recommandée.\n\n"
                    "Vous pouvez en informer les collègues chercheurs avant de leur envoyer les données",
                )
        return self.key

    def encrypt_file(self, file_path: str):
        try:
            self._get_public_key() #stored in self.key
        except Exception as exc:
            QMessageBox.critical(
                self, "Erreur de Clé", f"Impossible de charger la clé publique.\n{exc}"
            )
            return
        if self.key is None:
            return

        try:
            with open(file_path, "rb") as fh:
                data = fh.read()
        except Exception as exc:
            QMessageBox.critical(self, "Erreur", f"Impossible de lire le fichier.\n{exc}")
            return

        try:
            self.encrypted_data = crypto_utils.encrypt_file_hybrid(data, self.key)
            self.source_path = file_path
        except Exception as exc:
            QMessageBox.critical(self, "Erreur de Chiffrement", f"Chiffrement échoué.\n{exc}")
            return

        # Auto-save next to the source file; fall back to manual save on error
        enc_path = file_path + ".enc"
        with open(enc_path, "wb") as fh:
            fh.write(self.encrypted_data)
        self.drop_label.setText(
            f"Chiffrement réussi !\nFichier enregistré :\n{enc_path}"
        )
        QMessageBox.information(
            self, "Succès", f"Fichier chiffré enregistré :\n{enc_path}"
        )

def main():
    parser = argparse.ArgumentParser(description="Anonymizator — encryptor app")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    app = QApplication(sys.argv)
    window = EncryptorApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
