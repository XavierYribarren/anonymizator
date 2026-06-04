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
        self.setGeometry(100, 100, 600, 440)

        self.encrypted_data = None
        self.source_path = None
        self.key_input = None  # only set in developer mode

        layout = QVBoxLayout()

        if EMBEDDED_PUBLIC_KEY:
            layout.addWidget(QLabel("Prêt — glissez votre fichier ci-dessous."))
        else:
            layout.addWidget(QLabel("Clé publique du chercheur (format PEM) :"))
            self.key_input = QPlainTextEdit()
            self.key_input.setPlaceholderText(
                "Collez ici la clé publique reçue du chercheur…"
            )
            self.key_input.setFixedHeight(100)
            layout.addWidget(self.key_input)

        self.drop_label = DropLabel(
            "Glissez un fichier ici pour le chiffrer", self.encrypt_file
        )
        layout.addWidget(self.drop_label)

        self.save_button = QPushButton("Enregistrer le fichier chiffré")
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self.save_encrypted_file)
        layout.addWidget(self.save_button)

        central = QWidget()
        central.setLayout(layout)
        self.setCentralWidget(central)

    def _get_public_key(self):
        if EMBEDDED_PUBLIC_KEY:
            return crypto_utils.load_public_key(EMBEDDED_PUBLIC_KEY)
        if self.key_input is None:
            return None
        pem = self.key_input.toPlainText().strip()
        if not pem:
            QMessageBox.warning(
                self, "Clé Manquante",
                "Veuillez coller la clé publique avant de chiffrer.",
            )
            return None
        key = crypto_utils.load_public_key(pem)
        if getattr(key, "key_size", 0) < 4096:
            QMessageBox.warning(
                self, "Clé faible",
                f"La clé RSA fait {getattr(key, 'key_size', '?')} bits.\n"
                "Une clé d'au moins 4096 bits est recommandée.\n\n"
                "Le chiffrement est annulé.",
            )
            return None
        return key

    def encrypt_file(self, file_path: str):
        try:
            public_key = self._get_public_key()
        except Exception as exc:
            QMessageBox.critical(
                self, "Erreur de Clé", f"Impossible de charger la clé publique.\n{exc}"
            )
            return
        if public_key is None:
            return

        try:
            with open(file_path, "rb") as fh:
                data = fh.read()
        except Exception as exc:
            QMessageBox.critical(self, "Erreur", f"Impossible de lire le fichier.\n{exc}")
            return

        try:
            self.encrypted_data = crypto_utils.encrypt_file_hybrid(data, public_key)
            self.source_path = file_path
        except Exception as exc:
            QMessageBox.critical(self, "Erreur de Chiffrement", f"Chiffrement échoué.\n{exc}")
            return

        # Auto-save next to the source file; fall back to manual save on error
        enc_path = file_path + ".enc"
        try:
            with open(enc_path, "wb") as fh:
                fh.write(self.encrypted_data)
            self.drop_label.setText(
                f"Chiffrement réussi !\nFichier enregistré :\n{enc_path}"
            )
            QMessageBox.information(
                self, "Succès", f"Fichier chiffré enregistré :\n{enc_path}"
            )
            self.save_button.setEnabled(False)
        except Exception:
            logger.warning("Auto-save to %s failed, enabling manual save", enc_path)
            self.drop_label.setText(f"Chiffrement réussi !\n{os.path.basename(file_path)}")
            self.save_button.setEnabled(True)

    def save_encrypted_file(self):
        if not self.encrypted_data:
            return
        default = (self.source_path or "") + ".enc"
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Enregistrer le fichier chiffré", default,
            "Fichiers chiffrés (*.enc);;Tous les fichiers (*)",
        )
        if save_path:
            try:
                with open(save_path, "wb") as fh:
                    fh.write(self.encrypted_data)
                QMessageBox.information(self, "Succès", f"Fichier chiffré enregistré :\n{save_path}")
            except Exception as exc:
                QMessageBox.critical(self, "Erreur", f"Impossible d'enregistrer.\n{exc}")


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
