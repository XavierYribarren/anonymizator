import argparse
import json
import logging
import os
import sys
import webbrowser

from cryptography.hazmat.primitives import serialization
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication, QFileDialog, QHBoxLayout, QInputDialog, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit, QPushButton,
    QVBoxLayout, QWidget,
)

import crypto_utils

logger = logging.getLogger(__name__)

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "anonymizator_config.json")
# Stores only the path to the private key file — never the key itself.


def _load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}


def _save_config(data: dict):
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f)



class DropLabel(QLabel):
    def __init__(self, text: str, callback, parent=None):
        super().__init__(parent)
        self.callback = callback
        self.setAcceptDrops(True)
        self.setText(text)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(
            "border: 3px dashed #0078D7; padding: 20px; font-size: 14pt;"
        )
        self.setFixedHeight(200)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            self.callback(urls[0].toLocalFile())


class DecryptorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Anonymizator — Déchiffrement")
        self.setGeometry(100, 100, 700, 560)
        self.private_key = None
        self.private_key_visible = False

        layout = QVBoxLayout()

        # Status indicator
        status_row = QHBoxLayout()
        self.status_dot = QLabel()
        self.status_dot.setFixedSize(16, 16)
        self.status_text = QLabel("Aucune clé chargée")
        self._set_status(False)
        status_row.addWidget(self.status_dot)
        status_row.addWidget(self.status_text)
        status_row.addStretch()
        layout.addLayout(status_row)

        # Action buttons
        self.gen_btn = QPushButton("Générer une nouvelle paire de clés RSA-4096")
        self.gen_btn.clicked.connect(self.generate_keys)
        layout.addWidget(self.gen_btn)

        self.load_btn = QPushButton("Charger une clé privée existante")
        self.load_btn.clicked.connect(self.load_keys)
        layout.addWidget(self.load_btn)

        self.forget_btn = QPushButton("Oublier la clé enregistrée")
        self.forget_btn.clicked.connect(self.forget_keys)
        layout.addWidget(self.forget_btn)

        self.toggle_btn = QPushButton("Afficher la clé privée")
        self.toggle_btn.setEnabled(False)
        self.toggle_btn.clicked.connect(self.toggle_private_key)
        layout.addWidget(self.toggle_btn)

        self.dashboard_btn = QPushButton("Ouvrir le dashboard web")
        self.dashboard_btn.setEnabled(False)
        self.dashboard_btn.clicked.connect(self.open_dashboard)
        layout.addWidget(self.dashboard_btn)

        # Private key display (hidden by default)
        self.priv_display = QPlainTextEdit()
        self.priv_display.setPlaceholderText("Clé privée…")
        self.priv_display.setReadOnly(True)
        self.priv_display.setFixedHeight(80)
        self.priv_display.setVisible(False)
        layout.addWidget(self.priv_display)

        # Public key display with copy button
        pub_row = QHBoxLayout()
        pub_row.addWidget(QLabel("Clé Publique :"))
        self.copy_btn = QPushButton("Copier")
        self.copy_btn.setEnabled(False)
        self.copy_btn.clicked.connect(self.copy_public_key)
        pub_row.addWidget(self.copy_btn)
        layout.addLayout(pub_row)

        self.pub_display = QPlainTextEdit()
        self.pub_display.setPlaceholderText("La clé publique s'affichera ici.")
        self.pub_display.setReadOnly(True)
        self.pub_display.setFixedHeight(100)
        layout.addWidget(self.pub_display)

        # Decryption drop zone
        self.drop_label = DropLabel(
            "Glissez un fichier .enc ici pour le déchiffrer", self.decrypt_file
        )
        layout.addWidget(self.drop_label)

        central = QWidget()
        central.setLayout(layout)
        self.setCentralWidget(central)

        self._auto_load_saved_key()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _set_status(self, loaded: bool):
        color = "#2ecc71" if loaded else "#e74c3c"
        self.status_dot.setStyleSheet(
            f"background-color: {color}; border-radius: 8px;"
        )
        if hasattr(self, "dashboard_btn"):
            self.dashboard_btn.setEnabled(loaded)

    def _auto_load_saved_key(self):
        config = _load_config()
        path = config.get("private_key_path", "")
        if not path:
            return
        if not os.path.exists(path):
            _save_config({})
            QMessageBox.warning(
                self, "Clé Introuvable",
                f"La clé privée enregistrée n'existe plus :\n{path}\n\n"
                "Le chemin a été effacé de la configuration.",
            )
            return
        self._load_from_path(path, silent=True)

    def _load_from_path(self, path: str, silent: bool = False):
        try:
            with open(path, "rb") as fh:
                pem_bytes = fh.read()
        except Exception as exc:
            QMessageBox.critical(self, "Erreur", f"Impossible de lire le fichier.\n{exc}")
            return

        password = None
        if b"ENCRYPTED" in pem_bytes or pem_bytes.startswith(
            b"-----BEGIN OPENSSH PRIVATE KEY-----"
        ):
            pw, ok = QInputDialog.getText(
                self, "Mot de Passe",
                "Mot de passe de la clé privée :",
                QLineEdit.EchoMode.Password,
            )
            if not ok:
                return
            password = pw.encode("utf-8") if pw else None

        try:
            private_key = crypto_utils.load_private_key(pem_bytes, password=password)
        except ValueError:
            QMessageBox.critical(self, "Erreur", "Mot de passe incorrect ou clé invalide.")
            return
        except Exception as exc:
            QMessageBox.critical(self, "Erreur", f"Impossible de charger la clé.\n{exc}")
            return

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        self.private_key = private_key
        self.priv_display.setPlainText(pem_bytes.decode("utf-8", errors="replace"))
        self.pub_display.setPlainText(public_pem)
        self.toggle_btn.setEnabled(True)
        self.copy_btn.setEnabled(True)
        self._set_status(True)
        key_bits = getattr(private_key, "key_size", 0)
        self.status_text.setText(
            f"Clé RSA-{key_bits} bits — {os.path.basename(path)}"
        )

        if not silent:
            _save_config({"private_key_path": path})
            QMessageBox.information(
                self, "Succès", f"Clé RSA-{key_bits} bits chargée !"
            )

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def generate_keys(self):
        pw, ok = QInputDialog.getText(
            self, "Passphrase",
            "Passphrase pour protéger la clé privée\n(laisser vide pour ne pas chiffrer) :",
            QLineEdit.EchoMode.Password,
        )
        if not ok:
            return

        if pw:
            pw2, ok2 = QInputDialog.getText(
                self, "Confirmer", "Confirmer la passphrase :",
                QLineEdit.EchoMode.Password,
            )
            if not ok2 or pw != pw2:
                QMessageBox.warning(self, "Erreur", "Les passphrases ne correspondent pas.")
                return

        try:
            private_key, public_key = crypto_utils.generate_rsa_keypair(4096)
        except Exception as exc:
            QMessageBox.critical(self, "Erreur", f"Impossible de générer les clés.\n{exc}")
            return

        pw_bytes = pw.encode("utf-8") if pw else None
        enc_algo = (
            serialization.BestAvailableEncryption(pw_bytes)
            if pw_bytes
            else serialization.NoEncryption()
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_algo,
        ).decode("utf-8")

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        save_path, _ = QFileDialog.getSaveFileName(
            self, "Enregistrer la clé privée", "private_key.pem",
            "Clés PEM (*.pem);;Tous les fichiers (*)",
        )
        if save_path:
            try:
                with open(save_path, "w") as fh:
                    fh.write(private_pem)
                _save_config({"private_key_path": save_path})
            except Exception as exc:
                QMessageBox.critical(self, "Erreur", f"Impossible d'enregistrer.\n{exc}")
                return

        self.private_key = private_key
        self.priv_display.setPlainText(private_pem)
        self.pub_display.setPlainText(public_pem)
        self.toggle_btn.setEnabled(True)
        self.copy_btn.setEnabled(True)
        self._set_status(True)
        self.status_text.setText("Clé RSA-4096 bits générée")
        QMessageBox.information(self, "Succès", "Clé RSA-4096 générée avec succès !")

    def load_keys(self):
        config = _load_config()
        saved = config.get("private_key_path", "")
        if saved and os.path.exists(saved):
            choice, ok = QInputDialog.getItem(
                self, "Clé enregistrée",
                f"Clé enregistrée :\n{saved}\n\nQue faire ?",
                ["Charger la clé enregistrée", "Choisir une autre"],
                0, False,
            )
            if not ok:
                return
            if choice == "Charger la clé enregistrée":
                self._load_from_path(saved)
                return

        path, _ = QFileDialog.getOpenFileName(
            self, "Charger une clé privée", "",
            "Clés privées (*.pem *.key *id_rsa);;Tous les fichiers (*)",
        )
        if path:
            self._load_from_path(path)

    def forget_keys(self):
        _save_config({})
        self.private_key = None
        self.priv_display.clear()
        self.pub_display.clear()
        self.priv_display.setVisible(False)
        self.private_key_visible = False
        self.toggle_btn.setEnabled(False)
        self.toggle_btn.setText("Afficher la clé privée")
        self.copy_btn.setEnabled(False)
        self._set_status(False)
        self.status_text.setText("Aucune clé chargée")
        QMessageBox.information(self, "Succès", "La clé enregistrée a été oubliée.")

    def toggle_private_key(self):
        self.private_key_visible = not self.private_key_visible
        self.priv_display.setVisible(self.private_key_visible)
        self.toggle_btn.setText(
            "Masquer la clé privée" if self.private_key_visible else "Afficher la clé privée"
        )

    def copy_public_key(self):
        pem = self.pub_display.toPlainText()
        clipboard = QApplication.clipboard()
        if pem and clipboard is not None:
            clipboard.setText(pem)
            QMessageBox.information(self, "Copié", "Clé publique copiée dans le presse-papier.")

    def open_dashboard(self):
        base_url = _load_config().get("base_url", "http://localhost:8000").rstrip("/")
        webbrowser.open(base_url)

    def decrypt_file(self, file_path: str):
        if not self.private_key:
            QMessageBox.warning(
                self, "Clé Manquante",
                "Veuillez d'abord charger une clé privée.",
            )
            return

        try:
            with open(file_path, "rb") as fh:
                encrypted_data = fh.read()
        except Exception as exc:
            QMessageBox.critical(self, "Erreur", f"Impossible de lire le fichier.\n{exc}")
            return

        try:
            decrypted_data = crypto_utils.decrypt_file_hybrid(encrypted_data, self.private_key)
        except Exception as exc:
            QMessageBox.critical(
                self, "Erreur de Déchiffrement",
                f"Déchiffrement échoué.\n{exc}\n\n"
                "Vérifiez que le fichier a bien été chiffré avec votre clé publique.",
            )
            return

        default_name = (
            file_path[:-4] if file_path.endswith(".enc") else file_path + ".decrypted"
        )
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Enregistrer le fichier déchiffré", default_name,
            "Tous les fichiers (*)",
        )
        if save_path:
            try:
                with open(save_path, "wb") as fh:
                    fh.write(decrypted_data)
                self.drop_label.setText(f"Déchiffrement réussi !\n{save_path}")
                QMessageBox.information(self, "Succès", f"Fichier déchiffré :\n{save_path}")
            except Exception as exc:
                QMessageBox.critical(self, "Erreur", f"Impossible d'enregistrer.\n{exc}")


def main():
    parser = argparse.ArgumentParser(description="Anonymizator — decryptor app")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    app = QApplication(sys.argv)
    window = DecryptorApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
