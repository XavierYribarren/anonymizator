import argparse
import json
import logging
import os
import sys

from cryptography.hazmat.primitives import serialization
from PyQt6.QtWidgets import (
    QApplication, QDialog, QFileDialog, QHBoxLayout, QInputDialog,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit,
    QPushButton, QTabWidget, QTextBrowser, QVBoxLayout, QWidget,
)
from PyQt6.QtCore import Qt

import crypto_utils

logger = logging.getLogger(__name__)

CONFIG_FILE = "anonymizator_config.json"
# Stores only the path to the private key file — never the key itself.


def _save_config(data: dict):
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f)


def _load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}


class DropLabel(QLabel):
    def __init__(self, text: str, callback, parent=None):
        super().__init__(parent)
        self.callback = callback
        self.setAcceptDrops(True)
        self.setText(text)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(
            "border: 2px dashed #888; padding: 20px; font-size: 11pt;"
        )
        self.setFixedHeight(130)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            self.setText(f"Fichier :\n{path}")
            self.callback(path)


class PassphraseDialog(QDialog):
    """Ask for a passphrase with optional confirmation field."""

    def __init__(self, parent=None, confirm: bool = False):
        super().__init__(parent)
        self.setWindowTitle("Protéger la clé privée")
        self.setMinimumWidth(420)
        layout = QVBoxLayout()

        layout.addWidget(
            QLabel("Passphrase (laisser vide pour ne pas chiffrer la clé) :")
        )
        self.pw_input = QLineEdit()
        self.pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.pw_input)

        self.confirm_input = None
        if confirm:
            layout.addWidget(QLabel("Confirmer la passphrase :"))
            self.confirm_input = QLineEdit()
            self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
            layout.addWidget(self.confirm_input)

        btns = QHBoxLayout()
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("Annuler")
        cancel_btn.clicked.connect(self.reject)
        btns.addWidget(ok_btn)
        btns.addWidget(cancel_btn)
        layout.addLayout(btns)

        self.setLayout(layout)

    def passphrase(self) -> str:
        return self.pw_input.text()

    def confirmed(self) -> str:
        return self.confirm_input.text() if self.confirm_input else ""


class EncryptorTab(QWidget):
    """Encrypt a file using a RSA public key."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Clé publique (format PEM) :"))
        self.key_input = QPlainTextEdit()
        self.key_input.setPlaceholderText("Collez la clé publique RSA ici…")
        self.key_input.setFixedHeight(150)
        layout.addWidget(self.key_input)

        self.drop_label = DropLabel(
            "Glissez un fichier ici pour le chiffrer", self.encrypt_file
        )
        layout.addWidget(self.drop_label)

        self.save_button = QPushButton("Enregistrer le fichier chiffré")
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self.save_encrypted_file)
        layout.addWidget(self.save_button)

        self.setLayout(layout)
        self.encrypted_data = None
        self.source_path = None

    def set_public_key(self, pem: str):
        """Populate the key field from the key management tab."""
        self.key_input.setPlainText(pem)

    def encrypt_file(self, file_path: str):
        key_pem = self.key_input.toPlainText().strip()
        if not key_pem:
            QMessageBox.warning(
                self, "Clé Manquante",
                "Veuillez coller une clé publique avant de chiffrer."
            )
            return

        try:
            public_key = crypto_utils.load_public_key(key_pem)
        except Exception as exc:
            QMessageBox.critical(
                self, "Erreur de Clé",
                f"Impossible de charger la clé publique.\n{exc}"
            )
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
            self.drop_label.setText(f"Chiffrement réussi !\n{file_path}")
            self.save_button.setEnabled(True)
        except Exception as exc:
            QMessageBox.critical(
                self, "Erreur de Chiffrement", f"Chiffrement échoué.\n{exc}"
            )

    def save_encrypted_file(self):
        if not self.encrypted_data:
            return
        default = (self.source_path or "") + ".enc"
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Enregistrer le fichier chiffré", default,
            "Fichiers Chiffrés (*.enc);;Tous les fichiers (*)",
        )
        if save_path:
            try:
                with open(save_path, "wb") as fh:
                    fh.write(self.encrypted_data)
                QMessageBox.information(
                    self, "Succès", f"Fichier chiffré enregistré :\n{save_path}"
                )
            except Exception as exc:
                QMessageBox.critical(self, "Erreur", f"Impossible d'enregistrer.\n{exc}")


class DecryptorTab(QWidget):
    """Key management and file decryption."""

    def __init__(self, encrypt_tab: EncryptorTab, parent=None):
        super().__init__(parent)
        self.encrypt_tab = encrypt_tab
        self.private_key = None

        layout = QVBoxLayout()

        # Status indicator row
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
        btn_row = QHBoxLayout()
        self.gen_btn = QPushButton("Générer une nouvelle paire de clés RSA-4096")
        self.gen_btn.clicked.connect(self.generate_keys)
        btn_row.addWidget(self.gen_btn)

        self.load_btn = QPushButton("Charger une clé privée existante")
        self.load_btn.clicked.connect(self.load_keys)
        btn_row.addWidget(self.load_btn)

        self.forget_btn = QPushButton("Oublier les clés")
        self.forget_btn.clicked.connect(self.forget_keys)
        btn_row.addWidget(self.forget_btn)
        layout.addLayout(btn_row)

        # Public key display with copy / export
        pub_row = QHBoxLayout()
        pub_row.addWidget(QLabel("Clé Publique (à partager) :"))
        pub_row.addStretch()

        self.copy_btn = QPushButton("Copier")
        self.copy_btn.setEnabled(False)
        self.copy_btn.clicked.connect(self.copy_public_key)
        pub_row.addWidget(self.copy_btn)

        self.export_btn = QPushButton("Exporter (.pem)")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_public_key)
        pub_row.addWidget(self.export_btn)
        layout.addLayout(pub_row)

        self.pub_key_display = QPlainTextEdit()
        self.pub_key_display.setReadOnly(True)
        self.pub_key_display.setPlaceholderText("La clé publique RSA s'affichera ici…")
        self.pub_key_display.setFixedHeight(180)
        layout.addWidget(self.pub_key_display)

        # Decryption drop zone
        layout.addWidget(QLabel("Déchiffrement — glissez un fichier .enc ici :"))
        self.drop_label = DropLabel(
            "Glissez un fichier .enc ici pour le déchiffrer", self.decrypt_file
        )
        layout.addWidget(self.drop_label)

        self.setLayout(layout)
        self._auto_load_saved_key()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _set_status(self, loaded: bool):
        color = "#2ecc71" if loaded else "#e74c3c"
        self.status_dot.setStyleSheet(
            f"background-color: {color}; border-radius: 8px;"
        )

    def _auto_load_saved_key(self):
        config = _load_config()
        path = config.get("private_key_path", "")
        if not path:
            return
        if not os.path.exists(path):
            logger.warning("Saved private key path no longer exists: %s", path)
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
        needs_pw = b"ENCRYPTED" in pem_bytes or pem_bytes.startswith(
            b"-----BEGIN OPENSSH PRIVATE KEY-----"
        )
        if needs_pw:
            pw, ok = QInputDialog.getText(
                self, "Mot de Passe",
                "Entrez le mot de passe de la clé privée :",
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
        self.pub_key_display.setPlainText(public_pem)
        self.encrypt_tab.set_public_key(public_pem)
        self._set_status(True)
        self.status_text.setText(
            f"Clé RSA-{private_key.key_size} bits chargée — {os.path.basename(path)}"
        )
        self.copy_btn.setEnabled(True)
        self.export_btn.setEnabled(True)

        if not silent:
            _save_config({"private_key_path": path})
            QMessageBox.information(
                self, "Succès",
                f"Clé RSA-{private_key.key_size} bits chargée avec succès !"
            )

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def generate_keys(self):
        dlg = PassphraseDialog(self, confirm=True)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        pw = dlg.passphrase()
        if pw != dlg.confirmed():
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
            format=serialization.PrivateFormat.TraditionalOpenSSL,
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
                QMessageBox.critical(self, "Erreur", f"Impossible d'enregistrer la clé.\n{exc}")
                return

        self.private_key = private_key
        self.pub_key_display.setPlainText(public_pem)
        self.encrypt_tab.set_public_key(public_pem)
        self._set_status(True)
        self.status_text.setText("Clé RSA-4096 bits générée")
        self.copy_btn.setEnabled(True)
        self.export_btn.setEnabled(True)

        QMessageBox.information(
            self, "Succès",
            "Paire de clés RSA-4096 générée avec succès !\n"
            "Utilisez Copier ou Exporter pour partager la clé publique avec les collecteurs.",
        )

    def load_keys(self):
        config = _load_config()
        saved = config.get("private_key_path", "")
        if saved and os.path.exists(saved):
            choice, ok = QInputDialog.getItem(
                self, "Clé enregistrée",
                f"Clé enregistrée :\n{saved}\n\nQue souhaitez-vous faire ?",
                ["Charger la clé enregistrée", "Choisir une autre clé"],
                0, False,
            )
            if not ok:
                return
            if choice == "Charger la clé enregistrée":
                self._load_from_path(saved)
                return

        path, _ = QFileDialog.getOpenFileName(
            self, "Sélectionner une clé privée", "",
            "Clés privées (*.pem *.key *id_rsa);;Tous les fichiers (*)",
        )
        if path:
            self._load_from_path(path)

    def forget_keys(self):
        _save_config({})
        self.private_key = None
        self.pub_key_display.clear()
        self.encrypt_tab.set_public_key("")
        self._set_status(False)
        self.status_text.setText("Aucune clé chargée")
        self.copy_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        QMessageBox.information(self, "Clés oubliées", "La clé privée a été oubliée.")

    def copy_public_key(self):
        pem = self.pub_key_display.toPlainText()
        if pem:
            QApplication.clipboard().setText(pem)
            QMessageBox.information(self, "Copié", "Clé publique copiée dans le presse-papier.")

    def export_public_key(self):
        pem = self.pub_key_display.toPlainText()
        if not pem:
            return
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Exporter la clé publique", "public_key.pem",
            "Clés PEM (*.pem);;Tous les fichiers (*)",
        )
        if save_path:
            try:
                with open(save_path, "w") as fh:
                    fh.write(pem)
                QMessageBox.information(self, "Succès", f"Clé publique exportée :\n{save_path}")
            except Exception as exc:
                QMessageBox.critical(self, "Erreur", f"Impossible d'exporter.\n{exc}")

    def decrypt_file(self, file_path: str):
        if not self.private_key:
            QMessageBox.warning(
                self, "Clé Manquante",
                "Veuillez d'abord générer ou charger une clé privée.",
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
                "Vérifiez que le fichier a été chiffré avec la clé publique correspondante.",
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


_INSTRUCTIONS_HTML = """
<h2>Mode d'emploi — Anonymizator</h2>

<h3>1. Générer vos clés</h3>
<p>Cliquez sur <b>Générer une nouvelle paire de clés RSA-4096</b> dans l'onglet
<i>Clés &amp; Déchiffrement</i>.
Choisissez une passphrase forte pour protéger votre clé privée et enregistrez-la
dans un endroit sûr.</p>

<h3>2. Partager votre clé publique</h3>
<p>La clé publique affichée peut être partagée librement.
Utilisez <b>Copier</b> ou <b>Exporter (.pem)</b> pour la transmettre aux collecteurs.</p>

<h3>3. Le collecteur chiffre ses données</h3>
<p>Le collecteur ouvre <code>encryptor_app.py</code>, colle votre clé publique,
glisse son fichier, puis vous envoie le fichier <code>.enc</code> généré.
Ce fichier est illisible sans votre clé privée.</p>

<h3>4. Déchiffrer le fichier reçu</h3>
<p>Glissez le fichier <code>.enc</code> dans la zone de déchiffrement.
L'application utilise votre clé privée pour déchiffrer et propose d'enregistrer le résultat.</p>

<h3>Sécurité</h3>
<ul>
  <li>Chiffrement hybride RSA-4096 + AES-256-GCM</li>
  <li>Votre clé privée ne quitte jamais votre machine</li>
  <li>AES-GCM garantit l'intégrité des données (authentification intégrée)</li>
  <li>Ne jamais partager votre clé privée</li>
</ul>
"""


class InstructionsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout()
        browser = QTextBrowser()
        browser.setHtml(_INSTRUCTIONS_HTML)
        layout.addWidget(browser)
        self.setLayout(layout)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Anonymizator — Chercheur")
        self.setGeometry(100, 100, 820, 680)

        self.tabs = QTabWidget()
        self.encrypt_tab = EncryptorTab()
        self.decrypt_tab = DecryptorTab(encrypt_tab=self.encrypt_tab)

        self.tabs.addTab(self.decrypt_tab, "Clés & Déchiffrement")
        self.tabs.addTab(self.encrypt_tab, "Chiffrement")
        self.tabs.addTab(InstructionsTab(), "Instructions")

        self.setCentralWidget(self.tabs)


def main():
    parser = argparse.ArgumentParser(description="Anonymizator — researcher app")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
