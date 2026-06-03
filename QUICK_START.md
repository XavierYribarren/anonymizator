# Anonymizator — Quick Start

> No install required beyond Python. Works without email configuration.

---

## EN — 3 steps

**Step 1 — Start the app**

```bash
pip install -r requirements.txt
python researcher_app.py
```

Your browser opens automatically at `http://localhost:8000`.

**Step 2 — Generate a key and invite a collector**

1. Click **Generate a key pair** — save the private key file somewhere safe (you'll need it to decrypt)
2. Enter the collector's email (or leave it blank) → click **Send invitation**
3. The upload link appears on screen — copy and send it by email, SMS, or Slack

> **Email is optional.** If you don't configure SMTP, the link is simply shown in the interface and never sent automatically.

**Step 3 — Receive and decrypt files**

- When the collector uploads a file, refresh the page (F5) to see it appear
- Click **Decrypt**, paste your private key → the decrypted file downloads in your browser
- The private key never leaves your machine

---

## FR — 3 étapes

**Étape 1 — Lancer l'application**

```bash
pip install -r requirements.txt
python researcher_app.py
```

Le navigateur s'ouvre automatiquement sur `http://localhost:8000`.

**Étape 2 — Générer une clé et inviter un collecteur**

1. Cliquer **Générer une paire de clés** — sauvegarder le fichier de clé privée (nécessaire pour déchiffrer)
2. Entrer l'email du collecteur (ou laisser vide) → cliquer **Envoyer l'invitation**
3. Le lien d'envoi s'affiche à l'écran — le copier-coller par email, SMS ou Slack

> **L'email est optionnel.** Sans configuration SMTP, le lien est simplement affiché dans l'interface et n'est jamais envoyé automatiquement.

**Étape 3 — Recevoir et déchiffrer les fichiers**

- Quand le collecteur envoie un fichier, rafraîchir la page (F5) pour le voir apparaître
- Cliquer **Déchiffrer**, coller la clé privée → le fichier déchiffré se télécharge dans le navigateur
- La clé privée ne quitte jamais la machine

---

For SMTP configuration, VPS deployment, and advanced settings → [README.md](README.md)
