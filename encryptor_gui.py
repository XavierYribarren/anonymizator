# File: encryptor_gui.py

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Pour le Drag & Drop
from tkinterdnd2 import DND_FILES, TkinterDnD

# Importer les fonctions de cryptographie
import crypto_utils

class EncryptorDecryptorGUI(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()

        self.title("Applicatif d'Encryption/Décryption (RSA)")
        self.geometry("600x400")

        # Variables pour stocker les chemins
        self.file_path_var = tk.StringVar()
        self.key_path_var = tk.StringVar()

        # Variable pour choisir l'opération
        self.operation_var = tk.StringVar(value="encrypt")  # Valeur par défaut : encrypt

        # 1) Section pour choisir l'opération
        operation_frame = ttk.Frame(self)
        operation_frame.pack(pady=10)

        ttk.Radiobutton(operation_frame, text="Chiffrer un fichier", variable=self.operation_var, value="encrypt", command=self.update_interface).pack(side="left", padx=20)
        ttk.Radiobutton(operation_frame, text="Déchiffrer un fichier", variable=self.operation_var, value="decrypt", command=self.update_interface).pack(side="left", padx=20)

        # 2) Zone de Drag-and-Drop
        self.drop_label = ttk.Label(self, text="Glissez-déposez votre fichier ici", relief="ridge", padding=10)
        self.drop_label.pack(pady=10, fill='x', expand=True)

        # Enregistrer la zone comme cible de drop
        self.drop_label.drop_target_register(DND_FILES)
        self.drop_label.dnd_bind('<<Drop>>', self.on_drop)

        # 3) Afficher le chemin du fichier
        ttk.Label(self, text="Fichier à traiter:").pack()
        self.file_entry = ttk.Entry(self, textvariable=self.file_path_var, width=80)
        self.file_entry.pack(pady=5)

        # 4) Bouton pour parcourir le fichier
        browse_file_btn = ttk.Button(self, text="Parcourir", command=self.browse_file)
        browse_file_btn.pack(pady=5)

        # 5) Section pour la clé (seulement pour déchiffrer)
        self.key_frame = ttk.Frame(self)
        self.key_frame.pack(pady=10, fill='x', expand=True)

        self.key_label = ttk.Label(self.key_frame, text="Chemin de la Clé Privée:")
        self.key_entry = ttk.Entry(self.key_frame, textvariable=self.key_path_var, width=60)
        self.browse_key_btn = ttk.Button(self.key_frame, text="Parcourir Clé", command=self.browse_key)

        # Initialement caché, seulement visible en mode déchiffrer
        self.key_frame.pack_forget()

        # 6) Bouton pour traiter le fichier
        self.process_button = ttk.Button(self, text="Démarrer", command=self.process_file)
        self.process_button.pack(pady=10)

        # 7) Bouton pour générer une nouvelle paire de clés (pour le chercheur)
        self.gen_keys_button = ttk.Button(self, text="Générer une nouvelle paire de clés", command=self.gen_keypair)
        self.gen_keys_button.pack(pady=10)

        # Initialiser l'interface en fonction de l'opération par défaut
        self.update_interface()

    def update_interface(self):
        """Met à jour l'interface en fonction de l'opération sélectionnée."""
        operation = self.operation_var.get()
        if operation == "encrypt":
            self.key_frame.pack_forget()
        else:  # decrypt
            self.key_label.pack(side="left", padx=5)
            self.key_entry.pack(side="left", padx=5)
            self.browse_key_btn.pack(side="left", padx=5)

    def on_drop(self, event):
        """Gérer l'événement de drop."""
        file_path = event.data
        file_path = file_path.strip("{}")  # Nettoyer le chemin si nécessaire
        self.file_path_var.set(file_path)

    def browse_file(self):
        """Ouvrir une boîte de dialogue pour sélectionner un fichier."""
        if self.operation_var.get() == "encrypt":
            title = "Sélectionner un fichier à chiffrer"
        else:
            title = "Sélectionner un fichier à déchiffrer"
        path = filedialog.askopenfilename(title=title)
        if path:
            self.file_path_var.set(path)

    def browse_key(self):
        """Ouvrir une boîte de dialogue pour sélectionner la clé privée."""
        path = filedialog.askopenfilename(title="Sélectionner la clé privée (PEM)", filetypes=[("Clés PEM", "*.pem"), ("Tous les fichiers", "*.*")])
        if path:
            self.key_path_var.set(path)

    def process_file(self):
        """Chiffrer ou déchiffrer le fichier sélectionné."""
        file_path = self.file_path_var.get()
        operation = self.operation_var.get()

        if not file_path:
            messagebox.showerror("Erreur", "Veuillez sélectionner un fichier à traiter.")
            return
        if not os.path.exists(file_path):
            messagebox.showerror("Erreur", f"Le fichier '{file_path}' n'existe pas.")
            return

        try:
            if operation == "encrypt":
                output_path = crypto_utils.encrypt_file(file_path)
                messagebox.showinfo("Succès", f"Fichier chiffré avec succès!\nSauvegardé sous: {output_path}")
            else:  # decrypt
                key_path = self.key_path_var.get()
                if not key_path:
                    messagebox.showerror("Erreur", "Veuillez spécifier le chemin de la clé privée.")
                    return
                if not os.path.exists(key_path):
                    messagebox.showerror("Erreur", f"Le fichier de clé privée '{key_path}' n'existe pas.")
                    return
                output_path = crypto_utils.decrypt_file(file_path, key_path)
                messagebox.showinfo("Succès", f"Fichier déchiffré avec succès!\nSauvegardé sous: {output_path}")
        except Exception as e:
            if operation == "encrypt":
                context = "le chiffrement"
            else:
                context = "le déchiffrement"
            messagebox.showerror("Erreur", f"{context.capitalize()} a échoué:\n{str(e)}")

    def gen_keypair(self):
        """Générer une nouvelle paire de clés RSA et sauvegarder les fichiers."""
        confirm = messagebox.askyesno("Confirmation", "Voulez-vous générer une nouvelle paire de clés RSA? Cela écrasera les clés existantes.")
        if not confirm:
            return
        try:
            private_pem, public_ssh = crypto_utils.generate_key_pair()
            crypto_utils.save_keys(private_pem, public_ssh)
            # Mise à jour de la clé publique intégrée
            crypto_utils.EMBEDDED_PUBLIC_KEY = public_ssh
            messagebox.showinfo(
                "Clés Générées",
                "Une nouvelle paire de clés RSA a été générée.\n"
                "Clé privée: id_rsa\n"
                "Clé publique: id_rsa.pub\n\n"
                "Assurez-vous de distribuer la clé publique intégrée dans l'applicatif aux expérimentateurs."
            )
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de générer les clés:\n{str(e)}")

def main():
    app = EncryptorDecryptorGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
