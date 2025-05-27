import os
import re

# Répertoire à nettoyer
static_root = "frontend/static"

# Extensions à traiter
extensions = ['.js', '.css']

for root, _, files in os.walk(static_root):
    for file in files:
        if any(file.endswith(ext) for ext in extensions):
            path = os.path.join(root, file)
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            # Supprimer les lignes avec sourceMappingURL
            cleaned_lines = [line for line in lines if 'sourceMappingURL=' not in line]

            if len(cleaned_lines) < len(lines):
                with open(path, 'w', encoding='utf-8') as f:
                    f.writelines(cleaned_lines)
                print(f"[✔] Nettoyé : {path}")
