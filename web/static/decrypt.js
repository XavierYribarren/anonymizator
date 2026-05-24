/**
 * Decrypt page — loads .enc (from drop or ?file_id=), decrypts with private key.
 * The private key never leaves the browser.
 */

let _encBytes = null;
let _outputName = null;

async function init() {
    const dropZone = document.getElementById("drop-zone");
    const fileNameEl = document.getElementById("file-loaded-name");

    setupDropZone(dropZone, async (file) => {
        try {
            const buffer = await readFileAsBuffer(file);
            _encBytes = new Uint8Array(buffer);
            _outputName = file.name.endsWith(".enc") ? file.name.slice(0, -4) : file.name + ".decrypted";
            dropZone.classList.remove("error");
            dropZone.classList.add("success");
            dropZone.innerHTML = escapeHtml(file.name) +
                `<span class="drop-zone-hint">chargé — ${formatSize(file.size)}</span>`;
            fileNameEl.textContent = file.name;
            fileNameEl.classList.remove("hidden");
        } catch (err) {
            dropZone.classList.add("error");
            dropZone.textContent = "Erreur de lecture : " + err.message;
        }
    });

    // Auto-load from ?file_id= parameter
    const params = new URLSearchParams(window.location.search);
    const fileId = params.get("file_id");
    if (fileId) {
        try {
            const resp = await fetch(`/api/files/${encodeURIComponent(fileId)}`);
            if (resp.ok) {
                const blob = await resp.blob();
                let filename = "fichier.enc";
                const cd = resp.headers.get("content-disposition");
                if (cd) {
                    const m = cd.match(/filename[^;=\n]*=(['"]?)([^'";\n]+)\1/);
                    if (m) filename = m[2].trim();
                }
                const buffer = await blob.arrayBuffer();
                _encBytes = new Uint8Array(buffer);
                _outputName = filename.endsWith(".enc") ? filename.slice(0, -4) : filename;
                dropZone.classList.add("success");
                dropZone.innerHTML = escapeHtml(filename) +
                    `<span class="drop-zone-hint">chargé automatiquement — ${formatSize(blob.size)}</span>`;
                fileNameEl.textContent = filename;
                fileNameEl.classList.remove("hidden");
            }
        } catch {
            // Ignore — user can still drop manually
        }
    }

    document.getElementById("btn-decrypt").addEventListener("click", runDecrypt);
}

async function runDecrypt() {
    const errorEl = document.getElementById("decrypt-error");
    const successEl = document.getElementById("decrypt-success");
    errorEl.classList.add("hidden");
    successEl.classList.add("hidden");

    if (!_encBytes) {
        errorEl.textContent = "Glissez d'abord un fichier .enc dans la zone ci-dessus.";
        errorEl.classList.remove("hidden");
        return;
    }

    const privKeyInput = document.getElementById("private-key-input");
    const privateKeyPem = privKeyInput.value.trim();
    if (!privateKeyPem) {
        errorEl.textContent = "Collez votre clé privée dans le champ ci-dessous.";
        errorEl.classList.remove("hidden");
        return;
    }

    const btn = document.getElementById("btn-decrypt");
    btn.disabled = true;
    btn.textContent = "Déchiffrement…";

    try {
        const decrypted = await decryptFile(_encBytes, privateKeyPem);
        downloadBytes(decrypted, _outputName || "fichier_dechiffre");
        successEl.classList.remove("hidden");
    } catch (err) {
        errorEl.innerHTML =
            "<strong>Déchiffrement échoué.</strong><br>" +
            escapeHtml(err.message) +
            "<br><span class='text-muted'>Vérifiez que la clé privée correspond au fichier.</span>";
        errorEl.classList.remove("hidden");
    } finally {
        btn.disabled = false;
        btn.textContent = "Déchiffrer";
        // Erase private key from DOM immediately after use
        privKeyInput.value = "";
    }
}

document.addEventListener("DOMContentLoaded", init);
