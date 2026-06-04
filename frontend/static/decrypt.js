/**
 * Decrypt page — loads .enc (from drop or ?file_id=), decrypts with private key.
 * The private key never leaves the browser.
 * API_BASE is defined in api-base.js before this script.
 */

const FILE_ID = new URLSearchParams(window.location.search).get('file_id');

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

    if (FILE_ID) {
        const fileId = FILE_ID;
        try {
            const researcherToken = localStorage.getItem("anonymizator_researcher_token") || "";
            const resp = await fetch(
                `${API_BASE}/api/files/${encodeURIComponent(fileId)}`,
                { headers: { "X-Researcher-Token": researcherToken } }
            );
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
        errorEl.textContent = I18n.t("decrypt.error_no_file");
        errorEl.classList.remove("hidden");
        return;
    }

    const privKeyInput = document.getElementById("private-key-input");
    const privateKeyPem = privKeyInput.value.trim();
    if (!privateKeyPem) {
        errorEl.textContent = I18n.t("decrypt.error_no_key");
        errorEl.classList.remove("hidden");
        return;
    }

    const btn = document.getElementById("btn-decrypt");
    btn.disabled = true;
    btn.textContent = I18n.t("decrypt.decrypting");

    try {
        const decrypted = await decryptFile(_encBytes, privateKeyPem);
        downloadBytes(decrypted, _outputName || "fichier_dechiffre");
        successEl.classList.remove("hidden");
    } catch (err) {
        errorEl.innerHTML =
            `<strong>${I18n.t("decrypt.error_failed")}</strong><br>` +
            escapeHtml(err.message) +
            `<br><span class='text-muted'>${I18n.t("decrypt.error_format_hint")}</span>`;
        errorEl.classList.remove("hidden");
    } finally {
        btn.disabled = false;
        btn.textContent = I18n.t("decrypt.submit");
        // Erase private key from DOM immediately after use
        privKeyInput.value = "";
    }
}

document.addEventListener("DOMContentLoaded", init);
