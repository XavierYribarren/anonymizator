/**
 * Upload page — verifies token, encrypts file in-browser, sends to server.
 */

async function init() {
    const tokenId = document.getElementById("app").dataset.tokenId;

    const states = {
        loading: document.getElementById("state-loading"),
        invalid: document.getElementById("state-invalid"),
        used: document.getElementById("state-used"),
        upload: document.getElementById("state-upload"),
        success: document.getElementById("state-success"),
    };

    function showOnly(key) {
        Object.values(states).forEach(el => el.classList.add("hidden"));
        states[key].classList.remove("hidden");
    }

    try {
        const resp = await fetch(`/api/tokens/${encodeURIComponent(tokenId)}`);
        const status = await resp.json();

        if (status.expired || !status.valid) { showOnly("invalid"); return; }
        if (status.used) { showOnly("used"); return; }

        showOnly("upload");
        setupUpload(tokenId);
    } catch {
        showOnly("invalid");
    }
}

function setupUpload(tokenId) {
    const dropZone = document.getElementById("drop-zone");
    const progressWrap = document.getElementById("progress-wrap");
    const progressBar = document.getElementById("progress-bar");
    const progressLabel = document.getElementById("progress-label");

    function setStep(label, percent) {
        progressLabel.textContent = label;
        setProgress(progressBar, percent);
    }

    setupDropZone(dropZone, async (file) => {
        dropZone.classList.add("hidden");
        progressWrap.classList.remove("hidden");
        progressLabel.classList.remove("hidden");

        try {
            setStep("Lecture du fichier…", 10);
            const buffer = await readFileAsBuffer(file);

            setStep("Récupération de la clé publique…", 25);
            const keyResp = await fetch(`/api/tokens/${encodeURIComponent(tokenId)}/public-key`);
            if (!keyResp.ok) throw new Error("Impossible de récupérer la clé de chiffrement.");
            const { public_key } = await keyResp.json();

            setStep("Chiffrement en cours…", 45);
            const fileBytes = new Uint8Array(buffer);
            const encrypted = await encryptFile(fileBytes, public_key);

            setStep("Envoi du fichier…", 75);
            const formData = new FormData();
            formData.append(
                "file",
                new Blob([encrypted], { type: "application/octet-stream" }),
                file.name + ".enc"
            );
            formData.append("original_filename", file.name);

            const uploadResp = await fetch(`/api/upload/${encodeURIComponent(tokenId)}`, {
                method: "POST",
                body: formData,
            });

            if (!uploadResp.ok) {
                const err = await uploadResp.json();
                throw new Error(err.detail || "Erreur lors de l'envoi.");
            }

            setStep("Envoyé !", 100);
            document.getElementById("state-upload").classList.add("hidden");
            document.getElementById("state-success").classList.remove("hidden");

        } catch (err) {
            progressWrap.classList.add("hidden");
            progressLabel.classList.add("hidden");
            dropZone.classList.remove("hidden");
            dropZone.classList.add("error");
            dropZone.innerHTML =
                `<strong>Erreur</strong><br><span class="drop-zone-hint">${err.message}</span>`;
        }
    });
}

document.addEventListener("DOMContentLoaded", init);
