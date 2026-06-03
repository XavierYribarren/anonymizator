/**
 * Upload page — verifies token, encrypts file in-browser, sends to server.
 * API_BASE and MAX_FILE_SIZE_MB are defined in upload.html before this script.
 */

async function init() {
    // TOKEN_ID is resolved in upload.html (supports /upload/<uuid> and ?token=<uuid>)
    const tokenId = TOKEN_ID;

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
        const resp = await fetch(`${API_BASE}/api/tokens/${encodeURIComponent(tokenId)}`);
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
        const maxMB = window.MAX_FILE_SIZE_MB || 2;
        if (file.size > maxMB * 1024 * 1024) {
            dropZone.classList.add("error");
            dropZone.innerHTML =
                `<strong>${I18n.t("common.error")}</strong><br>` +
                `<span class="drop-zone-hint">${I18n.t("upload.file_too_large", { max: maxMB })}</span>`;
            return;
        }

        dropZone.classList.add("hidden");
        progressWrap.classList.remove("hidden");
        progressLabel.classList.remove("hidden");

        try {
            setStep(I18n.t("upload.step_reading"), 10);
            const buffer = await readFileAsBuffer(file);

            setStep(I18n.t("upload.step_fetching_key"), 25);
            const keyResp = await fetch(`${API_BASE}/api/tokens/${encodeURIComponent(tokenId)}/public-key`);
            if (!keyResp.ok) throw new Error(I18n.t("upload.error_key"));
            const { public_key } = await keyResp.json();

            setStep(I18n.t("upload.step_encrypting"), 45);
            const fileBytes = new Uint8Array(buffer);
            const encrypted = await encryptFile(fileBytes, public_key);

            setStep(I18n.t("upload.step_uploading"), 75);
            const formData = new FormData();
            formData.append(
                "file",
                new Blob([encrypted], { type: "application/octet-stream" }),
                file.name + ".enc"
            );
            formData.append("original_filename", file.name);

            const uploadResp = await fetch(`${API_BASE}/api/upload/${encodeURIComponent(tokenId)}`, {
                method: "POST",
                body: formData,
            });

            if (!uploadResp.ok) {
                const err = await uploadResp.json();
                throw new Error(err.detail || I18n.t("upload.error_upload"));
            }

            setStep(I18n.t("upload.step_done"), 100);
            document.getElementById("state-upload").classList.add("hidden");
            document.getElementById("state-success").classList.remove("hidden");

        } catch (err) {
            progressWrap.classList.add("hidden");
            progressLabel.classList.add("hidden");
            dropZone.classList.remove("hidden");
            dropZone.classList.add("error");
            dropZone.innerHTML =
                `<strong>${I18n.t("common.error")}</strong><br><span class="drop-zone-hint">${err.message}</span>`;
        }
    });
}

document.addEventListener("DOMContentLoaded", init);
