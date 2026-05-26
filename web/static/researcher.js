/**
 * Researcher page logic — key management, token generation, file list.
 */

const LS_PUB_KEY = "anonymizator_public_key";
const LS_FINGERPRINT = "anonymizator_fingerprint";
const LS_EMAIL = "anonymizator_researcher_email";

let _generatedPrivKey = null;
let _generatedPubKey = null;

// ── Bootstrap ─────────────────────────────────────────────────────────────────

async function init() {
    const saved = localStorage.getItem(LS_PUB_KEY);
    if (saved) {
        await activateKey(saved, true);
    } else {
        showNoKey();
    }

    const savedEmail = localStorage.getItem(LS_EMAIL);
    if (savedEmail) document.getElementById("researcher-email").value = savedEmail;

    bindEvents();
}

// ── State helpers ─────────────────────────────────────────────────────────────

function showNoKey() {
    show("key-empty");
    hide("key-loaded");
    hide("invite-form");
    show("invite-no-key");
    hide("files-table-wrap");
    hide("files-empty");
    show("files-no-key");
}

async function activateKey(publicKeyPem, silent) {
    // Read from localStorage first; compute and persist only if missing.
    let fp = localStorage.getItem(LS_FINGERPRINT);
    if (!fp) {
        try {
            fp = await getFingerprint(publicKeyPem);
        } catch {
            if (!silent) alert(I18n.t("researcher.key_invalid"));
            localStorage.removeItem(LS_PUB_KEY);
            showNoKey();
            return;
        }
        localStorage.setItem(LS_FINGERPRINT, fp);
    }

    hide("key-empty");
    show("key-loaded");
    document.getElementById("key-fingerprint").textContent = fp;
    document.getElementById("key-status-text").textContent =
        I18n.t("researcher.key_loaded") + " — " + fp;

    hide("invite-no-key");
    show("invite-form");
    hide("files-no-key");

    loadFiles(fp);
}

// ── File list ─────────────────────────────────────────────────────────────────

async function loadFiles(fp) {
    hide("files-table-wrap");
    hide("files-empty");
    show("files-loading");

    try {
        const resp = await fetch(`/api/files?fingerprint=${encodeURIComponent(fp)}`);
        const files = await resp.json();
        hide("files-loading");

        if (!files.length) {
            show("files-empty");
            return;
        }

        const tbody = document.getElementById("files-tbody");
        tbody.innerHTML = "";
        files.forEach(f => {
            const tr = document.createElement("tr");
            const name = f.original_filename || I18n.t("researcher.files_no_file");
            tr.innerHTML = `
                <td class="filename-cell" title="${escapeHtml(name)}">${escapeHtml(name)}</td>
                <td>${formatDate(f.uploaded_at)}</td>
                <td>${formatSize(f.file_size)}</td>
                <td>${formatDate(f.expires_at)}</td>
                <td>
                    <div class="btn-group">
                        <a href="/decrypt?file_id=${encodeURIComponent(f.id)}&fingerprint=${encodeURIComponent(fp)}"
                           class="btn btn-primary btn-sm">${I18n.t("researcher.files_decrypt")}</a>
                        <a href="/api/files/${encodeURIComponent(f.id)}?fingerprint=${encodeURIComponent(fp)}"
                           class="btn btn-secondary btn-sm" download>${I18n.t("researcher.files_download")}</a>
                        <button class="btn btn-danger btn-sm"
                                data-delete="${escapeHtml(f.id)}">${I18n.t("researcher.files_delete")}</button>
                    </div>
                </td>`;
            tbody.appendChild(tr);
        });

        tbody.addEventListener("click", async (e) => {
            const btn = e.target.closest("[data-delete]");
            if (!btn) return;
            if (!confirm(I18n.t("researcher.files_confirm_delete"))) return;
            btn.disabled = true;
            await fetch(`/api/files/${btn.dataset.delete}?fingerprint=${encodeURIComponent(fp)}`, { method: "DELETE" });
            loadFiles(fp);
        });

        show("files-table-wrap");
    } catch {
        hide("files-loading");
        const el = document.getElementById("files-empty");
        el.textContent = I18n.t("researcher.files_error");
        show("files-empty");
    }
}

// ── Event bindings ────────────────────────────────────────────────────────────

function bindEvents() {
    // Generate key pair
    document.getElementById("btn-generate-key").addEventListener("click", async () => {
        const modal = document.getElementById("keygen-modal");
        const progress = document.getElementById("keygen-progress");
        const result = document.getElementById("keygen-result");

        _generatedPrivKey = null;
        _generatedPubKey = null;
        hide(result);
        show(progress);
        progress.textContent = I18n.t("researcher.keygen_progress");
        modal.classList.add("active");

        try {
            const keys = await generateKeyPair();
            _generatedPrivKey = keys.privateKeyPem;
            _generatedPubKey = keys.publicKeyPem;
            document.getElementById("modal-pubkey").value = keys.publicKeyPem;
            hide(progress);
            show(result);
        } catch (err) {
            progress.textContent = I18n.t("researcher.keygen_error", { message: err.message });
        }
    });

    // Download private key from modal
    document.getElementById("btn-download-privkey").addEventListener("click", () => {
        if (_generatedPrivKey) downloadText(_generatedPrivKey, "private_key.pem");
    });

    // Save public key in localStorage and close modal
    document.getElementById("btn-save-pubkey").addEventListener("click", async () => {
        if (!_generatedPubKey) return;
        localStorage.removeItem(LS_FINGERPRINT);   // force recompute for the new key
        localStorage.setItem(LS_PUB_KEY, _generatedPubKey);
        document.getElementById("keygen-modal").classList.remove("active");
        const pub = _generatedPubKey;
        _generatedPrivKey = null;
        _generatedPubKey = null;
        await activateKey(pub, false);
    });

    // Close modal (private key is lost intentionally)
    document.getElementById("btn-close-keygen").addEventListener("click", () => {
        document.getElementById("keygen-modal").classList.remove("active");
        _generatedPrivKey = null;
        _generatedPubKey = null;
    });

    // Use pasted public key
    document.getElementById("btn-use-pasted-key").addEventListener("click", async () => {
        const pem = document.getElementById("paste-pubkey").value.trim();
        if (!pem) { alert(I18n.t("researcher.key_paste_prompt")); return; }
        try {
            await crypto.subtle.importKey(
                "spki", pemToBuffer(pem),
                { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]
            );
            localStorage.removeItem(LS_FINGERPRINT);   // force recompute for the new key
            localStorage.setItem(LS_PUB_KEY, pem);
            await activateKey(pem, false);
        } catch {
            alert(I18n.t("researcher.key_invalid"));
        }
    });

    // Change key
    document.getElementById("btn-change-key").addEventListener("click", () => {
        localStorage.removeItem(LS_PUB_KEY);
        localStorage.removeItem(LS_FINGERPRINT);
        showNoKey();
    });

    // Send invite
    document.getElementById("btn-send-invite").addEventListener("click", sendInvite);

    // Copy link
    document.getElementById("btn-copy-link").addEventListener("click", async () => {
        const link = document.getElementById("invite-link").value;
        const ok = await copyToClipboard(link);
        const btn = document.getElementById("btn-copy-link");
        btn.textContent = ok ? I18n.t("common.copied") : I18n.t("common.error");
        setTimeout(() => { btn.textContent = I18n.t("common.copy"); }, 2000);
    });
}

async function sendInvite() {
    const collectorEmail = document.getElementById("collector-email").value.trim();
    if (!collectorEmail) { alert(I18n.t("researcher.invite_email_required")); return; }

    const publicKey = localStorage.getItem(LS_PUB_KEY);
    if (!publicKey) { alert(I18n.t("researcher.invite_key_required")); return; }

    const researcherEmail = document.getElementById("researcher-email").value.trim();
    if (researcherEmail) localStorage.setItem(LS_EMAIL, researcherEmail);

    const btn = document.getElementById("btn-send-invite");
    btn.disabled = true;
    btn.textContent = I18n.t("researcher.invite_sending");

    try {
        const resp = await fetch("/api/tokens", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                public_key: publicKey,
                researcher_email: researcherEmail || null,
                collector_email: collectorEmail,
            }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || I18n.t("researcher.invite_server_error"));

        document.getElementById("invite-success-msg").textContent =
            I18n.t("researcher.invite_sent", { email: collectorEmail });
        document.getElementById("invite-link").value = data.upload_url;
        show("invite-result");
    } catch (err) {
        alert(I18n.t("researcher.invite_error", { message: err.message }));
    } finally {
        btn.disabled = false;
        btn.textContent = I18n.t("researcher.invite_submit");
    }
}

// ── Utility ───────────────────────────────────────────────────────────────────

function show(el) {
    const node = typeof el === "string" ? document.getElementById(el) : el;
    if (node) node.classList.remove("hidden");
}
function hide(el) {
    const node = typeof el === "string" ? document.getElementById(el) : el;
    if (node) node.classList.add("hidden");
}

document.addEventListener("DOMContentLoaded", init);
