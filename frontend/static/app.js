/**
 * Shared UI helpers — drag & drop, file I/O, clipboard, formatting.
 */

function setupDropZone(zone, onFile) {
    zone.addEventListener("dragover", (e) => {
        e.preventDefault();
        zone.classList.add("drag-over");
    });
    zone.addEventListener("dragleave", (e) => {
        if (!zone.contains(e.relatedTarget)) zone.classList.remove("drag-over");
    });
    zone.addEventListener("drop", (e) => {
        e.preventDefault();
        zone.classList.remove("drag-over");
        const file = e.dataTransfer.files[0];
        if (file) onFile(file);
    });
    zone.addEventListener("click", () => {
        const input = document.createElement("input");
        input.type = "file";
        input.onchange = () => { if (input.files[0]) onFile(input.files[0]); };
        input.click();
    });
}

function readFileAsBuffer(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(new Error("Erreur de lecture du fichier"));
        reader.readAsArrayBuffer(file);
    });
}

function downloadBytes(bytes, filename) {
    const blob = new Blob([bytes], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1500);
}

function downloadText(text, filename) {
    downloadBytes(new TextEncoder().encode(text), filename);
}

function setProgress(bar, percent) {
    if (bar) bar.style.width = percent + "%";
}

async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch {
        return false;
    }
}

function formatSize(bytes) {
    if (!bytes && bytes !== 0) return "—";
    if (bytes < 1024) return bytes + " o";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " Ko";
    return (bytes / (1024 * 1024)).toFixed(1) + " Mo";
}

function formatDate(isoStr) {
    if (!isoStr) return "—";
    try {
        return new Date(isoStr).toLocaleString("fr-FR", {
            dateStyle: "short",
            timeStyle: "short",
        });
    } catch {
        return isoStr;
    }
}

function escapeHtml(str) {
    if (!str) return "";
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}
