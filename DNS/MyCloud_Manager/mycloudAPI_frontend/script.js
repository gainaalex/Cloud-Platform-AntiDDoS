// Calea relativa procesata de Nginx Reverse Proxy
const API_URL = "/api";

const inputDomain = document.getElementById('domain');
const inputOrigin = document.getElementById('origin_ip');
const inputTimestamp = document.getElementById('timestamp');
const inputSignature = document.getElementById('signature');
const logBox = document.getElementById('log-box');

// Functie utilitara pentru loguri in UI
function log(msg, type = 'info') {
    const time = new Date().toLocaleTimeString();
    let colorClass = 'log-info';

    if (type === 'error') colorClass = 'log-error';
    if (type === 'success') colorClass = 'log-success';

    logBox.innerHTML += `<div><span class="log-time">[${time}]</span> <span class="${colorClass}">${msg}</span></div>`;
    logBox.scrollTop = logBox.scrollHeight;
}

// Handler inregistrare POP
document.getElementById('btn-register').addEventListener('click', async () => {
    const domain = inputDomain.value.trim().toLowerCase();
    const origin = inputOrigin.value.trim();
    const ts = inputTimestamp.value.trim();
    const sig = inputSignature.value.trim();

    if (!domain || !origin || !ts || !sig) {
        return log("[*Err]: Toate campurile sunt obligatorii", 'error');
    }

    // Trimitem URL-ul cu encode pe origin pentru a proteja porturile (ex: 8080)
    const encodedOrigin = encodeURIComponent(origin);
    const url = `${API_URL}/register?domain=${domain}&origin=${encodedOrigin}&t=${ts}&sig=${sig}`;

    log(`[*I]: Trimitem cerere de inregistrare pentru ${domain}...`, 'info');

    try {
        const response = await fetch(url, { method: 'POST' });
        const text = await response.text();

        if (response.ok) {
            log(text, 'success');
        } else {
            log(`Eroare backend: ${response.status} - ${text}`, 'error');
        }
    } catch (e) {
        log(`Conexiune esuata la Nginx/API.`, 'error');
    }
});

// Handler stergere POP
document.getElementById('btn-unregister').addEventListener('click', async () => {
    const domain = inputDomain.value.trim().toLowerCase();
    const origin = inputOrigin.value.trim();
    const ts = inputTimestamp.value.trim();
    const sig = inputSignature.value.trim();

    if (!domain || !origin || !ts || !sig) {
        return log("[*Err]: Specificati domeniul, origin-ul si token-ul pentru a sterge.", 'error');
    }

    const encodedOrigin = encodeURIComponent(origin);
    const url = `${API_URL}/unregister?domain=${domain}&original_ip=${encodedOrigin}&t=${ts}&sig=${sig}`;

    log(`Se solicita eliminarea nodului pentru ${domain}...`, 'info');

    try {
        const response = await fetch(url, { method: 'POST' });
        const text = await response.text();

        if (response.ok) {
            log(text, 'success');
        } else {
            log(`Eroare backend: ${response.status} - ${text}`, 'error');
        }
    } catch (e) {
        log(`Conexiune esuata la API.`, 'error');
    }
});

log("MyCloud command logs", 'info');