const API_URL = "/api";

const inputDomain = document.getElementById('domain');
const inputIp = document.getElementById('ip');
const logBox = document.getElementById('log-box');

//Functia pentru print logs in UI ul site ului
function log(msg, type = 'info') {
    const time = new Date().toLocaleTimeString();
    let colorClass = 'log-info';

    if (type === 'error') colorClass = 'log-error';
    if (type === 'success') colorClass = 'log-success';

    logBox.innerHTML += `<div><span class="log-time">[${time}]</span> <span class="${colorClass}">${msg}</span></div>`;
    logBox.scrollTop = logBox.scrollHeight;
}

document.getElementById('btn-buy').addEventListener('click', async () => {
    const domain = inputDomain.value.trim().toLowerCase();
    const ip = inputIp.value.trim();

    if (!domain) {
        return log("Eroare: Trebuie specificat un domeniu.", 'error');
    }

    let url = `${API_URL}/buy?domain=${domain}`;
    if (ip) {
        url += `&ip=${ip}`;
    }

    log(`Se initiaza tranzactia pentru ${domain}...`, 'info');

    try {
        const response = await fetch(url, { method: 'POST' });
        const text = await response.text();

        if (response.ok) {
            log(text, 'success');
        } else {
            log(`Eroare backend: ${response.status} - ${text}`, 'error');
        }
    } catch (e) {
        log(`Conexiune esuata la TLD. Verifica statusul containerului.`, 'error');
    }
});

log("Portalul ROTLD este online.", 'info');