/**
 * YARA Scanner Frontend Application
 * Connects to the YARA Operator API for running scans
 */

// Configuration
const CONFIG = {
    // API endpoint - update this to your deployed API URL
    apiUrl: localStorage.getItem('yaraApiUrl') || 'https://api.yara.example.com',
    pollInterval: 2000,
    maxPollAttempts: 150, // 5 minutes max
};

// State
const state = {
    connected: false,
    selectedRules: new Set(),
    selectedFile: null,
    currentTab: 'image',
    scans: [],
    rules: [],
};

// DOM Elements
const elements = {
    statusDot: document.getElementById('statusDot'),
    statusText: document.getElementById('statusText'),
    scanButton: document.getElementById('scanButton'),
    scanText: document.getElementById('scanText'),
    scanUrl: document.getElementById('scanUrl'),
    customRule: document.getElementById('customRule'),
    customRulesSection: document.getElementById('customRulesSection'),
    toggleCustomRules: document.getElementById('toggleCustomRules'),
    availableRules: document.getElementById('availableRules'),
    resultsContainer: document.getElementById('resultsContainer'),
    rulesGrid: document.getElementById('rulesGrid'),
    fileDropZone: document.getElementById('fileDropZone'),
    fileInput: document.getElementById('fileInput'),
    fileInfo: document.getElementById('fileInfo'),
    fileName: document.getElementById('fileName'),
    fileSize: document.getElementById('fileSize'),
    fileRemove: document.getElementById('fileRemove'),
    addRuleModal: document.getElementById('addRuleModal'),
    addRuleButton: document.getElementById('addRuleButton'),
    closeModal: document.getElementById('closeModal'),
    cancelRule: document.getElementById('cancelRule'),
    addRuleForm: document.getElementById('addRuleForm'),
    resultModal: document.getElementById('resultModal'),
    closeResultModal: document.getElementById('closeResultModal'),
    resultDetails: document.getElementById('resultDetails'),
    refreshResults: document.getElementById('refreshResults'),
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initFileUpload();
    initRulesToggle();
    initModals();
    initNavigation();
    initImageChips();
    
    // Check API configuration
    if (CONFIG.apiUrl === 'https://api.yara.example.com') {
        showApiConfigPrompt();
    } else {
        checkConnection();
    }
    
    // Load initial data
    loadRules();
    loadScans();
    
    // Setup event listeners
    elements.scanButton.addEventListener('click', handleScan);
    elements.refreshResults.addEventListener('click', loadScans);
    elements.addRuleForm.addEventListener('submit', handleCreateRule);
});

// Initialize image chip buttons
function initImageChips() {
    document.querySelectorAll('.image-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            const imageInput = document.getElementById('scanImage');
            if (imageInput) {
                imageInput.value = chip.dataset.image;
                imageInput.focus();
            }
        });
    });
}

// API Configuration Prompt
function showApiConfigPrompt() {
    const apiUrl = prompt(
        'Enter your YARA API endpoint URL:\n\n' +
        'This should be the URL where your YARA Operator API is deployed.\n' +
        'Example: https://yara-api.your-domain.com',
        CONFIG.apiUrl
    );
    
    if (apiUrl && apiUrl.trim()) {
        CONFIG.apiUrl = apiUrl.trim();
        localStorage.setItem('yaraApiUrl', CONFIG.apiUrl);
        checkConnection();
    } else {
        updateStatus('disconnected', 'API not configured');
    }
}

// Connection Check
async function checkConnection() {
    try {
        updateStatus('connecting', 'Connecting...');
        const response = await fetch(`${CONFIG.apiUrl}/health`, {
            method: 'GET',
            headers: { 'Accept': 'application/json' },
        });
        
        if (response.ok) {
            state.connected = true;
            updateStatus('connected', 'Connected');
        } else {
            throw new Error('API not healthy');
        }
    } catch (error) {
        state.connected = false;
        updateStatus('error', 'Disconnected');
        console.error('Connection error:', error);
    }
}

function updateStatus(status, text) {
    elements.statusDot.className = 'status-dot';
    if (status === 'connected') {
        elements.statusDot.classList.add('connected');
    } else if (status === 'error') {
        elements.statusDot.classList.add('error');
    }
    elements.statusText.textContent = text;
}

// Tab Navigation
function initTabs() {
    const tabs = document.querySelectorAll('.tab');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const targetTab = tab.dataset.tab;
            state.currentTab = targetTab;
            
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            
            tabContents.forEach(content => {
                content.classList.remove('active');
                if (content.id === `${targetTab}-tab`) {
                    content.classList.add('active');
                }
            });
        });
    });
}

// File Upload
function initFileUpload() {
    const dropZone = elements.fileDropZone;
    const fileInput = elements.fileInput;
    
    dropZone.addEventListener('click', () => fileInput.click());
    
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });
    
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });
    
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFile(files[0]);
        }
    });
    
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFile(e.target.files[0]);
        }
    });
    
    elements.fileRemove.addEventListener('click', () => {
        state.selectedFile = null;
        elements.fileInfo.classList.add('hidden');
        elements.fileDropZone.classList.remove('hidden');
        elements.fileInput.value = '';
    });
}

function handleFile(file) {
    if (file.size > 10 * 1024 * 1024) {
        alert('File size exceeds 10MB limit');
        return;
    }
    
    state.selectedFile = file;
    elements.fileName.textContent = file.name;
    elements.fileSize.textContent = formatFileSize(file.size);
    elements.fileDropZone.classList.add('hidden');
    elements.fileInfo.classList.remove('hidden');
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// Custom Rules Toggle
function initRulesToggle() {
    elements.toggleCustomRules.addEventListener('click', () => {
        elements.customRulesSection.classList.toggle('hidden');
        const isHidden = elements.customRulesSection.classList.contains('hidden');
        elements.toggleCustomRules.innerHTML = isHidden 
            ? '<span>+ Add Custom Rule</span>'
            : '<span>− Hide Custom Rule</span>';
    });
}

// Modals
function initModals() {
    elements.addRuleButton.addEventListener('click', () => {
        elements.addRuleModal.classList.remove('hidden');
    });
    
    elements.closeModal.addEventListener('click', () => {
        elements.addRuleModal.classList.add('hidden');
    });
    
    elements.cancelRule.addEventListener('click', () => {
        elements.addRuleModal.classList.add('hidden');
    });
    
    elements.closeResultModal.addEventListener('click', () => {
        elements.resultModal.classList.add('hidden');
    });
    
    // Close on overlay click
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
        overlay.addEventListener('click', () => {
            elements.addRuleModal.classList.add('hidden');
            elements.resultModal.classList.add('hidden');
        });
    });
}

// Navigation
function initNavigation() {
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
            link.classList.add('active');
        });
    });
}

// Load Rules
async function loadRules() {
    try {
        const response = await fetch(`${CONFIG.apiUrl}/api/v1/rules`);
        if (!response.ok) throw new Error('Failed to load rules');
        
        state.rules = await response.json() || [];
        renderAvailableRules();
        renderRulesGrid();
    } catch (error) {
        console.error('Error loading rules:', error);
        elements.availableRules.innerHTML = '<div class="rules-loading">Could not load rules</div>';
    }
}

function renderAvailableRules() {
    if (state.rules.length === 0) {
        elements.availableRules.innerHTML = '<div class="rules-loading">No rules available. Add custom rules below.</div>';
        return;
    }
    
    elements.availableRules.innerHTML = state.rules.map(rule => `
        <div class="rule-chip ${state.selectedRules.has(rule.name) ? 'selected' : ''}" 
             data-rule="${rule.name}">
            <span class="rule-chip-status ${rule.status === 'Valid' ? '' : 'invalid'}"></span>
            <span class="rule-chip-name">${escapeHtml(rule.name)}</span>
        </div>
    `).join('');
    
    document.querySelectorAll('.rule-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            const ruleName = chip.dataset.rule;
            if (state.selectedRules.has(ruleName)) {
                state.selectedRules.delete(ruleName);
                chip.classList.remove('selected');
            } else {
                state.selectedRules.add(ruleName);
                chip.classList.add('selected');
            }
        });
    });
}

function renderRulesGrid() {
    if (state.rules.length === 0) {
        elements.rulesGrid.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon empty-icon-svg">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                        <polyline points="14,2 14,8 20,8"></polyline>
                        <line x1="16" y1="13" x2="8" y2="13"></line>
                        <line x1="16" y1="17" x2="8" y2="17"></line>
                    </svg>
                </div>
                <h3>No rules configured</h3>
                <p>Add YARA rules to enable automated scanning</p>
            </div>
        `;
        return;
    }
    
    elements.rulesGrid.innerHTML = state.rules.map(rule => `
        <div class="rule-card">
            <div class="rule-card-header">
                <span class="rule-card-name">${escapeHtml(rule.name)}</span>
                <span class="rule-card-status ${(rule.status || 'pending').toLowerCase()}">${rule.status || 'Pending'}</span>
            </div>
            <p class="rule-card-desc">${escapeHtml(rule.description || 'No description provided')}</p>
            <div class="rule-card-tags">
                ${(rule.tags || []).map(tag => `<span class="rule-tag">${escapeHtml(tag)}</span>`).join('')}
            </div>
        </div>
    `).join('');
}

// Load Scans
async function loadScans() {
    try {
        const response = await fetch(`${CONFIG.apiUrl}/api/v1/scans`);
        if (!response.ok) throw new Error('Failed to load scans');
        
        state.scans = await response.json() || [];
        renderScans();
    } catch (error) {
        console.error('Error loading scans:', error);
    }
}

function renderScans() {
    if (state.scans.length === 0) {
        elements.resultsContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon empty-icon-svg">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                        <circle cx="11" cy="11" r="8"></circle>
                        <path d="m21 21-4.35-4.35"></path>
                    </svg>
                </div>
                <h3>No scans yet</h3>
                <p>Run your first scan to see results here</p>
            </div>
        `;
        return;
    }
    
    // Sort by most recent first
    const sortedScans = [...state.scans].sort((a, b) => {
        const dateA = new Date(a.startTime || 0);
        const dateB = new Date(b.startTime || 0);
        return dateB - dateA;
    });
    
    elements.resultsContainer.innerHTML = sortedScans.map(scan => {
        const isImageScan = scan.targetType === 'image';
        const summary = scan.summary || {};
        const riskClass = getRiskClass(summary.riskScore || 0);
        
        return `
        <div class="result-card" data-scan-id="${scan.id}">
            <div class="result-status ${(scan.status || 'pending').toLowerCase()}"></div>
            <div class="result-info">
                <div class="result-id">${isImageScan ? '[IMAGE] ' : ''}${escapeHtml(scan.id)}</div>
                <div class="result-time">${formatTime(scan.startTime)}</div>
            </div>
            ${isImageScan && scan.summary ? `
            <div class="result-matches ${summary.critical > 0 ? 'has-matches' : ''}">
                <span class="match-count ${riskClass}">${summary.riskScore || 0}</span>
                <span class="match-label">risk</span>
            </div>
            ` : `
            <div class="result-matches ${scan.matchCount > 0 ? 'has-matches' : ''}">
                <span class="match-count">${scan.matchCount || 0}</span>
                <span class="match-label">matches</span>
            </div>
            `}
            <div class="result-arrow">→</div>
        </div>
    `}).join('');
    
    document.querySelectorAll('.result-card').forEach(card => {
        card.addEventListener('click', () => {
            const scanId = card.dataset.scanId;
            showScanDetails(scanId);
        });
    });
}

function getRiskClass(score) {
    if (score >= 70) return 'critical';
    if (score >= 40) return 'high';
    if (score >= 20) return 'medium';
    return 'low';
}

function formatTime(timestamp) {
    if (!timestamp) return 'Pending...';
    const date = new Date(timestamp);
    return date.toLocaleString();
}

// Show Scan Details
async function showScanDetails(scanId) {
    try {
        const response = await fetch(`${CONFIG.apiUrl}/api/v1/scans/${scanId}`);
        if (!response.ok) throw new Error('Failed to load scan details');
        
        const scan = await response.json();
        const isImageScan = scan.targetType === 'image';
        
        let detailsHtml = '';
        
        if (isImageScan && scan.imageResult) {
            detailsHtml = renderImageScanDetails(scan);
        } else {
            detailsHtml = renderBasicScanDetails(scan);
        }
        
        elements.resultDetails.innerHTML = detailsHtml;
        elements.resultModal.classList.remove('hidden');
    } catch (error) {
        console.error('Error loading scan details:', error);
        alert('Failed to load scan details');
    }
}

function renderBasicScanDetails(scan) {
    return `
        <div class="detail-row">
            <span class="detail-label">ID</span>
            <span class="detail-value">${escapeHtml(scan.id)}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Status</span>
            <span class="detail-value ${scan.status === 'Completed' ? 'success' : ''}">${scan.status}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Started</span>
            <span class="detail-value">${formatTime(scan.startTime)}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Completed</span>
            <span class="detail-value">${formatTime(scan.endTime)}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Scanned</span>
            <span class="detail-value">${formatFileSize(scan.scannedBytes || 0)}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Matches</span>
            <span class="detail-value ${scan.matchCount > 0 ? 'danger' : ''}">${scan.matchCount || 0}</span>
        </div>
        ${scan.message ? `
        <div class="detail-row">
            <span class="detail-label">Message</span>
            <span class="detail-value">${escapeHtml(scan.message)}</span>
        </div>
        ` : ''}
        ${renderMatchesList(scan.matches)}
    `;
}

function renderImageScanDetails(scan) {
    const img = scan.imageResult;
    const summary = scan.summary || { critical: 0, high: 0, medium: 0, low: 0, riskScore: 0 };
    const riskClass = getRiskClass(summary.riskScore);
    
    return `
        <div class="image-info">
            <div class="image-info-item">
                <div class="image-info-label">Image</div>
                <div class="image-info-value">${escapeHtml(img.image)}</div>
            </div>
            <div class="image-info-item">
                <div class="image-info-label">Size</div>
                <div class="image-info-value">${formatFileSize(img.size || 0)}</div>
            </div>
            <div class="image-info-item">
                <div class="image-info-label">Layers</div>
                <div class="image-info-value">${(img.layers || []).length}</div>
            </div>
        </div>
        
        <div class="risk-score">
            <div>
                <div class="risk-score-value ${riskClass}">${summary.riskScore}</div>
                <div class="risk-score-label">Risk Score</div>
            </div>
            <div class="risk-score-bar">
                <div class="risk-score-fill ${riskClass}" style="width: ${summary.riskScore}%"></div>
            </div>
        </div>
        
        <div class="vuln-summary">
            <div class="vuln-stat critical">
                <div class="vuln-stat-count">${summary.critical}</div>
                <div class="vuln-stat-label">Critical</div>
            </div>
            <div class="vuln-stat high">
                <div class="vuln-stat-count">${summary.high}</div>
                <div class="vuln-stat-label">High</div>
            </div>
            <div class="vuln-stat medium">
                <div class="vuln-stat-count">${summary.medium}</div>
                <div class="vuln-stat-label">Medium</div>
            </div>
            <div class="vuln-stat low">
                <div class="vuln-stat-count">${summary.low}</div>
                <div class="vuln-stat-label">Low</div>
            </div>
        </div>
        
        ${scan.message ? `
        <div class="detail-row">
            <span class="detail-label">Summary</span>
            <span class="detail-value">${escapeHtml(scan.message)}</span>
        </div>
        ` : ''}
        
        ${renderVulnerabilityList(img.vulnerabilities)}
        ${renderSecretsList(img.secretsFound)}
        ${renderMatchesList(scan.matches)}
    `;
}

function renderVulnerabilityList(vulns) {
    if (!vulns || vulns.length === 0) return '';
    
    return `
        <div class="vuln-list">
            <h4>Vulnerabilities (${vulns.length})</h4>
            ${vulns.slice(0, 20).map(v => `
                <div class="vuln-item">
                    <span class="vuln-severity ${(v.severity || 'medium').toLowerCase()}">${v.severity || 'MEDIUM'}</span>
                    <div class="vuln-info">
                        <h5>${escapeHtml(v.id)}</h5>
                        <p>${escapeHtml(v.description || 'No description')}</p>
                    </div>
                    <span class="vuln-package">${escapeHtml(v.package || '')}</span>
                </div>
            `).join('')}
            ${vulns.length > 20 ? `<p class="text-muted">... and ${vulns.length - 20} more</p>` : ''}
        </div>
    `;
}

function renderSecretsList(secrets) {
    if (!secrets || secrets.length === 0) return '';
    
    return `
        <div class="vuln-list">
            <h4>Exposed Secrets (${secrets.length})</h4>
            ${secrets.slice(0, 10).map(s => `
                <div class="secret-item">
                    <span class="secret-type">${escapeHtml(s.type)}</span>
                    <span class="secret-path">${escapeHtml(s.path)}</span>
                    ${s.partial ? `<span class="secret-partial">${escapeHtml(s.partial)}</span>` : ''}
                </div>
            `).join('')}
            ${secrets.length > 10 ? `<p class="text-muted">... and ${secrets.length - 10} more</p>` : ''}
        </div>
    `;
}

function renderMatchesList(matches) {
    if (!matches || matches.length === 0) return '';
    
    return `
        <div class="matches-list">
            <h4>Matched Rules</h4>
            ${matches.map(match => `
                <div class="match-item">
                    <div class="match-rule">${escapeHtml(match.rule)}</div>
                    ${match.tags && match.tags.length > 0 ? `
                    <div class="rule-card-tags">
                        ${match.tags.map(tag => `<span class="rule-tag">${escapeHtml(tag)}</span>`).join('')}
                    </div>
                    ` : ''}
                    ${match.strings && match.strings.length > 0 ? `
                    <div class="match-strings">
                        ${match.strings.slice(0, 5).map(str => `
                            <div class="match-string-item">
                                <span>${escapeHtml(str.name)}</span>
                                <span>offset: ${str.offset}</span>
                                <span>${str.data ? str.data.slice(0, 32) + '...' : ''}</span>
                            </div>
                        `).join('')}
                        ${match.strings.length > 5 ? `<div class="match-string-item">... and ${match.strings.length - 5} more</div>` : ''}
                    </div>
                    ` : ''}
                </div>
            `).join('')}
        </div>
    `;
}

// Handle Scan
async function handleScan() {
    const button = elements.scanButton;
    const buttonText = button.querySelector('.button-text');
    const buttonIcon = button.querySelector('.button-icon');
    const buttonLoader = button.querySelector('.button-loader');
    
    // Get scan data based on current tab
    let scanData = {};
    
    switch (state.currentTab) {
        case 'image':
            const imageRef = document.getElementById('scanImage').value.trim();
            if (!imageRef) {
                alert('Please enter a container image reference');
                return;
            }
            scanData.image = imageRef;
            break;
            
        case 'text':
            const text = elements.scanText.value.trim();
            if (!text) {
                alert('Please enter text to scan');
                return;
            }
            scanData.text = text;
            break;
            
        case 'file':
            if (!state.selectedFile) {
                alert('Please select a file to scan');
                return;
            }
            const fileData = await readFileAsBase64(state.selectedFile);
            scanData.data = fileData;
            break;
            
        case 'url':
            const url = elements.scanUrl.value.trim();
            if (!url) {
                alert('Please enter a URL to scan');
                return;
            }
            scanData.url = url;
            break;
    }
    
    // Add rules
    const customRule = elements.customRule.value.trim();
    if (customRule) {
        scanData.rules = [customRule];
    }
    
    if (state.selectedRules.size > 0) {
        scanData.ruleNames = Array.from(state.selectedRules);
    }
    
    // If no rules selected, use all available
    if (!scanData.rules && !scanData.ruleNames && state.rules.length > 0) {
        scanData.ruleNames = state.rules.filter(r => r.status === 'Valid').map(r => r.name);
    }
    
    // Update UI
    button.disabled = true;
    buttonText.textContent = 'Scanning...';
    buttonIcon.classList.add('hidden');
    buttonLoader.classList.remove('hidden');
    
    try {
        // Create scan
        const response = await fetch(`${CONFIG.apiUrl}/api/v1/scans`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(scanData),
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'Failed to create scan');
        }
        
        const scan = await response.json();
        
        // Poll for results
        await pollScanResults(scan.id);
        
        // Reload scans
        await loadScans();
        
        // Show success
        buttonText.textContent = 'Scan Complete!';
        setTimeout(() => {
            resetButton();
        }, 2000);
        
    } catch (error) {
        console.error('Scan error:', error);
        alert('Scan failed: ' + error.message);
        resetButton();
    }
    
    function resetButton() {
        button.disabled = false;
        buttonText.textContent = 'Start Scan';
        buttonIcon.classList.remove('hidden');
        buttonLoader.classList.add('hidden');
    }
}

async function readFileAsBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
            const base64 = reader.result.split(',')[1];
            resolve(base64);
        };
        reader.onerror = reject;
        reader.readAsDataURL(file);
    });
}

async function pollScanResults(scanId) {
    let attempts = 0;
    
    while (attempts < CONFIG.maxPollAttempts) {
        await sleep(CONFIG.pollInterval);
        
        try {
            const response = await fetch(`${CONFIG.apiUrl}/api/v1/scans/${scanId}`);
            if (!response.ok) throw new Error('Failed to poll scan');
            
            const scan = await response.json();
            
            if (scan.status === 'Completed' || scan.status === 'Failed') {
                return scan;
            }
        } catch (error) {
            console.error('Poll error:', error);
        }
        
        attempts++;
    }
    
    throw new Error('Scan timed out');
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Handle Create Rule
async function handleCreateRule(e) {
    e.preventDefault();
    
    const name = document.getElementById('ruleName').value.trim();
    const description = document.getElementById('ruleDescription').value.trim();
    const tags = document.getElementById('ruleTags').value.trim().split(',').map(t => t.trim()).filter(Boolean);
    const content = document.getElementById('ruleContent').value.trim();
    
    try {
        const response = await fetch(`${CONFIG.apiUrl}/api/v1/rules`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                name,
                description,
                tags,
                content,
            }),
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'Failed to create rule');
        }
        
        // Close modal and reload rules
        elements.addRuleModal.classList.add('hidden');
        elements.addRuleForm.reset();
        await loadRules();
        
    } catch (error) {
        console.error('Create rule error:', error);
        alert('Failed to create rule: ' + error.message);
    }
}

// Utility Functions
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Expose config update function
window.updateApiUrl = function() {
    showApiConfigPrompt();
};

