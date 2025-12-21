const API_BASE = "http://127.0.0.1:8000";

// --- TAB SWITCHING LOGIC (NEW) ---
function switchTab(tabName) {
    // 1. Hide all contents
    document.querySelectorAll('[id^="tab-"]').forEach(el => {
        el.classList.add('hidden');
        el.classList.remove('animate-fade-in'); // Reset animation
    });

    // 2. Reset all button styles
    document.querySelectorAll('[id^="btn-"]').forEach(btn => {
        btn.classList.remove('tab-active');
        btn.classList.add('tab-inactive');
    });

    // 3. Show selected content
    const target = document.getElementById(`tab-${tabName}`);
    if (target) {
        target.classList.remove('hidden');
        setTimeout(() => target.classList.add('animate-fade-in'), 10);
    }

    // 4. Activate selected button
    const btn = document.getElementById(`btn-${tabName}`);
    if (btn) {
        btn.classList.add('tab-active');
        btn.classList.remove('tab-inactive');
    }
}

// Default variables from previous code
let currentSBox = null;
let currentAffineMatrix = null;
let standardSBox = null;
let sbox44 = null;
let standardFormat = 'hex'; // 'hex' or 'dec'
let sbox44Format = 'hex'; // 'hex' or 'dec'

// Variables untuk image encryption
let currentEncryptedImageBase64 = null;
let currentImageMetrics = null;
let histogramChart = null;
let histogramChartOriginal = null;  // For original image histogram
let histogramChartEncrypted = null;  // For encrypted image histogram


function parseSBox(text) {
  const raw = text
    .split(/[\s,]+/)
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
  if (raw.length === 0) {
    throw new Error("S-Box tidak boleh kosong.");
  }
  const nums = raw.map((v) => {
    const n = parseInt(v, 10);
    if (Number.isNaN(n)) {
      throw new Error("S-Box mengandung nilai non-angka.");
    }
    if (n < 0 || n > 255) {
      throw new Error("S-Box hanya boleh berisi angka 0..255.");
    }
    return n;
  });
  if (nums.length < 256) {
    throw new Error("S-Box harus berisi minimal 256 angka.");
  }
  return nums;
}

function toggleSBox(selectEl, wrapperEl) {
  if (selectEl.value === "custom") {
    wrapperEl.classList.remove("hidden");
  } else {
    wrapperEl.classList.add("hidden");
  }
}

function showError(el, message) {
  el.textContent = message;
  el.classList.remove("hidden");
}

function clearError(el) {
  el.textContent = "";
  el.classList.add("hidden");
}

async function handleEncryptText() {
  clearError(errorMsg);
  ciphertextOutput.value = "";
  infoMsg.textContent = "";

  const mode = modeSelect.value;
  const keyHex = keyInput.value.trim();
  const plaintext = plaintextInput.value;

  if (!keyHex) {
    showError(errorMsg, "Key wajib diisi (boleh teks bebas atau hex).");
    return;
  }
  if (!plaintext) {
    showError(errorMsg, "Plaintext wajib diisi.");
    return;
  }

  let sbox = null;
  if (mode === "custom") {
    try {
      sbox = parseSBox(sboxInput.value);
    } catch (e) {
      showError(errorMsg, e.message);
      return;
    }
  }

  const payload = {
    mode,
    key_hex: keyHex,
    plaintext,
    plaintext_hex: null,
    sbox,
  };

  try {
    const res = await fetch(`${API_BASE}/encrypt`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || "Terjadi error saat enkripsi.");
    }
    const data = await res.json();
    ciphertextOutput.value = data.ciphertext_hex || "";
    infoMsg.textContent = `Mode: ${data.used_mode}, panjang plaintext (byte): ${data.plaintext_len}`;
  } catch (err) {
    showError(errorMsg, err.message);
  }
}

async function handleDecryptText() {
  clearError(decErrorMsg);
  plaintextOutput.value = "";
  decInfoMsg.textContent = "";

  const mode = decModeSelect.value;
  const keyHex = decKeyInput.value.trim();
  const ciphertextHex = ciphertextInput.value.trim();

  if (!keyHex) {
    showError(decErrorMsg, "Key wajib diisi (boleh teks bebas atau hex).");
    return;
  }
  if (!ciphertextHex) {
    showError(decErrorMsg, "Ciphertext hex wajib diisi.");
    return;
  }

  let sbox = null;
  if (mode === "custom") {
    try {
      sbox = parseSBox(decSboxInput.value);
    } catch (e) {
      showError(decErrorMsg, e.message);
      return;
    }
  }

  const payload = {
    mode,
    key_hex: keyHex,
    ciphertext_hex: ciphertextHex,
    sbox,
  };

  try {
    const res = await fetch(`${API_BASE}/decrypt`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || "Terjadi error saat dekripsi.");
    }
    const data = await res.json();
    plaintextOutput.value = data.plaintext || "";
    decInfoMsg.textContent = `Mode: ${data.used_mode}, plaintext (hex): ${data.plaintext_hex}`;
  } catch (err) {
    showError(decErrorMsg, err.message);
  }
}

function renderMetrics(metrics) {
  const entries = [
    ["Nonlinearity (min)", metrics.nl_min],
    ["SAC (avg)", metrics.sac_avg.toFixed(5)],
    ["BIC-NL (min)", metrics.bic_nl_min],
    ["BIC-SAC (deviasi rata-rata)", metrics.bic_sac_score.toFixed(5)],
    ["LAP max bias", metrics.lap_max_bias.toFixed(5)],
    ["DU", metrics.du],
    ["DAP max", metrics.dap_max.toFixed(6)],
    ["Algebraic Degree (min)", metrics.ad_min],
    ["Correlation Immunity (min)", metrics.ci_min],
    ["Transparency Order (TO)", metrics.to_value],
  ];

  metricsResult.innerHTML = '<div class="grid grid-cols-1 md:grid-cols-2 gap-2">';
  entries.forEach(([label, value]) => {
    const div = document.createElement("div");
    div.className = "flex justify-between items-center bg-slate-800 p-2 rounded-lg hover:bg-slate-700 transition";
    div.innerHTML = `<span class="text-slate-300 text-sm">${label}</span><span class="font-mono text-emerald-400 font-semibold">${value}</span>`;
    metricsResult.appendChild(div);
  });
  metricsResult.innerHTML += '</div>';
}

function renderSboxTable(sbox) {
  if (!sboxDisplay) return;
  sboxDisplay.innerHTML = "";
  if (!Array.isArray(sbox) || sbox.length !== 256) {
    sboxDisplay.innerHTML = '<p class="text-xs text-slate-500">S-Box belum tersedia</p>';
    return;
  }
  let html = '<div class="overflow-auto max-h-[500px] border border-slate-600 rounded-lg"><table class="w-full text-[12px] font-mono border-collapse bg-slate-900">';
  for (let i = 0; i < 16; i++) {
    html += '<tr>';
    for (let j = 0; j < 16; j++) {
      const v = sbox[i * 16 + j];
      html += `<td class="px-3 py-2 text-center border border-slate-700 hover:bg-slate-700 transition-all duration-200 hover:text-emerald-300">${v.toString(16).padStart(2, '0')}</td>`;
    }
    html += '</tr>';
  }
  html += '</table></div>';
  sboxDisplay.innerHTML = html;
}

function renderSboxTableLarge(sbox, elementId, format = 'hex') {
  const display = document.getElementById(elementId);
  if (!display) return;
  display.innerHTML = "";
  if (!Array.isArray(sbox) || sbox.length !== 256) {
    display.innerHTML = '<p class="text-xs text-slate-500">S-Box belum tersedia</p>';
    return;
  }
  let html = '<table class="w-full text-[10px] font-mono border-collapse bg-slate-900 animate-fade-in">';
  for (let i = 0; i < 16; i++) {
    html += '<tr>';
    for (let j = 0; j < 16; j++) {
      const v = sbox[i * 16 + j];
      const displayValue = format === 'hex' ? v.toString(16).padStart(2, '0') : v.toString();
      const isHighlighted = (i + j) % 2 === 0; // Checkerboard pattern
      const cellClass = isHighlighted 
        ? 'bg-slate-800 hover:bg-blue-900/50' 
        : 'bg-slate-900 hover:bg-slate-700';
      html += `<td class="px-2 py-1 text-center border border-slate-700 transition-all duration-200 hover:scale-110 hover:z-10 relative ${cellClass} ${elementId.includes('standard') ? 'hover:text-blue-300' : 'hover:text-emerald-300'}" style="animation-delay: ${(i * 16 + j) * 5}ms">${displayValue}</td>`;
    }
    html += '</tr>';
  }
  html += '</table>';
  display.innerHTML = html;
}

function renderMetricsComparison(metrics, elementId) {
  const display = document.getElementById(elementId);
  if (!display) return;
  display.innerHTML = `
    <div class="space-y-1">
      <div class="flex justify-between"><span>NL:</span><span>${metrics.nl_min}</span></div>
      <div class="flex justify-between"><span>SAC:</span><span>${metrics.sac_avg.toFixed(5)}</span></div>
      <div class="flex justify-between"><span>BIC-NL:</span><span>${metrics.bic_nl_min}</span></div>
      <div class="flex justify-between"><span>BIC-SAC:</span><span>${metrics.bic_sac_score.toFixed(5)}</span></div>
      <div class="flex justify-between"><span>LAP:</span><span>${metrics.lap_max_bias.toFixed(5)}</span></div>
      <div class="flex justify-between"><span>DAP:</span><span>${metrics.dap_max.toFixed(5)}</span></div>
    </div>
  `;
}

function updateComparison() {
  const body = document.getElementById('comparison_body');
  if (!standardSBox || !sbox44) {
    body.innerHTML = '<tr><td colspan="4" class="px-3 py-4 text-center text-slate-500">Load kedua S-Box untuk melihat perbandingan</td></tr>';
    return;
  }

  // Get metrics for both
  Promise.all([
    fetch(`${API_BASE}/sbox/metrics`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sbox: standardSBox })
    }),
    fetch(`${API_BASE}/sbox/metrics`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sbox: sbox44 })
    })
  ]).then(async ([res1, res2]) => {
    const metrics1 = await res1.json();
    const metrics2 = await res2.json();

    const metrics = [
      { name: 'NL', key: 'nl_min', unit: '' },
      { name: 'SAC', key: 'sac_avg', unit: '', decimals: 5 },
      { name: 'BIC-NL', key: 'bic_nl_min', unit: '' },
      { name: 'BIC-SAC', key: 'bic_sac_score', unit: '', decimals: 5 },
      { name: 'LAP', key: 'lap_max_bias', unit: '', decimals: 5 },
      { name: 'DAP', key: 'dap_max', unit: '', decimals: 5 }
    ];

    let html = '';
    metrics.forEach((metric, index) => {
      const val1 = metrics1[metric.key];
      const val2 = metrics2[metric.key];
      const diff = val2 - val1;
      const diffStr = diff > 0 ? `+${diff.toFixed(metric.decimals || 0)}` : diff.toFixed(metric.decimals || 0);
      const diffClass = diff > 0 ? 'text-green-400 font-bold' : diff < 0 ? 'text-red-400 font-bold' : 'text-slate-400';
      const rowClass = diff > 0 ? 'bg-emerald-900/20 border-emerald-600/30' : diff < 0 ? 'bg-red-900/20 border-red-600/30' : '';

      html += `
        <tr class="hover:bg-slate-800 transition-all duration-300 animate-fade-in border border-slate-700 ${rowClass}" style="animation-delay: ${index * 100}ms">
          <td class="px-3 py-3 border-r border-slate-600 text-slate-300 font-medium">${metric.name}</td>
          <td class="px-3 py-3 border-r border-slate-600 text-center text-blue-400 font-mono">${val1.toFixed(metric.decimals || 0)}${metric.unit}</td>
          <td class="px-3 py-3 border-r border-slate-600 text-center text-emerald-400 font-mono">${val2.toFixed(metric.decimals || 0)}${metric.unit}</td>
          <td class="px-3 py-3 text-center ${diffClass} font-mono text-lg">${diffStr}${metric.unit}</td>
        </tr>
      `;
    });

    body.innerHTML = html;
  }).catch(err => {
    console.error('Error updating comparison:', err);
  });
}

function updateSboxDecimalText(sbox) {
  if (!sboxDecimalText) return;
  if (!Array.isArray(sbox) || sbox.length !== 256) {
    sboxDecimalText.value = "";
    return;
  }
  sboxDecimalText.value = sbox.join(", ");
}

function renderAffineMatrix(mat) {
  if (!affineMatrixDisplay) return;
  if (!Array.isArray(mat) || mat.length !== 8) {
    affineMatrixDisplay.innerHTML = "";
    return;
  }
  let html = '<div class="overflow-auto max-h-40 border border-slate-600 rounded-lg"><table class="w-full text-[10px] font-mono border-collapse bg-slate-900">';
  for (let i = 0; i < 8; i++) {
    html += "<tr>";
    const row = mat[i] || [];
    for (let j = 0; j < 8; j++) {
      const v = row[j] ?? 0;
      html += `<td class="px-2 py-1 text-center border border-slate-700 hover:bg-slate-700 transition">${v}</td>`;
    }
    html += "</tr>";
  }
  html += "</table></div>";
  affineMatrixDisplay.innerHTML = html;
}

function updateAffineText(mat) {
  if (!affineMatrixText) return;
  if (!Array.isArray(mat) || mat.length !== 8) {
    affineMatrixText.value = "";
    return;
  }
  affineMatrixText.value = mat.map((row) => (row || []).join(", ")).join("\n");
}

function setCurrentSBox(sbox) {
  currentSBox = sbox;
  if (Array.isArray(sbox) && sbox.length === 256) {
    renderSboxTable(sbox);
    updateSboxDecimalText(sbox);
  }
}

async function handleLoadSbox44() {
  clearError(metricsErrorMsg);
  metricsResult.innerHTML = '<p class="text-slate-500 text-xs">Memproses...</p>';
  try {
    const res = await fetch(`${API_BASE}/sbox/paper44`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Gagal load S-box 44.");
    }
    const data = await res.json();
    setCurrentSBox(data.sbox);
    currentAffineMatrix = data.affine_matrix || null;
    renderMetrics(data.metrics);
    renderAffineMatrix(currentAffineMatrix);
    updateAffineText(currentAffineMatrix);
    
    // Show paper info
    metricsResult.innerHTML += `
      <div class="mt-3 p-3 bg-emerald-900 rounded-lg border border-emerald-600">
        <p class="text-xs font-semibold text-emerald-200 mb-1">📄 ${data.paper_info.title}</p>
        <p class="text-[10px] text-emerald-300">${data.paper_info.authors} (${data.paper_info.year})</p>
        <p class="text-[10px] text-emerald-100 mt-1">${data.paper_info.description}</p>
      </div>
    `;
  } catch (e) {
    showError(metricsErrorMsg, e.message);
    metricsResult.innerHTML = '<p class="text-slate-500 text-xs">Hasil metric akan muncul di sini.</p>';
  }
}

async function handleLoadSbox44Comparison() {
  try {
    const res = await fetch(`${API_BASE}/sbox/paper44`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Gagal load S-box 44.");
    }
    const data = await res.json();
    sbox44 = data.sbox;
    renderSboxTableLarge(sbox44, 'sbox44_display', sbox44Format);
    renderMetricsComparison(data.metrics, 'sbox44_metrics');
    updateComparison();
  } catch (e) {
    console.error(e.message);
    document.getElementById('sbox44_display').innerHTML = '<p class="text-xs text-red-400">Error loading S-Box 44</p>';
  }
}

async function handleGenerateComparison() {
  // Show loading state with animation
  const btn = document.getElementById('generate_comparison_btn');
  btn.disabled = true;
  btn.innerHTML = `
    <div class="flex items-center space-x-3">
      <div class="animate-spin rounded-full h-6 w-6 border-2 border-blue-400 border-t-transparent"></div>
      <span>Loading Comparison...</span>
      <div class="animate-pulse">⚡</div>
    </div>
  `;
  btn.classList.add('bg-slate-700', 'cursor-not-allowed');
  btn.classList.remove('hover:scale-105', 'hover:shadow-blue-500/50', 'hover:border-blue-400');
  
  document.getElementById('standard_sbox_display').innerHTML = '<div class="flex items-center justify-center py-8"><div class="animate-spin rounded-full h-8 w-8 border-2 border-blue-400 border-t-transparent"></div><span class="ml-3 text-blue-400">Loading Standard S-Box...</span></div>';
  document.getElementById('sbox44_display').innerHTML = '<div class="flex items-center justify-center py-8"><div class="animate-spin rounded-full h-8 w-8 border-2 border-emerald-400 border-t-transparent"></div><span class="ml-3 text-emerald-400">Loading S-Box 44...</span></div>';
  document.getElementById('standard_metrics').innerHTML = '<div class="flex items-center justify-center py-4"><div class="animate-pulse text-blue-400">📊 Calculating metrics...</div></div>';
  document.getElementById('sbox44_metrics').innerHTML = '<div class="flex items-center justify-center py-4"><div class="animate-pulse text-emerald-400">📈 Analyzing performance...</div></div>';
  document.getElementById('comparison_body').innerHTML = '<tr><td colspan="4" class="px-3 py-8 text-center"><div class="flex items-center justify-center"><div class="animate-bounce">🔄</div><span class="ml-3 text-slate-400">Generating comparison table...</span></div></td></tr>';

  try {
    // Load both S-Boxes in parallel
    const [standardRes, sbox44Res] = await Promise.all([
      fetch(`${API_BASE}/sbox/standard`),
      fetch(`${API_BASE}/sbox/paper44`)
    ]);

    if (!standardRes.ok) {
      throw new Error("Failed to load standard S-Box");
    }
    if (!sbox44Res.ok) {
      throw new Error("Failed to load S-Box 44");
    }

    const [standardData, sbox44Data] = await Promise.all([
      standardRes.json(),
      sbox44Res.json()
    ]);

    // Set the data
    standardSBox = standardData.sbox;
    sbox44 = sbox44Data.sbox;

    // Render everything with smooth transitions
    setTimeout(() => {
      renderSboxTableLarge(standardSBox, 'standard_sbox_display', standardFormat);
      renderSboxTableLarge(sbox44, 'sbox44_display', sbox44Format);
      renderMetricsComparison(standardData.metrics, 'standard_metrics');
      renderMetricsComparison(sbox44Data.metrics, 'sbox44_metrics');
      updateComparison();
    }, 500); // Small delay for smooth transition

  } catch (e) {
    console.error(e.message);
    const errorMsg = '<div class="flex items-center justify-center py-8"><div class="text-red-400">❌ Error loading comparison</div></div>';
    document.getElementById('standard_sbox_display').innerHTML = errorMsg;
    document.getElementById('sbox44_display').innerHTML = errorMsg;
    document.getElementById('standard_metrics').innerHTML = '<div class="text-red-400 text-center py-4">Failed to load metrics</div>';
    document.getElementById('sbox44_metrics').innerHTML = '<div class="text-red-400 text-center py-4">Failed to load metrics</div>';
    document.getElementById('comparison_body').innerHTML = '<tr><td colspan="4" class="px-3 py-8 text-center text-red-400"><div>❌ Error generating comparison table</div></td></tr>';
  } finally {
    // Reset button with success animation
    setTimeout(() => {
      btn.disabled = false;
      btn.innerHTML = `
        <div class="flex items-center space-x-3">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
          </svg>
          <span>Comparison Generated!</span>
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
          </svg>
        </div>
      `;
      btn.classList.remove('bg-slate-700', 'cursor-not-allowed');
      btn.classList.add('bg-green-600', 'hover:bg-green-700');
      
      // Reset to normal state after 2 seconds
      setTimeout(() => {
        btn.innerHTML = `
          <div class="flex items-center space-x-3">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path>
            </svg>
            <span>Generate Comparison</span>
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
            </svg>
          </div>
        `;
        btn.classList.remove('bg-green-600', 'hover:bg-green-700');
        btn.classList.add('hover:scale-105', 'hover:shadow-blue-500/50', 'hover:border-blue-400');
      }, 2000);
    }, 1000);
  }
}

async function handleGenerateSbox() {
  clearError(metricsErrorMsg);
  metricsResult.innerHTML = '<p class="text-slate-500 text-xs">Memproses...</p>';
  try {
    const res = await fetch(`${API_BASE}/sbox/generate`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Gagal generate S-Box.");
    }
    const data = await res.json();
    setCurrentSBox(data.sbox);
    currentAffineMatrix = data.affine_matrix || null;
    renderMetrics(data.metrics);
    renderAffineMatrix(currentAffineMatrix);
    updateAffineText(currentAffineMatrix);
  } catch (e) {
    showError(metricsErrorMsg, e.message);
    metricsResult.innerHTML = '<p class="text-slate-500 text-xs">Hasil metric akan muncul di sini.</p>';
  }
}

async function handleUploadSbox(file) {
  if (!file) return;
  clearError(metricsErrorMsg);
  metricsResult.innerHTML = '<p class="text-slate-500 text-xs">Memproses...</p>';
  const fileName = file.name.toLowerCase();
  let sbox = null;

  try {
    if (fileName.endsWith('.json')) {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch(`${API_BASE}/sbox/upload`, {
        method: "POST",
        body: form,
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Gagal upload S-Box.");
      }
      const data = await res.json();
      setCurrentSBox(data.sbox);
      renderMetrics(data.metrics);
      currentAffineMatrix = null;
      renderAffineMatrix(null);
      updateAffineText(null);
    } else if (fileName.endsWith('.xlsx') || fileName.endsWith('.xls')) {
      const arrayBuffer = await file.arrayBuffer();
      const workbook = XLSX.read(arrayBuffer, { type: 'array' });
      const sheetName = workbook.SheetNames[0];
      const worksheet = workbook.Sheets[sheetName];
      const jsonData = XLSX.utils.sheet_to_json(worksheet, { header: 1 });

      let values = jsonData.flat().filter(v => v !== undefined && v !== null && !isNaN(parseInt(v, 10)));

      if (values.length < 256) {
        throw new Error("Excel harus berisi minimal 256 nilai S-Box.");
      }

      sbox = values.slice(0, 256).map(v => {
        const n = parseInt(v, 10);
        if (isNaN(n) || n < 0 || n > 255) {
          throw new Error("Nilai S-Box harus angka 0-255.");
        }
        return n;
      });

      const res = await fetch(`${API_BASE}/sbox/upload_json`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sbox }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Gagal upload S-Box dari Excel.");
      }
      const data = await res.json();
      setCurrentSBox(data.sbox);
      renderMetrics(data.metrics);
      currentAffineMatrix = null;
      renderAffineMatrix(null);
      updateAffineText(null);
    } else {
      throw new Error("Format file tidak didukung. Gunakan .json, .xlsx, atau .xls");
    }
  } catch (e) {
    showError(metricsErrorMsg, e.message);
    metricsResult.innerHTML = '<p class="text-slate-500 text-xs">Hasil metric akan muncul di sini.</p>';
  } finally {
    if (uploadSboxFile) uploadSboxFile.value = "";
  }
}

function handleDownloadJson() {
  if (!Array.isArray(currentSBox) || currentSBox.length !== 256) {
    showError(metricsErrorMsg, "Belum ada S-Box untuk di-download.");
    return;
  }
  clearError(metricsErrorMsg);
  const blob = new Blob([JSON.stringify({ sbox: currentSBox }, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "sbox.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function handleCopySbox() {
  if (!Array.isArray(currentSBox) || currentSBox.length !== 256) {
    showError(metricsErrorMsg, "Belum ada S-Box untuk disalin.");
    return;
  }
  const textToCopy = currentSBox.join(", ");
  navigator.clipboard.writeText(textToCopy).then(() => {
    const originalHTML = copySboxBtn.innerHTML;
    copySboxBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" fill="currentColor"/></svg>';
    copySboxBtn.classList.add("bg-green-600");
    setTimeout(() => {
        copySboxBtn.innerHTML = originalHTML;
        copySboxBtn.classList.remove("bg-green-600");
    }, 1500);
  }).catch(err => {
    showError(metricsErrorMsg, "Gagal menyalin ke clipboard.");
  });
}

function handleDownloadExcel() {
  if (!Array.isArray(currentSBox) || currentSBox.length !== 256) {
    showError(metricsErrorMsg, "Belum ada S-Box untuk di-download.");
    return;
  }
  clearError(metricsErrorMsg);

  const rows = [];
  for (let i = 0; i < 16; i++) {
    const rowData = currentSBox.slice(i * 16, (i + 1) * 16);
    rows.push(rowData);
  }

  const ws = XLSX.utils.aoa_to_sheet(rows);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, "S-Box");
  XLSX.writeFile(wb, "sbox_matrix.xlsx");
}

function updateFormatButtons(sboxType) {
  const hexBtn = document.getElementById(`${sboxType}_format_hex`);
  const decBtn = document.getElementById(`${sboxType}_format_dec`);
  const label = document.getElementById(`${sboxType}_format_label`);
  
  if (sboxType === 'standard') {
    if (standardFormat === 'hex') {
      hexBtn.classList.add('bg-blue-600', 'text-white');
      hexBtn.classList.remove('text-slate-300');
      decBtn.classList.remove('bg-blue-600', 'text-white');
      decBtn.classList.add('text-slate-300');
      if (label) label.textContent = 'hex';
    } else {
      decBtn.classList.add('bg-blue-600', 'text-white');
      decBtn.classList.remove('text-slate-300');
      hexBtn.classList.remove('bg-blue-600', 'text-white');
      hexBtn.classList.add('text-slate-300');
      if (label) label.textContent = 'decimal';
    }
  } else if (sboxType === 'sbox44') {
    if (sbox44Format === 'hex') {
      hexBtn.classList.add('bg-emerald-600', 'text-white');
      hexBtn.classList.remove('text-slate-300');
      decBtn.classList.remove('bg-emerald-600', 'text-white');
      decBtn.classList.add('text-slate-300');
      if (label) label.textContent = 'hex';
    } else {
      decBtn.classList.add('bg-emerald-600', 'text-white');
      decBtn.classList.remove('text-slate-300');
      hexBtn.classList.remove('bg-emerald-600', 'text-white');
      hexBtn.classList.add('text-slate-300');
      if (label) label.textContent = 'decimal';
    }
  }
}

document.addEventListener("DOMContentLoaded", () => {
  // Encrypt text
  modeSelect.addEventListener("change", () => toggleSBox(modeSelect, sboxWrapper));
  encryptBtn.addEventListener("click", handleEncryptText);
  toggleSBox(modeSelect, sboxWrapper);

  // Decrypt text
  decModeSelect.addEventListener("change", () => toggleSBox(decModeSelect, decSboxWrapper));
  decryptBtn.addEventListener("click", handleDecryptText);
  toggleSBox(decModeSelect, decSboxWrapper);

  // S-Box lab
  if (loadSbox44Btn) loadSbox44Btn.addEventListener("click", handleLoadSbox44);
  if (generateComparisonBtn) generateComparisonBtn.addEventListener("click", handleGenerateComparison);
  if (generateSboxBtn) generateSboxBtn.addEventListener("click", handleGenerateSbox);
  if (copySboxBtn) copySboxBtn.addEventListener("click", handleCopySbox);
  if (downloadJsonBtn) downloadJsonBtn.addEventListener("click", handleDownloadJson);
  if (downloadExcelBtn) downloadExcelBtn.addEventListener("click", handleDownloadExcel);
  if (uploadSboxFile) uploadSboxFile.addEventListener("change", (e) => handleUploadSbox(e.target.files[0]));

  // Format toggle buttons for comparison lab
  const standardFormatHex = document.getElementById('standard_format_hex');
  const standardFormatDec = document.getElementById('standard_format_dec');
  const sbox44FormatHex = document.getElementById('sbox44_format_hex');
  const sbox44FormatDec = document.getElementById('sbox44_format_dec');

  if (standardFormatHex) {
    standardFormatHex.addEventListener('click', () => {
      standardFormat = 'hex';
      updateFormatButtons('standard');
      if (standardSBox) renderSboxTableLarge(standardSBox, 'standard_sbox_display', standardFormat);
    });
  }
  if (standardFormatDec) {
    standardFormatDec.addEventListener('click', () => {
      standardFormat = 'dec';
      updateFormatButtons('standard');
      if (standardSBox) renderSboxTableLarge(standardSBox, 'standard_sbox_display', standardFormat);
    });
  }
  if (sbox44FormatHex) {
    sbox44FormatHex.addEventListener('click', () => {
      sbox44Format = 'hex';
      updateFormatButtons('sbox44');
      if (sbox44) renderSboxTableLarge(sbox44, 'sbox44_display', sbox44Format);
    });
  }
  if (sbox44FormatDec) {
    sbox44FormatDec.addEventListener('click', () => {
      sbox44Format = 'dec';
      updateFormatButtons('sbox44');
      if (sbox44) renderSboxTableLarge(sbox44, 'sbox44_display', sbox44Format);
    });
  }

  // init table state
  renderSboxTable(currentSBox);
  renderAffineMatrix(currentAffineMatrix);
  updateAffineText(currentAffineMatrix);
  updateSboxDecimalText(currentSBox);

  // Initialize format buttons
  updateFormatButtons('standard');
  updateFormatButtons('sbox44');
  
  // Initialize Default Tab
  switchTab('dashboard');
});

// DOM refs
const modeSelect = document.getElementById("mode");
const sboxWrapper = document.getElementById("sbox-wrapper");
const keyInput = document.getElementById("key_hex");
const plaintextInput = document.getElementById("plaintext");
const sboxInput = document.getElementById("sbox_input");
const encryptBtn = document.getElementById("encrypt_btn");
const ciphertextOutput = document.getElementById("ciphertext_output");
const infoMsg = document.getElementById("info_msg");
const errorMsg = document.getElementById("error_msg");

const decModeSelect = document.getElementById("dec_mode");
const decSboxWrapper = document.getElementById("dec-sbox-wrapper");
const decKeyInput = document.getElementById("dec_key_hex");
const ciphertextInput = document.getElementById("ciphertext_input");
const decSboxInput = document.getElementById("dec_sbox_input");
const decryptBtn = document.getElementById("decrypt_btn");
const plaintextOutput = document.getElementById("plaintext_output");
const decInfoMsg = document.getElementById("dec_info_msg");
const decErrorMsg = document.getElementById("dec_error_msg");

const metricsResult = document.getElementById("metrics_result");
const metricsErrorMsg = document.getElementById("metrics_error_msg");
const loadSbox44Btn = document.getElementById("load_sbox44_random_btn");
const generateComparisonBtn = document.getElementById("generate_comparison_btn");
const generateSboxBtn = document.getElementById("generate_sbox_btn");
const copySboxBtn = document.getElementById("copy_sbox_btn");
const downloadJsonBtn = document.getElementById("download_json_btn");
const downloadExcelBtn = document.getElementById("download_excel_btn");
const uploadSboxFile = document.getElementById("upload_sbox_file");
const sboxDisplay = document.getElementById("sbox_display");
const affineMatrixDisplay = document.getElementById("affine_matrix_display");
const affineMatrixText = document.getElementById("affine_matrix_text");
const sboxDecimalText = document.getElementById("sbox_decimal_text");

function toggleImageSBox(selectEl, wrapperEl) {
    if (selectEl.value === "custom") {
        wrapperEl.classList.remove("hidden");
    } else {
        wrapperEl.classList.add("hidden");
    }
}

async function handleImageEncrypt() {
    const imgErrorMsg = document.getElementById('img_error_msg');
    clearError(imgErrorMsg);
    
    const mode = document.getElementById('img_mode').value;
    const keyHex = document.getElementById('img_key_hex').value.trim();
    const fileInput = document.getElementById('img_upload');
    const sboxInput = document.getElementById('img_sbox_input');
    const encryptBtn = document.getElementById('img_encrypt_btn');
    
    if (!keyHex) {
        showError(imgErrorMsg, "Key wajib diisi");
        return;
    }
    
    if (!fileInput.files || fileInput.files.length === 0) {
        showError(imgErrorMsg, "Pilih gambar terlebih dahulu");
        return;
    }
    
    const file = fileInput.files[0];
    if (file.size > 5 * 1024 * 1024) { // 5MB limit
        showError(imgErrorMsg, "Ukuran gambar maksimal 5MB");
        return;
    }
    
    // Show loading state
    encryptBtn.disabled = true;
    const originalBtnHTML = encryptBtn.innerHTML;
    encryptBtn.innerHTML = `
        <div class="flex items-center justify-center space-x-3">
            <div class="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent"></div>
            <span>Processing...</span>
        </div>
    `;
    
    let sboxJson = null;
    if (mode === "custom") {
        try {
            const sbox = parseSBox(sboxInput.value);
            sboxJson = JSON.stringify(sbox);
        } catch (e) {
            showError(imgErrorMsg, e.message);
            encryptBtn.disabled = false;
            encryptBtn.innerHTML = originalBtnHTML;
            return;
        }
    }
    
    const formData = new FormData();
    formData.append('mode', mode);
    formData.append('key_hex', keyHex);
    formData.append('file', file);
    if (sboxJson) {
        formData.append('sbox_json', sboxJson);
    }
    
    try {
        const res = await fetch(`${API_BASE}/image/encrypt`, {
            method: 'POST',
            body: formData,
        });
        
        console.log('Response status:', res.status);
        console.log('Response ok:', res.ok);
        
        if (!res.ok) {
            const errText = await res.text();
            console.error('Error response:', errText);
            let err;
            try {
                err = JSON.parse(errText);
            } catch (e) {
                err = { detail: errText };
            }
            throw new Error(err.detail || `HTTP ${res.status}: ${errText}`);
        }
        
        const data = await res.json();
        console.log('Success response:', data);
        currentEncryptedImageBase64 = data.encrypted_image_base64;
        currentImageMetrics = data;
        
        // Show results
        document.getElementById('img_results').classList.remove('hidden');
        
        // Display original image
        const originalImg = document.getElementById('original_img');
        originalImg.src = URL.createObjectURL(file);
        
        // Display encrypted image as base64
        const encryptedImg = document.getElementById('encrypted_img');
        if (encryptedImg) {
            encryptedImg.src = `data:image/png;base64,${data.encrypted_image_base64}`;
        }
        
        // Display metrics - ORIGINAL AND ENCRYPTED SEPARATELY
        // Original metrics
        document.getElementById('img_entropy_original').textContent = data.original_entropy.toFixed(4);
        
        // Encrypted metrics  
        document.getElementById('img_entropy_encrypted').textContent = data.encrypted_entropy.toFixed(4);
        document.getElementById('img_npr').textContent = data.npr.toFixed(4);
        document.getElementById('img_uaci').textContent = data.uaci.toFixed(4);
        document.getElementById('img_npcr').textContent = data.npcr.toFixed(4);
        
        // Render histograms - TERPISAH (ORIGINAL DAN ENCRYPTED)
        renderHistogramOriginal(data.original_histogram);
        renderHistogramEncrypted(data.encrypted_histogram);
        
    } catch (err) {
        console.error('Full error object:', err);
        console.error('Error message:', err.message);
        console.error('Error stack:', err.stack);
        showError(imgErrorMsg, err.message);
    } finally {
        // Reset button
        encryptBtn.disabled = false;
        encryptBtn.innerHTML = originalBtnHTML;
    }
}

async function handleImageDecrypt() {
    const decImgErrorMsg = document.getElementById('dec_img_error_msg');
    clearError(decImgErrorMsg);
  const decryptBtn = document.getElementById('img_decrypt_btn');
  const decResults = document.getElementById('dec_img_results');
  if (decResults) decResults.classList.add('hidden');
    
    const mode = document.getElementById('dec_img_mode').value;
    const keyHex = document.getElementById('dec_img_key_hex').value.trim();
    const fileInput = document.getElementById('dec_img_upload');
    
    if (!keyHex) {
        showError(decImgErrorMsg, "Key wajib diisi");
        return;
    }
    
    if (!fileInput.files || fileInput.files.length === 0) {
        showError(decImgErrorMsg, "Upload gambar encrypted (PNG/JPG)");
        return;
    }
    
    const file = fileInput.files[0];
    if (file.size > 10 * 1024 * 1024) { // 10MB limit
        showError(decImgErrorMsg, "Ukuran gambar maksimal 10MB");
        return;
    }
    
    let sboxJson = null;
    if (mode === "custom") {
        try {
            const sboxInput = document.getElementById('dec_img_sbox_input');
            const sbox = parseSBox(sboxInput.value);
            sboxJson = JSON.stringify(sbox);
        } catch (e) {
            showError(decImgErrorMsg, e.message);
            return;
        }
    }
    
    const formData = new FormData();
    formData.append('mode', mode);
    formData.append('key_hex', keyHex);
    formData.append('file', file);
    if (sboxJson) {
        formData.append('sbox_json', sboxJson);
    }
    
    const originalBtnHTML = decryptBtn ? decryptBtn.innerHTML : '';
    if (decryptBtn) {
      decryptBtn.disabled = true;
      decryptBtn.innerHTML = `
      <div class="flex items-center justify-center space-x-3">
        <div class="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent"></div>
        <span>Processing...</span>
      </div>`;
    }

    try {
        const res = await fetch(`${API_BASE}/image/decrypt`, {
            method: 'POST',
            body: formData,
        });
        
        console.log('Decrypt response status:', res.status);
        
        if (!res.ok) {
            const errText = await res.text();
            console.error('Decrypt error:', errText);
            let err;
            try {
                err = JSON.parse(errText);
            } catch (e) {
                err = { detail: errText };
            }
            throw new Error(err.detail || `HTTP ${res.status}`);
        }
        
        const data = await res.json();
        
        // Show results
        if (decResults) decResults.classList.remove('hidden');
        
        // Display encrypted image (input)
        const decEncryptedImg = document.getElementById('dec_encrypted_img');
        decEncryptedImg.src = URL.createObjectURL(file);
        
        // Display decrypted image
        const decryptedImg = document.getElementById('decrypted_img');
        decryptedImg.src = `data:image/png;base64,${data.decrypted_image_base64}`;
        
    } catch (err) {
        showError(decImgErrorMsg, err.message);
      } finally {
        if (decryptBtn) {
          decryptBtn.disabled = false;
          decryptBtn.innerHTML = originalBtnHTML;
        }
    }
}

function renderHistogramOriginal(data) {
    const ctx = document.getElementById('histogram_original');
    if (!ctx) return;
    if (histogramChartOriginal) histogramChartOriginal.destroy();
    
    const labels = Array.from({length: 256}, (_, i) => i.toString());
    histogramChartOriginal = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                { label: 'R', data: data.R || data.r, backgroundColor: 'rgba(255, 0, 0, 0.5)' },
                { label: 'G', data: data.G || data.g, backgroundColor: 'rgba(0, 255, 0, 0.5)' },
                { label: 'B', data: data.B || data.b, backgroundColor: 'rgba(0, 0, 255, 0.5)' }
            ]
        },
        options: { responsive: true, maintainAspectRatio: false, scales: { x: {display:false}, y: {display:false} } }
    });
}

function renderHistogramEncrypted(data) {
    const ctx = document.getElementById('histogram_encrypted');
    if (!ctx) return;
    if (histogramChartEncrypted) histogramChartEncrypted.destroy();
    
    const labels = Array.from({length: 256}, (_, i) => i.toString());
    histogramChartEncrypted = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                { label: 'R', data: data.R || data.r, backgroundColor: 'rgba(255, 100, 100, 0.5)' },
                { label: 'G', data: data.G || data.g, backgroundColor: 'rgba(100, 255, 100, 0.5)' },
                { label: 'B', data: data.B || data.b, backgroundColor: 'rgba(100, 100, 255, 0.5)' }
            ]
        },
        options: { responsive: true, maintainAspectRatio: false, scales: { x: {display:false}, y: {display:false} } }
    });
}

document.addEventListener("DOMContentLoaded", () => {
    // ... (Event listeners dari kode asli Anda) ...
    // Image encryption
    const imgModeSelect = document.getElementById('img_mode');
    const imgSboxWrapper = document.getElementById('img-sbox-wrapper');
    const imgEncryptBtn = document.getElementById('img_encrypt_btn');
    const imgUpload = document.getElementById('img_upload');
    const imgPreview = document.getElementById('img_preview');
    const imgPreviewImg = document.getElementById('img_preview_img');
    
    if (imgModeSelect) {
        imgModeSelect.addEventListener('change', () => toggleImageSBox(imgModeSelect, imgSboxWrapper));
        toggleImageSBox(imgModeSelect, imgSboxWrapper);
    }
    
    if (imgEncryptBtn) {
        imgEncryptBtn.addEventListener('click', handleImageEncrypt);
    }
    
    if (imgUpload) {
        imgUpload.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    imgPreviewImg.src = e.target.result;
                    imgPreview.classList.remove('hidden');
                };
                reader.readAsDataURL(file);
            }
        });
    }
    
    // Image decryption
    const decImgModeSelect = document.getElementById('dec_img_mode');
    const decImgSboxWrapper = document.getElementById('dec_img-sbox-wrapper');
    const imgDecryptBtn = document.getElementById('img_decrypt_btn');
    const decImgUpload = document.getElementById('dec_img_upload');
    const decImgPreview = document.getElementById('dec_img_preview');
    const decImgPreviewImg = document.getElementById('dec_img_preview_img');
    
    if (decImgModeSelect) {
        decImgModeSelect.addEventListener('change', () => toggleImageSBox(decImgModeSelect, decImgSboxWrapper));
        toggleImageSBox(decImgModeSelect, decImgSboxWrapper);
    }
    
    if (imgDecryptBtn) {
        imgDecryptBtn.addEventListener('click', handleImageDecrypt);
    }

    if (decImgUpload) {
      decImgUpload.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
          const reader = new FileReader();
          reader.onload = (event) => {
            if (decImgPreviewImg) decImgPreviewImg.src = event.target.result;
            if (decImgPreview) decImgPreview.classList.remove('hidden');
          };
          reader.readAsDataURL(file);
        }
      });
    }

    // Download buttons
    const downloadEncryptedBtn = document.getElementById('download_encrypted_btn');
    const downloadDecryptedBtn = document.getElementById('download_decrypted_btn');
    
    if (downloadEncryptedBtn) {
        downloadEncryptedBtn.addEventListener('click', () => {
             const a = document.createElement('a');
            a.href = `data:image/png;base64,${currentEncryptedImageBase64}`;
            a.download = `encrypted_image_${Date.now()}.png`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        });
    }
    
    if (downloadDecryptedBtn) {
        downloadDecryptedBtn.addEventListener('click', () => {
            const img = document.getElementById('decrypted_img');
            const a = document.createElement('a');
            a.href = img.src;
            a.download = `decrypted_image_${Date.now()}.png`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        });
    }
});