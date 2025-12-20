const API_BASE = "http://127.0.0.1:8000";
let currentSBox = null;
let currentAffineMatrix = null;

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
  if (generateSboxBtn) generateSboxBtn.addEventListener("click", handleGenerateSbox);
  if (copySboxBtn) copySboxBtn.addEventListener("click", handleCopySbox);
  if (downloadJsonBtn) downloadJsonBtn.addEventListener("click", handleDownloadJson);
  if (downloadExcelBtn) downloadExcelBtn.addEventListener("click", handleDownloadExcel);
  if (uploadSboxFile) uploadSboxFile.addEventListener("change", (e) => handleUploadSbox(e.target.files[0]));

  // init table state
  renderSboxTable(currentSBox);
  renderAffineMatrix(currentAffineMatrix);
  updateAffineText(currentAffineMatrix);
  updateSboxDecimalText(currentSBox);
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
const loadSbox44Btn = document.getElementById("load_sbox44_btn");
const generateSboxBtn = document.getElementById("generate_sbox_btn");
const copySboxBtn = document.getElementById("copy_sbox_btn");
const downloadJsonBtn = document.getElementById("download_json_btn");
const downloadExcelBtn = document.getElementById("download_excel_btn");
const uploadSboxFile = document.getElementById("upload_sbox_file");
const sboxDisplay = document.getElementById("sbox_display");
const affineMatrixDisplay = document.getElementById("affine_matrix_display");
const affineMatrixText = document.getElementById("affine_matrix_text");
const sboxDecimalText = document.getElementById("sbox_decimal_text");