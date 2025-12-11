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
    ["SAC (avg)", metrics.sac_avg],
    ["BIC-NL (min)", metrics.bic_nl_min],
    ["BIC-SAC (deviasi rata-rata)", metrics.bic_sac_score],
    ["LAP max bias", metrics.lap_max_bias],
    ["DU", metrics.du],
    ["DAP max", metrics.dap_max],
    ["Algebraic Degree (min)", metrics.ad_min],
    ["Correlation Immunity (min)", metrics.ci_min],
    ["Transparency Order (TO)", metrics.to_value],
  ];

  metricsResult.innerHTML = "";
  entries.forEach(([label, value]) => {
    const p = document.createElement("p");
    p.className = "flex justify-between";
    p.innerHTML = `<span class="text-slate-400">${label}</span><span class="font-mono">${value}</span>`;
    metricsResult.appendChild(p);
  });
}

function renderSboxTable(sbox) {
  if (!sboxDisplay) return;
  sboxDisplay.innerHTML = "";
  if (!Array.isArray(sbox) || sbox.length !== 256) {
    sboxDisplay.innerHTML = '<p class="text-xs text-slate-500 col-span-16">S-Box belum tersedia</p>';
    return;
  }
  sbox.forEach((v) => {
    const cell = document.createElement("div");
    cell.className = "px-2 py-1 bg-slate-800 rounded text-center";
    cell.textContent = v.toString(16).padStart(2, "0");
    sboxDisplay.appendChild(cell);
  });
}

function renderAffineMatrix(mat) {
  if (!affineMatrixDisplay) return;
  if (!Array.isArray(mat) || mat.length !== 8) {
    affineMatrixDisplay.innerHTML = "";
    return;
  }
  let html = '<div class="overflow-auto max-h-40 border border-slate-700 rounded-xl"><table class="text-[11px] font-mono border-collapse w-full">';
  for (let i = 0; i < 8; i++) {
    html += "<tr>";
    const row = mat[i] || [];
    for (let j = 0; j < 8; j++) {
      const v = row[j] ?? 0;
      html += `<td class="px-1 py-0.5 text-center border border-slate-800">${v}</td>`;
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
  const form = new FormData();
  form.append("file", file);
  try {
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
  } catch (e) {
    showError(metricsErrorMsg, e.message);
    metricsResult.innerHTML = '<p class="text-slate-500 text-xs">Hasil metric akan muncul di sini.</p>';
  } finally {
    if (uploadSboxFile) uploadSboxFile.value = "";
  }
}

function handleDownloadSbox() {
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
  if (generateSboxBtn) generateSboxBtn.addEventListener("click", handleGenerateSbox);
  if (downloadSboxBtn) downloadSboxBtn.addEventListener("click", handleDownloadSbox);
  if (uploadSboxFile) uploadSboxFile.addEventListener("change", (e) => handleUploadSbox(e.target.files[0]));

  // init table state
  renderSboxTable(currentSBox);
  renderAffineMatrix(currentAffineMatrix);
  updateAffineText(currentAffineMatrix);
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
const generateSboxBtn = document.getElementById("generate_sbox_btn");
const downloadSboxBtn = document.getElementById("download_sbox_btn");
const uploadSboxFile = document.getElementById("upload_sbox_file");
const sboxDisplay = document.getElementById("sbox_display");
const affineMatrixDisplay = document.getElementById("affine_matrix_display");
const affineMatrixText = document.getElementById("affine_matrix_text");
