const API_BASE = "http://127.0.0.1:8000";

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
    showError(errorMsg, "Key hex wajib diisi.");
    return;
  }
  if (keyHex.length !== 32) {
    showError(errorMsg, "Key harus 32 karakter hex (128-bit).");
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
    showError(decErrorMsg, "Key hex wajib diisi.");
    return;
  }
  if (keyHex.length !== 32) {
    showError(decErrorMsg, "Key harus 32 karakter hex (128-bit).");
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

async function handleEncryptFile() {
  clearError(fileErrorMsg);
  fileCiphertextOutput.value = "";
  fileInfoMsg.textContent = "";

  const mode = fileModeSelect.value;
  const keyHex = fileKeyInput.value.trim();
  const file = fileInput.files[0];

  if (!keyHex) {
    showError(fileErrorMsg, "Key hex wajib diisi.");
    return;
  }
  if (keyHex.length !== 32) {
    showError(fileErrorMsg, "Key harus 32 karakter hex (128-bit).");
    return;
  }
  if (!file) {
    showError(fileErrorMsg, "File wajib dipilih.");
    return;
  }

  let sboxJson = null;
  if (mode === "custom") {
    try {
      const parsed = parseSBox(fileSboxInput.value);
      sboxJson = JSON.stringify(parsed);
    } catch (e) {
      showError(fileErrorMsg, e.message);
      return;
    }
  }

  const form = new FormData();
  form.append("mode", mode);
  form.append("key_hex", keyHex);
  form.append("file", file);
  if (sboxJson) {
    form.append("sbox_json", sboxJson);
  }

  try {
    const res = await fetch(`${API_BASE}/encrypt-file`, {
      method: "POST",
      body: form,
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || "Terjadi error saat enkripsi file.");
    }
    const data = await res.json();
    fileCiphertextOutput.value = data.ciphertext_hex || "";
    fileInfoMsg.textContent = `File: ${data.filename} | Plain: ${data.size_plain} byte | Cipher: ${data.size_cipher} byte`;
  } catch (err) {
    showError(fileErrorMsg, err.message);
  }
}

function renderMetrics(metrics) {
  const entries = [
    ["nl_min", metrics.nl_min],
    ["sac_avg", metrics.sac_avg],
    ["bic_nl_min", metrics.bic_nl_min],
    ["bic_sac_score", metrics.bic_sac_score],
    ["lap_max_bias", metrics.lap_max_bias],
    ["du", metrics.du],
    ["ad_min", metrics.ad_min],
    ["ci_min", metrics.ci_min],
    ["to_value (placeholder)", metrics.to_value],
  ];

  metricsOutput.innerHTML = "";
  entries.forEach(([label, value]) => {
    const p = document.createElement("p");
    p.className = "flex justify-between";
    p.innerHTML = `<span class="text-slate-400">${label}</span><span class="font-mono">${value}</span>`;
    metricsOutput.appendChild(p);
  });
}

async function handleMetrics() {
  clearError(metricsErrorMsg);
  metricsOutput.innerHTML = '<p class="text-slate-500 text-xs">Memproses...</p>';

  let sbox = null;
  try {
    sbox = parseSBox(metricsSboxInput.value);
  } catch (e) {
    showError(metricsErrorMsg, e.message);
    metricsOutput.innerHTML = '<p class="text-slate-500 text-xs">Hasil metric akan muncul di sini.</p>';
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/sbox/metrics`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sbox }),
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || "Terjadi error saat analisis S-Box.");
    }
    const data = await res.json();
    renderMetrics(data);
  } catch (err) {
    showError(metricsErrorMsg, err.message);
    metricsOutput.innerHTML = '<p class="text-slate-500 text-xs">Hasil metric akan muncul di sini.</p>';
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

  // Encrypt file
  fileModeSelect.addEventListener("change", () => toggleSBox(fileModeSelect, fileSboxWrapper));
  fileEncryptBtn.addEventListener("click", handleEncryptFile);
  toggleSBox(fileModeSelect, fileSboxWrapper);

  // Metrics
  metricsBtn.addEventListener("click", handleMetrics);
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

const fileModeSelect = document.getElementById("file_mode");
const fileSboxWrapper = document.getElementById("file-sbox-wrapper");
const fileKeyInput = document.getElementById("file_key_hex");
const fileInput = document.getElementById("file_input");
const fileSboxInput = document.getElementById("file_sbox_input");
const fileEncryptBtn = document.getElementById("file_encrypt_btn");
const fileCiphertextOutput = document.getElementById("file_ciphertext_output");
const fileInfoMsg = document.getElementById("file_info_msg");
const fileErrorMsg = document.getElementById("file_error_msg");

const metricsSboxInput = document.getElementById("metrics_sbox_input");
const metricsBtn = document.getElementById("metrics_btn");
const metricsOutput = document.getElementById("metrics_output");
const metricsErrorMsg = document.getElementById("metrics_error_msg");
