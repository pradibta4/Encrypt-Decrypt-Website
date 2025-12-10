const modeSelect = document.getElementById("mode");
const sboxWrapper = document.getElementById("sbox-wrapper");
const encryptBtn = document.getElementById("encrypt_btn");

const keyInput = document.getElementById("key_hex");
const plaintextInput = document.getElementById("plaintext");
const sboxInput = document.getElementById("sbox_input");

const ciphertextOutput = document.getElementById("ciphertext_output");
const errorMsg = document.getElementById("error_msg");
const infoMsg = document.getElementById("info_msg");

// toggle S-Box input kalau mode custom
modeSelect.addEventListener("change", () => {
  if (modeSelect.value === "custom") {
    sboxWrapper.classList.remove("hidden");
  } else {
    sboxWrapper.classList.add("hidden");
  }
});

// parse textarea S-Box -> array int
function parseSBox(text) {
  const raw = text
    .split(/[\s,]+/) // split by spasi & koma
    .filter((x) => x.length > 0);
  const nums = raw.map((v) => parseInt(v, 10));
  if (nums.some((x) => Number.isNaN(x))) {
    throw new Error("S-Box mengandung nilai non-angka.");
  }
  return nums;
}

encryptBtn.addEventListener("click", async () => {
  errorMsg.classList.add("hidden");
  errorMsg.textContent = "";
  ciphertextOutput.value = "";
  infoMsg.textContent = "";

  const mode = modeSelect.value;
  const keyHex = keyInput.value.trim();
  const plaintext = plaintextInput.value;

  if (!keyHex) {
    errorMsg.textContent = "Key hex wajib diisi.";
    errorMsg.classList.remove("hidden");
    return;
  }
  if (keyHex.length !== 32) {
    errorMsg.textContent = "Key harus 32 karakter hex (128-bit).";
    errorMsg.classList.remove("hidden");
    return;
  }
  if (!plaintext) {
    errorMsg.textContent = "Plaintext wajib diisi.";
    errorMsg.classList.remove("hidden");
    return;
  }

  let sbox = null;
  if (mode === "custom") {
    try {
      sbox = parseSBox(sboxInput.value);
    } catch (e) {
      errorMsg.textContent = e.message;
      errorMsg.classList.remove("hidden");
      return;
    }
  }

  const payload = {
    mode: mode,
    key_hex: keyHex,
    plaintext: plaintext,
    plaintext_hex: null,
    sbox: sbox,
  };

  try {
    const res = await fetch("http://127.0.0.1:8000/encrypt", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      const detail = errData.detail || "Terjadi error saat enkripsi.";
      throw new Error(detail);
    }

    const data = await res.json();
    ciphertextOutput.value = data.ciphertext_hex;
    infoMsg.textContent =
      `Mode: ${data.used_mode}, panjang plaintext (byte): ${data.plaintext_len}`;
  } catch (err) {
    errorMsg.textContent = err.message;
    errorMsg.classList.remove("hidden");
  }
});
