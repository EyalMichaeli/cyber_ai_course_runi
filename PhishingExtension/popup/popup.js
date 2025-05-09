/* popup/popup.js  (ES module) */
const card = document.getElementById("card");
const status = document.getElementById("status");
const detail = document.getElementById("detail");

chrome.runtime.sendMessage({ action: "PopupQuery" }, (resp) => {
  if (!resp) {
    card.classList.replace("wait", "wait");
    status.textContent = "No prediction yet";
    detail.textContent = "Reload the page or wait…";
    return;
  }

  if (resp.verdict) {
    card.classList.replace("wait", "phish");
    status.textContent = "⚠ Phishing!";
    detail.textContent = "This page looks risky";
  } else {
    card.classList.replace("wait", "safe");
    status.textContent = "✓ Safe";
    detail.textContent = "No phishing indicators detected.";
  }
});
