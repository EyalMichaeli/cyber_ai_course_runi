// popup/popup.js  (ES module)
const card = document.getElementById("card");
const status = document.getElementById("status");
const detail = document.getElementById("detail");

// set the grey “waiting” state
function showWaiting() {
  card.classList.remove("safe", "phish");
  card.classList.add("wait");
  status.textContent = "No prediction yet";
  detail.textContent = "Reload the page or wait…";
}

// set the green “safe” state
function showSafe() {
  card.classList.replace("wait", "safe");
  status.textContent = "✓ Safe";
  detail.textContent = "No phishing indicators detected.";
}

// set the red “phish” state
function showPhish() {
  card.classList.replace("wait", "phish");
  status.textContent = "⚠ Phishing!";
  detail.textContent = "This page looks risky";
}

// initial state
showWaiting();

// poll every 2 seconds until a verdict appears
const pollInterval = setInterval(() => {
  chrome.runtime.sendMessage({ action: "PopupQuery" }, (resp) => {
    if (resp && typeof resp.verdict === "boolean") {
      resp.verdict ? showPhish() : showSafe();
      clearInterval(pollInterval);
    }
  });
}, 0.5);

// also listen for any new verdicts while popup is open
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.action === "PredictionReady") {
    msg.verdict ? showPhish() : showSafe();
    clearInterval(pollInterval);
  }
});
