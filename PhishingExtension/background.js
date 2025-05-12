/* background.js  (already a module) */
const verdictByTab = new Map();

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg.action === "PredictionReady" && sender.tab) {
    verdictByTab.set(sender.tab.id, msg.result); // store latest verdict
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "PopupQuery") {
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      sendResponse(verdictByTab.get(tab.id) || null);
    });
    return true; // async response
  }
});

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg.action === "PredictionReady") {
    chrome.runtime.sendMessage({ action: "FromExtension", data: msg.result }, () => {});

    console.log(
      JSON.stringify({
        action: "PredictionReady",
        verdict:  msg.result.verdict,
        probUrl:  msg.result.probUrl,
        probHtml: msg.result.probHtml
      })
    );
  }
});
