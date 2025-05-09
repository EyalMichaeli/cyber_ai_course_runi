const url = chrome.runtime.getURL('content_main.js');
import(url).then(({ main }) => main());
