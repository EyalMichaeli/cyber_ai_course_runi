import { scorePhishingURL } from "./PhishingExtension/heuristic_prediction.mjs";
const url = process.argv[2];
console.log(scorePhishingURL(url));
