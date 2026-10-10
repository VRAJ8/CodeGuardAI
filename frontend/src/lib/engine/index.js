// The in-browser scan engine: a port of backend/codeguard held to the Python engine by parity.golden.json.
// Rules and constants come from rules.generated.json (`cd backend && python -m codeguard.browser_export`).
import { RULES } from "./lang";

export { scan } from "./engine";
export { toCycloneDx, toSarif } from "./exporters";
export { makeSourceFile } from "./lang";

/** What reports from this engine carry as engine_version, next to the server's plain codeguard version. */
export const ENGINE_VERSION = `browser-${RULES.version}`;
