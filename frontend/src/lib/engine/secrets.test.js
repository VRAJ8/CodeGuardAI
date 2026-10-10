/** @jest-environment node */
import GOLDEN from "./parity.golden.json";
import { pyRound } from "./lang";
import { looksPlaceholder, redact, scanSecrets, shannonEntropy } from "./secrets";

const V = GOLDEN.vectors;
const substitute = (text) =>
  Object.entries(GOLDEN.placeholders).reduce((t, [name, parts]) => t.split(name).join(parts.join("")), text);
const pub = (findings) => findings.map(({ fp_basis: _, ...f }) => f);

describe("secrets", () => {
  test("scan_secrets vectors", () => {
    V.patterns.scan_secrets.forEach((v) => {
      expect(pub(scanSecrets(substitute(v.content), v.path))).toEqual(v.findings);
    });
  });

  test("shannon_entropy", () => {
    const bad = V.secrets.shannon_entropy_rounded10.filter(([v, x]) => Math.abs(pyRound(shannonEntropy(v), 10) - x) > 1e-9);
    expect(bad).toEqual([]);
  });

  test("redact and _looks_placeholder", () => {
    expect(V.secrets.redact.map(([v]) => [v, redact(v)])).toEqual(V.secrets.redact);
    expect(V.secrets.looks_placeholder.map(([v]) => [v, looksPlaceholder(v)])).toEqual(V.secrets.looks_placeholder);
  });

  test("a line a provider signature already flagged is not reported again as a generic credential", () => {
    // Expected values from the Python engine's scan_secrets on the same input.
    const key = GOLDEN.placeholders.__FAKE_STRIPE_KEY__.join("");
    const got = scanSecrets(`password = "${key}"\napi_key = "Zr7wT4nBq9LmX2"\n`, "a.py");
    expect(got.map((f) => [f.rule_id, f.line_number, f.description])).toEqual([
      ["SEC-STRIPE", 1, "Potential Stripe secret key committed to source. Value: sk_l********Qr"],
      ["SEC-GENERIC", 2, "Potential Hardcoded credential in `api_key` committed to source (entropy 3.81 bits/char). Value: Zr7w********X2"],
    ]);
  });

  test("the entropy in the description rounds an exact tie half to even (4.625 -> 4.62, where toFixed gives 4.63)", () => {
    // Expected value from the Python engine's scan_secrets on the same input.
    const [f] = scanSecrets('auth_token = "aaaabbccdefghijklmnopqrstuvwxyz0"', "a.py");
    expect(f.description).toBe("Potential Hardcoded credential in `auth_token` committed to source (entropy 4.62 bits/char). Value: aaaa********z0");
  });

  test("the fingerprint basis masks every occurrence of the credential", () => {
    const key = GOLDEN.placeholders.__FAKE_STRIPE_KEY__.join("");
    const [f] = scanSecrets(`a = "${key}" or "${key}"`, "x.py");
    expect(f.fp_basis).toBe('a = "<secret>" or "<secret>"');
    expect(f.snippet).not.toContain(key.slice(6));
    expect(f.description).not.toContain(key.slice(6));
  });
});
