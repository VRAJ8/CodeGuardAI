/** @jest-environment node */
import { OSV_RELAY, viaSiteRelay } from "./worker";

test("OSV.dev calls go through the same-origin relay", () => {
  const origin = "https://codevigil.netlify.app";
  expect(viaSiteRelay("https://api.osv.dev/v1/querybatch", origin)).toBe(`${origin}${OSV_RELAY}v1/querybatch`);
  expect(viaSiteRelay("https://api.osv.dev/v1/vulns/GHSA-xxxx", origin)).toBe(`${origin}/osv/v1/vulns/GHSA-xxxx`);
});

test("other requests and origin-less contexts are left alone", () => {
  const origin = "https://codevigil.netlify.app";
  expect(viaSiteRelay("https://api.github.com/repos/a/b", origin)).toBe("https://api.github.com/repos/a/b");
  expect(viaSiteRelay("https://api.osv.dev.evil.example/v1/querybatch", origin)).toBe("https://api.osv.dev.evil.example/v1/querybatch");
  expect(viaSiteRelay("https://api.osv.dev/v1/querybatch", undefined)).toBe("https://api.osv.dev/v1/querybatch");
});
