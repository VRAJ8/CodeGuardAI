// Production builds read .env and .env.production (not .env.development). An API address there is baked into the
// deployed site and bypasses its same-origin /api rule in public/_redirects.
import fs from "fs";
import path from "path";

test("production env files don't pin an API address", () => {
  for (const name of [".env", ".env.production"]) {
    const file = path.join(__dirname, "..", "..", name);
    const text = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
    expect(text).not.toMatch(/^\s*REACT_APP_BACKEND_URL\s*=/m);
  }
});
