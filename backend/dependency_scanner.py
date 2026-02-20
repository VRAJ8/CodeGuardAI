import json
import httpx
import logging

class DependencyScanner:
    def __init__(self):
        self.api_url = "https://api.osv.dev/v1/query"

    async def scan_package_json(self, content, file_path):
        findings = []
        try:
            data = json.loads(content)
            all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            
            async with httpx.AsyncClient() as client:
                for pkg, ver in all_deps.items():
                    # OSV API needs a clean version (no symbols)
                    clean_ver = "".join(filter(lambda x: x.isdigit() or x == '.', ver))
                    
                    payload = {
                        "version": clean_ver,
                        "package": {"name": pkg, "ecosystem": "npm"}
                    }
                    
                    response = await client.post(self.api_url, json=payload, timeout=10.0)
                    
                    if response.status_code == 200:
                        vulns = response.json().get("vulns", [])
                        if vulns:
                            # Use the first vulnerability's ID as the main reference
                            vuln_id = vulns[0].get("aliases", [vulns[0].get("id")])[0]
                            findings.append({
                                "type": f"Vulnerable Dependency ({vuln_id})",
                                "severity": "high",
                                "file_path": file_path,
                                "description": f"Package '{pkg}' (v{clean_ver}) has {len(vulns)} known security issues.",
                                "recommendation": f"Update '{pkg}' immediately to the latest stable version.",
                            })
        except Exception as e:
            logging.error(f"Dependency Scanner error: {e}")
            
        return findings