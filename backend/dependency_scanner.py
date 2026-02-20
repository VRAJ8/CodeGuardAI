import json
import httpx
import logging

class DependencyScanner:
    def __init__(self):
        self.api_url = "https://api.osv.dev/v1/query"

    async def scan_package_json(self, content, file_path):
        findings = []
        print(f"--- DEBUG: Starting Scan for {file_path} ---") # LOG 1
        try:
            data = json.loads(content)
            dependencies = data.get("dependencies", {})
            dev_dependencies = data.get("devDependencies", {})
            all_deps = {**dependencies, **dev_dependencies}
            
            print(f"--- DEBUG: Found {len(all_deps)} dependencies to check ---") # LOG 2

            async with httpx.AsyncClient() as client:
                for package_name, version in all_deps.items():
                    # Clean the version string
                    clean_version = version.replace('^', '').replace('~', '').strip()
                    
                    print(f"--- DEBUG: Checking {package_name} v{clean_version} ---") # LOG 3
                    
                    payload = {
                        "version": clean_version,
                        "package": {"name": package_name, "ecosystem": "npm"}
                    }
                    
                    response = await client.post(self.api_url, json=payload, timeout=10.0)
                    
                    if response.status_code == 200:
                        vuln_data = response.json()
                        if "vulns" in vuln_data:
                            print(f"--- DEBUG: VULNERABILITY FOUND in {package_name} ---") # LOG 4
                            for vuln in vuln_data["vulns"]:
                                cve_id = vuln.get("aliases", [vuln.get("id", "Unknown CVE")])[0]
                                findings.append({
                                    "type": f"Vulnerable Dependency ({cve_id})",
                                    "severity": "high",
                                    "file_path": file_path,
                                    "description": f"Package '{package_name}' (v{clean_version}) is vulnerable.",
                                    "recommendation": f"Update {package_name} to a newer version.",
                                })
                    else:
                        print(f"--- DEBUG: API Error {response.status_code} for {package_name} ---")
        except Exception as e:
            print(f"--- DEBUG: Scanner CRASHED: {str(e)} ---")
            
        return findings