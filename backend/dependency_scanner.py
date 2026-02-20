import json
import httpx
import logging

class DependencyScanner:
    def __init__(self):
        self.api_url = "https://api.osv.dev/v1/query"

    async def scan_package_json(self, content, file_path):
        findings = []
        try:
            # Parse the package.json file
            data = json.loads(content)
            dependencies = data.get("dependencies", {})
            dev_dependencies = data.get("devDependencies", {})
            
            # Combine all dependencies
            all_deps = {**dependencies, **dev_dependencies}

            async with httpx.AsyncClient() as client:
                for package_name, version in all_deps.items():
                    # Clean the version string (remove ^ or ~)
                    clean_version = version.replace('^', '').replace('~', '').strip()
                    
                    # Ask Google OSV if this exact version is vulnerable
                    payload = {
                        "version": clean_version,
                        "package": {
                            "name": package_name,
                            "ecosystem": "npm"
                        }
                    }
                    
                    response = await client.post(self.api_url, json=payload, timeout=10.0)
                    
                    if response.status_code == 200:
                        vuln_data = response.json()
                        if "vulns" in vuln_data:
                            # A vulnerability was found!
                            for vuln in vuln_data["vulns"]:
                                # Get the CVE ID if available, otherwise use OSV ID
                                cve_id = vuln.get("aliases", [vuln.get("id", "Unknown CVE")])[0]
                                details = vuln.get("summary", "Known vulnerability detected in this package version.")
                                
                                findings.append({
                                    "type": f"Vulnerable Dependency ({cve_id})",
                                    "severity": "high",
                                    "file_path": file_path,
                                    "description": f"Package '{package_name}' (v{clean_version}) is vulnerable: {details}",
                                    "recommendation": f"Run 'npm update {package_name}' to install a secure, patched version.",
                                })
        except Exception as e:
            logging.error(f"Failed to scan package.json: {e}")
            
        return findings