import re

class SecretScanner:
    def __init__(self):
        # Startup-level patterns for common leaks
        self.patterns = {
            "AWS_KEY": r"AKIA[0-9A-Z]{16}",
            "STRIPE_KEY": r"sk_test_[0-9a-zA-Z]{24}",
            "GITHUB_TOKEN": r"ghp_[a-zA-Z0-9]{36}",
            "GOOGLE_API": r"AIza[0-9A-Za-z\\-_]{35}",
            "DATABASE_URL": r"postgresql://[a-zA-Z0-9:@/._-]+",
            "GENERIC_SECRET": r"(?i)(password|secret|api_key|access_token)\s*[:=]\s*['\"]([^'\"]+)['\"]"
        }

    def scan_content(self, content, file_path):
        findings = []
        for secret_type, pattern in self.patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                # We redact the actual secret for the report
                raw_match = match.group()
                redacted = f"{raw_match[:4]}****{raw_match[-4:]}" if len(raw_match) > 8 else "****"
                
                findings.append({
                    "type": "Hardcoded Secret Detection",
                    "severity": "critical", # Secrets are always CRITICAL
                    "file_path": file_path,
                    "description": f"Potential {secret_type} found hardcoded in the source code.",
                    "recommendation": "Remove hardcoded credentials. Use environment variables (.env) and ensure the .env file is added to your .gitignore.",
                    "snippet": redacted
                })
        return findings