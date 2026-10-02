import json

import httpx
import pytest

from codeguard.models import Dependency, SourceFile
from codeguard.scanners.dependencies import (
    collect_dependencies, cvss3_base_score, dependency_findings, enrich_with_osv, parse_go_mod,
    parse_requirements, parse_vuln,
)


def test_cvss_base_scores_match_first_calculator():
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert cvss3_base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N") == 5.5
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert cvss3_base_score("garbage") is None


def test_manifest_parsing():
    files = [
        SourceFile(path="web/package.json", language="json", lines=1, content=json.dumps(
            {"dependencies": {"lodash": "^4.17.11", "local": "file:../x"}, "devDependencies": {"jest": "~29.0.0"}})),
        SourceFile(path="requirements.txt", language="config", lines=3,
                   content="flask==0.12.2  # pinned\nrequests[socks]>=2.19.0\n-e .\nuvicorn\n"),
    ]
    deps = {(d.name, d.version, d.ecosystem, d.dev) for d in collect_dependencies(files)}
    assert ("lodash", "4.17.11", "npm", False) in deps
    assert ("jest", "29.0.0", "npm", True) in deps
    assert ("local", "", "npm", False) in deps
    assert ("flask", "0.12.2", "PyPI", False) in deps
    assert ("requests", "2.19.0", "PyPI", False) in deps
    assert ("uvicorn", "", "PyPI", False) in deps


def test_go_mod():
    deps = parse_go_mod("module x\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.0\n\tgolang.org/x/net v0.0.1 // indirect\n)\n"
                        "require github.com/pkg/errors v0.9.1\n", "go.mod")
    assert [(d.name, d.version) for d in deps] == [
        ("github.com/gin-gonic/gin", "1.6.0"), ("golang.org/x/net", "0.0.1"), ("github.com/pkg/errors", "0.9.1")]


def test_requirements_ignore_unpinned_upper_bounds():
    assert parse_requirements("django<4\n", "r.txt")[0].version == ""


ADVISORY = {
    "id": "GHSA-jf85-cpcp-j695",
    "aliases": ["CVE-2019-10744"],
    "summary": "Prototype Pollution in lodash",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"}],
    "database_specific": {"severity": "CRITICAL"},
    "affected": [{"package": {"name": "lodash", "ecosystem": "npm"},
                  "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.12"}]}]}],
    "references": [{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-10744"}],
}


def test_parse_vuln_prefers_ghsa_rating_and_finds_fix():
    v = parse_vuln(ADVISORY, Dependency(name="lodash", version="4.17.11", ecosystem="npm", manifest="package.json"))
    assert v.severity == "critical" and v.cvss == 9.1 and v.fixed_in == "4.17.12"
    assert v.url.startswith("https://nvd.nist.gov")


@pytest.mark.asyncio
async def test_enrich_with_osv_uses_batch_api():
    calls = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": ADVISORY["id"]}]} if q["package"]["name"] == "lodash" else {} for q in queries]})
        return httpx.Response(200, json=ADVISORY)

    deps = [Dependency(name="lodash", version="4.17.11", ecosystem="npm", manifest="package.json"),
            Dependency(name="react", version="18.2.0", ecosystem="npm", manifest="package.json"),
            Dependency(name="nover", version="", ecosystem="npm", manifest="package.json")]
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await enrich_with_osv(deps, client)

    assert calls == ["/v1/querybatch", f"/v1/vulns/{ADVISORY['id']}"]
    assert [len(d.vulnerabilities) for d in deps] == [1, 0, 0]

    pkg = SourceFile(path="package.json", language="json", lines=3,
                     content='{\n  "dependencies": {\n    "lodash": "4.17.11"\n  }\n}')
    [finding] = dependency_findings(deps, [pkg])
    assert finding.severity == "critical" and finding.line_number == 3
    assert "4.17.12" in finding.recommendation and finding.owasp == "A06:2021"


@pytest.mark.asyncio
async def test_osv_outage_is_non_fatal():
    deps = [Dependency(name="lodash", version="4.17.11", ecosystem="npm", manifest="package.json")]
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(503))) as client:
        assert (await enrich_with_osv(deps, client))[0].vulnerabilities == []
