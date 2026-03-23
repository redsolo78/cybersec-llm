
#!/usr/bin/env python3
"""
post_process_github_dataset.py
v2.1 – fix concorrenza + clone/extract separati

python3 post_process_github_dataset.py \
  --clone-dir cloned_repos \
  --output-dir extracted_code \
  --workers 16
"""

import os
import subprocess
import shutil
import re
import hashlib
from pathlib import Path
import argparse
import json
from typing import Set, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


# ================== CONFIG ==================
INPUT_TXT = "targets_2025_2026_super.txt"
INPUT_JSON = "targets_2025_2026_super.json"

CLONE_DIR = "cloned_repos"
OUTPUT_DIR = "extracted_code"
MANIFEST_FILE = "extracted_files_manifest.txt"

MAX_REPOS = 7000
CLONE_TIMEOUT = 60
MAX_WORKERS = 8


TARGET_EXTENSIONS = {
    # C/C++/C++
    ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp",
    # Rust
    ".rs",
    # Go
    ".go",
    # Python
    ".py", ".pyi",
    # C#
    ".cs", ".csx",
    # PowerShell (aggiunto ora!)
    ".ps1", ".psm1", ".psd1", ".ps1xml", ".pssc", ".psd"
}

USE_JSON_FOR_TERMS = True



SEARCH_CLUSTERS = {
    "loader_stealth": [
        "ekko+sleep+obfuscation",
        "cronos+sleep",
        "folly+sleep",
        "deathsleep",
        "d1rksleep",
        "sleep+obfuscation+waitable+timer",
        "timer+queue+sleep+obfuscation",
        "rx-rw-rx+sleep+obfuscation",
        "section+only+encryption",
        "rwx+section+reuse",
        "heap+encrypted+shellcode",
        "rwxt+space+reuse"
    ],

    "identity_abuse": [
        "azure+ad+prt+hijack",
        "primary+refresh+token+theft",
        "cloud+ap+token",
        "aadinternals+prt",
        "tokentactics+refresh",
        "oauth+device+code+attack",
        "device+code+phishing",
        "conditional+access+device+filter+bypass",
        "continuous+access+eval+abuse",
        "session+cookie+replay+365",
        "aad+session+cookie+theft",
        "webauthn+relay",
        "fido2+bypass",
        "aitm+token+theft",
        "illicit+consent+grant"
    ],

    "telemetry_tamper": [
        "etw+patch",
        "etw+blinding",
        "EtwEventWrite",
        "disable+etw",
        "etwti+tampering",
        "nttraceevent+patch",
        "etw+disable+syscall",
        "event+log+tampering",
        "wevtutil+clear",
        "wevtutil+sl",
        "windows+security+event+injection",
        "sysmon+tampering",
        "sysmon+event+hidden",
        "kernel+callback+table+abuse",
        "pssetcreateprocessnotifyroutine+remove",
        "minifilter+edr+unhook",
        "edr+user+mode+unhook"
    ],

    "evasion_next_gen": [
        "intel+cet+bypass",
        "shadow+stack+manipulation",
        "ibt+bypass",
        "hwp+evasion",
        "hardware+p-state+manipulation",
        "pmu+side+channel",
        "ekko+sleep+obfuscation",
        "cronos+sleep",
        "folly+printer",
        "deathsleep",
        "stack+graph+obfuscation",
        "thread+pool+injection",
        "tp-worker+factory",
        "dirty+pagetable",
        "pte+manipulation",
        "self-referencing+pte",
        "edr+silencing",
        "edr+wiper",
        "mde+bypass",
        "etwti+tampering",
        "syscall+knitting",
        "parallel+syscalls",
        "sw3_syscall",
        "freshycalls",
        "amsi+bypass",
        "AmsiScanBuffer",
        "amsiInitFailed",
        "etw+patch",
        "hell+gate",
        "halo+gate",
        "tartarus+gate",
        "stack+spoofing",
        "unhooking",
        "ntdll+unhook",
        "api+unhooking",
        "hardware+breakpoint+bypass",
        "cet+compliant+syscall",
        "shadow+stack+spoofing",
        "ibt+gadget",
        "hwp+breakpoint+bypass",
        "pmu+spoofing",
        "ghost+syscall",
        "recycled+gate",
        "inlinewhispers3",
        "bypass+wdac",
        "bypass+hvci+vbs",
        "syswhispers4",
        "syscalls+from+disk",
        "recycled+gate+validation",
        "hw+breakpoint+amsi",
        "veh2+amsi",
        "patchless+amsi",
        "blindside+technique",
        "ldrloaddll+breakpoint",
        "unhooked+ntdll+debug+process",
        "heap+encrypted+syscall",
        "xor+encrypted+syscall+stub",
        "nttraceevent+patch",
        "etw+disable+syscall",
        "sifu+memory+guard",
        "tp+alloc+work+proxy",
        "layered+syscall",
        "egg+hunt+syscall",
        "gadget+pool+syscall",
        "sleep+encryption",
        "call+stack+spoof+veh",
        "hardware+breakpoint+spoofing",
        "clear+debug+registers+dr0-dr7",
        "inline+syscall+obfuscation",
        "direct+syscall+evasion",
        "unhooked+process",
        "edr+killer",
        "edr+freeze",
        "byoi+installer+abuse",
        "pool+party+injection",
        "context+only+injection",
        "pointer+only+loadlibrary",
        "early+cryo+bird+injection",
        "job+object+suspend",
        "fudmodule+rootkit",
        "lnvmsrio+sys",
        "cve-2025-68947",
        "cve-2025-8061",
        "patchguard+bypass",
        "kpp+evasion",
        "byovd+embedded+ransomware",
        "nsecsoft+nseckrnl",
        "d1rksleep",
        "syscall+stomping",
        "syscall+proxying",
        "timer+queue+sleep+obfuscation",
        "rx-rw-rx+transition",
        "section+only+encryption+loader",
        "hardware+breakpoint+edr+evasion",
        "blindside+edr+evasion",
        "reynolds+byovd"
    ],
    "injection_modern": [
        "process+hollowing",
        "reflective+injection",
        "module+stomping",
        "process+ghosting",
        "process+herpaderping",
        "process+reimaging",
        "mockingjay+injection",
        "rwxt+space+reuse",
        "shinject",
        "darkloadlibrary",
        "enclave+shellcode+loader",
        "sgx+exploit",
        "apc+injection",
        "early+bird+apc",
        "thread+hijacking",
        "phantom+dll+hollowing",
        "dll+ghosting",
        "atom+bombing",
        "tp+alloc+work+proxy+injection",
        "pool+party",
        "early+cryo+bird",
        "job+object+injection",
        "context+hijacking",
        "pointer+only+dll+injection",
        "thread+execution+hijacking+suspended",
        "uwp+lifecycle+abuse",
        "dynamic+function+resolution+hash"
    ],
    "exploit_kernel": [
        "byovd",
        "vulnerable driver",
        "byovd+exploit",
        "nt device ioctl",
        "ntloaddriver",
        "KeServiceDescriptorTable",
        "PsInitialSystemProcess",
        "ZwCallbackReturn",
        "NtQuerySystemInformationEx",
        "pool spray",
        "pool feng shui",
        "arbitrary overwrite",
        "commit_creds",
        "prepare_kernel_cred",
        "copy_from_user",
        "use after free",
        "uaf exploit",
        "double fetch",
        "rop chain",
        "rop gadget",
        "ret2libc",
        "heap spray",
        "heap exploit",
        "type confusion",
        "race condition exploit",
        "format string exploit",
        "buffer overflow",
        "write what where",
        "vulnerable+driver",
        "ioctl+exploit",
        "io_uring+exploit",
        "ebpf+rootkit",
        "ebpf+backdoor",
        "slab+feng+shui+2025",
        "cross-cache+overflow",
        "hvci+bypass",
        "vbs+bypass",
        "vsl+impersonation",
        "clfs+exploit",
        "ksm+side+channel",
        "pool+spray",
        "token+stealing+payload",
        "edr+killshifter",
        "truesight+driver",
        "rtcore64+sys",
        "aswar+pot+sys",
        "procexp+sys",
        "cve-2025-8061",
        "cve-2025-68947",
        "cve-2025-52915",
        "lnvmsrio+sys",
        "k7rkscan+sys",
        "edr+killer",
        "defendnot",
        "dark+kill+driver",
        "cve-2025-62215",
        "cve-2025-24983",
        "fudmodule+rootkit",
        "afd+sys+exploit",
        "hyperv+kernel+exploit",
        "win32+kernel+privesc",
        "race+condition+kernel",
        "dkom+edr+disable",
        "unsigned+driver+map+2026"
    ],
    "credentials_cloud": [
        "azure+ad+prt+hijack",
        "primary+refresh+token+theft",
        "fido2+bypass",
        "webauthn+relay",
        "mfa+fatigue+automation",
        "graph+api+abusing",
        "conditional+access+bypass",
        "managed+identity+theft",
        "imds+v2+ssrf",
        "lsass dump",
        "minidumpwritedump",
        "pypykatz",
        "kerberoasting",
        "asreproast",
        "dcsync",
        "ntlm relay",
        "token impersonation",
        "cloud+ap+token",
        "seimpersonateprivilege",
        "prt+theft",
        "managed+identity+extraction",
        "sami+uami+token",
        "device+code+phishing",
        "aitm+token+theft",
        "illicit+consent+grant",
        "365+stealer",
        "token+replay+attack",
        "oauth+app+registration+abuse",
        "aadinternals+prt",
        "tokentactics+refresh"
    ],
    "evasion": [
        "amsi bypass",
        "amsi+bypass",
        "amsiInitFailed",
        "AmsiScanBuffer",
        "etw+patch",
        "etw+blinding",
        "EtwEventWrite",
        "disable etw",
        "indirect syscalls",
        "direct syscalls",
        "indirect+syscall",
        "hell gate",
        "halo gate",
        "tartarus gate",
        "stack spoofing",
        "stack+spoof",
        "sleep obfuscation",
        "sleep+mask",
        "module stomping",
        "module+stomp",
        "pe header stomp",
        "heap obfuscation",
        "heap+encrypt",
        "unhooking",
        "api unhook",
        "ntdll unhook",
        "inline hook",
        "veh hook",
        "hardware breakpoint",
        "gargoyle",
        "threadless injection",
        "fiber execution",
        "process doppelganging",
        "kernel callback table",
        "thread hijacking",
        "ppid spoof",
        "byovd+embedded",
        "edr+freeze",
        "inline+syscall+obfuscation",
        "pool+party"
    ],
    "injection": [
        "process hollowing",
        "process+hollow",
        "classic injection",
        "dll injection",
        "dll+inject",
        "shellcode loader",
        "shellcode+exec",
        "reflective injection",
        "reflective dll",
        "reflective+load",
        "manual map",
        "manual+mapping",
        "apc injection",
        "early bird apc",
        "queue user apc",
        "section injection",
        "nt injection",
        "ntwritevirtualmemory",
        "ntallocatevirtualmemory",
        "module stomping",
        "knowndlls injection",
        "enumchildwindows shellcode",
        "fiber shellcode",
        "callback injection",
        "pool+party",
        "early+cryo+bird",
        "context+only+injection",
        "pointer+only+loadlibrary",
        "uwp+job+object"
    ],
    "credentials": [
        "lsass dump",
        "lsass+memory",
        "minidumpwritedump",
        "lsass nt read",
        "kerberoasting",
        "asreproast",
        "as-rep roasting",
        "golden ticket",
        "silver ticket",
        "pass the ticket",
        "pass the hash",
        "over pass the hash",
        "dcsync",
        "ntlm relay",
        "token impersonation",
        "token+steal",
        "token manipulation",
        "named pipe impersonation",
        "seimpersonateprivilege",
        "dpapi decrypt",
        "credential manager dump",
        "lsa secret",
        "lsa policy"
    ],
    "persistence": [
        "registry run key",
        "scheduled task persistence",
        "schtask",
        "wmi event subscription",
        "wmi+persist",
        "com hijacking",
        "dll hijacking",
        "dll+sideload",
        "service persistence",
        "image file execution",
        "ifeo",
        "boot autostart",
        "uefi+bootkit",
        "blacklotus+uefi",
        "efi+persistence",
        "appdomainmanager+injection",
        "bits+job+persistence",
        "invisible+scheduled+task",
        "sd+delete+task",
        "secure+boot+bypass+2026",
        "certificate+expiry+uefi",
        "cve-2026-21265"
    ],
    "lateral_movement": [
        "pass the hash",
        "pass the ticket",
        "psexec lateral",
        "service lateral",
        "named pipe lateral",
        "smb lateral",
        "dcom lateral",
        "wmi lateral",
        "rdp hijacking",
        "rdp+session",
        "tscon",
        "token lateral"
    ],
    "c2": [
        "http c2",
        "winhttp c2",
        "wininet c2",
        "dns tunneling",
        "dns c2",
        "dns+tunnel",
        "icmp c2",
        "icmp+tunnel",
        "named pipe c2",
        "raw socket c2",
        "beacon",
        "cobalt strike",
        "havoc",
        "sliver",
        "graphql+c2",
        "telegram+c2",
        "discord+webhook+c2",
        "malleable+c2",
        "sliver+c2",
        "havoc+c2",
        "winrm+remote+powershell",
        "mythic+c2",
        "brute+ratel+c4",
        "adaptixc2",
        "nighthawk+c2",
        "poshc2",
        "merlin+c2",
        "sliver+custom+payload"
    ],
    "privilege_escalation": [
        "uac bypass",
        "uac+bypass",
        "ifileoperation uac",
        "potato attack",
        "juicy potato",
        "sweet potato",
        "rogue potato",
        "alpc privilege",
        "named pipe privesc",
        "token impersonation",
        "seimpersonateprivilege",
        "cve-2025-62215",
        "hyperv+kernel+privesc"
    ],
    "java_deserialization": [
        "ysoserial",
        "jndi injection",
        "log4shell",
        "ObjectInputStream",
        "readObject",
        "ClassLoader.defineClass",
        "InvocationHandler",
        "BinaryFormatter",
        "TypeNameHandling.Auto",
        "rmi://",
        "ldap://",
        "jndi:",
        "UnicastRemoteObject"
    ],
    "anti_forensics": [
        "event log tampering",
        "evtx clear",
        "wevtutil",
        "timestamp manipulation",
        "timestomp",
        "setfiletime",
        "fileless attack",
        "living off the land",
        "lolbin",
        "lolbas",
        "mbr wipe",
        "disk wipe",
        "data destruction",
        "secure delete",
        "wiper malware",
        "uefi+rootkit+2025",
        "esp+mounter+persistence",
        "acpi+table+injection",
        "bmc+rootkit",
        "ipmi+firmware+exploit",
        "wmi+event+subscription",
        "com+hijacking",
        "dll+sideload",
        "shim+database+persistence",
        "bitsadmin+job",
        "event+log+tampering",
        "wevtutil+clear"
    ],
    "powershell_offensive": [
        "invoke expression",
        "iex download",
        "downloadstring",
        "reflective assembly load",
        "system.reflection",
        "amsi bypass powershell",
        "amsiutils reflection",
        "executionpolicy bypass",
        "noninteractive",
        "add-type memberdef",
        "marshal copy",
        "powerview",
        "powersploit",
        "empire",
        "nishang",
        "bloodhound",
        "sharpview",
        "invoke-expression",
        "iex+downloadstring",
        "reflective+assembly+load",
        "amsiutils+reflection"
    ],
    "ad_attacks": [
        "dcsync",
        "drsuapi",
        "kerberoasting",
        "asreproast",
        "golden ticket",
        "silver ticket",
        "ldap enumeration",
        "ldap search",
        "get-domaincontroller",
        "get-aduser",
        "powerview",
        "ad enumeration",
        "netuserenum",
        "dsgetdcname",
        "bloodhound",
        "sharphound",
        "domain trust",
        "DsEnumerateDomainTrusts"
    ],
    "ai_offensive": [
        "prompt+injection+payload",
        "indirect+prompt+injection",
        "rag+poisoning",
        "vector+database+exfiltration",
        "llm+jailbreak+automation",
        "agent+hijacking",
        "copilot+token+theft",
        "cursor+editor+exploit",
        "adversarial+machine+learning+malware",
        "rag+poisoning+agentpoison",
        "tool+poisoning+attack",
        "knowledge+base+poisoning",
        "echoleak+copilot",
        "indirect+prompt+injection+rag",
        "sleeper+agent+rag",
        "cross+tenant+leakage",
        "cve-2025-32711",
        "ai+memory+poisoning",
        "copilot+prompt+leakage",
        "copilot+data+exfiltration",
        "llm+tool+injection",
        "function+calling+abuse",
        "toolformer+attack",
        "ai+package+hallucination+attack"
    ],
    "kernel_evasion_2026": [
        "byovd+2025",
        "clfs+exploit",
        "io_uring+rootkit",
        "ebpf+rootkit",
        "shadowguard",
        "linkpro+ebpf",
        "dse+bypass",
        "unsigned+driver+map",
        "reflective+driver+loading",
        "unsigned+reflective+driver",
        "lnvmsrio+sys",
        "nidhogg+rootkit",
        "sunder+rootkit",
        "fudmodule+rootkit",
        "patchguard+evasion",
        "ntaddatom+hooking",
        "kernel+inline+hooking",
        "minifilter+rootkit",
        "c2+compiled+rootkit",
        "voidlink+rootkit",
        "edr+killshifter",
        "byoi+edr",
        "edr+killer",
        "edr+freeze",
        "cve-2025-62215+kernel",
        "afd+sys+zero+day",
        "hyperv+exploit+2025",
        "reynolds+embedded+byovd",
        "kdmapper+fork",
        "kdmapper+variant",
        "driver+reflective+loading",
        "reflective+driver+loader",
        "xdp+rootkit",
        "ebpf+sockops+backdoor",
        "ebpf+magic+packet+rootkit",
        "magic+tcp+packet+rootkit",
        "minifilter+rootkit",
        "callback+object+manager+rootkit",
        "secure+boot+expiry+2026"
    ]
}

ALL_TERMS = set()
for terms in SEARCH_CLUSTERS.values():
    ALL_TERMS.update(terms)

TERM_PATTERNS = [re.compile(re.escape(t), re.IGNORECASE) for t in ALL_TERMS]


def repo_key_from_url(url: str) -> str:
    parts = url.rstrip("/").split("/")
    if len(parts) >= 2:
        owner = parts[-2]
        repo = parts[-1].removesuffix(".git")
        return f"{owner}__{repo}"
    return parts[-1].removesuffix(".git")


def load_repos_from_txt() -> List[str]:
    if not Path(INPUT_TXT).is_file():
        raise FileNotFoundError(f"{INPUT_TXT} non trovato")
    with open(INPUT_TXT, encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    print(f"Trovati {len(urls)} repository nel file TXT")
    return urls[:MAX_REPOS]


def load_repos_from_json() -> List[dict]:
    if not Path(INPUT_JSON).is_file():
        print(f"JSON {INPUT_JSON} non trovato → fallback su TXT")
        return []
    with open(INPUT_JSON, encoding="utf-8") as f:
        data = json.load(f)
    repos = sorted(data, key=lambda x: x.get("stars", 0), reverse=True)
    print(f"Caricati {len(repos)} repo dal JSON")
    return repos[:MAX_REPOS]


def clone_repo(url: str, dest_root: Path) -> Optional[Path]:
    repo_key = repo_key_from_url(url)
    clone_path = dest_root / repo_key

    if clone_path.exists():
        print(f"  Repo già presente, skip: {repo_key}")
        return clone_path

    print(f"  Cloning {url} → {clone_path}")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, str(clone_path)],
            check=True,
            timeout=CLONE_TIMEOUT,
            capture_output=True
        )
        return clone_path
    except Exception as e:
        print(f"  ERRORE clone {url}: {e}")
        if clone_path.exists():
            shutil.rmtree(clone_path, ignore_errors=True)
        return None


def strip_comments_and_cleanup(content: str, ext: str) -> str:
    if ext in {".c", ".cpp", ".cc", ".h", ".hpp", ".cs", ".csx"}:
        content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL | re.MULTILINE)
        content = re.sub(r'#\s*region.*?$|#endregion', '', content, flags=re.MULTILINE | re.IGNORECASE)

    elif ext in {".py", ".pyi"}:
        content = re.sub(r'#.*?$', '', content, flags=re.MULTILINE)
        content = re.sub(r"'''[\s\S]*?'''|\"\"\"[\s\S]*?\"\"\"", '', content, flags=re.DOTALL)

    elif ext in {".go", ".rs"}:
        content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        content = re.sub(r'//![^\n]*|/\*!.*?\*/', '', content, flags=re.DOTALL)

    # ─── AGGIUNTA: PowerShell ───────────────────────────────────────────────
    elif ext in {".ps1", ".psm1", ".psd1", ".ps1xml", ".pssc", ".psd"}:
        # Commenti single-line #
        content = re.sub(r'#.*?$', '', content, flags=re.MULTILINE)
        # Commenti multi-linea <# #>
        content = re.sub(r'<#[\s\S]*?#>', '', content, flags=re.DOTALL)

    # Pulizia generica finale    
    lines = [line.rstrip() for line in content.splitlines() if line.strip()]
    content = '\n'.join(lines).strip()
    content = re.sub(r'[ \t]{2,}', ' ', content)

    return content + '\n' if content else ''


def contains_relevant_term(file_path: Path, cleaned: bool = False) -> bool:
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        if cleaned:
            content = strip_comments_and_cleanup(content, file_path.suffix.lower())
        return any(pattern.search(content) for pattern in TERM_PATTERNS)
    except Exception:
        return False


def extract_relevant_files(repo_dir: Path, extract_root: Path, repo_url: str, repo_terms: Optional[Set[str]] = None):
    extracted = []
    repo_key = repo_key_from_url(repo_url)
    seen_hashes = set()

    for root, _, files in os.walk(repo_dir):
        for file in files:
            path = Path(root) / file
            ext = path.suffix.lower()
            if ext not in TARGET_EXTENSIONS:
                continue

            if not contains_relevant_term(path, cleaned=False):
                continue

            try:
                original_content = path.read_text(encoding="utf-8", errors="ignore")
                clean_content = strip_comments_and_cleanup(original_content, ext)

                if not clean_content:
                    continue

                if not any(p.search(clean_content) for p in TERM_PATTERNS):
                    continue

                content_hash = hashlib.sha256(clean_content.encode("utf-8")).hexdigest()
                if content_hash in seen_hashes:
                    continue
                seen_hashes.add(content_hash)

                rel_path = path.relative_to(repo_dir)
                dest = extract_root / repo_key / rel_path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(clean_content, encoding="utf-8")
                extracted.append(str(dest))

            except Exception:
                pass

    if extracted:
        print(f"  Estratti {len(extracted)} file rilevanti (puliti + dedup) da {repo_key}")
    return extracted


def clone_and_extract(repo_info, clone_root: Path, extract_root: Path, no_clone: bool, use_json: bool):
    url = repo_info["url"]
    repo_key = repo_key_from_url(url)
    repo_dir = clone_root / repo_key

    if no_clone:
        if not repo_dir.exists():
            return []
    else:
        repo_dir = clone_repo(url, clone_root)
        if repo_dir is None:
            return []

    repo_terms = None
    if use_json:
        t = repo_info.get("term")
        if t:
            repo_terms = {t}

    return extract_relevant_files(repo_dir, extract_root, url, repo_terms)


def main():
    global MAX_REPOS, OUTPUT_DIR, CLONE_DIR

    parser = argparse.ArgumentParser()
    parser.add_argument("--max-repos", type=int, default=MAX_REPOS)
    parser.add_argument("--output-dir", default=OUTPUT_DIR)
    parser.add_argument("--clone-dir", default=CLONE_DIR)
    parser.add_argument("--no-clone", action="store_true", help="Non clonare, usa solo repo esistenti")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS)
    args = parser.parse_args()

    MAX_REPOS = args.max_repos
    OUTPUT_DIR = args.output_dir
    CLONE_DIR = args.clone_dir

    clone_root = Path(CLONE_DIR)
    extract_root = Path(OUTPUT_DIR)

    clone_root.mkdir(exist_ok=True)
    extract_root.mkdir(exist_ok=True)

    repos = load_repos_from_json() if USE_JSON_FOR_TERMS else []
    use_json = bool(repos)

    if not use_json:
        urls = load_repos_from_txt()
        repos = [{"url": u, "cluster": "unknown", "term": "unknown"} for u in urls]

    all_extracted_files = []
    processed = 0

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                clone_and_extract,
                repo,
                clone_root,
                extract_root,
                args.no_clone,
                use_json
            ): repo
            for repo in repos
        }

        for i, future in enumerate(as_completed(futures), 1):
            repo = futures[future]
            try:
                extracted = future.result()
                all_extracted_files.extend(extracted)
                processed += 1
                print(f"[{i}/{len(repos)}] OK: {repo['url']} ({len(extracted)} file)")
            except Exception as e:
                processed += 1
                print(f"[{i}/{len(repos)}] ERRORE: {repo['url']}: {e}")

    with open(MANIFEST_FILE, "w", encoding="utf-8") as f:
        for path in sorted(all_extracted_files):
            f.write(path + "\n")

    print(f"\nFINITO!")
    print(f"  Repo processati: {processed}")
    print(f"  File estratti totali: {len(all_extracted_files)}")
    print(f"  Manifest: {MANIFEST_FILE}")
    print(f"  Clone dir: {clone_root}/")
    print(f"  Extract dir: {extract_root}/")


if __name__ == "__main__":
    main()
