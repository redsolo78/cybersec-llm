import os
import requests
import time
import json
from datetime import datetime
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv()
TOKEN = os.getenv("GITHUB_TOKEN")
HEADERS = {"Authorization": f"token {TOKEN}"} if TOKEN else {}

# ====================== CONFIGURAZIONE SUPER ======================
MIN_STARS = 3               # ← aumentato da 3 a 5 (più qualità)
MIN_FILE_SIZE = 100
MAX_PAGES_PER_QUERY = 10    # max ~300 risultati per term (sicuro sotto cap 1000)
MAX_REPOS_PER_LANG = 400
MAX_TOTAL_REPOS = 15000
START_DATE = "2025-01-01"
LANGS = ["C", "C++", "C#", "Python", "Go", "Rust", "PowerShell", "Java"]
OUTPUT_JSON = "targets_2025_2026_super.json"
OUTPUT_TXT = "targets_2025_2026_super.txt"

# Mappa GitHub corretta per language:
LANG_MAP = {
    "c": "C", "c_cpp": "C++", "csharp": "C#",
    "python": "Python", "go": "Go", "rust": "Rust",
    "powershell": "PowerShell", "java": "Java"
}

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
        "ai+memory+poisoning"
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
        "secure+boot+expiry+2026"
    ]
}

def normalize_term(term):
    """Prepara il termine per la query GitHub Repositories"""
    t = term.strip()
    # Per la ricerca repository, i termini con spazio vanno tra virgolette 
    # per cercare la frase esatta, poi convertiti in URL-encoded (+)
    if " " in t:
        t = f'"{t}"'
    return t.replace(" ", "+").replace("++", "%2B%2B").replace("#", "%23")

def start_hunting_super():
    found_repos = {}  # key: repo_url → dict completo
    total_found = 0

    print(f"[*] Super Hunter v4.2 (Fix 422) - Repository Search (pushed>={START_DATE})")

    for lang_key in LANGS:
        # Recupera il nome corretto del linguaggio per GitHub (es. csharp -> C#)
        lang = LANG_MAP.get(lang_key.lower(), lang_key)
        if total_found >= MAX_TOTAL_REPOS:
            break

        print(f"\n[+] Linguaggio: {lang.upper()}")

        for cluster_name, terms in SEARCH_CLUSTERS.items():
            if total_found >= MAX_TOTAL_REPOS:
                break

            for term in terms:
                if total_found >= MAX_TOTAL_REPOS:
                    break

                norm_term = normalize_term(term)
                # NOTA: Usiamo 'search/repositories', quindi il filtro 'size' si riferisce al repo totale
                # Rimuoviamo size se vogliamo essere più permissivi o lo teniamo per repo corposi
                base_query = f"{norm_term}+language:{lang}+pushed:>={START_DATE}+fork:false+stars:>={MIN_STARS}"
                
                for page in range(1, MAX_PAGES_PER_QUERY + 1):
                    if total_found >= MAX_TOTAL_REPOS:
                        break

                    # ENDPOINT CORRETTO: search/repositories
                    url = f"https://api.github.com/search/repositories?q={base_query}&sort=updated&order=desc&per_page=100&page={page}"
                    
                    print(f"    Ricerca: {term} [{lang}] (Pagina {page})")
                    
                    try:
                        r = requests.get(url, headers=HEADERS, timeout=15)
                        
                        if r.status_code == 200:
                            data = r.json()
                            items = data.get('items', [])
                            if not items:
                                break

                            for item in items:
                                repo_url = item['html_url']
                                stars = item.get('stargazers_count', 0)

                                if repo_url not in found_repos:
                                    found_repos[repo_url] = {
                                        "url": repo_url,
                                        "stars": stars,
                                        "description": item.get('description', ''),
                                        "language": lang,
                                        "cluster": cluster_name,
                                        "term": term,
                                        "pushed_at": item.get('pushed_at', '')
                                    }
                                    total_found += 1
                                    print(f"    [{total_found}] {repo_url} (⭐ {stars})")
                                    
                                    if total_found >= MAX_TOTAL_REPOS:
                                        break
                        
                        elif r.status_code == 422:
                            print(f"    [!] Errore 422 (Parametri non validi) per: {term}")
                            break
                        elif r.status_code == 403:
                            wait = int(r.headers.get("Retry-After", 60))
                            print(f"    [!] Rate Limit raggiunto. Attesa {wait}s...")
                            time.sleep(wait)
                            continue
                        else:
                            print(f"    [!] HTTP {r.status_code} su {term}")

                        time.sleep(2.5) # Rispetto conservativo dei limiti API

                    except Exception as e:
                        print(f"    [!] Errore: {e}")
                        time.sleep(5)

    # ====================== OUTPUT FINALE ======================
    sorted_repos = sorted(found_repos.values(), key=lambda x: x['stars'], reverse=True)

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(sorted_repos, f, indent=2, ensure_ascii=False)

    with open(OUTPUT_TXT, "w", encoding="utf-8") as f:
        for repo in sorted_repos:
            f.write(repo["url"] + "\n")

    print(f"\n[*] DATASET COMPLETATO!")
    print(f"    → {len(sorted_repos)} repository trovati per il periodo 2025-2026")
    print(f"    → JSON: {OUTPUT_JSON}")
    print(f"    → TXT:  {OUTPUT_TXT}")

if __name__ == "__main__":
    start_hunting_super()
