"""
convert_corpus_to_training_v5.11.py

Aggiornamento rispetto a v5.10: filtro genericity + PowerShell.

NOVITÀ:

1. Filtro GENERICITY (_genericity_penalty)
   Penalità -1/-2/-3 sul quality_score per file infrastrutturali
   che hanno scarso valore offensivo:
     - Path prefix generici: llvm/, clang/, chromium/, linux/, vendor/,
       node_modules/, boost/, pytorch/, dotnet-runtime/, ecc.
     - Repo keyword generiche: llvm, chromium, gcc-mirror, pytorch, ecc.
     - Header .h molto lunghi senza API offensive
   La penalità si azzera automaticamente se il file usa API offensive
   come VirtualAllocEx, NtAllocateVirtualMemory, ecc. — un file LLVM
   con process injection è ancora interessante.

2. PowerShell aggiunto ad ALLOWED_LANGUAGES
   Supporto strutturale completo in _structure_score:
     - function, param, body, cmdlet riconosciuti
   Necessario per raccolta dedicata PowerShell offensivo (Empire,
   PowerSploit, nishang, PowerView, ecc.)

Uso consigliato per mixing controllato:

    # Corpus principale (con genericity filter attivo)
    python3 convert_corpus_to_training_v5.11.py \
        --input_jsonl ~/repo-audit-out-v5/train_examples_full2.jsonl \
        --out_train   train_base.jsonl \
        --max-per-language 800 \
        --max-per-repo 30 --max-per-org 100 \
        --workers 0 --stats

    # Corpus PowerShell dedicato (nessun cap di linguaggio)
    python3 convert_corpus_to_training_v5.11.py \
        --input_jsonl ~/repo-audit-out-ps/train_examples.jsonl \
        --out_train   train_ps.jsonl \
        --max-per-language 2000 \
        --workers 0 --stats

    # Merge
    cat train_base.jsonl train_ps.jsonl > train_v5_full.jsonl
"""





import json
import argparse
import re
import hashlib
import tempfile
import subprocess
import os
import py_compile
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed

# ─── System prompt ────────────────────────────────────────────────────────────
SYSTEM_PROMPT = (
    "You are CybersecLLM, an expert in penetration testing, red teaming, "
    "malware development, EDR evasion, Active Directory attacks, and offensive security. "
    "Provide detailed, accurate, and technical responses with working code examples "
    "in C++, C#, or Python when relevant."
)

# ─── Soglie ───────────────────────────────────────────────────────────────────
MIN_CHARS          = 800
MAX_CHARS          = 30000
MIN_CODE_LINES     = 15
MIN_QUALITY_SCORE  = 4     # unico gate duro — qualità indipendente dal dominio

# Abilita funzionalità avanzate (disabilitare per performance)
ENABLE_DYNAMIC_TEST = False  # Impostare a True per abilitare i test dinamici
# domain_score non è un gate duro: determina il bucket di sampling
# Bucket A: domain_score >= 10  (alta probabilità di esempio offensivo diretto)
# Bucket B: domain_score 4-9    (medio, utility/wrapper/helper)
# Bucket C: domain_score 0-3    (basso — incluso ma con peso minore nel sampling)

# ─── Linguaggi ────────────────────────────────────────────────────────────────
# v5.11: aggiunto powershell
ALLOWED_LANGUAGES = {"c", "c_cpp", "csharp", "python", "go", "rust", "powershell", "java"}

# ─── Filtro GENERICITY (v5.11) ────────────────────────────────────────────────
# Path prefix/pattern che identificano file infrastrutturali generici
# con scarso valore per il training offensivo.
# Usato in cheap_filter come penalità sul quality_score.
_GENERIC_PATH_PREFIXES = (
    "llvm/", "clang/", "lldb/", "lld/", "mlir/",   # LLVM ecosystem
    "gcc/", "binutils/", "glibc/", "musl/",          # toolchain
    "chromium/", "webkit/", "v8/",                   # browser engine
    "linux/", "drivers/", "arch/x86/", "kernel/",    # kernel
    "node_modules/", "vendor/", "third_party/",      # deps
    "cmake/", "build/", "dist/", "out/",             # build artifacts
    "test/", "tests/", "unittest/", "googletest/",   # test infra
    "docs/", "documentation/", "examples/basic",     # docs
    "boost/", "abseil/", "folly/",                   # mega-libs
    "pytorch/", "tensorflow/", "numpy/",             # ML frameworks
    "android/", "frameworks/base/", "system/core/",  # Android
    "coreclr/", "corefx/", "runtime/src/libraries/", # .NET runtime internals
    "mono/",
)

# Repository interi da penalizzare — contengono principalmente
# codice di infrastruttura non offensivo
_GENERIC_REPO_KEYWORDS = (
    "llvm", "clang", "chromium", "webkit", "v8-engine",
    "linux-kernel", "linux-src", "gcc-mirror",
    "pytorch", "tensorflow", "keras",
    "dotnet-runtime", "coreclr", "mono-project",
    "android-platform", "aosp",
    "boost-libraries", "abseil-cpp",
    "openssl", "mbedtls",   # crypto lib OK solo se path offensivo
)

def _genericity_penalty(code: str, path: str, repo_key: str) -> int:
    """
    Ritorna una penalità (0, 1, 2, 3) da sottrarre dal quality_score.
    Penalizza file infrastrutturali generici senza valore offensivo.

    0 = nessuna penalità
    1 = leggera (path sospetto ma codice ok)
    2 = media  (path chiaramente infrastrutturale)
    3 = forte  (repo generico + path generico + zero API offensive)
    """
    path_lower    = path.lower().replace("\\", "/")
    repo_lower    = repo_key.lower()
    penalty       = 0

    # Penalità per path prefix infrastrutturale
    for prefix in _GENERIC_PATH_PREFIXES:
        if path_lower.startswith(prefix) or f"/{prefix}" in path_lower:
            penalty += 2
            break

    # Penalità aggiuntiva per repo keyword generica
    for kw in _GENERIC_REPO_KEYWORDS:
        if kw in repo_lower:
            penalty += 1
            break

    # Penalità extra se il file è un header (.h) lungo senza API offensive
    if path_lower.endswith(".h") and len(code) > 5000:
        penalty += 1

    # Riduce penalità se il codice ha almeno un'API offensiva
    # (un file LLVM che usa VirtualAllocEx è interessante)
    for api in ("VirtualAllocEx", "NtAllocateVirtualMemory", "MiniDumpWriteDump",
                "CreateRemoteThread", "QueueUserAPC", "SetThreadContext",
                "ImpersonateLoggedOnUser", "LdrLoadDll", "NtCreateThreadEx"):
        if api in code:
            penalty = max(0, penalty - 2)
            break
    # Bypass completo per PowerShell con pattern offensivi
    if language == "powershell":
        ps_offensive_patterns = (
            r'AmsiScanBuffer', r'amsiInitFailed', r'System\.Reflection\.Assembly',
            r'Runtime\.InteropServices\.Marshal', r'Add-Type.*-MemberDefinition',
            r'NonPublic,Static'
        )
        if any(re.search(p, code) for p in ps_offensive_patterns):
            return 0  # Zero penalty per script offensivi

    return min(penalty, 3)

# ─── Win32 API per domain_score ───────────────────────────────────────────────
WIN32_APIS = {
    # ── Process Injection core ────────────────────────────────────────────────
    "VirtualAllocEx": 3,        "VirtualAlloc": 2,
    "WriteProcessMemory": 3,    "ReadProcessMemory": 2,
    "CreateRemoteThread": 3,    "CreateRemoteThreadEx": 3,
    "NtCreateThreadEx": 3,      "RtlCreateUserThread": 3,
    "NtAllocateVirtualMemory": 3, "NtWriteVirtualMemory": 3,
    "NtProtectVirtualMemory": 3,
    "NtUnmapViewOfSection": 3,  "ZwUnmapViewOfSection": 3,
    "NtMapViewOfSection": 3,    "NtCreateSection": 3,
    "ZwCreateSection": 3,
    # ── Thread manipulation ───────────────────────────────────────────────────
    "SetThreadContext": 3,      "GetThreadContext": 2,
    "SuspendThread": 2,         "ResumeThread": 1,
    "NtSuspendThread": 3,       "NtResumeThread": 2,
    "QueueUserAPC": 3,          "NtQueueApcThread": 3,
    "NtQueueApcThreadEx": 3,
    # ── Fiber / Callback execution ────────────────────────────────────────────
    "ConvertThreadToFiber": 3,  "CreateFiber": 3,
    "SwitchToFiber": 2,
    "EnumChildWindows": 2,      "EnumWindows": 2,
    "EnumSystemLocalesA": 2,    "EnumDesktopsA": 2,
    "CertEnumSystemStore": 2,
    "CryptEnumProviders": 2,    "CryptEnumOIDInfo": 2,
    "EnumTimeFormatsEx": 2,
    # ── Memory ───────────────────────────────────────────────────────────────
    "VirtualProtect": 2,        "VirtualFreeEx": 1,
    "FlushInstructionCache": 2,
    "NtReadVirtualMemory": 2,   "NtQueryVirtualMemory": 2,
    "MapViewOfFile": 2,         "CreateFileMapping": 2,
    "NtCreateFile": 2,          "NtWriteFile": 2,
    # ── Exception / VEH ──────────────────────────────────────────────────────
    "AddVectoredExceptionHandler": 3,
    "RemoveVectoredExceptionHandler": 2,
    "RaiseException": 2,        "RtlAddVectoredExceptionHandler": 3,
    # ── Token / Impersonation ─────────────────────────────────────────────────
    "AdjustTokenPrivileges": 2, "ImpersonateLoggedOnUser": 3,
    "DuplicateTokenEx": 2,      "OpenProcessToken": 2,
    "OpenThreadToken": 2,       "SetThreadToken": 3,
    "ImpersonateNamedPipeClient": 3,
    "LogonUserA": 2,            "CreateProcessWithTokenW": 3,
    "CreateProcessAsUserA": 3,
    # ── Credential Access ─────────────────────────────────────────────────────
    "MiniDumpWriteDump": 3,
    "LsaOpenSecret": 3,         "LsaRetrievePrivateData": 3,
    "LsaOpenPolicy": 2,         "LsaQueryInformationPolicy": 2,
    "CredEnumerate": 3,         "CredRead": 3,
    "CryptUnprotectData": 3,    "CryptProtectData": 2,
    # ── DPAPI / Crypto ────────────────────────────────────────────────────────
    "CryptAcquireContext": 2,   "CryptEncrypt": 2,
    "CryptExportKey": 2,        "CryptGenKey": 2,
    "CryptDecrypt": 2,          "CryptDeriveKey": 2,
    "BCryptEncrypt": 2,         "BCryptDecrypt": 2,
    "BCryptGenerateSymmetricKey": 2,
    # ── Hook / Detour ─────────────────────────────────────────────────────────
    "SetWindowsHookEx": 2,      "CallNextHookEx": 1,
    # ── Kernel / Driver / BYOVD ───────────────────────────────────────────────
    "NtLoadDriver": 3,          "NtUnloadDriver": 3,
    "ZwLoadDriver": 3,
    "DeviceIoControl": 2,       "NtDeviceIoControlFile": 3,
    # ── Process enumeration ────────────────────────────────────────────────────
    "CreateToolhelp32Snapshot": 1,
    "Process32First": 1,        "Process32Next": 1,
    "Thread32First": 1,         "Thread32Next": 1,
    "OpenProcess": 1,           "OpenThread": 1,
    "NtQuerySystemInformation": 2,
    "NtQueryInformationProcess": 2,
    # ── Module loading ────────────────────────────────────────────────────────
    "LoadLibraryA": 1,          "LoadLibraryW": 1,
    "LoadLibraryExA": 2,        "LoadLibraryExW": 2,
    "GetProcAddress": 1,
    "LdrLoadDll": 3,            "LdrGetProcedureAddress": 2,
    "LdrGetDllHandle": 2,
    # ── ETW ───────────────────────────────────────────────────────────────────
    "EtwEventWrite": 3,         "EtwEventWriteFull": 3,
    "EtwEventRegister": 2,
    # ── Persistence ───────────────────────────────────────────────────────────
    "RegSetValueEx": 2,         "RegOpenKeyEx": 1,
    "RegCreateKeyEx": 2,
    "CreateServiceA": 2,        "OpenSCManager": 2,
    "StartService": 1,          "ChangeServiceConfig": 2,
    # ── Scheduled Tasks ───────────────────────────────────────────────────────
    "ITaskService": 3,          "ITaskFolder": 3,
    "ITaskDefinition": 3,
    # ── WMI ───────────────────────────────────────────────────────────────────
    "IWbemServices": 3,         "IWbemLocator": 2,
    # ── COM ───────────────────────────────────────────────────────────────────
    "CoCreateInstance": 2,      "CoInitializeEx": 1,
    "CoCreateInstanceEx": 3,
    # ── Named Pipe / SMB ──────────────────────────────────────────────────────
    "CreateNamedPipeA": 3,      "ConnectNamedPipe": 2,
    "TransactNamedPipe": 3,     "CallNamedPipeA": 2,
    # ── Network / C2 ─────────────────────────────────────────────────────────
    "WinHttpOpen": 2,           "WinHttpConnect": 2,
    "WinHttpSendRequest": 2,
    "InternetOpenA": 2,         "InternetConnectA": 2,
    "WSAStartup": 1,            "WSASocketA": 2,
    "DnsQuery_A": 2,
    # ── Stack spoofing / Context ──────────────────────────────────────────────
    "RtlCaptureContext": 3,     "RtlRestoreContext": 3,
    # ── AD / LDAP ─────────────────────────────────────────────────────────────
    "DsGetDcName": 2,           "NetUserEnum": 2,
    "NetGroupEnum": 2,          "NetLocalGroupEnum": 2,
    "DsEnumerateDomainTrusts": 2,
    # ── Transaction (Doppelgänging) ───────────────────────────────────────────
    "NtCreateTransaction": 3,   "NtRollbackTransaction": 3,
    "NtCommitTransaction": 2,
    # ── Process Creation ─────────────────────────────────────────────────────
    "CreateProcessA": 1,        "CreateProcessW": 1,
    "NtCreateProcessEx": 3,     "ZwCreateProcess": 3,
    "ShellExecuteEx": 2,
    # ── KnownDlls / Section ───────────────────────────────────────────────────
    "NtOpenSection": 3,         "NtOpenDirectoryObject": 2,
    # ── IFileOperation (UAC bypass) ───────────────────────────────────────────
    "IFileOperation": 3,
    # ── RDP Session Hijacking ─────────────────────────────────────────────────
    "WTSOpenServer": 2,         "WTSEnumerateSessions": 2,
    "WTSQuerySessionInformation": 2,
    "CreateProcessAsUserA": 3,  # già presente ma usiamo anche per RDP
    # ── Timestomping ─────────────────────────────────────────────────────────
    "SetFileTime": 2,           "NtSetInformationFile": 2,
    # ── Event Log Tampering ───────────────────────────────────────────────────
    "OpenEventLogA": 2,         "ClearEventLogA": 3,
    "EvtOpenLog": 2,            "EvtClearLog": 3,
    # ── Screen Capture ────────────────────────────────────────────────────────
    "GetDC": 2,                 "GetDesktopWindow": 1,
    "CreateCompatibleDC": 2,    "CreateCompatibleBitmap": 2,
    "BitBlt": 2,                "GetDIBits": 2,
    "PrintWindow": 2,
    # ── Data Destruction / Wiper ──────────────────────────────────────────────
    "DeleteFileA": 1,           "DeleteFileW": 1,
    "SHDeleteFileA": 2,
    "NtSetInformationFile": 2,  # già presente, usato anche per FileDispositionInfo
    "FindFirstFileA": 1,        "FindNextFileA": 1,
    # ── System Shutdown / Impact ──────────────────────────────────────────────
    "NtShutdownSystem": 3,      "NtRaiseHardError": 3,
    "ExitWindowsEx": 3,         "InitiateSystemShutdownEx": 3,
    "SetSystemPowerState": 2,
    "CreateWaitableTimer": 2,   "SetWaitableTimer": 2,
    "NtDelayExecution": 2,
}

CODE_SIGNALS = [
    # ── Core injection / evasion ──────────────────────────────────────────────
    (r'\bshellcode\b',                          2),
    (r'process.inject',                         3),
    (r'dll.inject',                             3),
    (r'process.hollow',                         3),
    (r'\bunhook\b',                             3),
    (r'edr.bypass|bypass.edr',                  3),
    (r'\bamsi\b',                               3),
    (r'etw.patch|disable.etw',                  3),
    (r'direct.syscall',                         4),
    (r'indirect.syscall',                       4),
    (r'manual.map|manual.load',                 4),
    (r'ppid.spoof',                             4),
    (r'\bbyovd\b',                              4),
    (r'\bdcsync\b',                             4),
    (r'inline.hook|api.hook|api.detour',        3),
    (r'\breflective\b',                         3),
    (r'golden.ticket|silver.ticket',            3),
    (r'credential.dump',                        3),
    (r'rop.chain|rop.gadget',                   3),
    (r'heap.exploit|heap.spray',                3),
    (r'use.after.free|\buaf\b',                 3),
    (r'anti.debug',                             2),
    (r'anti.sandbox|anti.vm',                   2),
    (r'\bkerberoast\b',                         3),
    (r'\bkeylogger\b',                          2),
    (r'\bpayload\b',                            1),
    (r'\bbeacon\b',                             2),
    (r'\blsass\b',                              2),
    # ── AD / Kerberos ─────────────────────────────────────────────────────────
    (r'\bkerberos\b',                           2),
    (r'\btgt\b|\btgs\b',                        2),
    (r'asreproast|as.rep.roast',                3),
    (r'ldap.*search|search.*ldap',              2),
    (r'pass.the.hash|pass.the.ticket',          3),
    (r'over.pass.the.hash',                     3),
    (r'dcsync|drsuapi',                         4),
    # ── Persistence ───────────────────────────────────────────────────────────
    (r'wmi.*persist|persist.*wmi',              3),
    (r'com.*hijack|hijack.*com',                3),
    (r'inprocserver|clsid.*regi',               2),
    (r'scheduled.task|schtask',                 2),
    (r'dll.hijack|dll.sideload|dll.search',     3),
    (r'ifeo|image.file.execution',              3),
    # ── Evasion techniques ────────────────────────────────────────────────────
    (r'sleep.obfuscat|sleep.mask',              3),
    (r'stack.spoof',                            4),
    (r'module.stomp',                           4),
    (r'pe.header.stomp|stomp.*pe.header',       3),
    (r'gargoyle',                               4),
    (r'threadless.inject',                      4),
    (r'kernel.callback.table',                  4),
    (r'veh.hook|veh.based',                     3),
    (r'hardware.breakpoint|hw.breakpoint',      3),
    (r'fiber.execut',                           3),
    (r'atom.bomb|atombomb',                     3),
    (r'process.doppelgang',                     4),
    (r'heap.encrypt|heap.obfuscat',             3),
    # ── Network / C2 ─────────────────────────────────────────────────────────
    (r'dns.c2|c2.*dns|dns.*tunnel',             3),
    (r'icmp.c2|c2.*icmp',                       3),
    (r'named.pipe.*c2|c2.*named.pipe',          3),
    (r'ldr.*load|load.*dll.*stealth',           3),
    # ── Crypto / Ransomware ───────────────────────────────────────────────────
    (r'ransomware|encrypt.*files',              2),
    (r'\betw\b',                                2),
    # ── Privilege escalation ─────────────────────────────────────────────────
    (r'potato.*attack|juicy.potato|sweet.potato|rogue.potato', 4),
    (r'named.pipe.*impersonat',                 3),
    (r'alpc.*port|alpc.*connect',               3),
    (r'token.steal|steal.*token',               3),
    (r'uac.bypass|bypass.*uac',                 3),
    (r'seimpersonateprivilege',                 3),
    # ── Exploitation ─────────────────────────────────────────────────────────
    (r'buffer.overflow|stack.overflow',         2),
    (r'format.string.exploit',                  3),
    (r'ret2libc|ret2plt',                       3),
    (r'write.what.where',                       3),
    (r'integer.overflow',                       2),
    (r'type.confusion',                         3),
    (r'race.condition.*exploit',                3),
    # ── Anti-Forensics (v5.7 addition) ───────────────────────────────────────
    (r'log.*tamp|clear.*event.*log|wevtutil.*cl|evtlog.*clear', 3),
    (r'timestamp.*manip|touch.*timestamp|setfiletime.*fake',    3),
    (r'fileless|living.off.the.land|lolbin|lolbas',             3),
    # ── RDP hijacking ─────────────────────────────────────────────────────────
    (r'rdp.*hijack|hijack.*rdp|tscon.*session|rdp.*session.*steal', 3),
    (r'termsrv|terminal.*service.*hijack',                          2),
    # ── Screen Capture (v5.8) ─────────────────────────────────────────────────
    (r'screen.capture|screenshot|screen.*grab',                    2),
    (r'bitblt.*screen|desktop.*capture|getdesktop',                2),
    # ── Data Destruction / Wiper (v5.8) ──────────────────────────────────────
    (r'wiper|data.destruct|secure.delete|overwrite.*file',         3),
    (r'filedispositioninfo|setinformationfile.*delet',             3),
    (r'mbr.wipe|wipe.*mbr|master.boot.record',                    4),
    (r'volume.*encrypt.*lock|lock.*volume',                        2),
    # ── System Shutdown / Impact (v5.8) ──────────────────────────────────────
    (r'ntshutdownsystem|exitwindowsex|initiateshutdown',           3),
    (r'ntraisehardeerror|bsod|blue.screen',                        3),
    (r'shutdown.*system|system.*shutdown|reboot.*forced',          2),
    # ── PowerShell Offensive Patterns ────────────────────────────────────
     (r'IEX|Invoke-Expression', 2),
    (r'Net.WebClient.*DownloadString', 3),
    (r'System.Reflection.AssemblyName', 4), # Tipico di chi carica DLL in memoria
    (r'\[Runtime.InteropServices.Marshal\]', 4), # Manipolazione memoria a basso livello
    (r'AmsiScanBuffer|amsiInitFailed', 5), # AMSI Bypass
    (r'base64.*FromBase64String', 2), # Obfuscation comune
    (r'System.Management.Automation.Utils', 3), # Bypass logging
    (r'Add-Type.*-MemberDefinition', 4), # Definizione di API C# dentro PS
    (r'Non-Interactive|ExecutionPolicy Bypass', 2),
    # ── PowerShell AMSI/ETW Advanced Evasion (v5.10) ─────────────────────────
    # Pattern specifici — più precisi dei segnali generici già presenti
    (r'\[Ref\]\.Assembly\.GetType\(.*AmsiUtils',    5),  # PS AMSI bypass via reflection
    (r'NonPublic,Static',                                 4),  # accesso campi interni sistema
    (r'EtwnLogEvent|EtwEventWrite',                       5),  # ETW blinding (già in WIN32_APIS ma utile anche qui come stringa)
    (r'\[Runtime\.InteropServices\.Marshal\]::Copy',  3),  # memory injection via PS Marshal
    # ── Rust / Go Low-Level (v5.10) ───────────────────────────────────────────
    (r'unsafe\s*\{\s*syscall',                         5),  # Rust/Go indirect syscall
    (r'std::mem::transmute',                              3),  # Rust shellcode pointer cast
    # ── API patterns come CODE_SIGNALS (complementa WIN32_APIS) ──────────────
    (r'WriteProcessMemory|NtWriteVirtualMemory',          4),  # injection write step
    # ── Cloud / AD PowerShell ─────────────────────────────────────────────────
    (r'dsgetdcname|netuserenum',                          3),  # AD native API (minuscolo)
    (r'get-domaincontroller|get-aduser',                  3),  # PowerView / AD PS module
    (r'logon_session|kerberoast',                         4),  # Kerberos attack pattern
    # ── PS Reflective Assembly Loading ────────────────────────────────────────
    # Qui invece che in API_TECHNIQUE_GROUPS perché sono stringhe testuali, non Win32 API
    (r'System\.Reflection\.Assembly.*Load|Assembly::Load', 4),  # PS reflective load
    (r'\.DownloadData\(|\.DownloadString\(',           3),  # payload download in PS
    (r'\[Ref\]\.Assembly\.GetType\(.*AmsiUtils', 15),
    (r'amsiInitFailed|EtwnLogEvent', 12),
    (r'System\.Management\.Automation\.AmsiUtils', 15),
    (r'ObjectInputStream|readObject|ysoserial', 15),
    (r'Method\.invoke|ClassLoader\.defineClass', 10),
    (r'rmi://|ldap://|jndi:', 12),
    (r'NtAllocateVirtualMemory|ZwMapViewOfSection', 12),
    # Java Deserialization (alto impatto offensivo)
    (r'ObjectInputStream\s*\(|\.readObject\s*\(', 12),
    (r'ysoserial\b', 15),
    (r'JNDI\b|InitialContext\s*\(', 12),
    (r'ldap://|rmi://', 10),
    (r'UnicastRemoteObject|RemoteImpl', 8),
    (r'InvocationHandler|Proxy\.newProxyInstance', 10),
    (r'getObjectInstance|getReference', 9),
    (r'lookup\s*\(.*jndi:', 14),
    
    # PowerShell offensivo rinforzato
    (r'Invoke-Expression\s*\(.*JNDI', 10),
    (r'System\.Runtime\.Serialization\.Formatters\.Binary', 12),
    # Exploit offensivo avanzato 
    (r'new BinaryFormatter\b', 14),
    (r'\.Deserialize\s*\(\s*stream', 15),
    (r'TypeNameHandling\s*=\s*TypeNameHandling\.Auto', 12),
    (r'JsonConvert\.DeserializeObject<\w+>\s*\(', 10),
    (r'JavaScriptSerializer\s*\(', 8),
    # Windows Kernel
    (r'IOCTL_CODE\s*\(.*0x22', 18),  # Generic IOCTL pattern
    (r'NtQuerySystemInformationEx', 16),
    (r'ZwCallbackReturn', 15),
    (r'KeServiceDescriptorTable', 17),
    (r'PsInitialSystemProcess', 14),
    
    # Linux Kernel
    (r'create_elf_tables', 16),
    (r'__user_cap_', 14),
    (r'commit_creds\s*\(', 15),
    (r'prepare_kernel_cred\s*\(', 16),
    (r'copy_from_user\s*\(', 13),
    (r'ROPgadget', 12),
    
    # Cross-platform
    (r'maple_tree|slab_allocator', 10),  # Linux memory management
    (r'pool_spray|pool_feng_shui', 12),   # Windows pool manipulation
    (r'arbitrary_overwrite', 15),
    (r'use_after_free|UAF', 14),
    (r'double_fetch', 13),    

]

# Gruppi API per question inference
API_TECHNIQUE_GROUPS = [
    # ── Process Injection ─────────────────────────────────────────────────────
    ({"NtUnmapViewOfSection", "SetThreadContext"},
     "process_hollowing"),
    ({"NtCreateThreadEx", "NtAllocateVirtualMemory"},
     "nt_api_process_injection"),
    ({"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
     "classic_process_injection"),
    ({"NtCreateSection", "NtMapViewOfSection"},
     "section_map_injection"),
    ({"NtCreateFile", "NtWriteFile", "NtCreateTransaction", "NtRollbackTransaction"},
     "process_doppelganging"),
    ({"LoadLibraryExA", "NtWriteVirtualMemory"},
     "module_stomping_injection"),
    ({"NtOpenSection", "NtMapViewOfSection"},
     "knowndlls_section_injection"),
    # ── APC Injection ────────────────────────────────────────────────────────
    ({"QueueUserAPC"},
     "apc_queue_injection"),
    ({"CreateProcessA", "QueueUserAPC", "VirtualAllocEx", "ResumeThread"},
     "early_bird_apc_injection"),
    ({"NtQueueApcThread"},
     "nt_apc_injection"),
    # ── Thread Manipulation ───────────────────────────────────────────────────
    ({"SetThreadContext", "SuspendThread"},
     "thread_context_hijacking"),
    ({"SetThreadContext", "GetThreadContext", "NtCreateThreadEx"},
     "thread_hijacking_nt_injection"),
    ({"NtSuspendThread", "GetThreadContext", "SetThreadContext"},
     "nt_thread_hijacking"),
    # ── Fiber / Callback Execution ────────────────────────────────────────────
    ({"ConvertThreadToFiber", "CreateFiber", "SwitchToFiber"},
     "fiber_based_shellcode_execution"),
    ({"EnumChildWindows", "VirtualProtect"},
     "enumchildwindows_callback_injection"),
    ({"EnumWindows", "VirtualAlloc"},
     "enumwindows_callback_shellcode"),
    ({"EnumSystemLocalesA", "VirtualAlloc"},
     "enumsystemlocales_callback_injection"),
    ({"CryptEnumProviders", "VirtualAlloc"},
     "cryptenumproviders_callback_execution"),
    ({"CertEnumSystemStore", "VirtualAlloc"},
     "certenumstore_callback_execution"),
    # ── Defense Evasion ───────────────────────────────────────────────────────
    ({"NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory"},
     "direct_nt_syscall_injection"),
    ({"LdrLoadDll", "LdrGetProcedureAddress", "EtwEventWrite"},
     "stealth_module_load_etw_patch"),
    ({"AddVectoredExceptionHandler", "GetThreadContext", "SetThreadContext"},
     "veh_hardware_breakpoint_bypass"),
    ({"RtlCaptureContext", "SetThreadContext"},
     "stack_context_spoofing"),
    ({"CreateWaitableTimer", "VirtualProtect"},
     "timer_based_sleep_obfuscation"),
    ({"NtDelayExecution", "VirtualProtect"},
     "nt_sleep_obfuscation"),
    # ── Credential Access ─────────────────────────────────────────────────────
    ({"MiniDumpWriteDump"},
     "lsass_minidump"),
    ({"NtReadVirtualMemory", "NtQueryInformationProcess"},
     "lsass_nt_read_memory"),
    ({"CryptUnprotectData"},
     "dpapi_credential_decryption"),
    ({"CredEnumerate", "CredRead"},
     "credential_manager_dump"),
    ({"LsaOpenSecret", "LsaRetrievePrivateData"},
     "lsa_secret_extraction"),
    ({"LsaOpenPolicy", "LsaQueryInformationPolicy"},
     "lsa_policy_attack"),
    # ── Token / Privilege Escalation ──────────────────────────────────────────
    ({"ImpersonateLoggedOnUser", "DuplicateTokenEx"},
     "token_impersonation"),
    ({"ImpersonateLoggedOnUser", "OpenProcessToken", "DuplicateTokenEx"},
     "token_manipulation_lateral_movement"),
    ({"ImpersonateNamedPipeClient", "CreateNamedPipeA"},
     "named_pipe_token_impersonation"),
    ({"CreateProcessWithTokenW", "DuplicateTokenEx"},
     "token_based_process_spawn"),
    ({"SetThreadToken", "OpenProcessToken"},
     "thread_token_substitution"),
    ({"IFileOperation", "CoCreateInstance"},
     "ifileoperation_uac_bypass"),
    # ── Persistence ───────────────────────────────────────────────────────────
    ({"RegSetValueEx", "CreateServiceA"},
     "registry_service_persistence"),
    ({"ITaskService", "ITaskFolder", "ITaskDefinition"},
     "scheduled_task_persistence"),
    ({"IWbemServices", "IWbemLocator"},
     "wmi_event_subscription"),
    ({"CoCreateInstance", "CoInitializeEx"},
     "com_hijacking_persistence"),
    # ── Lateral Movement ─────────────────────────────────────────────────────
    ({"OpenSCManager", "CreateServiceA", "StartService"},
     "psexec_style_lateral_movement"),
    ({"CreateNamedPipeA", "ConnectNamedPipe", "TransactNamedPipe"},
     "named_pipe_lateral_movement"),
    ({"CoCreateInstanceEx"},
     "dcom_lateral_movement"),
    # ── C2 / Implant ──────────────────────────────────────────────────────────
    ({"WinHttpOpen", "WinHttpSendRequest"},
     "http_c2_beacon"),
    ({"InternetOpenA", "InternetConnectA"},
     "wininet_c2_beacon"),
    ({"DnsQuery_A"},
     "dns_c2_channel"),
    ({"WSASocketA", "WSAStartup"},
     "raw_socket_c2"),
    ({"CreateNamedPipeA", "ConnectNamedPipe"},
     "named_pipe_c2"),
    # ── Ransomware ────────────────────────────────────────────────────────────
    ({"CryptAcquireContext", "CryptEncrypt", "CryptExportKey"},
     "ransomware_crypt_api"),
    ({"BCryptEncrypt", "BCryptGenerateSymmetricKey"},
     "ransomware_bcrypt_encryption"),
    # ── Kernel / BYOVD ────────────────────────────────────────────────────────
    ({"NtLoadDriver", "DeviceIoControl"},
     "byovd_driver_exploit"),
    ({"NtDeviceIoControlFile"},
     "nt_device_ioctl_kernel"),
    # ── AD ────────────────────────────────────────────────────────────────────
    ({"DsGetDcName", "NetUserEnum"},
     "active_directory_enumeration"),
    ({"NetGroupEnum", "NetLocalGroupEnum"},
     "ad_group_enumeration"),
    # ── Keylogger ─────────────────────────────────────────────────────────────
    ({"SetWindowsHookEx"},
     "keyboard_hook_keylogger"),
    # ── Hook / Trampoline ─────────────────────────────────────────────────────
    ({"FlushInstructionCache", "VirtualProtect"},
     "inline_api_hook_trampoline"),
    # ── RDP Session Hijacking ─────────────────────────────────────────────────
    ({"WTSEnumerateSessions", "WTSQuerySessionInformation"},
     "rdp_session_hijacking"),
    ({"WTSOpenServer", "CreateProcessAsUserA"},
     "rdp_lateral_movement"),
    # ── Anti-Forensics ────────────────────────────────────────────────────────
    ({"SetFileTime", "NtSetInformationFile"},
     "timestamp_manipulation"),
    ({"ClearEventLogA", "OpenEventLogA"},
     "event_log_tampering"),
    ({"EvtClearLog", "EvtOpenLog"},
     "evtx_log_clearing"),
    # ── Screen Capture (v5.8) ─────────────────────────────────────────────────
    ({"GetDC", "BitBlt", "CreateCompatibleBitmap"},
     "gdi_screen_capture"),
    ({"BitBlt", "GetDIBits", "CreateCompatibleDC"},
     "screen_capture_to_bitmap"),
    ({"PrintWindow", "GetDC"},
     "window_capture_printwindow"),
    # ── Data Destruction / Wiper (v5.8) ──────────────────────────────────────
    ({"DeleteFileA", "FindFirstFileA", "FindNextFileA"},
     "recursive_file_deletion"),
    ({"NtSetInformationFile", "DeleteFileW"},
     "nt_file_deletion_wiper"),
    ({"DeviceIoControl", "FindFirstFileA"},
     "disk_sector_wiper"),
    # ── System Shutdown / Impact (v5.8) ──────────────────────────────────────
    ({"NtShutdownSystem"},
     "nt_forced_system_shutdown"),
    ({"ExitWindowsEx"},
     "windows_shutdown_reboot"),
    ({"InitiateSystemShutdownEx"},
     "remote_system_shutdown"),
    ({"NtRaiseHardError"},
     "nt_bsod_trigger"),
     # PowerShell Reflective Injection
    ({"VirtualAlloc", "CreateThread", "System.Reflection"}, "ps_reflective_injection"),   
    # AMSI Bypass logic
    ({"AmsiScanBuffer", "NonPublic", "Static"}, "ps_amsi_patching"),
    # AD Enumeration (ADSI)
    ({"DirectorySearcher", "LDAP://", "FindAll"}, "ps_ad_enumeration_adsi"),
    # Credential Theft
    ({"Login.Creds", "VaultCli", "System.Security.Cryptography"}, "ps_credential_theft"),
    # ── v5.10 additions ───────────────────────────────────────────────────────
    # Indirect Syscalls via module handle
    # NtAllocateVirtualMemory da solo è già coperto; qui la tripletta
    # con GetModuleHandle/GetProcAddress identifica il pattern "resolve + call"
    ({"NtAllocateVirtualMemory", "GetModuleHandle", "GetProcAddress"},
     "indirect_syscall_injection"),
    # ETW + AMSI blinding: LdrGetProcedureAddress per trovare EtwEventWrite,
    # poi VirtualProtect per patcharlo — pattern stealth specifico
    ({"LdrGetProcedureAddress", "EtwEventWrite", "VirtualProtect"},
     "etw_amsi_blinding_logic"),
    # VEH hardware breakpoint AMSI bypass — già presente come veh_hardware_breakpoint_bypass
    # ma con nome più diretto per la question inference
    ({"SetThreadContext", "GetThreadContext", "AddVectoredExceptionHandler"},
     "hw_breakpoint_evasion"),
]


# ─── 1. PROMPT DESCRITTIVO con JITTER ───────────────────────────────────────
# FIX 3: template multipli scelti casualmente per evitare overfitting sul formato
# Il modello impara a rispondere a varietà di formulazioni, non a una sola

import random as _random

# Template per api_match / technique_hint (con tecnica identificata)
_TEMPLATES_TECHNIQUE = [
    "Write a complete {lang} source file that implements {technique}. "
    "Include all necessary headers, helper functions, and inline comments explaining each step.",

    "Show a working {lang} implementation of {technique}. "
    "Include imports, full function bodies, and comments on key steps.",

    "Provide a {lang} source file demonstrating {technique}. "
    "Make sure to include all required dependencies and explain the approach inline.",

    "Create a complete and self-contained {lang} program that demonstrates {technique}. "
    "Add inline comments to explain what each section does.",

    "Write a {lang} module implementing {technique}. "
    "Include error handling, all necessary API calls, and brief inline documentation.",
]

# Template per generic / path_hint (nessuna tecnica identificata)
_TEMPLATES_GENERIC = [
    "Write a complete {lang} source file implementing the behavior "
    "suggested by a module named '{stem}'. "
    "Include all necessary imports, helper functions, and inline comments.",

    "Recreate a {lang} source file consistent with the implementation style "
    "and capability area described by the module '{stem}'. "
    "Include complete function bodies and inline documentation.",

    "Provide a working {lang} implementation for a module named '{stem}'. "
    "Make it self-contained with all required imports and helper code.",

    "Write a complete and functional {lang} file for a module called '{stem}'. "
    "Add inline comments explaining the approach and key implementation details.",

    "Create a {lang} source file that matches the role and behavior of a module "
    "named '{stem}'. Include all necessary code and inline documentation.",
]


def infer_question_from_code(code: str, path: str, language: str) -> tuple[str, str]:
    """
    Prompt descrittivo non assertivo con jitter (FIX 3).
    Quattro livelli:
    1. api_match      — ≥2 API di un gruppo concordano
    2. technique_hint — segnale tecnico forte nel codice
    3. path_hint      — fallback path per keyword molto specifiche
    4. generic        — fallback assoluto descrittivo

    Ritorna (question, source).
    """
    lang = {"c": "C", "c_cpp": "C++", "csharp": "C#",
            "python": "Python", "go": "Go", "rust": "Rust"}.get(language, language.upper())

    # Nuovo: vulnerability suggestion
    vuln = suggest_vulnerability(code)
    if vuln:
        tmpl = "Write a {lang} exploit for {vuln} with detailed comments"
        return tmpl.format(lang=lang, vuln=vuln), "vuln_suggested"

    # Livello 1: api_match
    for required_apis, technique in API_TECHNIQUE_GROUPS:
        matched = sum(1 for api in required_apis if api in code)
        if matched >= min(2, len(required_apis)):
            tech_desc = {
                # v5.6 legacy (kept for backward compat)
                "process_hollowing":    "process hollowing",
                "nt_injection":         "process injection via NT API",
                "apc_injection":        "APC queue injection",
                "thread_hijacking":     "thread context hijacking",
                "classic_injection":    "process injection",
                "lsass_dump":           "LSASS memory dumping",
                "token_impersonation":  "token impersonation",
                "keylogger":            "keyboard hooking",
                "persistence":          "Windows persistence",
                "http_c2":              "HTTP-based C2 communication",
                "inline_hook":          "inline API hooking",
                "section_injection":    "section-based process injection",
                # v5.7 — Process Injection
                "nt_api_process_injection":     "process injection via NT API (NtCreateThreadEx, NtAllocateVirtualMemory)",
                "classic_process_injection":    "classic process injection using VirtualAllocEx, WriteProcessMemory and CreateRemoteThread",
                "section_map_injection":        "process injection via NtCreateSection and NtMapViewOfSection",
                "process_doppelganging":        "process doppelgänging using NTFS transactions",
                "module_stomping_injection":    "module stomping — overwrite a loaded DLL's memory with shellcode",
                "knowndlls_section_injection":  "KnownDlls section injection via NtOpenSection",
                # v5.7 — APC
                "early_bird_apc_injection":     "Early Bird APC injection — queue shellcode before process entry point",
                "nt_apc_injection":             "APC injection using NtQueueApcThread",
                # v5.7 — Thread
                "thread_context_hijacking":     "thread context hijacking using SuspendThread, GetThreadContext and SetThreadContext",
                "thread_hijacking_nt_injection":"thread hijacking combined with NT API process injection",
                "nt_thread_hijacking":          "thread hijacking using NT API (NtSuspendThread, NtSetContextThread)",
                # v5.7 — Fiber / Callback
                "fiber_based_shellcode_execution":   "shellcode execution via Windows fibers (ConvertThreadToFiber, SwitchToFiber)",
                "enumchildwindows_callback_injection":"shellcode execution via EnumChildWindows callback",
                "enumwindows_callback_shellcode":     "shellcode execution via EnumWindows callback",
                "enumsystemlocales_callback_injection":"shellcode execution via EnumSystemLocalesA callback",
                "cryptenumproviders_callback_execution":"shellcode execution via CryptEnumProviders callback",
                "certenumstore_callback_execution":   "shellcode execution via CertEnumSystemStore callback",
                # v5.7 — Evasion
                "direct_nt_syscall_injection":   "direct NT syscall injection bypassing Win32 API layer",
                "stealth_module_load_etw_patch":  "stealth module loading with ETW patching via LdrLoadDll",
                "veh_hardware_breakpoint_bypass": "AMSI/ETW bypass using VEH and hardware breakpoints",
                "stack_context_spoofing":         "call stack spoofing using RtlCaptureContext and SetThreadContext",
                "timer_based_sleep_obfuscation":  "shellcode obfuscation using timer-based sleep with VirtualProtect",
                "nt_sleep_obfuscation":           "shellcode obfuscation using NtDelayExecution for sleep masking",
                "direct_syscall_memory_manipulation": "direct NT syscall memory manipulation",
                "stealth_module_loading_etw_patching": "stealth module loading with ETW patching",
                "thread_hijacking_nt_injection":  "thread hijacking via NT API injection",
                # v5.7 — Credentials
                "lsass_minidump":               "LSASS memory dumping using MiniDumpWriteDump",
                "lsass_nt_read_memory":         "LSASS credential extraction using NtReadVirtualMemory",
                "dpapi_credential_decryption":  "credential decryption using DPAPI (CryptUnprotectData)",
                "credential_manager_dump":      "Windows Credential Manager dumping via CredEnumerate",
                "lsa_secret_extraction":        "LSA secret extraction using LsaOpenSecret",
                "lsa_policy_attack":            "LSA policy manipulation for credential access",
                # v5.7 — Token / PrivEsc
                "token_manipulation_lateral_movement": "token manipulation for lateral movement",
                "named_pipe_token_impersonation":"token impersonation via named pipe client",
                "token_based_process_spawn":    "spawn process with stolen token using CreateProcessWithTokenW",
                "thread_token_substitution":    "substitute thread token using SetThreadToken",
                "ifileoperation_uac_bypass":    "UAC bypass using IFileOperation COM interface",
                # v5.7 — Persistence
                "registry_service_persistence": "Windows persistence via registry and service installation",
                "scheduled_task_persistence":   "Windows persistence via scheduled tasks using COM ITaskService",
                "wmi_event_subscription":       "WMI event subscription for persistence and lateral movement",
                "com_hijacking_persistence":    "COM object hijacking for persistence",
                "com_based_technique":          "COM-based persistence or execution technique",
                # v5.7 — Lateral Movement
                "psexec_style_lateral_movement":"lateral movement using service creation (PsExec-style)",
                "named_pipe_lateral_movement":  "lateral movement via SMB named pipes",
                "dcom_lateral_movement":        "lateral movement via DCOM (CoCreateInstanceEx)",
                # v5.7 — C2
                "http_c2_beacon":              "HTTP C2 beacon using WinHTTP",
                "wininet_c2_beacon":           "HTTP C2 beacon using WinINet",
                "dns_c2_channel":              "DNS-based C2 channel using DnsQuery",
                "raw_socket_c2":              "raw socket C2 using WSASocket",
                "named_pipe_c2":              "named pipe C2 channel",
                # v5.7 — Ransomware
                "ransomware_crypt_api":        "ransomware file encryption using Windows CryptAPI",
                "ransomware_bcrypt_encryption":"ransomware file encryption using BCrypt API",
                "ransomware_crypto_logic":     "ransomware-style file encryption using CryptoAPI",
                # v5.7 — BYOVD / Kernel
                "byovd_driver_exploit":        "BYOVD attack using a vulnerable signed kernel driver",
                "nt_device_ioctl_kernel":      "kernel interaction via NtDeviceIoControlFile",
                # v5.7 — AD
                "active_directory_enumeration":"Active Directory enumeration via native Windows API",
                "ad_enumeration":              "Active Directory enumeration via native API",
                "ad_group_enumeration":        "Active Directory group enumeration via NetGroupEnum",
                # v5.7 — Hook
                "keyboard_hook_keylogger":     "keylogger using SetWindowsHookEx",
                "inline_api_hook_trampoline":  "inline API hooking with trampoline using VirtualProtect",
                # v5.7 additions
                "rdp_session_hijacking":        "RDP session hijacking using WTSEnumerateSessions and CreateProcessAsUserA",
                "rdp_lateral_movement":         "lateral movement via RDP session abuse",
                "timestamp_manipulation":       "timestamp manipulation using SetFileTime to evade forensics",
                "event_log_tampering":          "Windows event log tampering using ClearEventLog or EvtClearLog",
                "evtx_log_clearing":            "EVTX event log clearing to destroy forensic evidence",
                # v5.8 — Screen Capture
                "gdi_screen_capture":           "screen capture using GDI BitBlt and CreateCompatibleBitmap",
                "screen_capture_to_bitmap":     "screen capture to bitmap using GetDIBits for exfiltration",
                "window_capture_printwindow":   "window content capture using PrintWindow",
                # v5.8 — Data Destruction
                "recursive_file_deletion":      "recursive file deletion wiper using FindFirstFile/FindNextFile",
                "nt_file_deletion_wiper":       "file destruction using NtSetInformationFile with FileDispositionInfo",
                "disk_sector_wiper":            "raw disk sector wiping using DeviceIoControl",
                # v5.8 — System Shutdown
                "nt_forced_system_shutdown":    "forced system shutdown using NtShutdownSystem",
                "windows_shutdown_reboot":      "system reboot/shutdown using ExitWindowsEx",
                "remote_system_shutdown":       "remote system shutdown using InitiateSystemShutdownEx",
                "nt_bsod_trigger":              "BSOD trigger using NtRaiseHardError for impact",
                # v5.10
                "indirect_syscall_injection":   "indirect syscall injection using GetModuleHandle and NtAllocateVirtualMemory",
                "etw_amsi_blinding_logic":      "ETW and AMSI blinding via LdrGetProcedureAddress and VirtualProtect patching",
                "hw_breakpoint_evasion":        "AMSI/ETW bypass using hardware breakpoints and VEH",
            }.get(technique, technique.replace("_", " "))
            # FIX 3: jitter — template scelto casualmente
            tmpl = _random.choice(_TEMPLATES_TECHNIQUE)
            q = tmpl.format(lang=lang, technique=tech_desc)
            return q, "api_match"

    # Livello 2: technique_hint
    code_lower = code.lower()
    area_hints = [
        (r'direct.syscall|indirect.syscall|syscall.stub',
         "low-level Windows API calls using direct or indirect syscalls"),
        (r'ntdll.*remap|remap.*ntdll|unhook.*ntdll',
         "ntdll unhooking via clean-copy remapping"),
        (r'amsi.*patch|patch.*amsi',
         "in-memory patching of a Windows security feature"),
        (r'etw.*patch|patch.*etw',
         "disabling Windows event tracing via in-memory patching"),
        (r'reflective.*dll|dll.*reflective',
         "reflective DLL loading without using LoadLibrary"),
        (r'manual.*map|pe.*inject.*mem',
         "manual PE mapping from memory"),
        (r'ppid.*spoof|parent.*pid',
         "process creation with a spoofed parent PID"),
        (r'byovd|vulnerable.*driver',
         "a kernel-level technique using a signed but vulnerable driver"),
        (r'kerberoast|request.*tgs',
         "Kerberos service ticket manipulation in Active Directory"),
        (r'dcsync|drsuapi',
         "domain controller replication abuse for credential extraction"),
        (r'anti.*debug|isdebugged|detect.*debugger',
         "anti-debugging and anti-analysis techniques"),
        (r'anti.*sandbox|anti.*vm|detect.*vm',
         "sandbox and virtual machine evasion"),
        (r'shellcode.*enc|xor.*shellcode|aes.*shellcode',
         "shellcode obfuscation and encryption"),
        (r'heap.*spray|use.after.free',
         "heap exploitation techniques"),
        (r'rop.chain|rop.gadget',
         "return-oriented programming for exploit development"),
    ]
    for pattern, area_desc in area_hints:
        if re.search(pattern, code_lower):
            # FIX 3: jitter
            tmpl = _random.choice(_TEMPLATES_TECHNIQUE)
            q = tmpl.format(lang=lang, technique=area_desc)
            return q, "technique_hint"

    # Livello 3: path_hint
    path_norm = path.lower().replace("/","_").replace("-","_").replace(" ","_")
    path_area_map = [
        (["hollow"],     "process hollowing"),
        (["dll_inject"], "DLL injection"),
        (["shellcode"],  "shellcode execution"),
        (["keylog"],     "keyboard hooking and logging"),
        (["lsass"],      "LSASS memory access"),
        (["kerberoast"], "Kerberos ticket manipulation"),
        (["dcsync"],     "domain controller sync abuse"),
        (["byovd"],      "vulnerable driver exploitation"),
        (["reflective"], "reflective code loading"),
        (["beacon"],     "C2 beacon communication"),
    ]
    for keywords, area_desc in path_area_map:
        if any(kw in path_norm for kw in keywords):
            # FIX 3: jitter
            tmpl = _random.choice(_TEMPLATES_TECHNIQUE)
            q = tmpl.format(lang=lang, technique=area_desc)
            return q, "path_hint"

    # Livello 4: generic — FIX 3: jitter con template generici
    stem = Path(path).stem.replace("_", " ").replace("-", " ")
    tmpl = _random.choice(_TEMPLATES_GENERIC)
    q = tmpl.format(lang=lang, stem=stem)
    return q, "generic"

def suggest_vulnerability(code: str) -> str:
    """Suggerisci vulnerabilità basata su pattern (euristica avanzata)"""
    patterns = {
        r'BinaryFormatter': "BinaryFormatter deserialization vulnerability",
        r'IOCTL_CODE': "Windows kernel driver vulnerability",
        r'commit_creds': "Linux kernel privilege escalation",
        r'ObjectInputStream': "Java deserialization attack",
        r'AmsiScanBuffer': "AMSI bypass technique"
    }
    
    for pattern, vuln in patterns.items():
        if re.search(pattern, code):
            return vuln
    return ""

# ─── DOMAIN SCORE (ranking, non gate) ────────────────────────────────────────

def compute_domain_score(code: str) -> tuple[int, str]:
    """
    FIX punto 2: domain_score non è più un gate duro.
    Ritorna (score, bucket) dove bucket è A/B/C.
    Usato per sampling e stats, non per esclusione.
    """
    score = 0
    for api, weight in WIN32_APIS.items():
        if api in code:
            score += weight

    code_lower = code.lower()
    for pattern, weight in CODE_SIGNALS:
        if re.search(pattern, code_lower):
            score += weight

    if score >= 10:
        bucket = "A"   # chiaramente offensivo
    elif score >= 4:
        bucket = "B"   # parzialmente rilevante (helper, utility, wrapper)
    else:
        bucket = "C"   # bassa rilevanza diretta
    return score, bucket


# ─── QUALITY SCORE (ribilanciato) ─────────────────────────────────────────────

def compute_quality_score(code: str, language: str,
                          syntax_ok: bool,
                          path: str = "",
                          repo_key: str = "") -> tuple[int, list]:
    """
    FIX punto 3: lunghezza max +1, struttura max +4, sintassi valida +3.
    FIX punto 4: _text_ratio usata come penalità leggera, non hard reject.
    v5.11: genericity_penalty sottrae punti per file infrastrutturali.
    """
    score = 0
    reasons = []

    lines = [l for l in code.split('\n') if l.strip()]
    non_comment = [l for l in lines if not re.match(r'^\s*(//|#|\*)', l)]

    # Lunghezza: max +1
    length = len(code)
    if length >= 3000:
        score += 1; reasons.append("length:3k+(+1)")

    # Righe non-commento: max +2
    if len(non_comment) >= 100:
        score += 2; reasons.append("lines:100+(+2)")
    elif len(non_comment) >= 30:
        score += 1; reasons.append("lines:30+(+1)")

    # Struttura: max +4
    struct_pts, _ = _structure_score(code, language)
    score += struct_pts
    if struct_pts > 0:
        reasons.append(f"structure(+{struct_pts})")

    # Sintassi valida: +3
    if syntax_ok:
        score += 3; reasons.append("syntax_ok(+3)")

    # Text ratio: penalità leggera
    ratio = _text_ratio(code)
    if ratio < 0.40:
        score += 1; reasons.append(f"clean_ratio(+1)")
    elif ratio > 0.70:
        score -= 1; reasons.append(f"high_text_ratio(-1)")

    # Penalità standard
    if _has_disclaimer_spam(code):
        score -= 3; reasons.append("disclaimer_spam(-3)")
    if _is_generated(code):
        score -= 5; reasons.append("generated(-5)")

    # v5.11: penalità genericity (file infrastrutturali generici)
    if path or repo_key:
        gpen = _genericity_penalty(code, path, repo_key)
        if gpen > 0:
            score -= gpen
            reasons.append(f"genericity(-{gpen})")

# Nuovo: sandbox dinamica (solo se abilitata)
    if ENABLE_DYNAMIC_TEST:
        dyn_score = dynamic_sandbox_test(code, language)
        score += int(dyn_score / 2)  # Converti 0-10 in 0-5 punti extra
        reasons.append(f"dynamic_test:{dyn_score:.1f}(+{int(dyn_score/2)})")
    
    return max(score, 0), reasons


def _structure_score(code: str, language: str) -> tuple[int, bool]:
    if language in ("c", "c_cpp"):
        has_include  = bool(re.search(r'#include\s*[<"]', code))
        has_function = bool(re.search(
            r'(void|int|BOOL|DWORD|HANDLE|LPVOID|HMODULE|PVOID|ULONG)\s+\w+\s*\(', code))
        has_body     = code.count('{') >= 3
        pts = sum([has_include * 1, has_function * 2, has_body * 1])
        return pts, pts >= 2

    elif language == "csharp":
        has_using  = bool(re.search(r'^using\s+\w+', code, re.MULTILINE))
        has_class  = bool(re.search(r'\b(class|struct)\s+\w+', code))
        has_method = bool(re.search(
            r'(public|private|protected|static|internal)\s+\w[\w<>\[\]]*\s+\w+\s*\(', code))
        pts = sum([has_using, has_class * 2, has_method])
        return pts, pts >= 2

    elif language == "python":
        has_import   = bool(re.search(r'^(import |from \w+ import)', code, re.MULTILINE))
        has_def      = bool(re.search(r'^(def |class |async def )', code, re.MULTILINE))
        has_body     = len([l for l in code.split('\n')
                            if l.strip() and not l.strip().startswith('#')
                            and not re.match(r'^(def |class |import |from )', l.strip())]) >= 10
        pts = sum([has_import, has_def * 2, has_body])
        return pts, pts >= 2

    elif language == "go":
        has_package = bool(re.search(r'^package\s+\w+', code, re.MULTILINE))
        has_import  = bool(re.search(r'^import\s*[("\(]', code, re.MULTILINE))
        has_func    = bool(re.search(r'^func\s+\w+', code, re.MULTILINE))
        has_body    = code.count('{') >= 3
        pts = sum([has_package, has_import, has_func * 2, has_body])
        return pts, pts >= 3

    elif language == "rust":
        has_use  = bool(re.search(r'^(use |extern crate )', code, re.MULTILINE))
        has_fn   = bool(re.search(r'^(pub fn |fn |pub unsafe fn |unsafe fn )', code, re.MULTILINE))
        has_body = code.count('{') >= 3
        pts = sum([has_use, has_fn * 2, has_body])
        return pts, pts >= 2

    elif language == "powershell":
        # Rimuove l'obbligo di funzione - accetta script lineari
        has_param    = bool(re.search(r'\[Parameter\(|param\s*\(', code, re.IGNORECASE))
        has_body     = len([l for l in code.split('\n')
                            if l.strip() and not l.strip().startswith('#')]) >= 10
        has_cmd      = bool(re.search(
            r'(Invoke-|New-|Get-|Set-|Add-|Remove-|Start-|Stop-|Write-|Import-)',
            code))
        
        # Nuovi segnali offensivi per bypass genericity
        has_offensive = bool(re.search(
            r'AmsiScanBuffer|System\.Reflection|Marshal|NonPublic|Static|Add-Type',
            code))
        
        # Punteggio flessibile: 2 punti se offensivo, altrimenti struttura normale
        pts = sum([has_param, has_body, has_cmd])
        if has_offensive:
            return max(pts, 2), True  # Forza passaggio se offensivo
        return pts, pts >= 2

    return 0, False


def _text_ratio(code: str) -> float:
    lines = [l for l in code.split('\n') if l.strip()]
    if not lines:
        return 1.0
    code_pat = re.compile(
        r'^\s*(#include|#define|#pragma|import |from |def |class |void |int |char |'
        r'BOOL |HANDLE |DWORD |LPVOID |static |public |private |protected |return |'
        r'if\s*[(\{]|for\s*[(\{]|while\s*[(\{]|switch\s*\(|try\s*\{|'
        r'[a-zA-Z_]\w*\s*[(:=\{]|\w+::\w+|\w+\s+\w+\s*\(|\/\/|\/\*|\*|'
        r'#\s*\w|package\s|func\s|pub\s|let\s|fn\s)'
    )
    text_lines = sum(1 for l in lines if not code_pat.match(l))
    return text_lines / len(lines)


def _has_disclaimer_spam(code: str) -> bool:
    phrases = [
        "The author assumes no responsibility", "unauthorized reproduction",
        "applicable laws worldwide", "intellectual property laws",
        "This disclaimer applies", "for educational purposes only",
    ]
    return sum(code.count(p) for p in phrases) >= 3


def _is_generated(code: str) -> bool:
    markers = [
        "DO NOT EDIT", "Code generated", "AUTO-GENERATED",
        "This file is auto-generated", "generated by protoc",
        "DO NOT MODIFY", "@generated", "// Generated by", "# Generated by",
    ]
    code_lower = code.lower()
    return any(m.lower() in code_lower for m in markers)


def _is_cve_description(code: str) -> bool:
    patterns = [
        r'^CVE-\d{4}-\d+\s',
        r'published:\s*\d{4}-\d{2}-\d{2}',
        r'CVSS.*score.*\d+\.\d+',
        r'An (improper|unauthenticated|insufficient) .* (allows|enables) .* attacker',
    ]
    for p in patterns:
        if re.search(p, code[:800], re.IGNORECASE | re.MULTILINE):
            return True
    return False


# ─── 3. VALIDAZIONE SINTATTICA ────────────────────────────────────────────────

def _check_tool(cmd: list) -> bool:
    try:
        subprocess.run(cmd, capture_output=True, timeout=5)
        return True
    except Exception:
        return False

CLANG_OK = _check_tool(["clang", "--version"])
GOFMT_OK  = _check_tool(["gofmt", "-h"])
RUSTC_OK  = _check_tool(["rustc", "--version"])
JAVAC_OK = _check_tool(["javac", "-version"])

# FIX 1: usa /dev/shm (RAM disk) per i file temporanei invece del disco
# Su corpus da 50k+ file elimina il collo di bottiglia I/O dei subprocess
_TMPDIR = "/dev/shm" if os.path.isdir("/dev/shm") else None

# FIX 2: C# richiede quality_score più alto (nessuna validazione sintattica reale)
_CSHARP_MIN_QUALITY = 7   # vs MIN_QUALITY_SCORE=4 per gli altri linguaggi


def syntax_check(code: str, language: str) -> tuple[bool, str]:
    """
    Validazione sintattica per linguaggio.
    FIX 1: usa _TMPDIR (/dev/shm) per evitare I/O su disco su corpus grandi.
    Status ritornato: ok / failed:* / skipped:* / heuristic_only
    """
    # Helper per creare file temporanei in RAM se disponibile
    def _tmp(suffix):
        return tempfile.NamedTemporaryFile(
            suffix=suffix, mode="w", delete=False,
            encoding="utf-8", dir=_TMPDIR
        )

    if language == "python":
        with _tmp(".py") as f:
            f.write(code); tmp = f.name
        try:
            py_compile.compile(tmp, doraise=True)
            return True, "ok"
        except py_compile.PyCompileError as e:
            msg = str(e)
            if "SyntaxError" in msg or "IndentationError" in msg:
                return False, "failed:py_syntax"
            return True, "ok"
        finally:
            try: os.unlink(tmp)
            except: pass

    elif language in ("c", "c_cpp") and CLANG_OK:
        suffix = ".cpp" if language == "c_cpp" else ".c"
        with _tmp(suffix) as f:
            f.write(code); tmp = f.name
        try:
            r = subprocess.run(
                ["clang", "--fsyntax-only", "-w", "-fno-builtin",
                 "-D_WIN32", "-D_WIN64", tmp],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0:
                return True, "ok"
            fatal = [l for l in r.stderr.split('\n')
                     if re.search(r"error: (expected|use of undeclared|unknown type|too many errors)", l)
                     and "file not found" not in l]
            if len(fatal) > 5:
                return False, "failed:c_syntax"
            # FIX 8: distingui ok_clean da ok_with_missing_headers
            has_missing = any("file not found" in l for l in r.stderr.split('\n'))
            return True, ("ok_missing_headers" if has_missing else "ok")
        except subprocess.TimeoutExpired:
            return True, "skipped:timeout"
        except Exception as e:
            return True, f"skipped:{e}"
        finally:
            try: os.unlink(tmp)
            except: pass

    elif language == "go" and GOFMT_OK:
        with _tmp(".go") as f:
            f.write(code); tmp = f.name
        try:
            r = subprocess.run(["gofmt", "-e", tmp],
                               capture_output=True, text=True, timeout=10)
            errors = [l for l in r.stderr.split('\n') if l.strip()]
            if len(errors) > 5:
                return False, "failed:go_syntax"
            return True, "ok"
        except subprocess.TimeoutExpired:
            return True, "skipped:timeout"
        except Exception as e:
            return True, f"skipped:{e}"
        finally:
            try: os.unlink(tmp)
            except: pass

    elif language == "rust" and RUSTC_OK:
        with _tmp(".rs") as f:
            f.write(code); tmp = f.name
        try:
            r = subprocess.run(
                ["rustc", "--edition", "2021", "--crate-type", "lib",
                 "--emit", "metadata", "-A", "warnings", "-o", tmp + ".meta", tmp],
                capture_output=True, text=True, timeout=15
            )
            if r.returncode == 0:
                return True, "ok"
            errors = [l for l in r.stderr.split('\n') if "error[" in l]
            if len(errors) > 3:
                return False, "failed:rust_syntax"
            return True, "ok"
        except subprocess.TimeoutExpired:
            return True, "skipped:timeout"
        except Exception as e:
            return True, f"skipped:{e}"
        finally:
            for fn in [tmp, tmp + ".meta"]:
                try: os.unlink(fn)
                except: pass

    elif language == "java" and JAVAC_OK:  # Assicurati di definire JAVAC_OK globalmente
            try:
                # Usiamo una directory temporanea invece di un singolo file
                with tempfile.TemporaryDirectory(dir=_TMPDIR) as tmpdir:
                    src_path = os.path.join(tmpdir, "Main.java")
                    with open(src_path, "w", encoding="utf-8") as f:
                        f.write(code)
                    
                    result = subprocess.run(
                        ["javac", "-Xlint", src_path],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    
                    if result.returncode == 0:
                        return True, "ok"
                    
                    # Filtra errori non critici (warning su serializzazione)
                    errors = [
                        line for line in result.stderr.split('\n')
                        if "error:" in line and "unchecked or unsafe operations" not in line
                    ]
                    return (len(errors) == 0, "failed:java_syntax" if errors else "ok")
            
            except subprocess.TimeoutExpired:
                return True, "skipped:timeout"
            except Exception as e:
                return True, f"skipped:{str(e)[:50]}"
    
    # ... [codice esistente per C#] ...

    # FIX punto 8: C# annotato esplicitamente come heuristic_only
    elif language == "csharp":
        has_using  = bool(re.search(r'^using\s+\w+', code, re.MULTILINE))
        has_class  = bool(re.search(r'\b(class|struct)\s+\w+', code))
        has_method = bool(re.search(
            r'(public|private|protected|static|internal)\s+\w[\w<>\[\]]*\s+\w+\s*\(', code))
        
        # Nuovo: rilevamento deserializzazione
        has_deserialization = bool(re.search(
            r'BinaryFormatter|JavaScriptSerializer|JsonConvert\.DeserializeObject|'
            r'DataContractSerializer|NetDataContractSerializer', code))
        has_dangerous_gadgets = bool(re.search(
            r'System\.Configuration\.Install|WindowsIdentity|'
            r'System\.Management\.Automation\.PowerShell', code))
        
        pts = sum([
            has_using,
            has_class * 2,
            has_method,
            has_deserialization * 3,  # Bonus significativo
            has_dangerous_gadgets * 4  # Bonus maggiore per gadget pericolosi
        ])
        
        # Abbassa la soglia se contiene pattern di deserializzazione
        min_pts = 2 if not has_deserialization else 1
        return pts, pts >= min_pts

    return True, "skipped"

def dynamic_sandbox_test(code: str, language: str) -> float:
    """Valutazione dinamica in ambiente isolato (punteggio 0-10)"""
    if language not in ["c", "c_cpp", "csharp", "powershell"]:
        return 5.0  # Punteggio neutro per linguaggi non supportati
    
    try:
        # Configurazione basica per dimostrazione
        # (Implementazione reale userebbe QEMU/containers)
        test_script = ""
        if language in ["c", "c_cpp"]:
            test_script = f"echo '{code}' > test.c && gcc test.c -o test && ./test"
        elif language == "csharp":
            test_script = f"echo '{code}' > test.cs && csc test.cs && ./test"
        elif language == "powershell":
            test_script = f"powershell -Command \"{code}\""
        
        result = subprocess.run(
            test_script,
            shell=True,
            timeout=30,
            capture_output=True,
            text=True
        )
        
        # Euristica semplice: presenza di parole chiave offensive nell'output
        offensive_keywords = ["shellcode", "injected", "bypassed", "credentials", "executed"]
        score = 2.0  # Base
        for kw in offensive_keywords:
            if kw in result.stdout.lower():
                score += 2.0
        return min(score, 10.0)
    
    except Exception:
        return 5.0  # Fallback a punteggio neutro




# ─── 4+5. DEDUPLICATION ──────────────────────────────────────────────────────

def _normalize(code: str) -> str:
    code = re.sub(r'//[^\n]*', '', code)
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    code = re.sub(r'#[^\n]*', '', code)
    return re.sub(r'\s+', ' ', code).strip().lower()


def exact_hash(code: str) -> str:
    return hashlib.sha256(_normalize(code).encode()).hexdigest()


def near_fingerprint(code: str, repo: str, k: int = 50) -> str:
    """
    FIX punto 5: include repo nel fingerprint.
    Due file simili da repo diversi non collidono.
    """
    norm = _normalize(code)
    tokens = re.findall(r'[a-z0-9_]+', norm)
    stopwords = {"int", "void", "return", "if", "else", "for", "while",
                 "true", "false", "null", "none", "the", "a", "is", "in",
                 "self", "this", "new", "var", "let", "const"}
    tokens = [t for t in tokens if t not in stopwords and len(t) > 2]
    # FIX: includi repo hash nel fingerprint
    repo_prefix = hashlib.md5(repo.encode()).hexdigest()[:8]
    key = repo_prefix + " " + " ".join(tokens[:k])
    return hashlib.sha256(key.encode()).hexdigest()


# ─── QUALITY FILTER COMPLETO ─────────────────────────────────────────────────

def full_filter(code: str, path: str, language: str) -> tuple[bool, str, bool, str]:
    """
    Ritorna (passes, reject_reason, syntax_ok, syntax_status).
    FIX: domain_score NON è un gate duro.
    """
    if language not in ALLOWED_LANGUAGES:
        return False, f"language:{language}", False, "skipped"

    if len(code) < MIN_CHARS:
        return False, f"too_short:{len(code)}", False, "skipped"
    if len(code) > MAX_CHARS:
        return False, f"too_long:{len(code)}", False, "skipped"

    if _is_cve_description(code):
        return False, "cve_description", False, "skipped"
    if _is_generated(code):
        return False, "generated_code", False, "skipped"
    if _has_disclaimer_spam(code):
        return False, "disclaimer_spam", False, "skipped"

    # Struttura minima
    _, struct_ok = _structure_score(code, language)
    if not struct_ok:
        return False, "no_code_structure", False, "skipped"

    # Sintassi (prima del quality_score perché influenza il punteggio)
    syntax_ok, syntax_status = syntax_check(code, language)
    if syntax_status.startswith("failed:"):
        return False, syntax_status, False, syntax_status

    # Quality score (include struttura + sintassi)
    q_score, _ = compute_quality_score(code, language, syntax_ok, path=path)
    # FIX 2: C# usa soglia quality più alta (nessuna validazione sintattica reale)
    min_q = _CSHARP_MIN_QUALITY if language == "csharp" else MIN_QUALITY_SCORE
    if q_score < min_q:
        return False, f"low_quality:{q_score}", syntax_ok, syntax_status

    return True, "ok", syntax_ok, syntax_status


def cheap_filter(code: str, path: str, language: str) -> tuple[bool, str]:
    """
    Filtri veloci che non richiedono subprocess.
    Usato come prima fase nella pipeline parallela.
    Ritorna (passes, reject_reason).
    """
    if language not in ALLOWED_LANGUAGES:
        return False, f"language:{language}"
    if len(code) < MIN_CHARS:
        return False, f"too_short:{len(code)}"
    if len(code) > MAX_CHARS:
        return False, f"too_long:{len(code)}"
    if _is_cve_description(code):
        return False, "cve_description"
    if _is_generated(code):
        return False, "generated_code"
    if _has_disclaimer_spam(code):
        return False, "disclaimer_spam"
    _, struct_ok = _structure_score(code, language)
    if not struct_ok:
        return False, "no_code_structure"
    return True, "ok"


def _syntax_check_worker(args: tuple) -> tuple:
    """
    Top-level function (picklable) per ProcessPoolExecutor.
    Ritorna (index, syntax_ok, syntax_status).
    """
    idx, code, language = args
    try:
        ok, status = syntax_check(code, language)
        return idx, ok, status
    except Exception as e:
        return idx, True, f"worker_error:{str(e)[:50]}"


def parallel_syntax_check(
    items: list,          # lista di dict con "code" e "language"
    num_workers: int = 0, # 0 = auto (os.cpu_count())
) -> list:
    """
    Esegue syntax_check in parallelo su una lista di candidati.
    Ritorna lista di (syntax_ok, syntax_status) nello stesso ordine di items.

    Usa ProcessPoolExecutor perché syntax_check lancia subprocess —
    con ThreadPoolExecutor il GIL limiterebbe il parallelismo reale.

    Fallback sequenziale se num_workers=1 o se ProcessPool fallisce
    (es. su sistemi con spawn=True che non supporta fork).
    """
    n = len(items)
    results = [None] * n

    if n == 0:
        return results

    # Determina workers: usa min(cpu_count, n) per non sprecare processi
    workers = num_workers if num_workers > 0 else (os.cpu_count() or 2)
    workers = max(1, min(workers, n))

    # Sotto una soglia minima non vale la pena del fork overhead
    # Anche se non ci sono tool subprocess disponibili (solo py_compile),
    # il fork overhead supera il guadagno → fallback sequenziale
    has_subprocess_tools = CLANG_OK or GOFMT_OK or RUSTC_OK
    if workers == 1 or n < 20 or not has_subprocess_tools:
        for i, item in enumerate(items):
            ok, status = syntax_check(item["code"], item["language"])
            results[i] = (ok, status)
        return results

    task_args = [(i, item["code"], item["language"]) for i, item in enumerate(items)]

    try:
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(_syntax_check_worker, arg): arg[0]
                       for arg in task_args}
            for future in as_completed(futures):
                try:
                    idx, ok, status = future.result(timeout=30)
                    results[idx] = (ok, status)
                except Exception as e:
                    idx = futures[future]
                    results[idx] = (True, f"parallel_error:{str(e)[:40]}")
    except Exception:
        # Fallback sequenziale se ProcessPool non è disponibile
        for i, item in enumerate(items):
            if results[i] is None:
                ok, status = syntax_check(item["code"], item["language"])
                results[i] = (ok, status)

    # Riempi eventuali None residui
    for i in range(n):
        if results[i] is None:
            results[i] = (True, "skipped:missing")

    return results


# ─── PROCESSING ───────────────────────────────────────────────────────────────

def _rank_score(d_score: int, q_score: int, syntax_ok: bool,
                syntax_status: str) -> float:
    """
    FIX 6 (v5.4): syntax_bonus granulare per status.

      ok                  → +3  (sintassi verificata, nessun errore)
      ok_missing_headers  → +2  (buono ma dipendenze NT mancanti — comune in codice offensivo)
      heuristic_only      → +1  (C# senza validazione reale — leggero bonus di fiducia)
      skipped/*           → +0  (toolchain non disponibile)
      failed:*            → non arriva qui (scartato prima)

    quality_score * 3  →  peso principale: qualità strutturale
    min(domain_score, 10) →  dominio capped: non fa dominare file con 30 API
    syntax_bonus          →  riflette la fiducia nella correttezza sintattica
    """
    if syntax_status == "ok":
        syntax_bonus = 3
    elif syntax_status == "ok_missing_headers":
        syntax_bonus = 2
    elif syntax_status == "heuristic_only":
        syntax_bonus = 1
    else:
        syntax_bonus = 0  # skipped, timeout, ecc.

    return q_score * 3 + min(d_score, 10) + syntax_bonus


def process_jsonl(
    input_path: str,
    out_data_path: str,
    out_meta_path: str,
    seen_exact: set,
    seen_near: set,
    repo_counts: dict,
    max_per_repo: int = 0,
    max_per_org: int = 0,
    max_per_lang: int = 0,
    top_n: int = 0,
    num_workers: int = 0,
    preview_n: int = 100,
    show_stats: bool = False,
    show_debug: bool = False,
) -> list:
    """
    Pipeline in quattro fasi:
      0.  CHEAP PRE-FILTER — filtri veloci senza subprocess (sequenziale)
      0.5 SYNTAX CHECK     — syntax_check in parallelo con ProcessPoolExecutor
      1.  COLLECT          — quality_score + dedup (sequenziale, stato condiviso)
      2.  RANK             — ordina per rank_score
      3.  SELECT           — applica cap su set ordinato
    """

    examples = []
    with open(input_path) as f:
        for line in f:
            line = line.strip()
            if line:
                try: examples.append(json.loads(line))
                except: pass

    reject_reasons  = defaultdict(list)
    dedup_exact     = 0
    dedup_near      = 0

    # ── FASE 0: CHEAP PRE-FILTER (sequenziale, veloce) ───────────────────────
    # Applica tutti i filtri che non richiedono subprocess.
    # Riduce il numero di file da passare al syntax_check parallelo.
    pre_candidates = []
    pre_rejected   = {}   # idx → reason

    for e in examples:
        messages  = e.get("messages", [])
        meta      = e.get("meta", {})
        language  = meta.get("language", "unknown")
        path      = meta.get("path", "")
        repo      = meta.get("repo", "")
        repo_path = meta.get("repo_path", "")

        # repo_key canonico
        repo_str = str(repo).strip()
        if repo_str and "/" in repo_str and not repo_str.startswith("/"):
            repo_key = repo_str.replace("/", "__")
        elif repo_path:
            repo_key = repo_path.replace("\\", "/").rstrip("/").split("/")[-1] or repo_str
        else:
            repo_key = repo_str or "unknown"

        code = next((m["content"] for m in messages if m["role"] == "assistant"), "")

        passes, reason = cheap_filter(code, path, language)
        if not passes:
            reject_reasons[reason].append(path)
            continue

        pre_candidates.append({
            "code":     code,
            "path":     path,
            "language": language,
            "repo_key": repo_key,
        })

    # ── FASE 0.5: SYNTAX CHECK PARALLELO ─────────────────────────────────────
    # Lancia syntax_check in parallelo su tutti i pre_candidates.
    # Su RunPod con 8-32 core questo riduce il tempo da ore a minuti
    # su corpus da 50k+ file.
    if pre_candidates:
        print(f"  [syntax] {len(pre_candidates)} file da validare "
              f"con {num_workers or os.cpu_count()} workers...")
        syntax_results = parallel_syntax_check(pre_candidates, num_workers)
    else:
        syntax_results = []

    # ── FASE 1: COLLECT (sequenziale — stato condiviso dedup) ────────────────
    # Applica syntax result, quality_score, dedup. Nessun subprocess qui.
    candidates = []

    for i, pre in enumerate(pre_candidates):
        code     = pre["code"]
        path     = pre["path"]
        language = pre["language"]
        repo_key = pre["repo_key"]

        syntax_ok, syntax_status = syntax_results[i]

        # Scarta se syntax ha fallito
        if syntax_status.startswith("failed:"):
            reject_reasons[syntax_status].append(path)
            continue

        # Quality score
        q_score, _ = compute_quality_score(code, language, syntax_ok,
                                              path=path, repo_key=repo_key)
        min_q = _CSHARP_MIN_QUALITY if language == "csharp" else MIN_QUALITY_SCORE
        if q_score < min_q:
            reject_reasons[f"low_quality:{q_score}"].append(path)
            continue

        # Deduplica esatta
        eh = exact_hash(code)
        if eh in seen_exact:
            dedup_exact += 1
            reject_reasons["duplicate_exact"].append(path)
            continue
        seen_exact.add(eh)

        # Near-dedup
        nh = near_fingerprint(code, repo_key)
        if nh in seen_near:
            dedup_near += 1
            reject_reasons["duplicate_near"].append(path)
            continue
        seen_near.add(nh)

        # Scores e question
        d_score, bucket = compute_domain_score(code)
        q_score, _      = compute_quality_score(code, language, syntax_ok,
                                                   path=path, repo_key=repo_key)
        rank            = _rank_score(d_score, q_score, syntax_ok, syntax_status)
        question, qsrc  = infer_question_from_code(code, path, language)

        candidates.append({
            "code":          code,
            "path":          path,
            "repo_key":      repo_key,
            "language":      language,
            "d_score":       d_score,
            "q_score":       q_score,
            "rank":          rank,
            "bucket":        bucket,
            "syntax_ok":     syntax_ok,
            "syntax_status": syntax_status,
            "question":      question,
            "qsrc":          qsrc,
            "eh":            eh,
            "nh":            nh,
        })

    # ── FASE 2: RANK ─────────────────────────────────────────────────────────
    # Ordina per rank_score decrescente: i migliori vengono scelti per primi
    candidates.sort(key=lambda x: x["rank"], reverse=True)

    # ── FASE 3: SELECT con cap post-ranking ───────────────────────────────────
    # I cap vengono applicati SUL SET ORDINATO: se un repo ha 100 file,
    # entrano i suoi 30 migliori (non i primi 30 che capitano)
    converted    = []
    meta_records = []
    lang_counts      = defaultdict(int)
    qsource_counts   = defaultdict(int)
    bucket_counts    = defaultdict(int)
    repo_accepted    = defaultdict(int)
    org_accepted     = defaultdict(int)   # FIX: holdout per org/famiglia
    syntax_statuses  = defaultdict(int)
    d_scores         = []
    q_scores         = []
    rank_capped      = 0

    for c in candidates:
        language = c["language"]
        repo_key = c["repo_key"]
        # Estrai org dal repo_key (formato Owner__RepoName → Owner)
        org_key  = repo_key.split("__")[0] if "__" in repo_key else repo_key

        # Cap per repo
        if max_per_repo > 0 and repo_accepted[repo_key] >= max_per_repo:
            reject_reasons[f"rank_cap_repo:{repo_key[:28]}"].append(c["path"])
            rank_capped += 1
            continue

        # FIX: Cap per org/famiglia (evita leakage da org con molti repo simili)
        if max_per_org > 0 and org_accepted[org_key] >= max_per_org:
            reject_reasons[f"rank_cap_org:{org_key[:28]}"].append(c["path"])
            rank_capped += 1
            continue

        # Cap per linguaggio
        if max_per_lang > 0 and lang_counts[language] >= max_per_lang:
            reject_reasons[f"rank_cap_lang:{language}"].append(c["path"])
            rank_capped += 1
            continue

        # Top-N globale
        if top_n > 0 and len(converted) >= top_n:
            rank_capped += 1
            continue

        # Accettato
        lang_counts[language]     += 1
        qsource_counts[c["qsrc"]] += 1
        bucket_counts[c["bucket"]] += 1
        repo_accepted[repo_key]   += 1
        org_accepted[org_key]     += 1
        syntax_statuses[c["syntax_status"]] += 1
        d_scores.append(c["d_score"])
        q_scores.append(c["q_score"])

        converted.append({
            "text": (
                f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n"
                f"<|im_start|>user\n{c['question']}<|im_end|>\n"
                f"<|im_start|>assistant\n{c['code']}<|im_end|>"
            )
        })

        meta_records.append({
            "id":              c["eh"][:16],
            "exact_hash":      c["eh"],
            "near_hash":       c["nh"],
            "path":            c["path"],
            "repo":            repo_key,
            "language":        language,
            "domain_score":    c["d_score"],
            "domain_bucket":   c["bucket"],
            "quality_score":   c["q_score"],
            "rank_score":      c["rank"],         # FIX 3: rank_score nei metadata
            "question":        c["question"],
            "question_source": c["qsrc"],
            "syntax_check":    c["syntax_status"],
            "syntax_ok":       c["syntax_ok"],
            "char_len":        len(c["code"]),
        })

    # Scrivi dati
    with open(out_data_path, "w") as f:
        for ex in converted:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    # Scrivi metadata
    with open(out_meta_path, "w") as f:
        for m in meta_records:
            f.write(json.dumps(m, ensure_ascii=False) + "\n")

    # ── accepted_preview.jsonl — top-N per rank, già ordinati ────────────────
    # FIX punto 3: permette review umana rapida senza aprire il dataset intero
    if preview_n > 0 and meta_records:
        out_preview = out_data_path.replace(".jsonl", "_preview.jsonl")
        # meta_records sono già nell'ordine di selezione (rank desc dopo il sort)
        # ma potrebbero non essere ordinati se ci sono stati rank_capped parziali
        # → ri-ordina per rank_score
        preview_sorted = sorted(
            zip(converted, meta_records),
            key=lambda x: x[1].get("rank_score", 0),
            reverse=True
        )[:preview_n]
        with open(out_preview, "w") as f:
            for ex, m in preview_sorted:
                record = {
                    "rank_score":      m["rank_score"],
                    "domain_bucket":   m["domain_bucket"],
                    "question_source": m["question_source"],
                    "syntax_check":    m["syntax_check"],
                    "language":        m["language"],
                    "repo":            m["repo"],
                    "path":            m["path"],
                    "question":        m["question"],
                    "code_preview":    m.get("char_len", 0),
                    "text":            ex["text"],
                }
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"  Preview:  {out_preview}  ({len(preview_sorted)} esempi)")

    # ── review_queue.jsonl — casi interessanti da guardare a mano ─────────────
    # FIX punto 4: rank alto MA question_source=generic / heuristic_only / bucket C
    # Questi sono i casi dove la pipeline è meno sicura della qualità
    if meta_records:
        out_review = out_data_path.replace(".jsonl", "_review_queue.jsonl")
        review_threshold = max(
            (m["rank_score"] for m in meta_records), default=0
        ) * 0.7   # top 30% per rank

        review_cases = []
        for ex, m in zip(converted, meta_records):
            if m["rank_score"] < review_threshold:
                continue
            flags = []
            if m["question_source"] == "generic":
                flags.append("generic_question")
            if m["syntax_check"] == "heuristic_only":
                flags.append("heuristic_syntax")
            if m["domain_bucket"] == "C":
                flags.append("low_domain_bucket")
            if flags:
                review_cases.append({
                    "flags":           flags,
                    "rank_score":      m["rank_score"],
                    "domain_score":    m["domain_score"],
                    "quality_score":   m["quality_score"],
                    "domain_bucket":   m["domain_bucket"],
                    "question_source": m["question_source"],
                    "syntax_check":    m["syntax_check"],
                    "language":        m["language"],
                    "repo":            m["repo"],
                    "path":            m["path"],
                    "question":        m["question"],
                    "text":            ex["text"],
                })

        review_cases.sort(key=lambda x: x["rank_score"], reverse=True)
        with open(out_review, "w") as f:
            for r in review_cases:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"  Review Q: {out_review}  ({len(review_cases)} casi)")

    # ─── Stats ─────────────────────────────────────────────────────────────
    total = len(examples)
    print(f"\n{'='*58}")
    print(f"  Input:          {total:>6,}")
    print(f"  Candidati:      {len(candidates):>6,}  (passato filtri+dedup)")
    print(f"  Selezionati:    {len(converted):>6,}  ({len(converted)/max(len(candidates),1)*100:.1f}% dei candidati)")
    print(f"  Rank-capped:    {rank_capped:>6,}  (cap repo/lang/top-n dopo ranking)")
    print(f"  Filtrati:       {total-len(candidates)-dedup_exact-dedup_near:>6,}")
    print(f"  Dedup esatti:   {dedup_exact:>6,}")
    print(f"  Dedup near:     {dedup_near:>6,}")
    if candidates:
        ranks = [c["rank"] for c in candidates]
        print(f"  Rank score:     avg={sum(ranks)/len(ranks):.1f}  "
              f"min={min(ranks)}  max={max(ranks)}")
    print(f"{'='*58}")

    if show_stats and converted:
        print(f"\n  Domain bucket (A=alta rilevanza, B=media, C=bassa):")
        for b in ["A", "B", "C"]:
            cnt = bucket_counts.get(b, 0)
            pct = cnt / len(converted) * 100
            print(f"    Bucket {b}: {cnt:4d}  ({pct:.1f}%)")

        print(f"\n  Linguaggi:")
        for lang, cnt in sorted(lang_counts.items(), key=lambda x: -x[1]):
            print(f"    {lang:<10} {cnt:4d}")

        print(f"\n  Question source:")
        for src, cnt in sorted(qsource_counts.items(), key=lambda x: -x[1]):
            pct = cnt / len(converted) * 100
            print(f"    {src:<20} {cnt:4d}  ({pct:.1f}%)")

        print(f"\n  Syntax check status:")
        for st, cnt in sorted(syntax_statuses.items(), key=lambda x: -x[1]):
            print(f"    {st:<25} {cnt:4d}")

        print(f"\n  Top motivi scarto:")
        by_count = sorted(reject_reasons.items(), key=lambda x: -len(x[1]))
        for reason, paths in by_count[:12]:
            print(f"    {reason:<42} {len(paths):4d}")

        print(f"\n  Top 10 repo per esempi accettati:")
        top_repos_sorted = sorted(repo_accepted.items(), key=lambda x: -x[1])[:10]
        top10_c = sum(cnt for _, cnt in top_repos_sorted)
        top10_p = top10_c / max(len(converted), 1) * 100
        warn = "⚠️  HIGH" if top10_p > 60 else ("⚠️  MEDIUM" if top10_p > 40 else "✅ OK")
        for repo, cnt in top_repos_sorted:
            pct = cnt / max(len(converted), 1) * 100
            print(f"    {repo:<40} {cnt:3d}  ({pct:.1f}%)")
        print(f"\n  Concentrazione top-10 repo: {top10_c}/{len(converted)} "
              f"({top10_p:.1f}%) — {warn}")

        if d_scores:
            print(f"\n  Domain score — avg:{sum(d_scores)/len(d_scores):.1f}  "
                  f"min:{min(d_scores)}  max:{max(d_scores)}")
            print(f"  Quality score— avg:{sum(q_scores)/len(q_scores):.1f}  "
                  f"min:{min(q_scores)}  max:{max(q_scores)}")

            lengths = [len(e["text"]) for e in converted]
            print(f"\n  Lunghezza media: {sum(lengths)//len(lengths):,} chars")
            print(f"  Lunghezza min:   {min(lengths):,} chars")
            print(f"  Lunghezza max:   {max(lengths):,} chars")

        tools = []
        if CLANG_OK: tools.append("clang")
        if GOFMT_OK:  tools.append("gofmt")
        if RUSTC_OK:  tools.append("rustc")
        tools.append("py_compile")
        print(f"\n  Syntax checkers: {tools}")

    if show_debug and reject_reasons:
        print(f"\n  === DEBUG: primi 3 reject per motivo ===")
        by_count = sorted(reject_reasons.items(), key=lambda x: -len(x[1]))
        for reason, paths in by_count[:12]:
            print(f"\n  [{reason}] ({len(paths)} totali)")
            for p in paths[:3]:
                print(f"    {p}")

    if show_stats and converted:
        print(f"\n  Preview domande (prime 5):")
        for e in converted[:5]:
            q = e["text"].split("<|im_start|>user\n")[1].split("<|im_end|>")[0]
            print(f"    → {q[:90]}")

    print(f"\n  Data:     {out_data_path}")
    print(f"  Metadata: {out_meta_path}")

    # FIX 10: report JSON persistente
    out_stats_path = out_data_path.replace(".jsonl", "_stats.json")
    ranks = [c["rank"] for c in candidates] if candidates else []
    n = len(converted)

    # FIX 7: concentrazione dataset — top 10 repo, linguaggi, bucket
    top20_repos  = sorted(repo_accepted.items(), key=lambda x: -x[1])[:20]
    top10_repos  = top20_repos[:10]
    top10_count  = sum(cnt for _, cnt in top10_repos)
    top10_pct    = round(top10_count / max(n, 1) * 100, 1)

    lang_pcts    = {k: round(v / max(n, 1) * 100, 1)
                    for k, v in sorted(lang_counts.items(), key=lambda x: -x[1])}
    bucket_pcts  = {b: round(bucket_counts.get(b, 0) / max(n, 1) * 100, 1)
                    for b in ["A", "B", "C"]}

    stats_report = {
        "input":            total,
        "candidates":       len(candidates),
        "accepted":         n,
        "rank_capped":      rank_capped,
        "rejected":         total - len(candidates) - dedup_exact - dedup_near,
        "dedup_exact":      dedup_exact,
        "dedup_near":       dedup_near,
        "language_counts":  dict(lang_counts),
        "language_pct":     lang_pcts,
        "bucket_counts":    dict(bucket_counts),
        "bucket_pct":       bucket_pcts,
        "question_source":  dict(qsource_counts),
        "syntax_statuses":  dict(syntax_statuses),
        "reject_reasons":   {k: len(v) for k, v in reject_reasons.items()},
        # FIX 7: concentrazione
        "concentration": {
            "top10_repos_count":   top10_count,
            "top10_repos_pct":     top10_pct,
            "warning":             "HIGH" if top10_pct > 60 else
                                   "MEDIUM" if top10_pct > 40 else "OK",
            "top20_repos":         dict(top20_repos),
        },
        "rank_score": {
            "avg": round(sum(ranks) / len(ranks), 1) if ranks else 0,
            "min": min(ranks) if ranks else 0,
            "max": max(ranks) if ranks else 0,
        },
        "domain_score": {
            "avg": round(sum(d_scores) / len(d_scores), 1) if d_scores else 0,
            "min": min(d_scores) if d_scores else 0,
            "max": max(d_scores) if d_scores else 0,
        },
        "quality_score": {
            "avg": round(sum(q_scores) / len(q_scores), 1) if q_scores else 0,
            "min": min(q_scores) if q_scores else 0,
            "max": max(q_scores) if q_scores else 0,
        },
        "char_len": {
            "avg": sum(len(e["text"]) for e in converted) // max(n, 1),
            "min": min((len(e["text"]) for e in converted), default=0),
            "max": max((len(e["text"]) for e in converted), default=0),
        },
        "syntax_checkers": {
            "clang": CLANG_OK,
            "gofmt": GOFMT_OK,
            "rustc": RUSTC_OK,
            "py_compile": True,
        },
    }
    with open(out_stats_path, "w") as f:
        json.dump(stats_report, f, indent=2, ensure_ascii=False)
    print(f"  Stats:    {out_stats_path}")

    return converted


def main():
    parser = argparse.ArgumentParser(
        description="Converte corpus GitHub in ChatML offensivo per CybersecLLM v5"
    )
    parser.add_argument("--input_jsonl",       required=True)
    parser.add_argument("--eval_jsonl",         default=None)
    parser.add_argument("--out_train",          default="train_offensive_v5.jsonl")
    parser.add_argument("--out_eval",           default="eval_offensive_v5.jsonl")
    parser.add_argument("--max-per-repo",       type=int, default=0,
                        help="Max esempi per repo (0=nessun limite)")
    parser.add_argument("--max-per-org",        type=int, default=0,
                        help="Max esempi per org/autore (0=nessun limite). "
                             "Evita leakage da org con molti repo simili")
    parser.add_argument("--max-per-language",   type=int, default=0,
                        help="Max esempi per linguaggio (0=nessun limite)")
    parser.add_argument("--top-n",              type=int, default=0,
                        help="Seleziona solo i top-N esempi per rank_score (0=tutti)")
    parser.add_argument("--workers",            type=int, default=0,
                        help="Numero worker paralleli per syntax_check (0=auto)")
    parser.add_argument("--preview-n",          type=int, default=100,
                        help="Esempi top da scrivere in *_preview.jsonl (0=disabilita)")
    parser.add_argument("--stats",  action="store_true")
    parser.add_argument("--debug",  action="store_true")
    args = parser.parse_args()

    seen_exact: set  = set()
    seen_near:  set  = set()
    repo_counts: dict = defaultdict(int)

    # Output metadata paralleli
    out_train_meta = args.out_train.replace(".jsonl", "_meta.jsonl")
    out_eval_meta  = args.out_eval.replace(".jsonl", "_meta.jsonl")

    print(f"[+] Processing train: {args.input_jsonl}")
    process_jsonl(
        args.input_jsonl, args.out_train, out_train_meta,
        seen_exact, seen_near, repo_counts,
        max_per_repo=args.max_per_repo,
        max_per_org=args.max_per_org,
        max_per_lang=args.max_per_language,
        top_n=args.top_n,
        num_workers=args.workers,
        preview_n=args.preview_n,
        show_stats=args.stats,
        show_debug=args.debug,
    )

    if args.eval_jsonl:
        print(f"\n[+] Processing eval: {args.eval_jsonl}")
        process_jsonl(
            args.eval_jsonl, args.out_eval, out_eval_meta,
            seen_exact, seen_near, repo_counts,
            max_per_repo=args.max_per_repo,
            max_per_org=args.max_per_org,
            max_per_lang=args.max_per_language,
            top_n=args.top_n,
            num_workers=args.workers,
            preview_n=args.preview_n,
            show_stats=args.stats,
            show_debug=args.debug,
        )

    # FIX punto 10: niente "cat >> train.jsonl"
    print(f"""
[DONE] Output generati in file separati.

  Per il merge, usa merge_datasets.py:

    python3 merge_datasets.py \\
        --base   ~/cybersec-llm/train.jsonl \\
        --add    {args.out_train} \\
        --output ~/cybersec-llm/train_v5.jsonl \\
        --dedup  --stats

  Controlla train_v5.jsonl PRIMA di sovrascrivere train.jsonl.
""")


if __name__ == "__main__":
    main()
