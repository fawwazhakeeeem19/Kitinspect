 
"""
KitInspect Python Analysis Engine v1.0.0
Advanced APK analysis with YARA integration, ML-based scoring, and behavioral analysis.
For defensive security analysis and threat detection only.
"""

import sys
import os
import json
import hashlib
import zipfile
import re
import math
import argparse
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from typing import List, Dict, Optional

 

@dataclass
class BehaviorIndicator:
    name: str
    description: str
    severity: str
    category: str
    evidence: str = ""

@dataclass
class AdvancedResult:
    file_path: str
    file_name: str
    analyzed_at: str
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    file_size: int = 0
    entropy: float = 0.0
    behavior_indicators: list = field(default_factory=list)
    yara_matches: list = field(default_factory=list)
    ml_score: float = 0.0
    ml_features: dict = field(default_factory=dict)
    obfuscation_score: float = 0.0
    network_indicators: list = field(default_factory=list)
    crypto_usage: list = field(default_factory=list)
    suspicious_apis: list = field(default_factory=list)
    embedded_dex_count: int = 0
    threat_indicators: list = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "low"
    confidence: float = 0.0
    recommendations: list = field(default_factory=list)
    raw_strings_count: int = 0

BEHAVIOR_PATTERNS = [
 
    (r'Runtime\.exec|ProcessBuilder|cmd\.exe|/bin/sh|/bin/bash',
     "Command Execution", "critical", "runtime_exec",
     "Code capable of executing system commands detected"),
 
    (r'DexClassLoader|PathClassLoader|loadDex|dalvik\.system',
     "Dynamic Code Loading", "high", "dynamic_loading",
     "Application loads code dynamically at runtime, evading static analysis"),
 
    (r'AccessibilityService|onAccessibilityEvent|performAction',
     "Accessibility Service Abuse", "critical", "accessibility",
     "Accessibility service usage — may enable screen reading or click injection"),
 
    (r'captureScreen|screenshot|MediaProjection|createVirtualDisplay',
     "Screen Capture Capability", "critical", "screen_capture",
     "Code capable of capturing device screen"),
 
    (r'getDeviceId|getSubscriberId|getSimSerialNumber|getImei|IMEI',
     "Device ID Harvesting", "high", "device_id",
     "Reads unique device identifiers"),
 
    (r'SmsManager|sendTextMessage|sendDataMessage|SmsMessage',
     "SMS Operations", "high", "sms",
     "Can send or intercept SMS messages"),
 
    (r'isDebuggerConnected|Debug\.isDebuggerConnected|android\.os\.Debug',
     "Anti-Debug Detection", "high", "anti_debug",
     "Checks whether a debugger is attached"),
    (r'isEmulator|goldfish|vbox|genymotion|generic.*Build\.FINGERPRINT',
     "Emulator Detection", "high", "anti_emulator",
     "Detects analysis environments to alter behavior"),
    (r'/system/bin/su|/sbin/su|RootBeer|checkRoot|isRooted',
     "Root/Jailbreak Detection", "medium", "root_detection",
     "Detects rooted devices — may refuse to run in analysis environment"),
    (r'BOOT_COMPLETED|PACKAGE_REPLACED|autostart',
     "Boot Persistence", "high", "persistence",
     "Registers to start automatically at device boot"),
    (r'ServerSocket|DatagramSocket|socket\(\s*AF_INET',
     "Raw Socket Usage", "high", "raw_socket",
     "Creates raw network connections — unusual for standard apps"),
    (r'getDeclaredMethods|getDeclaredFields|invoke\(|forName\(',
     "Reflection Usage", "medium", "reflection",
     "Heavy use of Java reflection — common in obfuscated/packed apps"),
    (r'Cipher\.getInstance|SecretKeySpec|AESCrypt|DESKeySpec',
     "Cryptographic Operations", "medium", "crypto",
     "Performs cryptographic operations on data"),
    (r'javascript:|addJavascriptInterface|loadUrl.*javascript',
     "JavaScript Interface Exposure", "high", "js_injection",
     "WebView exposes Java methods to JavaScript — XSS attack surface"),
    (r'onKeyEvent|KeyEvent|getKeyCharacterMap|dispatchKeyEvent',
     "Key Event Monitoring", "high", "keylogging",
     "Monitors all key events — potential keylogging behavior"),
    (r'System\.loadLibrary|System\.load|dlopen|dlsym',
     "Native Library Loading", "medium", "native_load",
     "Loads native code at runtime"),
    (r'HttpURLConnection|OkHttpClient|Retrofit|Volley',
     "HTTP Client Usage", "info", "http_client",
     "Network communication library detected"),
    (r'getExternalStorageDirectory|DIRECTORY_DOWNLOADS|Environment\.getExternal',
     "External Storage Access", "medium", "file_system",
     "Reads or writes to external storage"),
    (r'AccountManager|getPassword|getAuthToken|invalidateAuthToken',
     "Account Manager Access", "high", "account_access",
     "Accesses account credentials stored on device"),
    (r'Camera\.open|CameraManager|AudioRecord|MediaRecorder',
     "Camera/Microphone Access", "high", "av_capture",
     "Accesses camera or microphone hardware"),
]


CRYPTO_PATTERNS = {
    'AES': r'AES|AESCrypt|SecretKeySpec.*AES',
    'RSA': r'RSA|RSAPublicKey|RSAPrivateKey',
    'DES': r'DESKeySpec|DES/|TripleDES',
    'MD5': r'MessageDigest.*MD5|\.md5\(',
    'SHA': r'MessageDigest.*SHA|\.sha256\(',
    'Base64': r'Base64\.encode|Base64\.decode',
    'XOR_Obfuscation': r'xor|XOR|\^=|\^\s+0x[0-9a-fA-F]',
}

SUSPICIOUS_API_CLASSES = [
    'android.telephony.SmsManager',
    'android.location.LocationManager',
    'android.hardware.Camera',
    'android.media.AudioRecord',
    'android.accounts.AccountManager',
    'android.app.admin.DevicePolicyManager',
    'android.accessibilityservice.AccessibilityService',
    'java.lang.Runtime',
    'java.lang.ProcessBuilder',
    'java.lang.reflect.Method',
    'dalvik.system.DexClassLoader',
    'android.media.projection.MediaProjection',
]


def compute_obfuscation_score(strings: List[str]) -> float:
    """Score 0-100 based on obfuscation indicators."""
    score = 0.0
    total = len(strings) + 1

    short_names = sum(1 for s in strings if re.match(r'^[a-z]{1,3}$', s) and '.' not in s)
    score += min(short_names / total * 40, 25)

    b64_count = sum(1 for s in strings if re.match(r'^[A-Za-z0-9+/]{40,}={0,2}$', s))
    score += min(b64_count / total * 60, 25)

    long_strings = sum(1 for s in strings if len(s) > 500)
    score += min(long_strings / total * 40, 20)

    unicode_count = sum(1 for s in strings if re.search(r'\\u[0-9a-fA-F]{4}', s))
    score += min(unicode_count / total * 30, 15)

    packed_names = sum(1 for s in strings if re.match(r'^([a-z]{1,3}\.){2,}[a-z]{1,3}$', s))
    score += min(packed_names / total * 30, 15)

    return min(score, 100.0)

def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def compute_hashes(path: str) -> Dict[str, str]:
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
    return {
        'md5': h_md5.hexdigest(),
        'sha1': h_sha1.hexdigest(),
        'sha256': h_sha256.hexdigest(),
    }

def extract_strings_from_bytes(data: bytes, min_len: int = 5) -> List[str]:
    results = []
    current = []
    for byte in data:
        if 0x20 <= byte < 0x7f:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                results.append(''.join(current))
            current = []
    if len(current) >= min_len:
        results.append(''.join(current))
    return results

def extract_ml_features(strings: List[str], file_size: int, entropy: float) -> Dict:
    """Extract numerical features for ML-based risk scoring."""
    combined = '\n'.join(strings)

    features = {
        'file_size_kb': file_size / 1024,
        'entropy': entropy,
        'string_count': len(strings),
        'url_count': len(re.findall(r'https?://', combined)),
        'ip_count': len(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', combined)),
        'base64_count': len(re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', combined)),
        'crypto_api_count': sum(1 for p in CRYPTO_PATTERNS.values()
                                if re.search(p, combined)),
        'reflection_count': len(re.findall(r'getDeclared|forName|invoke\(', combined)),
        'exec_count': len(re.findall(r'Runtime\.exec|ProcessBuilder', combined)),
        'dynamic_load_count': len(re.findall(r'DexClassLoader|loadDex', combined)),
        'accessibility_count': len(re.findall(r'AccessibilityService', combined)),
        'sms_count': len(re.findall(r'SmsManager|sendTextMessage', combined)),
        'short_class_ratio': sum(1 for s in strings if re.match(r'^[a-z]{1,3}$', s)) / max(len(strings), 1),
    }
    return features

def ml_risk_score(features: Dict) -> float:
    """
    Heuristic ML-style scoring.
    Weights are tuned based on known malware behavioral patterns.
    """
    score = 0.0

 
    if features['entropy'] > 7.5:
        score += 20
    elif features['entropy'] > 7.0:
        score += 12
    elif features['entropy'] > 6.5:
        score += 6

 
    score += min(features['exec_count'] * 15, 25)
    score += min(features['dynamic_load_count'] * 12, 20)
    score += min(features['accessibility_count'] * 18, 20)
    score += min(features['sms_count'] * 10, 15)

 
    score += min(features['ip_count'] * 5, 15)
    score += min(features['url_count'] * 0.5, 10)

 
    score += min(features['crypto_api_count'] * 4, 12)

 
    score += min(features['short_class_ratio'] * 30, 15)
    score += min(features['base64_count'] * 2, 10)

 
    score += min(features['reflection_count'] * 3, 10)

    return min(round(score, 2), 100.0)

 

def run_yara_scan(apk_path: str, rules_dir: str) -> List[Dict]:
    """Run YARA rules if yara-python is available."""
    matches = []
    try:
        import yara
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            return []

        for rule_file in rules_path.glob('*.yar'):
            try:
                rules = yara.compile(str(rule_file))
                file_matches = rules.match(apk_path)
                for m in file_matches:
                    matches.append({
                        'rule': m.rule,
                        'tags': list(m.tags),
                        'meta': dict(m.meta),
                        'severity': m.meta.get('severity', 'medium'),
                        'description': m.meta.get('description', ''),
                        'rule_file': rule_file.name,
                    })
            except Exception:
                continue
    except ImportError:
        pass
    return matches

 

class APKAnalyzer:
    def __init__(self, apk_path: str, rules_dir: str = None):
        self.apk_path = apk_path
        self.rules_dir = rules_dir or str(Path(__file__).parent.parent / 'yara_rules')

    def analyze(self) -> AdvancedResult:
        path = Path(self.apk_path)
        result = AdvancedResult(
            file_path=str(path.resolve()),
            file_name=path.name,
            analyzed_at=datetime.utcnow().isoformat() + 'Z',
        )

 
        hashes = compute_hashes(self.apk_path)
        result.md5 = hashes['md5']
        result.sha1 = hashes['sha1']
        result.sha256 = hashes['sha256']
        result.file_size = path.stat().st_size

 
        if not zipfile.is_zipfile(self.apk_path):
            result.risk_level = "unknown"
            return result

        all_strings = []
        dex_count = 0

        with zipfile.ZipFile(self.apk_path, 'r') as zf:
            for entry in zf.namelist():
                if entry.endswith('.dex'):
                    dex_count += 1
                    try:
                        data = zf.read(entry)
                        strings = extract_strings_from_bytes(data, min_len=5)
                        all_strings.extend(strings)
                    except Exception:
                        continue

        result.embedded_dex_count = dex_count
        result.raw_strings_count = len(all_strings)

 
        try:
            with open(self.apk_path, 'rb') as f:
                sample = f.read(1024 * 1024)
            result.entropy = compute_entropy(sample)
        except Exception:
            pass

 
        combined_text = '\n'.join(all_strings)
        for pattern, name, severity, category, description in BEHAVIOR_PATTERNS:
            if re.search(pattern, combined_text):
                evidence_matches = re.findall(pattern, combined_text)
                evidence = evidence_matches[0] if evidence_matches else ""
                result.behavior_indicators.append(asdict(BehaviorIndicator(
                    name=name,
                    description=description,
                    severity=severity,
                    category=category,
                    evidence=str(evidence)[:100],
                )))

 
        for crypto_name, pattern in CRYPTO_PATTERNS.items():
            if re.search(pattern, combined_text):
                result.crypto_usage.append(crypto_name)

 
        urls = list(set(re.findall(r'https?://[a-zA-Z0-9.\-_/?=&#%+@:]{8,}', combined_text)))
        ips = list(set(re.findall(r'\b(?!10\.|192\.168\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.)(\d{1,3}\.){3}\d{1,3}\b', combined_text)))
        domains = list(set(re.findall(r'(?i)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|app|dev|xyz)', combined_text)))
        result.network_indicators = urls[:50] + [f"ip:{ip}" for ip in ips[:20]] + [f"domain:{d}" for d in domains[:30]]

 
        for api in SUSPICIOUS_API_CLASSES:
            if api.replace('.', '/') in combined_text or api in combined_text:
                result.suspicious_apis.append(api)

 
        result.obfuscation_score = compute_obfuscation_score(all_strings)

 
        result.ml_features = extract_ml_features(all_strings, result.file_size, result.entropy)
        result.ml_score = ml_risk_score(result.ml_features)

 
        result.yara_matches = run_yara_scan(self.apk_path, self.rules_dir)

 
        result.risk_score = self._compute_final_score(result)
        result.risk_level = self._classify_risk(result.risk_score)
        result.confidence = self._compute_confidence(result)

 
        result.recommendations = self._generate_recommendations(result)

        return result

    def _compute_final_score(self, r: AdvancedResult) -> float:
        score = r.ml_score * 0.5

 
        sev_weights = {'critical': 20, 'high': 12, 'medium': 6, 'low': 2, 'info': 0}
        for b in r.behavior_indicators:
            score += sev_weights.get(b['severity'], 0)

 
        score += len(r.yara_matches) * 15

 
        score += r.obfuscation_score * 0.15

 
        if r.embedded_dex_count > 3:
            score += 10

        return min(round(score, 2), 100.0)

    def _classify_risk(self, score: float) -> str:
        if score >= 75: return "critical"
        if score >= 50: return "high"
        if score >= 25: return "medium"
        return "low"

    def _compute_confidence(self, r: AdvancedResult) -> float:
        base = 0.5
        if r.raw_strings_count > 1000:
            base += 0.2
        if r.embedded_dex_count > 0:
            base += 0.1
        if len(r.behavior_indicators) > 0:
            base += 0.1
        if len(r.yara_matches) > 0:
            base += 0.1
        return min(base, 1.0)

    def _generate_recommendations(self, r: AdvancedResult) -> List[str]:
        recs = []

        if r.risk_level in ('critical', 'high'):
            recs.append("⚠️  HIGH RISK: Do not install or distribute this application without further investigation.")

        critical_behaviors = [b for b in r.behavior_indicators if b['severity'] == 'critical']
        if critical_behaviors:
            names = [b['name'] for b in critical_behaviors]
            recs.append(f"🔴 Critical behavior detected: {', '.join(names)}")

        if r.obfuscation_score > 50:
            recs.append("🔐 High obfuscation score suggests code is intentionally hidden. Consider full decompilation analysis.")

        if r.entropy > 7.0:
            recs.append("📦 High entropy suggests packing or encryption. Dynamic analysis in a sandbox is recommended.")

        if r.embedded_dex_count > 2:
            recs.append(f"📦 Multiple DEX files ({r.embedded_dex_count}) detected. This is unusual and may indicate dynamic code loading.")

        if len(r.yara_matches) > 0:
            recs.append(f"🎯 {len(r.yara_matches)} YARA rule(s) matched. Review matches carefully.")

        for b in r.behavior_indicators:
            if b['category'] == 'accessibility':
                recs.append("♿ Accessibility service usage is rare in legitimate apps. Investigate thoroughly.")
                break

        for b in r.behavior_indicators:
            if b['category'] == 'dynamic_loading':
                recs.append("🔄 Dynamic code loading detected. Static analysis alone is insufficient — use dynamic analysis.")
                break

        if not recs:
            recs.append("✅ No critical indicators found. Low risk profile. Verify with full decompilation if needed.")

        return recs


 

def main():
    parser = argparse.ArgumentParser(
        description='KitInspect Python Analysis Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('apk_path', help='Path to the APK file to analyze')
    parser.add_argument('--rules-dir', help='YARA rules directory', default=None)
    parser.add_argument('--pretty', action='store_true', help='Pretty-print JSON output')
    args = parser.parse_args()

    if not os.path.exists(args.apk_path):
        print(json.dumps({"error": f"File not found: {args.apk_path}"}))
        sys.exit(1)

    analyzer = APKAnalyzer(args.apk_path, rules_dir=args.rules_dir)

    try:
        result = analyzer.analyze()
        output = asdict(result)
        indent = 2 if args.pretty else None
        print(json.dumps(output, indent=indent, default=str))
    except Exception as e:
        print(json.dumps({"error": str(e), "file": args.apk_path}))
        sys.exit(1)


if __name__ == '__main__':
    main()
