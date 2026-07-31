# -*- coding: utf-8 -*-
"""
常量配置模块
所有配置常量、漏洞类型映射、标签定义

使用方式:
    from constants import REGEX_TEMPLATES, TAG_MAP, VULN_NAME_MAP
"""
from typing import Dict, List, Tuple

# ============================================================
# 漏洞类型正则模板
# ============================================================
REGEX_TEMPLATES: Dict[str, str] = {
    "SQLi": (
        r"(?i:\b(select|union|update|order|insert|\x2f\x2a\x2a|delete|updatexml|extractvalue|"
        r"substr|or|and)\b[^\x0a\x0d]*?\b(select|sleep|by|from|where|into|set|md5|concat|version|convert|char)\b|"
        r"\bWAITFOR\b[\s\S]*\bDELAY\b|(substring\x28|int\x2c)sys\x2efn\x5fsqlvarbasetostr)"
    ),

    "XSS": (
        r"(?i:\x3c\b(script|iframe|img|svg|div|bgsound|link|input|body|table|base|embed|"
        r"href)\b.*?\b((fromcharcode|alert|write|eval|confirm|expression|prompt|style|src|xss|location)\b|"
        r"on[a-z]{3,15}|\bconsole\x2e\w+)\s*[\x28\x60\x3d].*\x3e)"
    ),

    "Code_Exec": (
        r"(?i:system\s*\(|exec\s*\(|\bpassthru\s*\(|\bshell\x5fexec\s*\(|\bpopen\s*\(|\bproc\x5fopen\s*\(|"
        r"\beval\s*\(|\x60[^`]+\x60)"
    ),

    "OS_Command": (
        r"(?i:[\x3b\x60\x26\x7c]*?\b((rm|cp|md)\s\S+|(cat|net|reg|del)\s\S+|"
        r"(move|copy|more|curl|echo)\s\S+|ipconfig|systeminfo|shutdown|taskkill|"
        r"whoami|ifconfig|netstat|reboot|poweroff|shutdown|mkdir|useradd|userdel|"
        r"head|xcopy|replace|dir|schtasks|tasklist|ipconfig|execute|more|less|"
        r"tac|head|tail|od|id|rename|wget|ping)\b)"
    ),

    "Dir_Traversal": (
        r"(\.{1,}\x3b{0,}[\x2f\x5c]+){2,}"
    ),

    "File_Read": (
        r"(?i:\b(file|path|folder|dir|load\x5ffile|readfile|download)\b.*?(\.\.|\x2fetc\x2f|\x2fwindows\x2f|"
        r"WEB\x2dINF|boot\.ini|c\x3a\\|\.\x2f|\.\.\x2f))"
    ),

    "File_Upload": (
        r"(?i:\bContent\x2dDisposition\b.*?\bfilename\b.*?\.(jsp|php|asp|aspx|phtml|pht|shtml|war|jar|exe|sh|"
        r"py|pl|cgi|cer|asa|jspx)\b|\bfilename[=:]\s*[\x22\x27]?.*?\.(jsp|php|asp|aspx|phtml|pht|shtml|war|"
        r"jar|exe|sh|py|pl|cgi|cer|asa|jspx)\b)"
    ),

    "SSRF": (
        r"(?i:(file|https?|ftp)\x3a\x2f\x2f(127\x2e0\x2e0\x2e1|127\x2e1|localhost|(192|172|10)\x2e|169\x2e254\x2e169\x2e254))"
    ),

    "XXE": (
        r"(?i:\x3c\x21ENTITY\b.*?\b(SYSTEM|PUBLIC)\b|\bDOCTYPE\b.*?\bENTITY\b)"
    ),

    "File_Include": (
        r"(?i:\b(include|require|require\x5fonce|include\x5fonce)\s*\(?\s*[\x22\x27]?\s*(http|https|ftp|php|"
        r"data|expect|ogg|phar|zip)\x3a\x2f\x2f|\.\.\x2f|file\x3a\x2f\x2f|php\x3a\x2f\x2finput|"
        r"php\x3a\x2f\x2ffilter|data\x3a\x2f\x2f|expect\x3a\x2f\x2f|phar\x3a\x2f\x2f|ogg\x3a\x2f\x2f|"
        r"zip\x3a\x2f\x2f)"
    ),

    "Template_Injection": (
        r"(?i:\{\{.*?\}\}|\{\x25\s*.*?\s*\x25\}|\$\{.*?\}|\{\{.*?\.\w+|\{\{.*?\[|\#\{.*?\})"
    ),

    "Info_Leak": (
        r"(?i:\b[a-z_]*password[a-z_]*\b\s*[:=]|\b[a-z_]*passwd[a-z_]*\b\s*[:=]|"
        r"\b[a-z_]*secret[a-z_]*\b\s*[:=]|\b[a-z_]*token[a-z_]*\b\s*[:=]|\b[a-z_]*api[_-]?key[a-z_]*\b\s*[:=]|"
        r"\b[a-z_]*access[_-]?key[a-z_]*\b\s*[:=]|\b[a-z_]*private[_-]?key[a-z_]*\b\s*[:=]|"
        r"\b[a-z_]*key[a-z_]*\b\s*[:=]|\b[a-z_]*connection[_-]?string[a-z_]*\b\s*[:=]|\bjdbc\x3a|\bmysql\x3a|"
        r"\bredis\x3a|\bmongodb\x3a|\broot\x3a\w+\x3a\d+\x3a\d+\x3a|\x3c\?(?:php|\x3d)\b|\x2fWEB\x2dINF\x2f|"
        r"\x2fMETA\x2dINF\x2f|\.git\x2f|\.env\b|\.svn\x2f|\.DS\x5fStore|\x2factuator\x2f|\x2fswagger|"
        r"\x2fapi\x2ddocs|\x2fdruid\x2f|\x2fheapdump|\x2fthreaddump|\x2ftrace|\x2fmappings|\x2fconfigprops|"
        r"\x2fbeans|\x2fautoconfig|\x2fmetrics|\x2fhealth|\x2finfo|\x2fdump|\x2fjolokia\x2f|\x2fphpinfo|"
        r"\x2fserver\x2dstatus|\x2fserver\x2dinfo|\"threadName\"|\"stackTrace\"|heapdump|threaddump)"
    ),
}

# ============================================================
# 扩展名分组（用于 File_Upload 规则压缩）
# ============================================================
EXTENSION_GROUPS: Dict[str, List[str]] = {
    "jsp": ["jsp", "jspx"],
    "php": ["php", "phtml", "pht", "php3", "php4", "php5", "php7", "php8"],
    "asp": ["asp", "aspx"],
}

# 分组正则覆盖：对需要精简表达的分组直接指定正则片段
GROUP_REGEX_OVERRIDE: Dict[str, str] = {
    "php": r"\x2eph(p\d?|t(ml)?)",
}

# 漏洞类型中文名
VULN_NAME_MAP: Dict[str, str] = {
    "SQLi": "SQL injection vulnerability",
    "XSS": "Cross-site scripting vulnerability",
    "Code_Exec": "Code execution vulnerability",
    "OS_Command": "OS command injection vulnerability",
    "Dir_Traversal": "Directory traversal vulnerability",
    "File_Read": "arbitrary file read vulnerability",
    "File_Upload": "arbitrary file upload vulnerability",
    "SSRF": "Server-side request forgery vulnerability",
    "XXE": "XML external entity vulnerability",
    "File_Include": "File inclusion vulnerability",
    "Info_Leak": "Information leakage vulnerability",
    "Auth_Bypass": "Authentication bypass vulnerability",
}

# 上下文参数白名单：典型漏洞场景参数，强制加入 chain 作为上下文匹配
CONTEXT_PARAM_WHITELIST: Tuple[str, ...] = ("action", "cmd", "topicurl")

# 标签映射
TAG_MAP: Dict[str, str] = {
    "SQLi": "TOPWAF_CRS/WEB_ATTACK/SQLi",
    "XSS": "TOPWAF_CRS/WEB_ATTACK/XSS",
    "Code_Exec": "TOPWAF_CRS/WEB_ATTACK/OSI",
    "OS_Command": "TOPWAF_CRS/WEB_ATTACK/OSI",
    "Dir_Traversal": "TOPWAF_CRS/WEB_ATTACK/Path Traversal",
    "File_Read": "TOPWAF_CRS/WEB_ATTACK/File_Read",
    "File_Upload": "TOPWAF_CRS/WEB_ATTACK/File_Upload",
    "SSRF": "TOPWAF_CRS/WEB_ATTACK/SSRF",
    "XXE": "TOPWAF_CRS/WEB_ATTACK/XXE",
    "File_Include": "TOPWAF_CRS/WEB_ATTACK/Path Traversal",
    "Template_Injection": "TOPWAF_CRS/WEB_ATTACK/Template_Injection",
    "Info_Leak": "TOPWAF_CRS/WEB_ATTACK/Info_Leak",
    "Auth_Bypass": "TOPWAF_CRS/WEB_ATTACK/Auth_Bypass",
}

# 默认规则版本信息
DEFAULT_REV: str = "rev:'1',ver:'TOPWAF_CRS/1.0.7'"

# 所有支持的漏洞类型
SUPPORTED_VULN_TYPES: Tuple[str, ...] = tuple(REGEX_TEMPLATES.keys()) + ("Auth_Bypass",)
