#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell_guard.py —— PHP2Shell（CVE-2026-109618 / 109619）检测与加固工具

支持 Linux / Windows / macOS，单文件，仅用 Python 3 标准库。
**同时检测宿主机 PHP 与 Docker 容器内的 PHP。**

设计原则：
  1. 默认只检测，不改动
  2. 改配置前自动备份，且必须用户确认
  3. 升级只给命令，逐条确认后才执行
  4. 容器场景不直接改容器内文件（重启即失效），只给改 compose 的指引

用法：
  python3 php2shell_guard.py                 交互模式
  python3 php2shell_guard.py --scan          只检测
  python3 php2shell_guard.py --json          输出 JSON
  python3 php2shell_guard.py --json-out f    写入 JSON 文件
  python3 php2shell_guard.py --php /usr/bin/php8.2
  python3 php2shell_guard.py --no-docker     跳过容器检测

退出码：0 安全 / 1 有风险 / 2 检测失败
"""

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time

# ---------------------------------------------------------------- 常量

FIXED = {"8.2": (8, 2, 35), "8.3": (8, 3, 36), "8.4": (8, 4, 27), "8.5": (8, 5, 12)}
EOL_PREFIXES = ("5.", "7.", "8.0.", "8.1.")

IS_WIN = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"

C_OK, C_WARN, C_ERR = "\033[32m", "\033[33m", "\033[31m"
C_DIM, C_BOLD, C_END = "\033[2m", "\033[1m", "\033[0m"
if not sys.stdout.isatty():
    C_OK = C_WARN = C_ERR = C_DIM = C_BOLD = C_END = ""
elif IS_WIN:
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        C_OK = C_WARN = C_ERR = C_DIM = C_BOLD = C_END = ""


def ok(m):   print("%s[+]%s %s" % (C_OK, C_END, m))
def warn(m): print("%s[!]%s %s" % (C_WARN, C_END, m))
def err(m):  print("%s[-]%s %s" % (C_ERR, C_END, m))
def dim(m):  print("%s    %s%s" % (C_DIM, m, C_END))


def title(m):
    print()
    print("%s%s%s" % (C_BOLD, "=" * 64, C_END))
    print("%s %s%s" % (C_BOLD, m, C_END))
    print("%s%s%s" % (C_BOLD, "=" * 64, C_END))


# ---------------------------------------------------------------- 通用

def run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def ask(prompt, default=""):
    try:
        s = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return s or default


def confirm(prompt, default_no=True):
    s = ask(prompt + (" [y/N]: " if default_no else " [Y/n]: "), "").lower()
    if not s:
        return not default_no
    return s in ("y", "yes", "是")


def is_admin():
    if IS_WIN:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def backup_file(path):
    bak = "%s.bak.%s" % (path, time.strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(path, bak)
    return bak


# ---------------------------------------------------------------- 平台

def detect_os():
    info = {"system": platform.system(), "machine": platform.machine(),
            "distro": "", "pkg": ""}
    if platform.system() == "Linux":
        try:
            with open("/etc/os-release", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        info["distro"] = line.split("=", 1)[1].strip().strip('"')
                        break
        except OSError:
            pass
        for tool in ("apt-get", "dnf", "yum", "apk", "zypper", "pacman"):
            if shutil.which(tool):
                info["pkg"] = tool.replace("-get", "")
                break
    elif platform.system() == "Darwin":
        info["distro"] = "macOS %s" % platform.mac_ver()[0]
        if shutil.which("brew"):
            info["pkg"] = "brew"
    elif platform.system() == "Windows":
        info["distro"] = "Windows %s" % platform.version()
        if shutil.which("winget"):
            info["pkg"] = "winget"
    return info


def find_php(explicit=None):
    if explicit:
        return (explicit, "命令行指定") if os.path.exists(explicit) else (None, "指定的路径不存在")
    p = shutil.which("php")
    if p:
        return p, "PATH 中"
    cands = []
    if IS_WIN:
        cands = [r"C:\php\php.exe", r"C:\xampp\php\php.exe",
                 r"C:\wamp64\bin\php\php.exe", r"C:\laragon\bin\php\php.exe"]
        for base in (r"C:\wamp64\bin\php", r"C:\laragon\bin\php", r"C:\tools\php"):
            if os.path.isdir(base):
                for n in sorted(os.listdir(base), reverse=True):
                    cands.append(os.path.join(base, n, "php.exe"))
    elif IS_MAC:
        cands = ["/opt/homebrew/bin/php", "/usr/local/bin/php", "/opt/local/bin/php"]
    else:
        cands = ["/usr/bin/php", "/usr/local/bin/php"]
        import glob
        for pat in ("/usr/bin/php8*", "/usr/local/bin/php8*"):
            cands.extend(sorted(glob.glob(pat), reverse=True))
    for c in cands:
        if os.path.isfile(c):
            return c, "常见路径"
    return None, "未找到"


# ---------------------------------------------------------------- 探测（抽象出宿主机/容器两种执行器）

def _probe(runner, label):
    """runner(php_args) -> (rc, out, err)
    php_args 是传给 php 的参数（不含 "php" 本身），例如 ["-v"]、["--ini"]
    宿主机 runner:    lambda a: run([php_exe] + a)
    容器 runner:      lambda a: run(["docker","exec",name,"php"] + a)
    """
    r = {"target": label, "ok": False, "version": None, "sapi": None,
         "ini": None, "status": "unknown", "reason": "", "patch_flag": None,
         "config": {}, "risks": []}

    rc, out, err = runner(["-v"])
    if rc != 0:
        r["reason"] = "无法执行 php：%s" % ((err or out).strip()[:100] or "未知错误")
        return r

    r["ok"] = True
    m = re.search(r"PHP\s+(\d+\.\d+\.\d+)", out)
    r["version"] = m.group(1) if m else None
    m = re.search(r"\(([a-z0-9-]+)\)", out)
    r["sapi"] = m.group(1) if m else None

    st, reason = judge_version(r["version"])
    r["status"], r["reason"] = st, reason

    # 配置文件
    rc, out2, _ = runner(["--ini"])
    if rc == 0:
        for line in out2.splitlines():
            if "Loaded Configuration File" in line:
                v = line.split(":", 1)[1].strip() if ":" in line else ""
                if v and v.lower() != "(none)":
                    r["ini"] = v
                break

    # 补丁标志 + 关键配置
    for key in ("memory_hard_limit_percent", "session.upload_progress.enabled",
                "session.use_strict_mode", "memory_limit", "display_errors"):
        rc, o, _ = runner(["-r", 'echo var_export(ini_get("%s"), true);' % key])
        v = o.strip() if rc == 0 else ""
        if v in ("false", ""):
            v = "(不存在)"
        else:
            v = v.strip("'")
        if key == "memory_hard_limit_percent":
            r["patch_flag"] = v
        else:
            r["config"][key] = v

    # 风险项
    if r["patch_flag"] == "(不存在)":
        r["risks"].append({"level": "high", "item": "补丁标志缺失",
                           "detail": "memory_hard_limit_percent 不存在 → 未包含本次修复"})
    if r["config"].get("session.upload_progress.enabled") in ("1", "On", "on"):
        r["risks"].append({"level": "medium", "item": "上传进度功能开启",
                           "detail": "session.upload_progress.enabled = On（出厂默认）"})
    if r["config"].get("session.use_strict_mode") in ("0", "Off", "off"):
        r["risks"].append({"level": "medium", "item": "会话 ID 可被指定",
                           "detail": "session.use_strict_mode = 0，建议设为 1"})
    if r["config"].get("display_errors") in ("1", "On", "on"):
        r["risks"].append({"level": "low", "item": "开启错误显示",
                           "detail": "display_errors = On，会向客户端暴露内部错误"})
    return r


def list_containers():
    """列出运行中的 PHP 相关容器 [{'name':..,'image':..}]"""
    if not shutil.which("docker"):
        return [], "本机没有 docker 命令"
    rc, out, err = run(["docker", "ps", "--format", "{{.Names}}\t{{.Image}}"], timeout=15)
    if rc != 0:
        return [], "docker ps 失败：%s" % (err.strip()[:120] or "检查 docker 权限")
    res = []
    for line in out.strip().splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and "php" in parts[1].lower():
            res.append({"name": parts[0], "image": parts[1]})
    return res, ""


def probe_container(name):
    """在容器内跑同一套检测"""
    r = _probe(lambda a: run(["docker", "exec", name, "php"] + a, timeout=25),
               "容器 %s" % name)
    r["container"] = name
    return r


# ---------------------------------------------------------------- 判定

def parse_ver(v):
    try:
        parts = [int(x) for x in v.split(".")[:3]]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts)
    except Exception:
        return None


def judge_version(ver):
    """-> (vulnerable | safe | eol | unknown, 说明)"""
    if not ver:
        return "unknown", "无法解析版本号"
    v = parse_ver(ver)
    if not v:
        return "unknown", "版本号格式异常"

    for eol in EOL_PREFIXES:
        if ver.startswith(eol):
            return "eol", "PHP %s 已停止安全支持，不会获得官方补丁" % ver

    mm = "%d.%d" % (v[0], v[1])
    if mm in FIXED:
        fixed = FIXED[mm]
        if v < fixed:
            return "vulnerable", "版本 %s < 修复版本 %d.%d.%d" % (ver, *fixed)
        return "safe", "版本 %s ≥ 修复版本 %d.%d.%d" % (ver, *fixed)

    return "unknown", "未知分支 %s，请对照官方公告" % ver


# ---------------------------------------------------------------- 检测入口

def detect(php_path=None, skip_docker=False):
    r = {"ok": False, "os": detect_os(), "host": None,
         "containers": [], "docker_error": "",
         "problem_count": 0, "exit": 2}

    # --- 宿主机 ---
    hp, src = find_php(php_path)
    if hp:
        h = _probe(lambda a: run([hp] + a), "宿主机 %s" % hp)
        h["path"] = hp
        h["source"] = src
        r["host"] = h
        r["ok"] = True
    else:
        r["host"] = {"target": "宿主机", "ok": False, "reason": "未找到 php：%s" % src,
                     "version": None, "status": "unknown", "risks": [], "config": {}}

    # --- 容器（无论宿主机有没有都查）---
    if not skip_docker:
        cs, why = list_containers()
        r["docker_error"] = why
        for c in cs:
            pc = probe_container(c["name"])
            pc["image"] = c["image"]
            r["containers"].append(pc)
            if pc["ok"]:
                r["ok"] = True

    # --- 汇总 ---
    allr = ([r["host"]] if r["host"] and r["host"].get("ok") else []) + \
           [c for c in r["containers"] if c.get("ok")]
    bad = [x for x in allr if x["status"] in ("vulnerable", "eol")]
    r["problem_count"] = len(bad)
    if not r["ok"]:
        r["exit"] = 2
    elif bad:
        r["exit"] = 1
    else:
        r["exit"] = 0
    r["scanned"] = len(allr)
    return r


# ---------------------------------------------------------------- 报告

def _one(x, indent="  "):
    st = x["status"]
    if st == "vulnerable":
        err("%s【存在风险】%s" % (indent, x["reason"]))
    elif st == "eol":
        err("%s【已停止支持】%s" % (indent, x["reason"]))
    elif st == "safe":
        ok("%s【已修复】%s" % (indent, x["reason"]))
    else:
        warn("%s【无法确定】%s" % (indent, x["reason"]))
    dim("%s版本 %s · SAPI %s" % (indent, x["version"], x["sapi"] or "?"))
    dim("%s配置 %s" % (indent, x["ini"] or "（未加载 php.ini）"))
    dim("%s补丁标志 memory_hard_limit_percent = %s" % (indent, x["patch_flag"]))


def print_report(r):
    title("检测报告")
    o = r["os"]
    ok("系统      : %s %s (%s)" % (o["system"], o["distro"], o["machine"]))
    ok("包管理器  : %s" % (o["pkg"] or "未识别"))

    # 宿主机
    title("宿主机 PHP")
    h = r["host"]
    if not h or not h.get("ok"):
        warn("未检测到：%s" % (h.get("reason") if h else "未知"))
        dim("如果你用的是 Docker / 面板 / 集成环境，PHP 可能在容器或子目录里，")
        dim("下面的容器部分会继续检查。")
    else:
        ok("路径 %s（%s）" % (h["path"], h["source"]))
        _one(h)

    # 容器
    if r["containers"]:
        title("Docker 容器内的 PHP")
        for c in r["containers"]:
            if c.get("ok"):
                ok("%s  (%s)" % (c["container"], c.get("image", "")))
                _one(c)
            else:
                warn("%s  —— %s" % (c["container"], c["reason"]))
    elif r["docker_error"]:
        dim("容器检测：%s" % r["docker_error"])

    # 汇总
    title("汇总")
    ok("共扫描 %d 个 PHP 实例" % r["scanned"])
    if r["problem_count"]:
        err("%d 个存在风险或已停止支持，需要处置" % r["problem_count"])
    elif r["scanned"] == 0:
        err("没有找到任何 PHP 实例")
        dim("常见原因：PHP 在容器里但没跑 docker ps 权限、或在别的机器上。")
        dim("可指定路径：--php /usr/bin/php8.2")
    else:
        ok("全部已修复")


# ---------------------------------------------------------------- 加固

HARDEN = [("session.upload_progress.enabled", "Off", "关闭上传进度功能"),
          ("session.use_strict_mode", "1", "拒绝客户端自选未初始化会话 ID")]


def harden(target, is_container):
    title("配置加固")

    if is_container:
        warn("目标是容器，不能直接改容器内的 php.ini —— 容器重启/重建就没了。")
        print()
        print("正确做法是在 compose 里挂载配置文件，然后重建：")
        dim("1. 本地准备 php.ini，写死这两行：")
        for k, v, d in HARDEN:
            dim("     %s = %s" % (k, v))
        dim("2. docker-compose.yml 里加挂载：")
        dim("     volumes:")
        dim("       - ./php.ini:/usr/local/etc/php/php.ini:ro")
        dim("3. docker compose up -d --force-recreate")
        print()
        dim("或者直接换镜像到修复版本（最终解法）：")
        dim("   php:8.2.35-fpm → 注意不能写浮动 tag php:8.2-fpm")
        return False

    ini = target.get("ini")
    if not ini:
        err("没有加载 php.ini，无法通过文件加固")
        dim("可改用：php -d session.upload_progress.enabled=0 启动参数")
        return False
    if not os.access(ini, os.W_OK):
        err("没有写权限：%s" % ini)
        dim("Linux/macOS：sudo python3 %s" % os.path.basename(__file__))
        dim("Windows：以管理员身份运行 PowerShell")
        return False

    print("将修改：")
    for k, v, d in HARDEN:
        print("  %-34s → %s" % (k, v))
        dim("    " + d)
    print()
    dim("文件：%s" % ini)
    dim("修改前自动备份")

    if not confirm("确认应用？"):
        warn("已取消")
        return False

    bak = backup_file(ini)
    ok("已备份：%s" % bak)

    with open(ini, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    changed = []
    for key, val, _ in HARDEN:
        act = re.compile(r"^\s*%s\s*=" % re.escape(key))
        anyp = re.compile(r"^\s*;?\s*%s\s*=" % re.escape(key))
        done = False
        for i, ln in enumerate(lines):
            if act.match(ln):
                lines[i] = "%s = %s\n" % (key, val)
                changed.append(key)
                done = True
                break
            if anyp.match(ln):
                lines[i] = "%s = %s\n" % (key, val)
                changed.append(key + "（原为注释）")
                done = True
                break
        if not done:
            if lines and not lines[-1].endswith("\n"):
                lines.append("\n")
            lines.append("\n; === php2shell_guard 添加 ===\n%s = %s\n" % (key, val))
            changed.append(key + "（追加）")

    with open(ini, "w", encoding="utf-8", newline="") as f:
        f.writelines(lines)

    ok("已写入 %d 项" % len(changed))
    print()
    warn("改动需要重启 PHP 才生效，脚本不会替你重启：")
    if platform.system() == "Linux":
        dim("sudo systemctl restart php8.2-fpm    # 或 apache2 / nginx")
    elif platform.system() == "Darwin":
        dim("brew services restart php")
    else:
        dim("重启 IIS / Apache，或结束 php-cgi 后重新拉起")
    print()
    print("回滚：")
    dim(('copy "%s" "%s"' if IS_WIN else 'cp "%s" "%s"') % (bak, ini))
    return True


# ---------------------------------------------------------------- 升级

def upgrade_plan(osinfo, ver):
    pkg = osinfo.get("pkg", "")
    if not ver:
        return [], "无法识别版本", False
    mm = ".".join(ver.split(".")[:2])
    if pkg == "apt":
        return ([["apt-get", "update"]] +
                [["apt-get", "install", "--only-upgrade", "-y", p]
                 for p in ("php%s" % mm, "php%s-fpm" % mm, "php%s-cli" % mm)],
                "Debian/Ubuntu：只升级不装新包", True)
    if pkg in ("dnf", "yum"):
        return [[pkg, "update", "-y", "php*"]], "RHEL 系", True
    if pkg == "apk":
        return [["apk", "upgrade", "php%s" % ver.replace(".", "")]], "Alpine", True
    if pkg == "zypper":
        return [["zypper", "update", "php%s" % mm]], "openSUSE", True
    if pkg == "pacman":
        return [["pacman", "-Syu", "php"]], "Arch", True
    if pkg == "brew":
        return [["brew", "upgrade", "php"]], "Homebrew", False
    if pkg == "winget":
        return [["winget", "upgrade", "--id", "PHP.PHP"]], "Windows winget", False
    return [], "未识别包管理器", False


def _compose_bin():
    """返回可用的 compose 命令前缀，如 ['docker','compose'] 或 ['docker-compose']"""
    rc, _, _ = run(["docker", "compose", "version"], timeout=10)
    if rc == 0:
        return ["docker", "compose"]
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    return None


def get_container_image(name):
    rc, out, _ = run(["docker", "inspect", name, "--format", "{{.Config.Image}}"], timeout=15)
    return out.strip() if rc == 0 else ""


def get_compose_meta(name):
    """从容器 label 里拿 compose 信息"""
    rc, out, _ = run(["docker", "inspect", name,
                      "--format", "{{json .Config.Labels}}"], timeout=15)
    if rc != 0:
        return {}
    try:
        labels = json.loads(out.strip() or "{}") or {}
    except Exception:
        return {}
    return {
        "config_files": labels.get("com.docker.compose.project.config_files", ""),
        "service": labels.get("com.docker.compose.service", ""),
        "working_dir": labels.get("com.docker.compose.project.working_dir", ""),
    }


def _verify_container(name):
    """重建后验证：版本 + 补丁标志"""
    rc, out, _ = run(["docker", "exec", name, "php", "-r",
                      'echo PHP_VERSION, "\n"; var_dump(ini_get("memory_hard_limit_percent"));'],
                     timeout=25)
    if rc != 0:
        err("验证失败：容器可能没起来，或里面没有 php")
        for ln in (out or "").strip().splitlines()[-5:]:
            dim("  | " + ln)
        return False
    print()
    dim("容器内输出：")
    for ln in out.strip().splitlines():
        dim("  | " + ln)
    if "bool(false)" in out or "NULL" in out:
        err("补丁标志仍不存在 —— 镜像可能没拉到修复版本，或版本判断有误")
        return False
    ok("验证通过：已包含修复（memory_hard_limit_percent 存在）")
    return True


def container_upgrade_auto(target, osinfo):
    """容器自动升级：改 compose 的 image tag -> 重建 -> 验证"""
    name = target["container"]
    cur_ver = target["version"]
    mm = ".".join(cur_ver.split(".")[:2])

    if mm not in FIXED:
        warn("目标版本 %s 不在已知修复分支内，无法自动推算目标版本" % cur_ver)
        return False
    new_ver = "%d.%d.%d" % FIXED[mm]

    cur_image = get_container_image(name)
    if not cur_image:
        err("拿不到容器当前镜像名（docker inspect 失败）")
        return False

    # php:8.2.34-fpm / php:8.2-fpm 都统一成 php:8.2.35-fpm
    m = re.match(r"^(php:)([^-]+)(-.*)?$", cur_image)
    if m:
        new_image = "%s%s%s" % (m.group(1), new_ver, m.group(3) or "")
    else:
        # 自定义镜像（如 myapp-php:1.2），只能按版本号替换
        if cur_ver not in cur_image:
            warn("镜像名 %s 里没有版本号，无法自动改写" % cur_image)
            dim("请手动把镜像换成含 PHP %s 的版本" % new_ver)
            return False
        new_image = cur_image.replace(cur_ver, new_ver)

    title("容器自动升级")
    ok("容器    : %s" % name)
    ok("当前镜像: %s" % cur_image)
    ok("目标镜像: %s" % new_image)
    ok("当前版本: %s" % cur_ver)
    ok("目标版本: ≥ %s" % new_ver)
    print()

    meta = get_compose_meta(name)
    compose = _compose_bin()

    # ---------------- 路线 A：compose 管理 ----------------
    if meta.get("config_files") and compose:
        cfg = meta["config_files"].split(",")[0].strip()
        svc = meta.get("service", "")

        if not os.path.exists(cfg):
            err("compose 文件找不到：%s" % cfg)
            dim("容器可能是在别的机器/别的目录创建的")
            return False

        print("检测到 compose 管理：")
        dim("  配置文件: %s" % cfg)
        dim("  服务名  : %s" % svc)
        dim("  重建命令: %s -f %s up -d --force-recreate %s"
            % (" ".join(compose), cfg, svc))
        print()
        print("将要执行：")
        print("  1. 备份 %s" % os.path.basename(cfg))
        print("  2. 把 image 行 %s → %s" % (cur_image, new_image))
        print("  3. 重建服务 %s（会拉新镜像，可能要几分钟）" % svc)
        print("  4. 自动验证版本与补丁标志")
        print()
        warn("重建期间该服务会短暂中断。生产环境请确认在维护窗口。")
        print()

        if not confirm("确认自动升级？", default_no=True):
            warn("已取消，未做任何修改")
            return False

        # 备份
        bak = backup_file(cfg)
        ok("已备份：%s" % bak)

        # 改 image
        with open(cfg, "r", encoding="utf-8", errors="replace") as f:
            txt = f.read()
        if cur_image not in txt:
            err("compose 里没找到 %s" % cur_image)
            dim("可能用了 ${VAR} 变量或 YAML 锚点，请手动改这一行")
            dim("备份文件：%s" % bak)
            return False
        with open(cfg, "w", encoding="utf-8", newline="") as f:
            f.write(txt.replace(cur_image, new_image))
        ok("已改写 image 行")

        # 重建
        print()
        print("开始重建（首次会拉取镜像，请耐心等待）...")
        t0 = time.time()
        rc, out, e = run(compose + ["-f", cfg, "up", "-d", "--force-recreate", svc],
                         timeout=1800)
        dur = time.time() - t0
        for ln in (out + e).strip().splitlines()[-18:]:
            dim("  | " + ln)

        if rc != 0:
            err("重建失败（退出码 %d，耗时 %.0f 秒）" % (rc, dur))
            print()
            warn("回滚 compose：")
            dim(('copy "%s" "%s"' if IS_WIN else 'cp "%s" "%s"') % (bak, cfg))
            dim("docker compose -f %s up -d --force-recreate %s" % (cfg, svc))
            return False
        ok("重建完成（耗时 %.0f 秒）" % dur)

        # 找新容器名（compose 重建后容器名可能变）
        rc, out, _ = run(["docker", "ps",
                          "--filter", "label=com.docker.compose.service=%s" % svc,
                          "--format", "{{.Names}}"], timeout=15)
        cand = [x for x in out.strip().splitlines() if x.strip()]
        new_name = cand[0] if cand else name
        if new_name != name:
            dim("容器名变化：%s → %s" % (name, new_name))

        return _verify_container(new_name)

    # ---------------- 路线 B：非 compose ----------------
    warn("这个容器不是 docker compose 管理的，无法安全自动重建。")
    print()
    print("原因：用 docker run 起的容器，重建需要完整的 ports / volumes / env / network 参数，")
    print("      猜错一个就可能丢数据或起不来。所以这一步留给你手动确认。")
    print()
    print("先把当前配置导出来（照着重建）：")
    dim("docker inspect %s > %s.json" % (name, name))
    print()
    print("然后用新镜像重建，例如：")
    dim("docker rm -f %s" % name)
    dim("docker run -d --name %s ... %s" % (name, new_image))
    print()
    dim("或者：在测试环境用新镜像先跑一遍，确认没报错再替换。")
    return False


def show_upgrade(target, osinfo, is_container):
    title("版本升级")
    ver = target.get("version")
    print("当前版本：%s" % ver)
    mm = ".".join(ver.split(".")[:2]) if ver else "?"
    if mm in FIXED:
        print("目标版本：≥ %d.%d.%d" % FIXED[mm])
    print()

    if is_container:
        container_upgrade_auto(target, osinfo)
        return

    plan, note, need_root = upgrade_plan(osinfo, ver)
    if not plan:
        warn(note)
        print()
        if IS_WIN:
            print("Windows 手动升级：")
            dim("1. 备份 C:\\php 整个目录")
            dim("2. https://windows.php.net/download/ 下载对应分支最新 NTS 包")
            dim("3. 解压覆盖（保留 php.ini）")
            dim("4. 重启 IIS / Apache / php-cgi")
            dim("5. 验证 php -r \"var_dump(ini_get('memory_hard_limit_percent'));\"")
        return

    print("计划执行：")
    for c in plan:
        print("  " + " ".join(c))
    print()
    dim("说明：%s" % note)
    if need_root and not is_admin():
        warn("当前不是管理员/root，命令会失败")
    print()
    print("  [1] 只打印命令，我自己执行（推荐）")
    print("  [2] 由脚本逐条执行（每条都问你）")
    print("  [3] 跳过")
    c = ask("选择 [1]: ", "1")

    if c == "3":
        warn("已跳过")
        return
    if c == "1":
        print()
        print("复制执行：")
        for x in plan:
            print("  " + ("sudo " if (need_root and not is_admin()) else "") + " ".join(x))
        return

    for x in plan:
        cmd = (["sudo"] + x) if (need_root and not is_admin()) else x
        print()
        warn("即将执行：%s" % " ".join(cmd))
        if not confirm("  确认？"):
            warn("  跳过")
            continue
        rc, out, e = run(cmd, timeout=900)
        for ln in (out or "").strip().splitlines()[-12:]:
            dim("  | " + ln)
        if rc == 0:
            ok("  完成")
        else:
            err("  失败（退出码 %d）" % rc)
            for ln in (e or "").strip().splitlines()[-6:]:
                dim("  | " + ln)
            break

    print()
    warn("升级后必须重启 PHP 进程才生效")
    print("重启后重新运行本工具复检。")


# ---------------------------------------------------------------- 主流程

def main():
    ap = argparse.ArgumentParser(description="PHP2Shell 检测与加固")
    ap.add_argument("--php", default="", help="指定宿主机 php 路径")
    ap.add_argument("--scan", action="store_true", help="只检测")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--json-out", default="", help="JSON 写入文件")
    ap.add_argument("--no-docker", action="store_true", help="跳过容器检测")
    ap.add_argument("--yes-i-know", action="store_true", help="跳过免责确认")
    args = ap.parse_args()

    if not args.json and not args.json_out:
        print()
        print("%s PHP2Shell 检测与加固 %s" % (C_BOLD, C_END))
        dim("CVE-2026-109618 / CVE-2026-109619 · 宿主机 + Docker 容器")
        if not args.scan and not args.yes_i_know:
            print()
            warn("默认只检测不改动；任何修改前都会备份并要求确认。")
            if not confirm("继续？", default_no=False):
                return 0

    r = detect(args.php or None, args.no_docker)

    if args.json or args.json_out:
        payload = json.dumps(r, ensure_ascii=False, indent=2)
        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8", newline="\n") as f:
                f.write(payload + "\n")
            if not args.scan:
                print("[+] JSON 已写入 %s" % args.json_out)
        else:
            print(payload)
        return r["exit"]

    print_report(r)

    if args.scan or r["scanned"] == 0:
        return r["exit"]

    # 处置
    targets = []
    if r["host"] and r["host"].get("ok"):
        targets.append(("宿主机", r["host"], False))
    for c in r["containers"]:
        if c.get("ok"):
            targets.append((c["container"], c, True))

    need = [t for t in targets if t[1]["status"] in ("vulnerable", "eol")]
    if not need:
        ok("没有需要处置的目标")
        return r["exit"]

    title("处置")
    for i, (label, t, isc) in enumerate(need, 1):
        tag = "容器" if isc else "宿主机"
        print("  [%d] %s（%s）：%s %s" % (i, label, tag, t["version"], t["status"]))
    print("  [0] 不做任何修改")
    print()

    sel = ask("选择要处置的目标编号 [0]: ", "0")
    if sel == "0":
        ok("未做修改")
        return r["exit"]
    try:
        idx = int(sel) - 1
        label, t, isc = need[idx]
    except (ValueError, IndexError):
        warn("输入无效")
        return r["exit"]

    print()
    print("对 %s 执行：" % label)
    print("  [1] 配置加固（关 upload_progress + 开 strict_mode）")
    print("  [2] 版本升级")
    print("  [3] 取消")
    act = ask("选择 [3]: ", "3")

    if act == "1":
        harden(t, isc)
    elif act == "2":
        show_upgrade(t, r["os"], isc)
    else:
        ok("已取消")
    return r["exit"]


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        warn("已中断（未完成的修改不会生效）")
        sys.exit(130)
