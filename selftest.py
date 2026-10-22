#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""selftest.py —— 验证 php2shell_guard 的判定逻辑与检测通路"""

import argparse
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MAIN = os.path.join(HERE, "php2shell_guard.py")


def load():
    spec = importlib.util.spec_from_file_location("guard", MAIN)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--php", default="", help="顺带测一次真实 PHP")
    args = ap.parse_args()

    if not os.path.exists(MAIN):
        print("[!] 找不到 php2shell_guard.py")
        return 2

    g = load()

    print("=" * 62)
    print(" 1. 版本判定（15 个用例）")
    print("=" * 62)

    cases = [
        ("5.6.40", "eol"), ("7.4.33", "eol"), ("8.0.30", "eol"), ("8.1.31", "eol"),
        ("8.2.34", "vulnerable"), ("8.2.35", "safe"),
        ("8.3.35", "vulnerable"), ("8.3.36", "safe"),
        ("8.4.26", "vulnerable"), ("8.4.27", "safe"),
        ("8.5.11", "vulnerable"), ("8.5.12", "safe"),
        ("8.5.13", "safe"),
        ("9.0.0", "unknown"),
        ("8.10.1", "unknown"),   # 边界：不能被当成 8.1
    ]

    bad = 0
    for ver, expect in cases:
        st, _ = g.judge_version(ver)
        if st != expect:
            bad += 1
            print("  [FAIL] %-9s -> %-11s (期望 %s)" % (ver, st, expect))
        else:
            print("  [OK  ] %-9s -> %s" % (ver, st))
    print()
    print("  结果：%d/%d" % (len(cases) - bad, len(cases)))

    print()
    print("=" * 62)
    print(" 2. 检测通路")
    print("=" * 62)

    php = args.php or None
    if not php:
        p, src = g.find_php()
        if p:
            php = p
            print("  自动找到：%s（%s）" % (p, src))
        else:
            print("  [i] 宿主机没有 PHP，检查容器通路")

    r = g.detect(php, skip_docker=False)
    print("  宿主机 :", "OK " + r["host"]["version"] if r["host"].get("ok")
          else "未找到（%s）" % r["host"].get("reason", ""))
    print("  容器   : %d 个" % len(r["containers"]))
    for c in r["containers"]:
        if c.get("ok"):
            print("    - %-24s %s %s" % (c["container"], c["version"], c["status"]))
        else:
            print("    - %-24s 检测失败：%s" % (c["container"], c["reason"][:50]))
    if r["docker_error"]:
        print("  docker : %s" % r["docker_error"][:70])
    print("  汇总   : scanned=%d problems=%d exit=%d"
          % (r["scanned"], r["problem_count"], r["exit"]))

    print()
    print("=" * 62)
    if bad:
        print(" 自检失败：%d 个用例不符预期" % bad)
        return 1
    if r["scanned"] == 0:
        print(" 判定逻辑全部通过，但没检测到任何 PHP —— 检查 --php 或 docker 权限")
        return 2
    print(" 自检通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
