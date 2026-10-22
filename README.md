# php2shell-guard

> **PHP2Shell（CVE-2026-109618 / CVE-2026-109619）一键检测与修复脚本**
>
> Linux / Windows / macOS 通用 · 单文件 · 零依赖（只用 Python 3 标准库）

2026 年 10 月，PHP 官方发布 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35，修复两处 CVSS v4.0 均为 9.2 的核心引擎漏洞（社区称 php2shell）。漏洞位于 PHP 解释器本身，触发发生在请求启动阶段，**任何由未修复 PHP 处理、接受 POST 的站点都在受影响范围内**，与业务代码是否使用 session 无关。

手动排查麻烦在哪：

- 服务器不止一台，每台都要 `php -v` / `php -i`
- 命令行版本和 Web 进程实际加载的版本经常不一致
- 容器里的 PHP 不在宿主机上
- **光看版本号不准** —— 发行版 backport 可能不改版本号
- 查出来还要改配置、升包、重启

这个脚本把「查」和「修」串成一条命令。

---

## 快速开始

```bash
git clone https://github.com/<你的用户名>/php2shell-guard.git
cd php2shell-guard

# 只检测，不改任何东西
python3 php2shell_guard.py --scan

# 交互模式（要修的时候用）
python3 php2shell_guard.py
```

Windows 上用 `python` 代替 `python3`；改配置需要**以管理员身份运行 PowerShell**。

---

## 它能做什么

| 能力 | 说明 |
|---|---|
| **检测** | 找出 PHP 在哪、什么版本、有没有打补丁、配置有没有风险 |
| **容器检测** | 宿主机没有 PHP 也行 —— 自动进 Docker 容器里查 |
| **配置加固** | 改 `php.ini`，**改前自动备份**，可回滚 |
| **版本升级** | 按平台生成命令；容器场景可**全自动**改 compose + 重建 + 验证 |
| **复检** | 改完/升完重新检测，对比前后 |

**默认只检测，不改任何东西。**

---

## 检测什么

### 1. 版本

| 分支 | 修复版本 |
|---|---|
| 8.2 | **8.2.35** |
| 8.3 | **8.3.36** |
| 8.4 | **8.4.27** |
| 8.5 | **8.5.12** |

判定四类：**存在风险** / **已修复** / **已停止支持**（5.x、7.x、8.0、8.1）/ **无法确定**。

### 2. 补丁标志（比版本号可靠）

```bash
php -r 'var_dump(ini_get("memory_hard_limit_percent"));'
```

- `bool(false)` → **未包含本次修复**
- `string(0) ""` → 已包含

**为什么要看这个**：发行版 backport 可能不改版本号（如 `8.2.34-1ubuntu0.3`），但会带上这个 INI。只看版本字符串会误判。

### 3. 配置项

| 配置 | 风险 | 建议 |
|---|---|---|
| `session.upload_progress.enabled = On` | 中 | 不用进度条就关掉 |
| `session.use_strict_mode = 0` | 中 | 改成 1 |
| `display_errors = On` | 低 | 生产环境关掉 |

### 4. Docker 容器

宿主机没有 `php` 命令也没关系：

```bash
docker exec <容器名> php -v
docker exec <容器名> php -r 'var_dump(ini_get("memory_hard_limit_percent"));'
```

输出会分两段展示：

```
============================================================
 宿主机 PHP
============================================================
[!] 未检测到

============================================================
 Docker 容器内的 PHP
============================================================
[+] php2shell-fpm  (php:8.2.34-fpm)
    【存在风险】版本 8.2.34 < 修复版本 8.2.35
    补丁标志 memory_hard_limit_percent = (不存在)
```

---

## 处置流程

扫描后列出需要处理的目标：

```
============================================================
 处置
============================================================
  [1] php2shell-fpm（容器）：8.2.34 vulnerable
  [2] php2shell-apache（容器）：8.2.34 vulnerable
  [0] 不做任何修改
```

选中后选动作：

```
对 php2shell-fpm 执行：
  [1] 配置加固（关 upload_progress + 开 strict_mode）
  [2] 版本升级
  [3] 取消
```

### 配置加固

改 `php.ini` 两项，**改前备份**：

```
将修改：
  session.upload_progress.enabled     → Off
  session.use_strict_mode             → 1

文件：/etc/php/8.2/fpm/php.ini
修改前自动备份

确认应用？ [y/N]:
```

**改完不会替你重启** —— 重启是业务影响动作，什么时候做由你决定。

### 版本升级

**宿主机**：按包管理器生成命令（apt / dnf / yum / apk / zypper / pacman / brew），先打印计划，你选「只打印」或「由脚本执行」，执行时每条命令还会再问一次。

**容器**：**全自动**。脚本自己找 compose 文件、改 image tag、重建、验证：

```
[+] 当前镜像: php:8.2.34-fpm
[+] 目标镜像: php:8.2.35-fpm

检测到 compose 管理：
  配置文件: /path/to/docker-compose.yml
  服务名  : php-fpm

将要执行：
  1. 备份 docker-compose.yml
  2. 把 image 行 php:8.2.34-fpm → php:8.2.35-fpm
  3. 重建服务（会拉新镜像）
  4. 自动验证版本与补丁标志

确认自动升级？ [y/N]:
```

`y` 之后全自动，最后验证：

```
容器内输出：
  | 8.2.35
  | string(0) ""
[+] 验证通过：已包含修复
```

**浮动 tag 也能处理**：

| 当前镜像 | 升级后 |
|---|---|
| `php:8.2.34-fpm` | `php:8.2.35-fpm` |
| `php:8.2-fpm`（浮动） | `php:8.2.35-fpm` |
| `myrepo/php:8.4.26-custom` | `myrepo/php:8.4.27-custom` |

**唯一的例外**：`docker run` 直接起的容器（非 compose）。重建需要完整的 ports / volumes / env / network 参数，猜错可能丢数据，所以只给命令不自动执行。

---

## 三个刻意的设计

**① 默认不动手** —— 不加参数跑，只检测 + 出报告 + 问你。

**② 改前一定备份** —— `php.ini` 和 `docker-compose.yml` 都备份成 `.bak.<时间戳>`，回滚命令直接打印。

**③ 升级不偷偷跑** —— 先看计划、再确认、执行时逐条确认；失败立即停并给回滚。

**自动升级 PHP 是高危操作**，出问题影响的是线上业务。脚本能省掉「查」的力气，但「改」的决定权得留给人。

---

## 给 CI / 监控用

```bash
# 用退出码判断
python3 php2shell_guard.py --scan
# 0 安全 / 1 有风险 / 2 没找到 PHP

# 输出 JSON（UTF-8 无 BOM）
python3 php2shell_guard.py --scan --json-out /var/log/php2shell.json

# 跳过容器检测
python3 php2shell_guard.py --scan --no-docker
```

---

## 它**不能**做什么

这一节比上面都重要。

**关掉 `upload_progress` 不等于修好。**
它只切断 619 的一条已知会话路径。**618 是 OOM 引发的内存破坏，跟上传功能完全无关**，关它没用。

**调小 `memory_limit` 不是修复。**
OOM 本身就是触发条件之一。而且 `memory_limit = -1` 会让分配走内存映射失败路径，**反而进入同一条脆弱路径**（这条要特别注意）。

**不检测应用层缺陷。**
参数拼接进 `include`、对不可信数据调 `unserialize()` —— 这些得单独审代码。

**不覆盖所有部署形态。**
面板捆绑的 PHP、编译进二进制的 PHP、别的机器上的 PHP，都需要单独看。

**唯一完整的修复**：**升级到 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 及以上，并重启所有 PHP 进程。**

---

## 自检

```bash
python3 selftest.py
```

验证版本判定逻辑（15 个用例，含 `8.10.1` 不会被误判成 `8.1`）+ 端到端检测。

---

## 参考

- PHP 官方安全公告：<https://www.php.net/security/>
- GHSA-w8hw-w9fx-j79w（CVE-2026-109618）
- GHSA-6wmf-4rv5-p3rp（CVE-2026-109619）

---

## 许可

MIT

**本工具仅用于自查与防守。请勿用于未授权测试。**
