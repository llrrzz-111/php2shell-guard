php2shell-guard

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)]()

PHP2Shell（CVE-2026-109618 / CVE-2026-109619）检测与加固工具。

单文件、零依赖（仅 Python 3 标准库），支持宿主机与 Docker 容器内的 PHP 实例。

## 特性

- **检测**：版本、补丁标志、风险配置项
- **容器支持**：自动发现并进入 Docker 容器检测
- **配置加固**：修改 `php.ini`，改动前自动备份
- **版本升级**：按平台生成升级命令；容器场景支持自动改写 compose 并重建
- **CI 友好**：支持 JSON 输出与退出码判定

## 快速开始

```bash
git clone https://github.com/llrrzz-111/php2shell-guard.git
cd php2shell-guard

# 仅检测（不做任何修改）
python3 php2shell_guard.py --scan

# 交互模式（检测 + 处置）
python3 php2shell_guard.py
```

Windows 使用 `python` 替代 `python3`；修改配置需以管理员身份运行 PowerShell。

## 用法

```
python3 php2shell_guard.py [OPTIONS]

OPTIONS:
  --scan              仅检测，不进入处置流程
  --json              输出 JSON 到标准输出
  --json-out <PATH>   输出 JSON 到文件（UTF-8，无 BOM）
  --php <PATH>        指定宿主机 php 可执行文件路径
  --no-docker         跳过 Docker 容器检测
  --yes-i-know        跳过免责确认（CI 用，仍不会自动修改）
```

退出码：

| 码  | 含义                |
| --- | ------------------- |
| 0   | 全部已修复          |
| 1   | 检测到风险          |
| 2   | 未找到任何 PHP 实例 |

## 检测项

### 版本

| 分支 | 修复版本 |
| ---- | -------- |
| 8.2  | 8.2.35   |
| 8.3  | 8.3.36   |
| 8.4  | 8.4.27   |
| 8.5  | 8.5.12   |

判定结果：`vulnerable` / `safe` / `eol`（5.x、7.x、8.0、8.1）/ `unknown`。

### 补丁标志

```bash
php -r 'var_dump(ini_get("memory_hard_limit_percent"));'
```

| 返回值         | 含义           |
| -------------- | -------------- |
| `bool(false)`  | 未包含本次修复 |
| `string(0) ""` | 已包含修复     |

该判据优于版本号比较：发行版 backport 可能保持原版本号（如 `8.2.34-1ubuntu0.3`）而实际已修复。

### 配置项

| 配置项                            | 建议值                      |
| --------------------------------- | --------------------------- |
| `session.upload_progress.enabled` | `Off`（不使用上传进度条时） |
| `session.use_strict_mode`         | `1`                         |
| `display_errors`                  | `Off`（生产环境）           |

### Docker

宿主机未安装 PHP 时，仍会扫描运行中的 PHP 容器：

```bash
docker exec <容器名> php -v
docker exec <容器名> php -r 'var_dump(ini_get("memory_hard_limit_percent"));'
```

## 处置

`--scan` 之后的交互模式提供三个动作：

### 配置加固

写入 `php.ini`：

```ini
session.upload_progress.enabled = Off
session.use_strict_mode = 1
```

修改前自动备份为 `php.ini.bak.<时间戳>`，并打印回滚命令。修改后需手动重启 PHP 服务。

### 版本升级

**宿主机**：按包管理器生成命令（apt / dnf / yum / apk / zypper / pacman / brew），先展示计划，再逐条确认执行。

**Docker**：自动完成以下步骤：

1. 从容器 label 读取 compose 文件路径与服务名
2. 备份 `docker-compose.yml`
3. 改写 `image` 行（支持浮动 tag 与固定版本）
4. `docker compose up -d --force-recreate <service>`
5. 重新检测版本与补丁标志

仅支持 compose 管理的容器。`docker run` 创建的容器只输出重建指引。

## 安全设计

| 原则       | 实现                               |
| ---------- | ---------------------------------- |
| 默认只读   | 不加参数运行时不做任何修改         |
| 改动可回滚 | 所有文件修改前自动备份             |
| 升级需确认 | 展示计划 → 选择执行方式 → 逐条确认 |
| 凭据不落盘 | 不收集任何凭据                     |

## 限制

以下事项不在本工具范围内：

- **关闭 `session.upload_progress` 不等于修复**。该配置仅切断 CVE-2026-109619 的一条已知会话路径，对 CVE-2026-109618 的内存破坏无效。
- **调整 `memory_limit` 不是修复**。OOM 本身即为触发条件之一；设置 `memory_limit = -1` 会使分配进入另一条失败路径，反而落入同一脆弱点。
- **不检测应用层缺陷**。如参数拼接进 `include`、对不可信数据调用 `unserialize()`。
- **不覆盖全部部署形态**。面板捆绑的 PHP、编译进二进制的 PHP、远程主机上的 PHP 需单独处理。

完整修复方式为：升级至 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 及以上，并重启所有 PHP 进程。

## 自检

```bash
python3 selftest.py
```

验证版本判定逻辑（15 个用例）与端到端检测通路。

## 参考

- [PHP 安全公告](https://www.php.net/security/)
- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) — CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) — CVE-2026-109619
