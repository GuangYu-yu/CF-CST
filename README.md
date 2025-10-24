# Cloudflare-CIDR-Speedtest

这是一个通过调用 CloudflareST-Rust 来测速 CloudFlare CIDR 的工具。

[![zread](https://img.shields.io/badge/Ask_Zread-_.svg?style=flat&color=00b0aa&labelColor=000000&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTQuOTYxNTYgMS42MDAxSDIuMjQxNTZDMS44ODgxIDEuNjAwMSAxLjYwMTU2IDEuODg2NjQgMS42MDE1NiAyLjI0MDFWNC45NjAxQzEuNjAxNTYgNS4zMTM1NiAxLjg4ODEgNS42MDAxIDIuMjQxNTYgNS42MDAxSDQuOTYxNTZDNS4zMTUwMiA1LjYwMDEgNS42MDE1NiA1LjMxMzU2IDUuNjAxNTYgNC45NjAxVjIuMjQwMUM1LjYwMTU2IDEuODg2NjQgNS4zMTUwMiAxLjYwMDEgNC45NjE1NiAxLjYwMDFaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00Ljk2MTU2IDEwLjM5OTlIMi4yNDE1NkMxLjg4ODEgMTAuMzk5OSAxLjYwMTU2IDEwLjY4NjQgMS42MDE1NiAxMS4wMzk5VjEzLjc1OTlDMS42MDE1NiAxNC4xMTM0IDEuODg4MSAxNC4zOTk5IDIuMjQxNTYgMTQuMzk5OUg0Ljk2MTU2QzUuMzE1MDIgMTQuMzk5OSA1LjYwMTU2IDE0LjExMzQgNS42MDE1NiAxMy43NTk5VjExLjAzOTlDNS42MDE1NiAxMC42ODY0IDUuMzE1MDIgMTAuMzk5OSA0Ljk2MTU2IDEwLjM5OTlaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik0xMy43NTg0IDEuNjAwMUgxMS4wMzg0QzEwLjY4NSAxLjYwMDEgMTAuMzk4NCAxLjg4NjY0IDEwLjM5ODQgMi4yNDAxVjQuOTYwMUMxMC4zOTg0IDUuMzEzNTYgMTAuNjg1IDUuNjAwMSAxMS4wMzg0IDUuNjAwMUgxMy43NTg0QzE0LjExMTkgNS42MDAxIDE0LjM5ODQgNS4zMTM1NiAxNC4zOTg0IDQuOTYwMVYyLjI0MDFDMTQuMzk4NCAxLjg4NjY0IDE0LjExMTkgMS42MDAxIDEzLjc1ODQgMS42MDAxWiIgZmlsbD0iI2ZmZiIvPgo8cGF0aCBkPSJNNCAxMkwxMiA0TDQgMTJaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00IDEyTDEyIDQiIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSIxLjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIvPgo8L3N2Zz4K&logoColor=ffffff)](https://zread.ai/GuangYu-yu/CF-CST)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/GuangYu-yu/CF-CST)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![GitHub Star](https://img.shields.io/github/stars/GuangYu-yu/CF-CST.svg?style=flat-square&label=Star&color=00ADD8&logo=github)](https://github.com/GuangYu-yu/CF-CST)
[![GitHub Fork](https://img.shields.io/github/forks/GuangYu-yu/CF-CST.svg?style=flat-square&label=Fork&color=00ADD8&logo=github)](https://github.com/GuangYu-yu/CF-CST)

### 获取程序

```bash
ARCH=$(uname -m); FILENAME=$([ "$ARCH" = "x86_64" ] && echo "CF-CST_linux_amd64.tar.gz" || echo "CF-CST_linux_arm64.tar.gz"); curl -ksSL https://github.com/GuangYu-yu/CloudFlare-DDNS/releases/download/setup/setup.sh | bash -s -- GuangYu-yu CF-CST main-latest "$FILENAME" CF-CST
```

### 命令行参数

| 参数 | 描述 | 默认值 |
|------|------|--------|
| `-f` | 指定 CloudflareST-Rust 可执行程序文件名 | `CloudflareST-Rust.exe` |
| `-cidr` | 指定要解析的 CIDR 地址 | 无 |
| `-cf` | 从指定文件获取 CIDR 列表 | 无 |
| `-cu` | 从 URL 远程获取 CIDR 列表 | 无 |
| `-ic` | 从每个 CIDR 中分别随机选取的 IP 数量 | 2 |
| `-s4` | 为 IPv4 CIDR 附加数量后缀 | 无 |
| `-s6` | 为 IPv6 CIDR 附加数量后缀 | 无 |
| `-ca` | 可传递给测速程序的参数: t tp colo tl tll tlr n timeout intf hu | 无 |
| `-o` | 指定输出 CSV 文件名 | `CIDR-Result.csv` |
| `-ot` | 指定输出 TXT 文件名 | `ip.txt` |
| `-lc` | 限制写入文件的条目数量 | 无限制 |
| `-sc` | 跳过删除临时文件 | false |

### 使用示例

```bash
# 基本用法
CF-CST.exe -cidr 192.168.1.0/24

# 从文件获取 CIDR 列表
CF-CST.exe -cf cidr_list.txt -o my_results.csv

# 从远程 URL 获取 CIDR 列表
CF-CST.exe -cu https://example.com/cidr_list.txt -ic 5

# 自定义测速参数
CF-CST.exe -cidr 192.168.1.0/24 -ca "-t 8 -tp 80" -s4 100
```

## 输出文件

- **CSV 文件**：包含 CIDR 和数据中心、平均延迟、平均丢包信息
- **TXT 文件**：包含测速结果的 CIDR 列表
