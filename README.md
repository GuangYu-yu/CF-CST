# Cloudflare-CIDR-Speedtest

这是一个通过调用 CloudflareST-Rust 来测速 CloudFlare CIDR 的工具。

[![zread](https://img.shields.io/badge/Ask_Zread-_.svg?style=flat&color=00b0aa&labelColor=000000&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTQuOTYxNTYgMS42MDAxSDIuMjQxNTZDMS44ODgxIDEuNjAwMSAxLjYwMTU2IDEuODg2NjQgMS42MDE1NiAyLjI0MDFWNC45NjAxQzEuNjAxNTYgNS4zMTM1NiAxLjg4ODEgNS42MDAxIDIuMjQxNTYgNS42MDAxSDQuOTYxNTZDNS4zMTUwMiA1LjYwMDEgNS42MDE1NiA1LjMxMzU2IDUuNjAxNTYgNC45NjAxVjIuMjQwMUM1LjYwMTU2IDEuODg2NjQgNS4zMTUwMiAxLjYwMDEgNC45NjE1NiAxLjYwMDFaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00Ljk2MTU2IDEwLjM5OTlIMi4yNDE1NkMxLjg4ODEgMTAuMzk5OSAxLjYwMTU2IDEwLjY4NjQgMS42MDE1NiAxMS4wMzk5VjEzLjc1OTlDMS42MDE1NiAxNC4xMTM0IDEuODg4MSAxNC4zOTk5IDIuMjQxNTYgMTQuMzk5OUg0Ljk2MTU2QzUuMzE1MDIgMTQuMzk5OSA1LjYwMTU2IDE0LjExMzQgNS42MDE1NiAxMy43NTk5VjExLjAzOTlDNS42MDE1NiAxMC42ODY0IDUuMzE1MDIgMTAuMzk5OSA0Ljk2MTU2IDEwLjM5OTlaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik0xMy43NTg0IDEuNjAwMUgxMS4wMzg0QzEwLjY4NSAxLjYwMDEgMTAuMzk4NCAxLjg4NjY0IDEwLjM5ODQgMi4yNDAxVjQuOTYwMUMxMC4zOTg0IDUuMzEzNTYgMTAuNjg1IDUuNjAwMSAxMS4wMzg0IDUuNjAwMUgxMy43NTg0QzE0LjExMTkgNS42MDAxIDE0LjM5ODQgNS4zMTM1NiAxNC4zOTg0IDQuOTYwMVYyLjI0MDFDMTQuMzk4NCAxLjg4NjY0IDE0LjExMTkgMS42MDAxIDEzLjc1ODQgMS42MDAxWiIgZmlsbD0iI2ZmZiIvPgo8cGF0aCBkPSJNNCAxMkwxMiA0TDQgMTJaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00IDEyTDEyIDQiIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSIxLjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIvPgo8L3N2Zz4K&logoColor=ffffff)](https://zread.ai/GuangYu-yu/CF-CST)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/GuangYu-yu/CF-CST)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![GitHub Star](https://img.shields.io/github/stars/GuangYu-yu/CF-CST.svg?style=flat-square&label=Star&color=00ADD8&logo=github)](https://github.com/GuangYu-yu/CF-CST)
[![GitHub Fork](https://img.shields.io/github/forks/GuangYu-yu/CF-CST.svg?style=flat-square&label=Fork&color=00ADD8&logo=github)](https://github.com/GuangYu-yu/CF-CST)

### 获取程序

#### 获取 CloudflareST-Rust

```bash
bash -c 'ARCH=$(uname -m); FILENAME="CloudflareST-Rust_linux_$([ "$ARCH" = "x86_64" ] && echo "amd64" || echo "arm64").tar.gz"; curl -ksSL https://github.com/GuangYu-yu/CloudFlare-DDNS/releases/download/setup/setup.sh | bash -s -- GuangYu-yu CloudflareST-Rust main-latest "$FILENAME" CloudflareST-Rust'
```

#### 获取 CF-CST
```bash
bash -c 'ARCH=$(uname -m); FILENAME="CF-CST_linux_$([ "$ARCH" = "x86_64" ] && echo "amd64" || echo "arm64").tar.gz"; curl -ksSL https://github.com/GuangYu-yu/CloudFlare-DDNS/releases/download/setup/setup.sh | bash -s -- GuangYu-yu CF-CST main-latest "$FILENAME" CF-CST'
```

#### 一次性获取 CloudflareST-Rust 和 CF-CST

```bash
bash -c 'download() { local project=$1 exec=$2; ARCH=$(uname -m); FILENAME="${exec}_linux_$([ "$ARCH" = "x86_64" ] && echo "amd64" || echo "arm64").tar.gz"; curl -ksSL https://github.com/GuangYu-yu/CloudFlare-DDNS/releases/download/setup/setup.sh | bash -s -- GuangYu-yu "$project" main-latest "$FILENAME" "$exec"; }; download CloudflareST-Rust CloudflareST-Rust && download CF-CST CF-CST'
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

## 演示

```
./CF-CST -cidr 104.16.0.0/14
# CF-CST
[信息] 执行 CloudflareST-Rust
# CloudflareST-Rust

开始延迟测速（模式：Httping, 端口：443, 范围：0 ~ 2000 ms, 丢包：1.00)
2048/2048 [=================================================================================================================================================↙] 可用: 2035              
[信息] 已禁用下载测速
 IP 地址        已发送  已接收  丢包率  平均延迟  下载速度(MB/s)  数据中心 
 104.18.45.95   4       4       0.00    106.31                    SIN 
 104.18.35.66   4       4       0.00    110.72                    SIN 
 104.18.37.73   4       4       0.00    111.46                    SIN 
 104.18.43.88   4       4       0.00    114.38                    SIN 
 104.18.43.204  4       4       0.00    116.82                    SIN 
 104.18.36.67   4       4       0.00    117.32                    SIN 
 104.18.39.163  4       4       0.00    118.75                    SIN 
 104.18.33.193  4       4       0.00    125.47                    SIN 
 104.18.47.117  4       4       0.00    126.16                    SIN 
 104.18.47.250  4       4       0.00    126.91                    SIN 

[信息] 测速结果已写入 result_1761320445.csv 文件，可使用记事本/表格软件查看
程序执行完毕
[信息] 已生成结果文件: CIDR-Result.csv 和 ip.txt
 数据中心  数量  平均延迟  平均丢包 
 SJC       913   319.50    0.00 
 LAX       231   339.87    0.00 
 SIN       16    139.95    0.00 
[信息] CIDR 测速完毕
```

## 输出文件

- **CSV 文件**：包含 CIDR 和数据中心、平均延迟、平均丢包信息
- **TXT 文件**：包含测速结果的 CIDR 列表
