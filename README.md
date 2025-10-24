# Cloudflare-CIDR-Speedtest

这是一个通过调用 CloudflareST-Rust 来测速 CloudFlare CIDR 的工具。

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
