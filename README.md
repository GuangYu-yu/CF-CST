# CloudFlare CIDR 测速工具

这是一个用于测试和筛选 CloudFlare CIDR 的工具

## 使用方法

```
基本参数:
  -url string      测速的CIDR链接
  -f string        指定测速的文件路径 (当未设置-url时使用)
  -o string        结果文件名 (默认: IP_Speed.csv)
  -h               显示帮助信息
  -notest          不进行测速，只生成随机IP (需配合 -useip4 或 -useip6 使用)
  -showall         显示所有结果，包括未查询到数据中心的结果

测速参数:
  -t int           延迟测试次数 (默认: 4)
  -tp int          测试端口号 (默认: 443)
  -ts int          每个CIDR测试的IP数量 (默认: 2)
  -n int           并发测试线程数量 (默认: 128)

筛选参数:
  -colo string     指定数据中心，多个用逗号分隔 (例: HKG,NRT,LAX,SJC)
  -tl int          延迟上限 (默认: 500ms)
  -tll int         延迟下限 (默认: 0ms)
  -tlr float       丢包率上限 (默认: 0.5)
  -p string        输出结果数量 (默认: all)

输出选项:
  -nocsv           不生成CSV文件
  -useip4 string   生成IPv4列表
                   - 使用 all: 输出所有IPv4 CIDR的完整IP列表
                   - 使用数字 (如9999): 输出指定数量的不重复IPv4
  -useip6 string   生成IPv6列表
                   - 使用数字 (如9999): 输出指定数量的不重复IPv6
  -iptxt string    指定IP列表输出文件名 (默认: ip.txt)
                   - 使用此参数时必须至少使用 -useip4 或 -useip6
```

### 基本用法

```
# 从 URL 获取 CIDR 列表并测速
./cfspeed -url "https://example.com/cidr.txt"

# 从本地文件获取 CIDR 列表
./cfspeed -f cidr.txt
```

### 示例

```bash
# 测试指定地区的节点，限制延迟在 500ms 以内
./cfspeed -url "https://example.com/cidr.txt" -colo "HKG,NRT,LAX,SJC,IAD,CDG,SEA" -tl 500

# 生成 IPv4 列表而不进行测速
./cfspeed -url "https://example.com/cidr.txt" -notest -useip4 all
```

## 数据文件说明

- `IP_Speed.csv`: 测速结果文件
- `ip.txt`: 生成的 IP 列表文件
