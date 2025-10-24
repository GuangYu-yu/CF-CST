# Cloudflare-CIDR-Speedtest

这是一个通过调用 CloudflareST-Rust 来测速 CloudFlare CIDR 的工具

## 使用方法

```
# CF-CST
  -f            指定 CloudflareST-Rust 可执行文件名                             CloudflareST-Rust.exe
  -cidr         指定要解析的地址                                                无
  -cf           从指定文件获取列表                                              无
  -cu           从URL远程获取列表                                               无
  -ic           从每个CIDR中分别随机选择用于测速的 IP 数量                        2
  -s4           为 IPv4 CIDR 附加数量后缀                                       无
  -s6           为 IPv6 CIDR 附加数量后缀                                       无
  -ca           可传递给测速程序的参数: t tp colo tl tll tlr n timeout intf hu   无
  -o            指定输出 csv 文件名                                             CIDR-Result.csv
  -ot           指定输出 txt 文件名                                             ip.txt    
  -lc           指定写入文件的条目数量                                           无限制       
  -sc           跳过删除临时文件 (cidr_split_*.txt, result_*.csv)               false    
```
