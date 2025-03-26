package main

import (
	"flag"
	"fmt"
	"strings"
)

// 命令行参数结构
type CommandArgs struct {
	URLFlag     string
	FileFlag    string
	TestCount   int
	PortFlag    int
	IPPerCIDR   int
	ColoFlag    string
	MaxLatency  int
	MinLatency  int
	MaxLossRate float64
	ScanThreads int
	PrintCount  string
	OutFile     string
	NoCSV       bool
	UseIPv4     string
	UseIPv6     string
	IPTxtFile   string
	NoTest      bool
	ShowAll     bool
	Help        bool
	Timeout     string
}

// 解析命令行参数
func parseArgs() CommandArgs {
	args := CommandArgs{}

	// 定义命令行参数
	flag.StringVar(&args.URLFlag, "url", "", "测速的CIDR链接")
	flag.StringVar(&args.FileFlag, "f", "", "指定测速的文件")
	flag.IntVar(&args.TestCount, "t", 4, "延迟测速的次数")
	flag.IntVar(&args.PortFlag, "tp", 443, "指定测速的端口号")
	flag.IntVar(&args.IPPerCIDR, "ts", 2, "从CIDR内随机选择IP的数量")
	flag.StringVar(&args.ColoFlag, "colo", "", "匹配指定数据中心，用逗号分隔，例如 HKG,KHH,NRT,LAX")
	flag.IntVar(&args.MaxLatency, "tl", 500, "平均延迟上限(ms)")
	flag.IntVar(&args.MinLatency, "tll", 0, "平均延迟下限(ms)")
	flag.Float64Var(&args.MaxLossRate, "tlr", 0.5, "丢包率上限")
	flag.IntVar(&args.ScanThreads, "n", 128, "并发数")
	flag.StringVar(&args.PrintCount, "p", "all", "输出延迟最低的CIDR数量")
	flag.StringVar(&args.OutFile, "o", "IP_Speed.csv", "写入结果文件")
	flag.BoolVar(&args.NoCSV, "nocsv", false, "不输出CSV文件")
	flag.StringVar(&args.UseIPv4, "useip4", "", "输出IPv4列表，使用 all 表示输出所有IPv4")
	flag.StringVar(&args.UseIPv6, "useip6", "", "输出IPv6列表，使用 all 表示输出所有IPv6")
	flag.StringVar(&args.IPTxtFile, "iptxt", "ip.txt", "指定IP列表输出文件名")
	flag.BoolVar(&args.NoTest, "notest", false, "不进行测速，只生成随机IP")
	flag.BoolVar(&args.ShowAll, "showall", false, "使用后显示所有结果，包括未查询到数据中心的结果")
	flag.BoolVar(&args.Help, "h", false, "打印帮助")
	flag.StringVar(&args.Timeout, "timeout", "5h", "程序执行超时时间，格式如：5h30m10s，设置为0则不限制时间")

	flag.Parse()

	return args
}

// 打印帮助信息
func printHelp() {
	fmt.Println("\n基本参数:")
	fmt.Println("  -url string      测速的CIDR链接")
	fmt.Println("  -f string        指定测速的文件路径 (当未设置-url时使用)")
	fmt.Println("  -o string        结果文件名 (默认: IP_Speed.csv)")
	fmt.Println("  -h               显示帮助信息")
	fmt.Println("  -notest          不进行测速，只生成随机IP (需配合 -useip4 或 -useip6 使用)")
	fmt.Println("  -showall         使用后显示所有结果，包括未查询到数据中心的结果")
	fmt.Println("  -timeout string  程序执行超时退出 (默认: 5h0m0s)，设置为 0 则不限制时间")

	fmt.Println("\n测速参数:")
	fmt.Println("  -t int           延迟测试次数 (默认: 4)")
	fmt.Println("  -tp int          测试端口号 (默认: 443)")
	fmt.Println("  -ts int          每个CIDR测试的IP数量 (默认: 2)")
	fmt.Println("  -n int           并发测试线程数量 (默认: 128)")
	fmt.Println("\n  注意避免 -t 和 -ts 导致测速量过于庞大！")

	fmt.Println("\n筛选参数:")
	fmt.Println("  -colo string     指定数据中心，多个用逗号分隔 (例: HKG,NRT,LAX,SJC)")
	fmt.Println("  -tl int          延迟上限 (默认: 500ms)")
	fmt.Println("  -tll int         延迟下限 (默认: 0ms)")
	fmt.Println("  -tlr float       丢包率上限 (默认: 0.5)")
	fmt.Println("  -p string        输出结果数量 (默认: all)")

	fmt.Println("\n输出选项:")
	fmt.Println("  -nocsv           不生成CSV文件 (默认: 不使用)")
	fmt.Println("  -useip4 string   生成IPv4列表 (默认: 不使用)")
	fmt.Println("                   - 使用 all: 输出所有IPv4 CIDR的完整IP列表")
	fmt.Println("                   - 使用数字 (如9999): 输出指定数量的不重复IPv4")
	fmt.Println("  -useip6 string   生成IPv6列表 (默认: 不使用)")
	fmt.Println("                   - 使用数字 (如9999): 输出指定数量的不重复IPv6")
	fmt.Println("  -iptxt string    指定IP列表输出文件名 (默认: ip.txt)")
	fmt.Println("                   - 使用此参数时必须至少使用 -useip4 或 -useip6")
}

// 检查结果是否符合过滤条件
// shouldIncludeResult 检查结果是否符合过滤条件
func shouldIncludeResult(result TestResult, coloFlag *string, minLatency, maxLatency *int, maxLossRate *float64, showAll *bool) bool {
	// 如果不显示所有结果，则跳过未知数据中心的结果
	if !*showAll && result.DataCenter == "Unknown" {
		return false
	}

	// 检查数据中心
	if *coloFlag != "" {
		coloList := strings.Split(*coloFlag, ",")
		match := false
		for _, colo := range coloList {
			if result.DataCenter == strings.TrimSpace(colo) {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}

	// 检查延迟
	if result.AvgLatency < *minLatency || result.AvgLatency > *maxLatency {
		return false
	}

	// 检查丢包率
	if result.LossRate > *maxLossRate {
		return false
	}

	return true
}
