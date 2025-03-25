package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/sync/semaphore"
)

// ----------------------- 数据类型定义 -----------------------

type TestResult struct {
	IP         string
	CIDR       string
	DataCenter string
	Region     string
	City       string
	AvgLatency int // 直接存储毫秒值
	LossRate   float64
}

func (r *TestResult) Clear() {
	r.IP = ""
	r.CIDR = ""
	r.DataCenter = ""
	r.Region = ""
	r.City = ""
	r.AvgLatency = 0
	r.LossRate = 0
}

// 临时测试数据
type CIDRTestData struct {
	IPs     []string
	Results []TestResult
}

// 最终结果
type CIDRResult struct {
	CIDR       string
	DataCenter string
	Region     string
	City       string
	AvgLatency int
	LossRate   float64
}

// 测试过程中的结构
type CIDRGroup struct {
	CIDR   string
	Data   *CIDRTestData // 临时数据
	Result *TestResult
}

type location struct {
	Iata   string `json:"iata"`
	Region string `json:"region"`
	City   string `json:"city"`
}

// ----------------------- 主程序入口 -----------------------

var (
	globalSem      *semaphore.Weighted
	testDataPool   sync.Pool
	resultPool     sync.Pool
	testResultPool sync.Pool
	cidrStringPool sync.Map // CIDR 字符串池
)

// 获取共享 CIDR 字符串的函数
func getSharedCIDR(cidr string) string {
	if pooledCIDR, ok := cidrStringPool.Load(cidr); ok {
		return pooledCIDR.(string)
	}
	cidrStringPool.Store(cidr, cidr)
	return cidr
}

func init() {
	// 初始化对象池
	testDataPool = sync.Pool{
		New: func() interface{} {
			return &CIDRTestData{
				IPs:     make([]string, 0),
				Results: make([]TestResult, 0),
			}
		},
	}

	// 初始化 resultPool
	resultPool = sync.Pool{
		New: func() interface{} {
			return &TestResult{}
		},
	}

	// 初始化 TestResult 对象池
	testResultPool = sync.Pool{
		New: func() interface{} {
			return &TestResult{}
		},
	}
}

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

func main() {
	// 添加全局超时控制
	defaultTimeout := 5 * time.Hour // 修改默认超时时间为5小时
	timeoutFlag := flag.String("timeout", defaultTimeout.String(), "程序执行超时时间，格式如：5h30m10s，设置为0则不限制时间")

	// 解析超时时间
	globalTimeout, err := time.ParseDuration(*timeoutFlag)
	if err != nil {
		fmt.Printf("无效的超时时间格式: %s, 使用默认值: %s\n", *timeoutFlag, defaultTimeout)
		globalTimeout = defaultTimeout
	}

	// 创建上下文，如果超时时间为0则不设置超时
	var ctx context.Context
	var cancel context.CancelFunc
	if globalTimeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), globalTimeout)
		defer cancel()
	} else {
		ctx, cancel = context.WithCancel(context.Background())
		defer cancel()
		fmt.Println("已设置为不限制执行时间")
	}

	// 创建一个通道用于接收程序完成信号
	done := make(chan bool)

	// 在后台运行主程序逻辑
	go func() {
		// 主程序逻辑
		runMainProgram()
		done <- true
	}()

	// 等待程序完成或超时
	select {
	case <-done:
		// 程序正常完成
		fmt.Println("程序执行完成")
	case <-ctx.Done():
		// 程序超时
		fmt.Println("程序执行超时，强制退出")
		os.Exit(1)
	}
}

func runMainProgram() {
	// 定义命令行参数
	urlFlag := flag.String("url", "", "测速的CIDR链接")
	fileFlag := flag.String("f", "", "指定测速的文件")
	testCount := flag.Int("t", 4, "延迟测速的次数")
	portFlag := flag.Int("tp", 443, "指定测速的端口号")
	ipPerCIDR := flag.Int("ts", 2, "从CIDR内随机选择IP的数量")
	coloFlag := flag.String("colo", "", "匹配指定数据中心，用逗号分隔，例如 HKG,KHH,NRT,LAX")
	maxLatency := flag.Int("tl", 500, "平均延迟上限(ms)")
	minLatency := flag.Int("tll", 0, "平均延迟下限(ms)")
	maxLossRate := flag.Float64("tlr", 0.5, "丢包率上限")
	scanThreads := flag.Int("n", 128, "并发数")
	printCount := flag.String("p", "all", "输出延迟最低的CIDR数量")
	outFile := flag.String("o", "IP_Speed.csv", "写入结果文件")
	noCSV := flag.Bool("nocsv", false, "不输出CSV文件")
	useIPv4 := flag.String("useip4", "", "输出IPv4列表，使用 all 表示输出所有IPv4")
	useIPv6 := flag.String("useip6", "", "输出IPv6列表，使用 all 表示输出所有IPv6")
	ipTxtFile := flag.String("iptxt", "ip.txt", "指定IP列表输出文件名")
	noTest := flag.Bool("notest", false, "不进行测速，只生成随机IP")
	showAll := flag.Bool("showall", false, "使用后显示所有结果，包括未查询到数据中心的结果")
	help := flag.Bool("h", false, "打印帮助")

	flag.Parse()

	// 限制最大并发数
	if *scanThreads > 1024 {
		// 限制最大并发数为1024
		*scanThreads = 1024
	}

	// 使用统一的并发控制
	maxConcurrent := *scanThreads
	globalSem = semaphore.NewWeighted(int64(maxConcurrent))

	// 显示帮助信息
	if *help {
		printHelp()
		return
	}

	// 检查必要参数
	if *urlFlag == "" && *fileFlag == "" {
		fmt.Println("错误: 必须指定 -url 或 -f 参数")
		printHelp()
		return
	}

	// 如果使用 -notest 参数，检查是否指定了 -useip4 或 -useip6
	if *noTest && *useIPv4 == "" && *useIPv6 == "" {
		fmt.Println("错误: 使用 -notest 参数时必须至少指定 -useip4 或 -useip6 参数")
		return
	}

	// 获取CIDR列表
	var cidrList []string
	var err error

	if *urlFlag != "" {
		fmt.Printf("从URL获取CIDR列表: %s\n", *urlFlag)
		cidrList, err = getCIDRFromURL(*urlFlag)
	} else {
		fmt.Printf("从文件获取CIDR列表: %s\n", *fileFlag)
		cidrList, err = getCIDRFromFile(*fileFlag)
	}

	if err != nil {
		fmt.Printf("获取CIDR列表失败: %v\n", err)
		return
	}

	fmt.Printf("共获取到 %d 个CIDR\n", len(cidrList))

	// 处理CIDR列表，将大于/24的IPv4 CIDR拆分为多个/24，将大于/48的IPv6 CIDR拆分为多个/48
	expandedCIDRs := expandCIDRs(cidrList)
	fmt.Printf("处理后共有 %d 个CIDR\n", len(expandedCIDRs))

	// 如果指定了 -notest 参数，直接生成IP文件并退出
	if *noTest {
		var results []TestResult
		for _, cidr := range expandedCIDRs {
			_, _, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			results = append(results, TestResult{
				CIDR: cidr,
			})
		}

		fmt.Printf("跳过测速，直接生成IP列表\n")
		err = generateIPFile(results, *useIPv4, *useIPv6, *ipTxtFile)
		if err != nil {
			fmt.Printf("生成IP文件失败: %v\n", err)
		} else {
			fmt.Printf("IP列表已写入: %s\n", *ipTxtFile)
		}
		return
	}

	// 获取Cloudflare数据中心位置信息
	locationMap, err := getLocationMap()
	if err != nil {
		fmt.Printf("获取数据中心位置信息失败: %v\n", err)
		return
	}

	// 从每个CIDR中随机选择IP进行测试
	cidrGroups := make([]CIDRGroup, len(expandedCIDRs))
	for i, cidr := range expandedCIDRs {
		cidrGroups[i] = CIDRGroup{
			CIDR: cidr,
		}
	}

	// 测试IP性能
	cidrGroups = testIPs(cidrGroups, *portFlag, *testCount, *scanThreads, *ipPerCIDR, locationMap,
		coloFlag, minLatency, maxLatency, maxLossRate, showAll)

	// 收集已合并的结果
	var filteredResults []TestResult
	for _, group := range cidrGroups {
		if group.Result != nil {
			// 直接添加 Result 的副本，不需要转换
			filteredResults = append(filteredResults, *group.Result)

			// 回收 Result 对象
			testResultPool.Put(group.Result)
			group.Result = nil
		}
	}

	// 过滤结果
	fmt.Printf("符合条件的结果: %d 个\n", len(filteredResults))

	// 排序结果
	sort.Slice(filteredResults, func(i, j int) bool {
		if filteredResults[i].LossRate == filteredResults[j].LossRate {
			return filteredResults[i].AvgLatency < filteredResults[j].AvgLatency
		}
		return filteredResults[i].LossRate < filteredResults[j].LossRate
	})

	// 限制输出数量
	if *printCount != "all" {
		count, err := strconv.Atoi(*printCount)
		if err == nil && count > 0 {
			// 只有当结果数量大于指定数量时才截取
			if count < len(filteredResults) {
				filteredResults = filteredResults[:count]
			}
			// 否则保持原有结果不变
		}
	}

	// 输出结果
	if !*noCSV {
		err = writeResultsToCSV(filteredResults, *outFile)
		if err != nil {
			fmt.Printf("写入CSV文件失败: %v\n", err)
		} else {
			fmt.Printf("结果已写入: %s\n", *outFile)
		}
	}

	// 输出IP列表
	if *useIPv4 != "" || *useIPv6 != "" {
		err = generateIPFile(filteredResults, *useIPv4, *useIPv6, *ipTxtFile)
		if err != nil {
			fmt.Printf("生成IP文件失败: %v\n", err)
		} else {
			fmt.Printf("IP列表已写入: %s\n", *ipTxtFile)
		}
	}

	// 打印结果摘要
	printResultsSummary(filteredResults)
}

// ----------------------- 功能模块 -----------------------

// 打印帮助信息
func printHelp() {
	fmt.Println("\nCloudflare CIDR 测速工具")
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

// 从URL获取CIDR列表
func getCIDRFromURL(url string) ([]string, error) {
	maxRetries := 10
	retryDelay := 3 * time.Second

	var cidrList []string
	var lastErr error

	// 创建带超时的HTTP客户端
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// 重试逻辑
	for retry := 0; retry < maxRetries; retry++ {
		if retry > 0 {
			fmt.Printf("第 %d 次重试获取CIDR列表...\n", retry)
			time.Sleep(retryDelay)
			// 每次重试增加延迟时间
			retryDelay *= 1
		}

		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			// 只显示重试提示，不显示具体错误
			fmt.Println("获取失败，准备重试...")
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP请求失败，状态码: %d", resp.StatusCode)
			// 只显示重试提示，不显示具体错误
			fmt.Println("获取失败，准备重试...")
			continue
		}

		// 成功获取，解析CIDR列表
		cidrList, err = parseCIDRList(resp.Body)
		resp.Body.Close()

		if err != nil {
			lastErr = err
			// 只显示重试提示，不显示具体错误
			fmt.Println("解析失败，准备重试...")
			continue
		}

		// 检查是否成功获取到CIDR
		if len(cidrList) > 0 {
			return cidrList, nil
		}

		lastErr = fmt.Errorf("获取到的CIDR列表为空")
		// 只显示重试提示，不显示具体错误
		fmt.Println("获取结果为空，准备重试...")
	}

	// 修改这里，使用lastErr变量而不是创建新的错误
	return nil, lastErr
}

// 从文件获取CIDR列表
func getCIDRFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return parseCIDRList(file)
}

// 解析CIDR列表
func parseCIDRList(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	var cidrList []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 处理不同格式的CIDR
		if !strings.Contains(line, "/") {
			// 如果是IPv4
			if strings.Count(line, ".") == 3 {
				line = line + "/32"
			}
			// 如果是IPv6
			if strings.Contains(line, ":") {
				line = line + "/128"
			}
		}

		cidrList = append(cidrList, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return cidrList, nil
}

// 扩展CIDR列表，将大于/24的IPv4 CIDR拆分为多个/24，将大于/48的IPv6 CIDR拆分为多个/48
func expandCIDRs(cidrList []string) []string {
	var expandedList []string

	for _, cidr := range cidrList {
		// 检查是否是有效的CIDR
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		// 使用共享 CIDR 字符串
		sharedCIDR := getSharedCIDR(cidr)
		expandedList = append(expandedList, sharedCIDR)

		// 判断是IPv4还是IPv6
		if ipNet.IP.To4() != nil {
			// IPv4
			ones, _ := ipNet.Mask.Size()
			if ones >= 24 {
				// 已经是/24或更小，直接添加
				expandedList = append(expandedList, cidr)
			} else {
				// 需要拆分为多个/24
				subCIDRs := expandIPv4CIDR(ipNet, ones)
				expandedList = append(expandedList, subCIDRs...)
			}
		} else {
			// IPv6
			ones, _ := ipNet.Mask.Size()
			if ones >= 48 {
				// 已经是/48或更小，直接添加
				expandedList = append(expandedList, cidr)
			} else {
				// 需要拆分为多个/48
				subCIDRs := expandIPv6CIDR(ipNet, ones)
				expandedList = append(expandedList, subCIDRs...)
			}
		}
	}

	return expandedList
}

// 将IPv4 CIDR拆分为多个/24
func expandIPv4CIDR(ipNet *net.IPNet, ones int) []string {
	// 如果已经是/24或更小，直接返回
	if ones >= 24 {
		return []string{ipNet.String()}
	}

	// 计算需要拆分的子网数量
	splitBits := 24 - ones
	count := 1 << uint(splitBits) // 2^splitBits

	// 将IP地址转换为uint32
	ip := ipNet.IP.To4()
	baseIP := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])

	// 创建掩码
	mask := uint32(0xffffffff) << uint(32-ones)

	// 应用掩码获取网络地址
	baseIP = baseIP & mask

	result := make([]string, 0, count)

	// 生成所有/24子网
	for i := 0; i < count; i++ {
		// 计算新的子网地址
		newIP := baseIP | (uint32(i) << 8)

		// 转换回IP地址格式
		a := byte((newIP >> 24) & 0xFF)
		b := byte((newIP >> 16) & 0xFF)
		c := byte((newIP >> 8) & 0xFF)

		// 创建新的CIDR字符串
		newCIDR := fmt.Sprintf("%d.%d.%d.0/24", a, b, c)
		result = append(result, newCIDR)
	}

	return result
}

// 将IPv6 CIDR拆分为多个/48
func expandIPv6CIDR(ipNet *net.IPNet, ones int) []string {
	// 如果已经是/48或更小，直接返回
	if ones >= 48 {
		return []string{ipNet.String()}
	}

	// 计算需要拆分的位数
	splitBits := 48 - ones

	// 限制拆分数量，避免生成过多的子网
	if splitBits > 16 {
		splitBits = 16
	}

	// 计算需要拆分的子网数量 (2^splitBits)
	subnetCount := 1 << uint(splitBits)

	// 获取原始 IP 地址的 16 字节表示
	ip := ipNet.IP.To16()
	if ip == nil {
		return nil
	}

	result := make([]string, 0, subnetCount)

	// 生成所有/48子网
	for i := 0; i < subnetCount; i++ {
		// 复制原始 IP 地址
		newIP := make(net.IP, 16)
		copy(newIP, ip)

		// 将子网索引 i 设置到 IP 地址的相应位置
		// IPv6 地址是 16 字节，每个字节 8 位
		// ones 是网络前缀长度，我们需要修改从 ones 到 48 的位

		// 计算起始字节和位偏移
		startByte := ones / 8
		startBit := ones % 8

		// 设置子网索引位
		remainingBits := splitBits
		value := i

		// 处理第一个字节（可能需要保留部分位）
		if startBit > 0 {
			// 计算第一个字节可以设置的位数
			bitsInFirstByte := 8 - startBit
			if bitsInFirstByte > remainingBits {
				bitsInFirstByte = remainingBits
			}

			// 创建掩码，保留前 startBit 位
			mask := byte(0xFF << (8 - startBit))

			// 计算要设置的值
			valueToSet := byte(value>>(remainingBits-bitsInFirstByte)) << (8 - startBit - bitsInFirstByte)

			// 设置值，保留前 startBit 位
			newIP[startByte] = (newIP[startByte] & mask) | valueToSet

			remainingBits -= bitsInFirstByte
			startByte++
		}

		// 处理完整字节
		for remainingBits >= 8 {
			newIP[startByte] = byte(value >> (remainingBits - 8))
			remainingBits -= 8
			startByte++
		}

		// 处理最后一个不完整字节
		if remainingBits > 0 {
			valueToSet := byte(value&((1<<remainingBits)-1)) << (8 - remainingBits)
			newIP[startByte] = valueToSet
		}

		// 将 48 位之后的所有位清零
		for j := 6; j < 16; j++ {
			newIP[j] = 0
		}

		// 创建新的 /48 CIDR
		newCIDR := &net.IPNet{
			IP:   newIP,
			Mask: net.CIDRMask(48, 128),
		}
		result = append(result, newCIDR.String())
	}

	return result
}

// 通用的IPv4地址生成函数 - 新增函数
func generateRandomIPv4Address(ipNet *net.IPNet) string {
	// 获取网络地址和掩码
	ip := ipNet.IP.To4()
	if ip == nil {
		return ""
	}

	mask := ipNet.Mask
	ones, bits := mask.Size()
	randomBits := bits - ones

	// 将IP地址转换为uint32
	baseIP := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])

	// 创建掩码
	netMask := uint32(0xffffffff) << uint(randomBits)
	networkAddr := baseIP & netMask

	// 计算最大偏移量
	maxOffset := uint32(1) << uint(randomBits)

	if maxOffset == 1 {
		// /32，只有一个IP，直接返回
		return ip.String()
	}

	// 生成随机偏移量
	randomOffset := uint32(0)
	if maxOffset > 2 {
		randomOffset = rand.Uint32() % (maxOffset - 1) // 避开网络地址
	} else {
		randomOffset = 1 // /31 的情况，两个地址都可以用
	}

	// 计算最终IP
	finalIP := networkAddr | randomOffset

	// 转换回IP地址格式
	result := net.IPv4(
		byte(finalIP>>24),
		byte(finalIP>>16),
		byte(finalIP>>8),
		byte(finalIP),
	)

	return result.String()
}

// 通用的IPv6地址生成函数 - 新增函数
func generateRandomIPv6Address(ipNet *net.IPNet) string {
	// 获取网络地址
	ip := ipNet.IP.To16()
	if ip == nil {
		return ""
	}

	// 计算可以随机的位数
	ones, bits := ipNet.Mask.Size()
	randomBits := bits - ones

	// 创建新IP
	newIP := make(net.IP, 16)
	copy(newIP, ip)

	// 计算需要随机的字节数和位数
	randomBytes := randomBits / 8
	remainingBits := randomBits % 8

	// 完全随机的字节
	for i := 0; i < 16; i++ {
		// 只处理需要随机化的字节
		if i >= 16-randomBytes {
			// 生成完全随机的字节
			randValue := byte(rand.Intn(256))
			// 保留网络前缀部分
			maskByte := ipNet.Mask[i]
			newIP[i] = (newIP[i] & maskByte) | (randValue &^ maskByte)
		}
	}

	// 处理剩余的不足一个字节的位
	if remainingBits > 0 {
		bytePos := 16 - randomBytes - 1
		if bytePos >= 0 {
			// 创建位掩码，只修改需要随机的位
			bitMask := byte(0xFF >> (8 - remainingBits))
			// 生成随机值
			randValue := byte(rand.Intn(1 << remainingBits))
			// 应用掩码和随机值
			maskByte := ipNet.Mask[bytePos]
			// 保留网络前缀，修改主机部分
			newIP[bytePos] = (newIP[bytePos] & maskByte) | (randValue & bitMask & (^maskByte))
		}
	}

	// 检查生成的IP是否为全零地址
	isZero := true
	for _, b := range newIP {
		if b != 0 {
			isZero = false
			break
		}
	}

	// 如果是全零地址，重新生成
	if isZero {
		// 简单地将最后一个字节设为1，确保不是全零地址
		newIP[15] = 1
	}

	return newIP.String()
}

// 获取Cloudflare数据中心位置信息
func getLocationMap() (map[string]*location, error) {
	// 设置最大重试次数
	maxRetries := 5
	retryDelay := 2 * time.Second

	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		if retry > 0 {
			time.Sleep(retryDelay)
		}

		// 创建带超时的客户端
		client := &http.Client{
			Timeout: 3 * time.Second,
		}

		resp, err := client.Get("https://speed.cloudflare.com/locations")
		if err != nil {
			lastErr = fmt.Errorf("无法获取 locations.json: %v", err)
			continue // 重试
		}

		// 确保响应体被关闭
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP请求失败，状态码: %d", resp.StatusCode)
			continue // 重试
		}

		// 读取整个响应体到内存
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("读取响应体失败: %v", err)
			continue // 重试
		}

		// 检查响应体是否为空
		if len(body) == 0 {
			lastErr = fmt.Errorf("获取到的响应体为空")
			continue // 重试
		}

		// 解析JSON
		var locations []location
		if err := json.Unmarshal(body, &locations); err != nil {
			lastErr = fmt.Errorf("无法解析JSON: %v", err)
			continue // 重试
		}

		// 检查解析后的数据是否为空
		if len(locations) == 0 {
			lastErr = fmt.Errorf("解析后的数据中心列表为空")
			continue // 重试
		}

		// 构造 location 映射，key 为数据中心代码，使用指针
		locationMap := make(map[string]*location)
		for i := range locations {
			locationMap[locations[i].Iata] = &locations[i]
		}

		// 成功获取数据
		return locationMap, nil
	}

	// 所有重试都失败
	return nil, fmt.Errorf("在%d次尝试后仍然失败: %v", maxRetries, lastErr)
}

// 时间格式化
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%d时%d分%d秒", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%d分%d秒", m, s)
	}
	return fmt.Sprintf("%d秒", s)
}

// 测试IP性能
func testIPs(cidrGroups []CIDRGroup, port, testCount, maxThreads, ipPerCIDR int, locationMap map[string]*location,
	coloFlag *string, minLatency, maxLatency *int, maxLossRate *float64, showAll *bool) []CIDRGroup {
	// 初始化并发控制
	if globalSem == nil {
		globalSem = semaphore.NewWeighted(int64(maxThreads))
	}

	// 添加内存管理相关变量
	var processedGroupCount int32
	var mutex sync.Mutex
	var wg sync.WaitGroup

	resultChan := make(chan TestResult, maxThreads)

	// CIDR 完成计数器
	cidrIPCounts := make(map[string]struct {
		total   int
		current int
	})

	// 初始化每个 CIDR 的计数
	for _, group := range cidrGroups {
		cidrIPCounts[group.CIDR] = struct {
			total   int
			current int
		}{
			total: ipPerCIDR,
		}
	}

	// 计算总IP数量
	totalIPs := len(cidrGroups) * ipPerCIDR

	// CIDR数据中心信息缓存
	type cidrCache struct {
		sync.RWMutex
		dataCenter *string
		region     *string
		city       *string
		found      bool
	}
	cidrColoMap := make(map[string]*cidrCache)

	// 初始化CIDR缓存
	for _, group := range cidrGroups {
		cidrColoMap[group.CIDR] = &cidrCache{}
	}

	// 计数器
	var (
		processedCount  int32
		tcpSuccessCount int32
	)

	startTime := time.Now()

	// 创建进度条
	tmpl := `{{counters . }} {{ bar . "[" "=" (cycle . "↖" "↗" "↘" "↙") "_" "]"}} {{string . "elapsed"}}` // 使用等宽块字符
	bar := pb.ProgressBarTemplate(tmpl).Start(totalIPs)
	bar.Set("total", fmt.Sprintf("%d", totalIPs))
	bar.Set("current", "0")
	bar.Start()

	// 初始化每个 CIDR 组的 Data 字段
	for i := range cidrGroups {
		cidrGroups[i].Data = testDataPool.Get().(*CIDRTestData)
	}

	// 启动结果处理协程
	go func() {
		defer close(resultChan)
		for result := range resultChan {
			mutex.Lock()

			counts := cidrIPCounts[result.CIDR]

			// 添加结果到临时存储
			for i := range cidrGroups {
				if cidrGroups[i].CIDR == result.CIDR {
					cidrGroups[i].Data.Results = append(cidrGroups[i].Data.Results, result)

					// 使用实际结果数量判断是否完成
					if len(cidrGroups[i].Data.Results) == counts.total {
						// 调用 finalize 方法处理结果
						cidrGroups[i].finalize()

						// 检查结果是否符合过滤条件
						if !shouldIncludeResult(TestResult{
							CIDR:       cidrGroups[i].Result.CIDR,
							DataCenter: cidrGroups[i].Result.DataCenter,
							Region:     cidrGroups[i].Result.Region,
							City:       cidrGroups[i].Result.City,
							AvgLatency: cidrGroups[i].Result.AvgLatency,
							LossRate:   cidrGroups[i].Result.LossRate,
						}, coloFlag, minLatency, maxLatency, maxLossRate, showAll) {
							cidrGroups[i].Result = nil
						}

						// 增加已处理组计数
						atomic.AddInt32(&processedGroupCount, 1)
					}
					break
				}
			}
			mutex.Unlock()
		}
	}()

	// 创建工作池
	for i := 0; i < maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				// 获取一个未完成的CIDR
				mutex.Lock()
				var currentGroup *CIDRGroup
				for i := range cidrGroups {
					counts := cidrIPCounts[cidrGroups[i].CIDR]
					if counts.current < counts.total {
						currentGroup = &cidrGroups[i]
						counts.current++ // 提前增加计数
						cidrIPCounts[cidrGroups[i].CIDR] = counts
						break
					}
				}
				if currentGroup == nil {
					mutex.Unlock()
					return // 所有CIDR都已处理完成
				}
				mutex.Unlock()

				// 使用对象池
				data := testDataPool.Get().(*CIDRTestData)
				defer testDataPool.Put(data)

				// 生成并测试一个IP
				_, ipNet, err := net.ParseCIDR(currentGroup.CIDR)
				if err != nil {
					continue
				}

				// 生成随机IP
				var ip string
				if ipNet.IP.To4() != nil {
					ip = generateRandomIPv4Address(ipNet)
				} else {
					ip = generateRandomIPv6Address(ipNet)
				}

				resultObj := testResultPool.Get().(*TestResult)
				resultObj.Clear() // 清空对象

				// 设置基本信息
				resultObj.IP = ip
				resultObj.CIDR = currentGroup.CIDR

				// 执行TCP测试
				localSuccessCount := 0
				totalLatency := time.Duration(0)
				for i := 0; i < testCount; i++ {
					start := time.Now()
					conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), time.Second)
					if err != nil {
						continue
					}
					latency := time.Since(start)
					conn.Close()

					localSuccessCount++
					totalLatency += latency
				}

				if localSuccessCount > 0 {
					// TCP测试成功
					avgLatency := totalLatency / time.Duration(localSuccessCount)
					resultObj.AvgLatency = int(avgLatency.Milliseconds())
					resultObj.LossRate = float64(testCount-localSuccessCount) / float64(testCount)

					// 检查CIDR是否已有数据中心信息
					cache := cidrColoMap[currentGroup.CIDR]
					cache.RLock()
					if cache.found {
						resultObj.DataCenter = *cache.dataCenter
						resultObj.Region = *cache.region
						resultObj.City = *cache.city
						cache.RUnlock()
					} else {
						cache.RUnlock()
						dataCenter, region, city := getDataCenterInfo(ip, locationMap)
						if dataCenter != "Unknown" {
							cache.Lock()
							if !cache.found {
								// 查找locationMap中是否有该数据中心
								if loc, ok := locationMap[dataCenter]; ok {
									// 使用指针指向locationMap中的数据
									cache.dataCenter = &dataCenter
									cache.region = &loc.Region
									cache.city = &loc.City
								} else {
									// 如果locationMap中没有，则创建新的字符串
									dcCopy := dataCenter
									regionCopy := region
									cityCopy := city
									cache.dataCenter = &dcCopy
									cache.region = &regionCopy
									cache.city = &cityCopy
								}
								cache.found = true
							}
							cache.Unlock()
						}
						resultObj.DataCenter = dataCenter
						resultObj.Region = region
						resultObj.City = city
					}

					// 发送结果到结果通道
					resultChan <- *resultObj // 发送副本而不是指针
					atomic.AddInt32(&tcpSuccessCount, 1)
				}

				// 将对象放回池中
				testResultPool.Put(resultObj)

				// 更新进度
				current := atomic.AddInt32(&processedCount, 1)
				elapsed := time.Since(startTime)
				bar.Set("current", fmt.Sprintf("%d", current))
				bar.Set("elapsed", formatDuration(elapsed))
				bar.SetCurrent(int64(current))
			}
		}()
	}

	// 等待所有工作完成
	wg.Wait()

	// 先完成进度条
	bar.Finish()

	// 计算TCP测试成功率
	tcpSuccessRate := float64(tcpSuccessCount) / float64(totalIPs) * 100
	fmt.Printf("TCP测试完成，成功率: %.2f%% (%d/%d)\n", tcpSuccessRate, tcpSuccessCount, totalIPs)

	// 过滤结果时只保留有最终结果的组
	var filteredGroups []CIDRGroup
	for _, group := range cidrGroups {
		// 只保留有Result且不为nil的组
		if group.Result != nil {
			filteredGroups = append(filteredGroups, group)
		} else if group.Data != nil {
			// 对于没有最终结果的组，确保其Data被放回对象池
			group.Data.Results = group.Data.Results[:0]
			group.Data.IPs = group.Data.IPs[:0]
			testDataPool.Put(group.Data)
		}
	}

	return filteredGroups
}

// 获取数据中心信息
func getDataCenterInfo(ip string, locationMap map[string]*location) (string, string, string) {

	// 使用全局通道控制并发
	ctx := context.Background()
	if err := globalSem.Acquire(ctx, 1); err != nil {
		return "Unknown", "", ""
	}
	defer globalSem.Release(1)

	maxRetries := 2                      // 重试次数
	retryDelay := 800 * time.Millisecond // 添加重试延迟

	// 使用共享的 Transport 对象
	transport := &http.Transport{
		DisableKeepAlives: true,
		IdleConnTimeout:   1500 * time.Millisecond, // 超时时间
		MaxIdleConns:      100,
		MaxConnsPerHost:   10,
	}

	client := &http.Client{
		Timeout:   1000 * time.Millisecond, // 超时时间
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 确保资源被释放
	defer transport.CloseIdleConnections()

	for retry := 0; retry <= maxRetries; retry++ {
		// 添加重试延迟，第一次尝试不延迟
		if retry > 0 {
			time.Sleep(retryDelay)
		}
		hostIP := ip
		if !strings.Contains(ip, ".") {
			hostIP = "[" + ip + "]"
		}

		req, err := http.NewRequest("HEAD", "http://cloudflare.com", nil)
		if err != nil {
			continue
		}

		req.Host = "cloudflare.com"
		req.URL.Host = hostIP
		req.Close = true

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		cfRay := resp.Header.Get("Cf-Ray")
		resp.Body.Close()

		if cfRay == "" {
			continue
		}

		lastDashIndex := strings.LastIndex(cfRay, "-")
		if lastDashIndex == -1 {
			continue
		}

		dataCenter := cfRay[lastDashIndex+1:]
		if dataCenter != "" {
			loc, ok := locationMap[dataCenter]
			if ok {
				return dataCenter, loc.Region, loc.City
			}
			return dataCenter, "", ""
		}
	}

	return "Unknown", "", ""
}

// 生成IP文件
func generateIPFile(results []TestResult, ipv4Mode, ipv6Mode, filename string) error {
	// 检查是否至少指定了一种IP类型
	if ipv4Mode == "" && ipv6Mode == "" {
		return fmt.Errorf("必须至少指定 -useip4 或 -useip6 参数")
	}

	var ipList []string

	// 检查是否有IPv4和IPv6的CIDR
	hasIPv4CIDR := false
	hasIPv6CIDR := false

	// 根据需要检查的IP类型进行判断
	needCheckIPv4 := ipv4Mode != ""
	needCheckIPv6 := ipv6Mode != ""

	for _, result := range results {
		_, ipNet, err := net.ParseCIDR(result.CIDR)
		if err != nil {
			continue
		}

		// 分别判断IPv4和IPv6
		if needCheckIPv4 && !hasIPv4CIDR && ipNet.IP.To4() != nil {
			hasIPv4CIDR = true
		}

		if needCheckIPv6 && !hasIPv6CIDR && ipNet.IP.To4() == nil && ipNet.IP.To16() != nil {
			hasIPv6CIDR = true
		}

		// 如果需要检查的类型都已找到，就可以提前结束检查
		if (!needCheckIPv4 || hasIPv4CIDR) && (!needCheckIPv6 || hasIPv6CIDR) {
			break
		}
	}

	// 处理 IPv4
	if ipv4Mode != "" && hasIPv4CIDR {
		ipv4Count := 0
		ipv4Limit := 1000000 // 设置IPv4上限为100万

		if ipv4Mode == "all" {
			// 遍历每个CIDR生成所有IP
			for _, result := range results {
				_, ipNet, err := net.ParseCIDR(result.CIDR)
				if err != nil || ipNet.IP.To4() == nil {
					continue // 跳过非IPv4
				}

				// 获取掩码大小
				ones, _ := ipNet.Mask.Size()
				randomBits := 32 - ones

				// 计算该CIDR包含的IP数量
				totalIPs := 1 << uint(randomBits)

				// 生成该CIDR下的所有IP
				for i := 0; i < totalIPs && ipv4Count < ipv4Limit; i++ {
					// 创建新IP
					newIP := make(net.IP, 4)
					copy(newIP, ipNet.IP.To4())

					// 应用值到IP
					for j := 0; j < 4; j++ {
						shift := uint(8 * (3 - j))
						if shift < uint(randomBits) {
							bitValue := byte((i >> shift) & 0xFF)
							maskByte := ipNet.Mask[j]
							newIP[j] = (newIP[j] & maskByte) | (bitValue &^ maskByte)
						}
					}

					ipStr := newIP.String()
					if ipStr != "" {
						ipList = append(ipList, ipStr)
						ipv4Count++
					}
				}

				// 检查是否达到上限
				if ipv4Count >= ipv4Limit {
					fmt.Printf("已达到IPv4生成上限 %d 个\n", ipv4Limit)
					break
				}
			}
		} else if count, err := strconv.Atoi(ipv4Mode); err == nil && count > 0 {
			targetCount := count
			if targetCount > ipv4Limit {
				targetCount = ipv4Limit
				fmt.Printf("IPv4生成数量已限制为 %d 个\n", ipv4Limit)
			}

			// 准备CIDR列表和计算总IP数量
			type cidrInfo struct {
				ipNet   *net.IPNet
				ipCount int
			}

			var cidrList []cidrInfo
			totalAvailableIPs := 0

			// 初始化CIDR信息并计算总IP数量
			for _, result := range results {
				_, ipNet, err := net.ParseCIDR(result.CIDR)
				if err != nil || ipNet.IP.To4() == nil {
					continue // 跳过非IPv4
				}

				if ipNet.IP.To4() != nil {
					ones, _ := ipNet.Mask.Size()
					ipCount := 1 << uint(32-ones)

					cidrList = append(cidrList, cidrInfo{
						ipNet:   ipNet,
						ipCount: ipCount,
					})

					totalAvailableIPs += ipCount

					// 一旦总IP数量足够，就可以开始生成随机IP
					if totalAvailableIPs >= targetCount {
						break
					}
				}
			}

			// 如果总IP数量不足，则使用所有可用的IP
			if totalAvailableIPs < targetCount {
				fmt.Printf("警告: 可用IPv4地址总数(%d)小于请求数量(%d)\n", totalAvailableIPs, targetCount)
				targetCount = totalAvailableIPs
			}

			// 循环生成IP直到达到指定数量
			cidrIndex := 0

			for ipv4Count < targetCount && len(cidrList) > 0 {
				// 获取当前CIDR
				currentCIDR := cidrList[cidrIndex]

				// 使用通用函数生成随机IPv4地址
				ipStr := generateRandomIPv4Address(currentCIDR.ipNet)

				if ipStr != "" {
					ipList = append(ipList, ipStr)
					ipv4Count++
				}

				// 移动到下一个CIDR
				cidrIndex = (cidrIndex + 1) % len(cidrList)
			}
		}
	}

	// 处理 IPv6
	if ipv6Mode != "" && hasIPv6CIDR {
		ipv6Count := 0
		ipv6Limit := 1000000 // 设置IPv6上限为100万

		if count, err := strconv.Atoi(ipv6Mode); err == nil && count > 0 {
			targetCount := count
			if targetCount > ipv6Limit {
				targetCount = ipv6Limit
				fmt.Printf("IPv6生成数量已限制为 %d 个\n", ipv6Limit)
			}

			// 准备CIDR列表
			type cidrInfo struct {
				ipNet    *net.IPNet
				maskSize int
			}

			var cidrList []cidrInfo

			hasLargeCIDR := false  // 标记是否有/0到/108的大CIDR
			totalSmallCIDRIPs := 0 // 记录/109到/128的CIDR的IP总数

			// 第一次遍历：检查IP数量是否足够
			for _, result := range results {
				_, ipNet, err := net.ParseCIDR(result.CIDR)
				if err != nil || ipNet.IP.To4() != nil {
					continue // 跳过无效CIDR和非IPv6
				}

				ones, _ := ipNet.Mask.Size()
				// 检查是否有/0到/108的大CIDR
				if ones <= 108 {
					hasLargeCIDR = true
					break
				} else {
					// 计算小CIDR的IP数量并累加
					ipCount := 1 << uint(128-ones)
					totalSmallCIDRIPs += ipCount
				}

				// 如果小CIDR的IP总数已经足够，也可以停止检查
				if totalSmallCIDRIPs >= targetCount {
					break
				}
			}

			// 第二次遍历：收集所有CIDR
			for _, result := range results {
				_, ipNet, err := net.ParseCIDR(result.CIDR)
				if err != nil || ipNet.IP.To4() != nil {
					continue
				}
				ones, _ := ipNet.Mask.Size()
				cidrList = append(cidrList, cidrInfo{
					ipNet:    ipNet,
					maskSize: ones,
				})
			}

			// 如果没有大CIDR且小CIDR的IP总数不足，调整目标数量
			if !hasLargeCIDR && totalSmallCIDRIPs < targetCount {
				fmt.Printf("警告: 可用IPv6地址总数(%d)小于请求数量(%d)\n", totalSmallCIDRIPs, targetCount)
				targetCount = totalSmallCIDRIPs
			}

			// 循环生成IP直到达到指定数量
			cidrIndex := 0

			for ipv6Count < targetCount && len(cidrList) > 0 {
				// 获取当前CIDR
				currentCIDR := cidrList[cidrIndex]

				// 使用通用函数生成随机IPv6地址
				ipStr := generateRandomIPv6Address(currentCIDR.ipNet)

				if ipStr != "" {
					ipList = append(ipList, ipStr)
					ipv6Count++
				}

				// 移动到下一个CIDR
				cidrIndex = (cidrIndex + 1) % len(cidrList)
			}

			if ipv6Count > 0 {
				fmt.Printf("成功生成 %d 个IPv6地址\n", ipv6Count)
			}
		}
	}

	// 写入文件
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, ip := range ipList {
		_, err := writer.WriteString(ip + "\n")
		if err != nil {
			return err
		}
	}
	return writer.Flush()
}

// 写入结果到CSV
func writeResultsToCSV(results []TestResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入标题行
	err = writer.Write([]string{"CIDR", "数据中心", "区域", "城市", "平均延迟", "平均丢包"})
	if err != nil {
		return err
	}

	// 写入数据行
	for _, result := range results {
		// 直接使用原始CIDR，不尝试转换
		row := []string{
			result.CIDR,
			result.DataCenter,
			result.Region,
			result.City,
			fmt.Sprintf("%d", result.AvgLatency), // 直接使用 int 值
			fmt.Sprintf("%.1f", result.LossRate*100),
		}

		err = writer.Write(row)
		if err != nil {
			return err
		}
	}

	return nil
}

// 打印结果摘要
func printResultsSummary(results []TestResult) {
	if len(results) == 0 {
		fmt.Println("\n未找到符合条件的结果")
		return
	}

	fmt.Println("\n测试结果摘要:")

	// 统计数据中心分布和延迟
	dcMap := make(map[string]struct {
		count        int
		minLatency   int
		maxLatency   int
		totalLatency int
	})

	// 统计未知数据中心的数量
	unknownCount := 0
	for _, result := range results {
		dc := result.DataCenter
		if dc == "Unknown" {
			unknownCount++
		}

		stats, exists := dcMap[dc]
		if !exists {
			stats = struct {
				count        int
				minLatency   int
				maxLatency   int
				totalLatency int
			}{
				minLatency: result.AvgLatency,
				maxLatency: result.AvgLatency,
			}
		}

		stats.count++
		stats.totalLatency += result.AvgLatency

		if result.AvgLatency < stats.minLatency {
			stats.minLatency = result.AvgLatency
		}
		if result.AvgLatency > stats.maxLatency {
			stats.maxLatency = result.AvgLatency
		}

		dcMap[dc] = stats
	}

	fmt.Println()

	// 创建数据中心统计表格
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"数据中心", "数量", "最高延迟", "平均延迟", "最低延迟"})
	table.SetBorder(false)
	table.SetColumnAlignment([]int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_RIGHT, tablewriter.ALIGN_RIGHT, tablewriter.ALIGN_RIGHT, tablewriter.ALIGN_RIGHT})

	for dc, stats := range dcMap {
		avgLatency := stats.totalLatency / stats.count
		table.Append([]string{
			dc,
			fmt.Sprintf("%d", stats.count),
			fmt.Sprintf("%dms", stats.maxLatency),
			fmt.Sprintf("%dms", avgLatency),
			fmt.Sprintf("%dms", stats.minLatency),
		})
	}
	table.Render()

	// 计算总体延迟统计
	var totalLatency int
	minLatency := results[0].AvgLatency
	maxLatency := results[0].AvgLatency
	for _, result := range results {
		totalLatency += result.AvgLatency
		if result.AvgLatency < minLatency {
			minLatency = result.AvgLatency
		}
		if result.AvgLatency > maxLatency {
			maxLatency = result.AvgLatency
		}
	}

	fmt.Println()

	// 显示最佳结果表格
	resultTable := tablewriter.NewWriter(os.Stdout)
	resultTable.SetHeader([]string{"CIDR", "城市(数据中心)", "平均延迟", "平均丢包"})
	resultTable.SetBorder(false)
	resultTable.SetColumnAlignment([]int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_RIGHT, tablewriter.ALIGN_RIGHT})

	limit := 10
	if len(results) < limit {
		limit = len(results)
	}

	for i := 0; i < limit; i++ {
		result := results[i]
		locationInfo := fmt.Sprintf("%s(%s)", result.City, result.DataCenter)
		resultTable.Append([]string{
			result.CIDR,
			locationInfo,
			fmt.Sprintf("%dms", result.AvgLatency),
			fmt.Sprintf("%.1f%%", result.LossRate*100),
		})
	}
	resultTable.Render()

	fmt.Println()
}

// 在计算完平均值后调用
func (g *CIDRGroup) finalize() {
	if len(g.Data.Results) > 0 {
		// 计算平均值
		var totalLatency int
		var totalLossRate float64
		for _, r := range g.Data.Results {
			totalLatency += r.AvgLatency
			totalLossRate += r.LossRate
		}

		// 从对象池获取结果对象
		g.Result = resultPool.Get().(*TestResult)

		// 填充结果
		g.Result.CIDR = g.CIDR
		g.Result.DataCenter = g.Data.Results[0].DataCenter
		g.Result.Region = g.Data.Results[0].Region
		g.Result.City = g.Data.Results[0].City
		g.Result.AvgLatency = totalLatency / len(g.Data.Results)
		g.Result.LossRate = totalLossRate / float64(len(g.Data.Results))

		// 清理临时数据并放回对象池
		g.Data.Results = g.Data.Results[:0]
		g.Data.IPs = g.Data.IPs[:0]
		testDataPool.Put(g.Data)
		g.Data = nil
	}
}
