package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
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

type CIDRGroup struct {
	CIDR       string
	IPs        []string
	DataCenter string
	Region     string
	City       string
	AvgLatency int
	LossRate   float64
	Results    []TestResult // 存储组内每个IP的测试结果
}

type location struct {
	Iata   string  `json:"iata"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
	Cca2   string  `json:"cca2"`
	Region string  `json:"region"`
	City   string  `json:"city"`
}

// ----------------------- 主程序入口 -----------------------

var (
	globalSem *semaphore.Weighted
)

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
		os.Remove(filepath.Join(os.TempDir(), "cache_results.bin"))
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
	testIPs(cidrGroups, *portFlag, *testCount, *scanThreads, *ipPerCIDR, locationMap,
		coloFlag, minLatency, maxLatency, maxLossRate, showAll)

	// 打开缓存文件
	cacheFilePath := filepath.Join(os.TempDir(), "cache_results.bin")
	cacheFile, err := os.Open(cacheFilePath)
	if err != nil {
		fmt.Printf("打开缓存文件失败: %v\n", err)
		return
	}
	defer cacheFile.Close()

	// 分块读取并排序
	chunkSize := 10000      // 每个块的大小
	tempDir := os.TempDir() // 临时文件目录
	var tempFiles []string

	// 第一阶段：分块排序并写入临时文件
	chunkIndex := 0
	for {
		// 读取一个块的数据
		chunk := make([]TestResult, 0, chunkSize)
		decoder := gob.NewDecoder(cacheFile)

		for i := 0; i < chunkSize; i++ {
			var result TestResult
			err := decoder.Decode(&result)
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Printf("读取结果失败: %v\n", err)
				continue
			}
			chunk = append(chunk, result)
		}

		if len(chunk) == 0 {
			break // 没有更多数据
		}

		// 对块内数据排序
		sort.Slice(chunk, func(i, j int) bool {
			if chunk[i].LossRate == chunk[j].LossRate {
				return chunk[i].AvgLatency < chunk[j].AvgLatency
			}
			return chunk[i].LossRate < chunk[j].LossRate
		})

		// 写入临时文件
		tempFile := filepath.Join(tempDir, fmt.Sprintf("cfspeed_sort_%d.tmp", chunkIndex))
		file, err := os.Create(tempFile)
		if err != nil {
			fmt.Printf("创建临时文件失败: %v\n", err)
			return
		}

		encoder := gob.NewEncoder(file)
		for _, result := range chunk {
			if err := encoder.Encode(result); err != nil {
				fmt.Printf("写入临时文件失败: %v\n", err)
			}
		}

		file.Close()
		tempFiles = append(tempFiles, tempFile)
		chunkIndex++
	}

	// 第二阶段：归并排序
	var filteredResults []TestResult

	if len(tempFiles) == 0 {
		fmt.Println("没有找到有效的测试结果")
		return
	} else if len(tempFiles) == 1 {
		// 只有一个临时文件，直接读取
		file, err := os.Open(tempFiles[0])
		if err != nil {
			fmt.Printf("打开临时文件失败: %v\n", err)
			return
		}

		decoder := gob.NewDecoder(file)
		for {
			var result TestResult
			err := decoder.Decode(&result)
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Printf("读取临时文件失败: %v\n", err)
				continue
			}

			// 直接添加结果
			filteredResults = append(filteredResults, result)
		}

		file.Close()
	} else {

		// 创建一个优先队列用于归并
		type QueueItem struct {
			result    TestResult
			fileIndex int
		}

		queue := make([]QueueItem, 0, len(tempFiles))
		files := make([]*os.File, len(tempFiles))
		decoders := make([]*gob.Decoder, len(tempFiles))

		// 初始化，从每个文件读取第一个元素
		for i, tempFile := range tempFiles {
			file, err := os.Open(tempFile)
			if err != nil {
				fmt.Printf("打开临时文件失败: %v\n", err)
				continue
			}

			files[i] = file
			decoders[i] = gob.NewDecoder(file)

			var result TestResult
			if err := decoders[i].Decode(&result); err == nil {
				queue = append(queue, QueueItem{result, i})
			}
		}

		// 使用堆排序进行归并
		for len(queue) > 0 {
			// 找出最小元素
			minIdx := 0
			for i := 1; i < len(queue); i++ {
				if (queue[i].result.LossRate < queue[minIdx].result.LossRate) ||
					(queue[i].result.LossRate == queue[minIdx].result.LossRate &&
						queue[i].result.AvgLatency < queue[minIdx].result.AvgLatency) {
					minIdx = i
				}
			}

			// 添加到结果集
			filteredResults = append(filteredResults, queue[minIdx].result)

			// 从对应文件读取下一个元素
			fileIdx := queue[minIdx].fileIndex
			var nextResult TestResult
			if err := decoders[fileIdx].Decode(&nextResult); err == nil {
				// 替换当前元素
				queue[minIdx].result = nextResult
			} else {
				// 文件读完了，从队列中移除
				queue = append(queue[:minIdx], queue[minIdx+1:]...)
			}
		}

		// 关闭所有文件
		for _, file := range files {
			if file != nil {
				file.Close()
			}
		}
	}

	// 清理临时文件
	for _, tempFile := range tempFiles {
		os.Remove(tempFile)
	}

	// 限制输出数量
	if *printCount != "all" {
		count, err := strconv.Atoi(*printCount)
		if err == nil && count > 0 {
			if count < len(filteredResults) {
				filteredResults = filteredResults[:count]
			}
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

	// 使用big.Int处理IP地址
	startIP := big.NewInt(0).SetBytes(ipNet.IP.To16())

	// 计算子网间隔 (2^(128-48))
	subnetStep := big.NewInt(1)
	subnetStep.Lsh(subnetStep, uint(128-48))

	// 计算需要拆分的子网数量 (2^splitBits)
	subnetCount := 1 << uint(splitBits)

	result := make([]string, 0, subnetCount)

	// 生成所有/48子网
	for i := 0; i < subnetCount; i++ {
		// 计算新的IP地址
		offset := big.NewInt(int64(i))
		offset.Mul(offset, subnetStep)

		newIP := big.NewInt(0).Add(startIP, offset)

		// 转换为IP地址格式
		ipBytes := newIP.Bytes()
		if len(ipBytes) < 16 {
			// 补全到16字节
			padding := make([]byte, 16-len(ipBytes))
			ipBytes = append(padding, ipBytes...)
		}

		ip := net.IP(ipBytes)

		// 创建新的CIDR字符串
		newCIDR := fmt.Sprintf("%s/48", ip.String())
		result = append(result, newCIDR)
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
func getLocationMap() (map[string]location, error) {
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

		// 构造 location 映射，key 为数据中心代码
		locationMap := make(map[string]location)
		for _, loc := range locations {
			locationMap[loc.Iata] = loc
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
func testIPs(cidrGroups []CIDRGroup, port, testCount, maxThreads, ipPerCIDR int, locationMap map[string]location,
	coloFlag *string, minLatency, maxLatency *int, maxLossRate *float64, showAll *bool) {
	// 初始化并发控制
	if globalSem == nil {
		globalSem = semaphore.NewWeighted(int64(maxThreads))
	}

	// 删除已存在的缓存文件
	cacheFilePath := filepath.Join(os.TempDir(), "cache_results.bin")
	os.Remove(cacheFilePath)

	// 创建缓存文件，使用当前目录
	cacheFile, err := os.Create(cacheFilePath)
	if err != nil {
		fmt.Printf("创建缓存文件失败: %v\n", err)
		return
	}
	defer cacheFile.Close()

	// 使用 gob
	encoder := gob.NewEncoder(cacheFile)

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
		dataCenter string
		region     string
		city       string
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

	// 启动结果处理协程
	go func() {
		defer close(resultChan)
		for result := range resultChan {
			mutex.Lock()
			counts := cidrIPCounts[result.CIDR]

			// 添加结果到临时存储
			for i := range cidrGroups {
				if cidrGroups[i].CIDR == result.CIDR {
					cidrGroups[i].Results = append(cidrGroups[i].Results, result)

					if len(cidrGroups[i].Results) == counts.total {
						// 计算平均值并写入文件
						avgResult := calculateAverageResult(cidrGroups[i].Results)

						// 写入文件后清理内存
						if shouldIncludeResult(avgResult, coloFlag, minLatency, maxLatency, maxLossRate, showAll) {
							err := encoder.Encode(avgResult)
							if err != nil {
								fmt.Printf("写入结果失败: %v\n", err)
							}
						}

						// 清理内存
						cidrGroups[i].Results = nil
						// 清理该CIDR的计数信息
						delete(cidrIPCounts, result.CIDR)
						// 清理该CIDR的缓存信息
						delete(cidrColoMap, result.CIDR)

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

				// 创建测试结果
				result := TestResult{
					IP:   ip,
					CIDR: currentGroup.CIDR,
				}

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
					result.AvgLatency = int(avgLatency.Milliseconds())
					result.LossRate = float64(testCount-localSuccessCount) / float64(testCount)

					// 检查CIDR是否已有数据中心信息
					cache := cidrColoMap[currentGroup.CIDR]
					cache.RLock()
					if cache.found {
						result.DataCenter = cache.dataCenter
						result.Region = cache.region
						result.City = cache.city
						cache.RUnlock()
					} else {
						cache.RUnlock()
						dataCenter, region, city := getDataCenterInfo(ip, locationMap)
						if dataCenter != "Unknown" {
							cache.Lock()
							if !cache.found {
								cache.dataCenter = dataCenter
								cache.region = region
								cache.city = city
								cache.found = true
							}
							cache.Unlock()
						}
						result.DataCenter = dataCenter
						result.Region = region
						result.City = city
					}

					// 发送结果到结果通道
					resultChan <- result
					atomic.AddInt32(&tcpSuccessCount, 1)
				}

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
}

// 计算平均结果的辅助函数
func calculateAverageResult(results []TestResult) TestResult {
	if len(results) == 0 {
		return TestResult{}
	}

	var totalLatency int
	var totalLossRate float64

	for _, r := range results {
		totalLatency += r.AvgLatency
		totalLossRate += r.LossRate
	}

	return TestResult{
		CIDR:       results[0].CIDR,
		DataCenter: results[0].DataCenter,
		Region:     results[0].Region,
		City:       results[0].City,
		AvgLatency: totalLatency / len(results),
		LossRate:   totalLossRate / float64(len(results)),
	}
}

// 获取数据中心信息
func getDataCenterInfo(ip string, locationMap map[string]location) (string, string, string) {

	// 使用全局通道控制并发
	ctx := context.Background()
	if err := globalSem.Acquire(ctx, 1); err != nil {
		return "Unknown", "", ""
	}
	defer globalSem.Release(1)

	maxRetries := 3 // 减少重试次数

	// 使用共享的 Transport 对象
	transport := &http.Transport{
		DisableKeepAlives: true,
		IdleConnTimeout:   1000 * time.Millisecond, // 减少超时时间
		MaxIdleConns:      100,
		MaxConnsPerHost:   10,
	}

	client := &http.Client{
		Timeout:   800 * time.Millisecond, // 减少超时时间
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 确保资源被释放
	defer transport.CloseIdleConnections()

	for retry := 0; retry <= maxRetries; retry++ {
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
	err = writer.Write([]string{"CIDR", "数据中心", "地区", "城市", "平均延迟(ms)", "丢包率(%)"})
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
