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
	"math"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/olekukonko/tablewriter"
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

type coloInfo struct {
	dataCenter string
	region     string
	city       string
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

func main() {
	// 添加全局超时控制
	globalTimeout := 120 * time.Minute // 设置全局超时时间
	ctx, cancel := context.WithTimeout(context.Background(), globalTimeout)
	defer cancel()

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
	coloFlag := flag.String("colo", "", "匹配指定地区，用逗号分隔，例如 HKG,KHH,NRT,LAX")
	maxLatency := flag.Int("tl", 500, "平均延迟上限(ms)")
	minLatency := flag.Int("tll", 0, "平均延迟下限(ms)")
	maxLossRate := flag.Float64("tlr", 0.5, "丢包率上限")
	scanThreads := flag.Int("n", 128, "扫描并发数")
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

	// 获取Cloudflare数据中心位置信息
	locationMap, err := getLocationMap()
	if err != nil {
		fmt.Printf("获取数据中心位置信息失败: %v\n", err)
		return
	}

	// 从每个CIDR中随机选择IP进行测试
	cidrGroups := generateRandomIPs(expandedCIDRs, *ipPerCIDR)
	fmt.Printf("共生成 %d 个CIDR组，每组 %d 个IP\n", len(cidrGroups), *ipPerCIDR)

	// 如果指定了 -notest 参数，直接生成IP文件并退出
	if *noTest {
		// 创建一个空的结果列表，只包含IP和CIDR信息
		var results []TestResult
		for _, group := range cidrGroups {
			for _, ip := range group.IPs {
				results = append(results, TestResult{
					IP:         ip,
					CIDR:       group.CIDR,
					DataCenter: "Unknown",
					Region:     "",
					City:       "",
					AvgLatency: 0,
					LossRate:   0,
				})
			}
		}

		// 输出IP列表
		err = generateIPFile(results, *useIPv4, *useIPv6, *ipTxtFile)
		if err != nil {
			fmt.Printf("生成IP文件失败: %v\n", err)
		} else {
			fmt.Printf("IP列表已写入: %s\n", *ipTxtFile)
		}
		return
	}

	// 测试IP性能
	cidrGroups = testIPs(cidrGroups, *portFlag, *testCount, *scanThreads, locationMap)

	// 将测试结果按CIDR分组
	cidrResultMap := make(map[string][]TestResult)
	var cidrMapMutex sync.Mutex // 添加互斥锁保护map访问

	for _, group := range cidrGroups {
		if len(group.Results) == 0 {
			continue
		}

		// 使用CIDR作为键，收集所有相同CIDR的测试结果
		for _, result := range group.Results {
			cidrMapMutex.Lock() // 加锁保护map写入
			cidrResultMap[result.CIDR] = append(cidrResultMap[result.CIDR], result)
			cidrMapMutex.Unlock() // 解锁
		}
	}

	// 合并每个CIDR的结果
	var results []TestResult
	for cidr, cidrResults := range cidrResultMap {
		// 计算平均值
		var totalLatency int
		var totalLossRate float64
		var dataCenter, region, city string

		for _, result := range cidrResults {
			totalLatency += result.AvgLatency
			totalLossRate += result.LossRate

			// 使用第一个有效的数据中心信息
			if dataCenter == "" {
				dataCenter = result.DataCenter
				if dataCenter == "" {
					dataCenter = "Unknown"
				}
				region = result.Region
				city = result.City
			}
		}

		avgLatency := totalLatency / len(cidrResults)
		avgLossRate := totalLossRate / float64(len(cidrResults))

		// 创建合并后的结果
		results = append(results, TestResult{
			IP:         cidrResults[0].IP, // 使用第一个IP作为代表
			CIDR:       cidr,
			DataCenter: dataCenter,
			Region:     region,
			City:       city,
			AvgLatency: avgLatency,
			LossRate:   avgLossRate,
		})
	}

	// 过滤结果
	filteredResults := filterResults(results, *coloFlag, *minLatency, *maxLatency, *maxLossRate, *showAll)
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
		if err == nil && count > 0 && count < len(filteredResults) {
			filteredResults = filteredResults[:count]
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

	fmt.Println("\n测速参数:")
	fmt.Println("  -t int           延迟测试次数 (默认: 4)")
	fmt.Println("  -tp int          测试端口号 (默认: 443)")
	fmt.Println("  -ts int          每个CIDR测试的IP数量 (默认: 2)")
	fmt.Println("  -n int           并发测试线程数量 (默认: 128)")

	fmt.Println("\n筛选参数:")
	fmt.Println("  -colo string     指定数据中心，多个用逗号分隔 (例: HKG,NRT,LAX,SJC)")
	fmt.Println("  -tl int          延迟上限 (默认: 500ms)")
	fmt.Println("  -tll int         延迟下限 (默认: 0ms)")
	fmt.Println("  -tlr float       丢包率上限 (默认: 0.5)")
	fmt.Println("  -p string        输出结果数量 (默认: all)")

	fmt.Println("\n输出选项:")
	fmt.Println("  -nocsv           不生成CSV文件")
	fmt.Println("  -useip4 string   生成IPv4列表")
	fmt.Println("                   - 使用 all: 输出所有IPv4 CIDR的完整IP列表")
	fmt.Println("                   - 使用数字 (如9999): 输出指定数量的不重复IPv4")
	fmt.Println("  -useip6 string   生成IPv6列表")
	fmt.Println("                   - 使用数字 (如9999): 输出指定数量的不重复IPv6")
	fmt.Println("  -iptxt string    指定IP列表输出文件名 (默认: ip.txt)")
	fmt.Println("                   - 使用此参数时必须至少使用 -useip4 或 -useip6")
}

// 从URL获取CIDR列表
func getCIDRFromURL(url string) ([]string, error) {
	maxRetries := 5
	retryDelay := 2 * time.Second

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
			fmt.Printf("获取失败: %v，准备重试...\n", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP请求失败，状态码: %d", resp.StatusCode)
			fmt.Printf("%v，准备重试...\n", lastErr)
			continue
		}

		// 成功获取，解析CIDR列表
		cidrList, err = parseCIDRList(resp.Body)
		resp.Body.Close()

		if err != nil {
			lastErr = err
			fmt.Printf("解析CIDR列表失败: %v，准备重试...\n", err)
			continue
		}

		// 检查是否成功获取到CIDR
		if len(cidrList) > 0 {
			return cidrList, nil
		}

		lastErr = fmt.Errorf("获取到的CIDR列表为空")
		fmt.Printf("%v，准备重试...\n", lastErr)
	}

	return nil, fmt.Errorf("在%d次尝试后仍然失败: %v", maxRetries, lastErr)
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

// 从每个CIDR中随机生成IP
func generateRandomIPs(cidrList []string, ipPerCIDR int) []CIDRGroup {
	rand.Seed(time.Now().UnixNano())
	var cidrGroups []CIDRGroup
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// 控制并发数量
	maxConcurrent := runtime.NumCPU() * 2
	semaphore := make(chan struct{}, maxConcurrent)

	for _, cidr := range cidrList {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(cidr string) {
			defer func() {
				<-semaphore
				wg.Done()
			}()

			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return
			}

			// 创建新的CIDR组
			group := CIDRGroup{
				CIDR: cidr,
				IPs:  []string{},
			}

			// 判断是IPv4还是IPv6
			if ipNet.IP.To4() != nil {
				// IPv4
				for i := 0; i < ipPerCIDR; i++ {
					ip := generateRandomIPv4(ipNet)
					if ip != "" {
						group.IPs = append(group.IPs, ip)
					}
				}
			} else {
				// IPv6
				for i := 0; i < ipPerCIDR; i++ {
					ip := generateRandomIPv6(ipNet)
					if ip != "" {
						group.IPs = append(group.IPs, ip)
					}
				}
			}

			if len(group.IPs) > 0 {
				mutex.Lock()
				cidrGroups = append(cidrGroups, group)
				mutex.Unlock()
			}
		}(cidr)
	}

	wg.Wait()
	return cidrGroups
}

// 生成随机IPv4地址
func generateRandomIPv4(ipNet *net.IPNet) string {
	// 调用通用的IPv4地址生成函数
	return generateRandomIPv4Address(ipNet)
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

// 生成随机IPv6地址
func generateRandomIPv6(ipNet *net.IPNet) string {
	// 调用通用的IPv6地址生成函数
	return generateRandomIPv6Address(ipNet)
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

// 测试IP性能
func testIPs(cidrGroups []CIDRGroup, port, testCount, maxThreads int, locationMap map[string]location) []CIDRGroup {
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// 添加CIDR数据中心信息缓存
	cidrColoCache := make(map[string]coloInfo)
	var cacheMapMutex sync.RWMutex

	// 创建任务通道，使用固定大小的缓冲区
	tasks := make(chan struct{}, maxThreads)

	// 计算总IP数量
	var totalIPs int
	for _, group := range cidrGroups {
		totalIPs += len(group.IPs)
	}

	var count int32
	var failCount int32

	// 遍历所有IP进行测试
	for i := range cidrGroups {
		group := &cidrGroups[i]
		for _, ip := range group.IPs {
			wg.Add(1)
			go func(ip string, group *CIDRGroup) {
				defer wg.Done()

				// 使用通道控制并发
				tasks <- struct{}{}
				defer func() { <-tasks }()

				successCount := 0
				totalLatency := time.Duration(0)
				minLatency := time.Duration(math.MaxInt64)
				maxLatency := time.Duration(0)

				// 进行多次测试
				for i := 0; i < testCount; i++ {
					start := time.Now()
					conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), time.Second)

					if err != nil {
						continue
					}

					latency := time.Since(start)
					conn.Close()

					successCount++
					totalLatency += latency

					if latency < minLatency {
						minLatency = latency
					}
					if latency > maxLatency {
						maxLatency = latency
					}
				}

				// 处理测试结果
				if successCount == 0 {
					atomic.AddInt32(&failCount, 1)
				} else {
					avgLatency := totalLatency / time.Duration(successCount)
					lossRate := float64(testCount-successCount) / float64(testCount)

					// 先检查缓存中是否已有该CIDR的数据中心信息
					var dataCenter, region, city string
					cacheMapMutex.RLock()
					if cache, ok := cidrColoCache[group.CIDR]; ok && cache.dataCenter != "Unknown" {
						dataCenter = cache.dataCenter
						region = cache.region
						city = cache.city
					}
					cacheMapMutex.RUnlock()

					// 如果缓存中没有找到，则查询数据中心信息
					if dataCenter == "" {
						dataCenter, region, city = getDataCenterInfo(ip, locationMap)

						// 如果查询到有效的数据中心信息，则缓存
						if dataCenter != "Unknown" {
							cacheMapMutex.Lock()
							cidrColoCache[group.CIDR] = coloInfo{
								dataCenter: dataCenter,
								region:     region,
								city:       city,
							}
							cacheMapMutex.Unlock()
						}
					}

					result := TestResult{
						IP:         ip,
						CIDR:       group.CIDR,
						DataCenter: dataCenter,
						Region:     region,
						City:       city,
						AvgLatency: int(avgLatency.Milliseconds()),
						LossRate:   lossRate,
					}

					mutex.Lock()
					group.Results = append(group.Results, result)
					mutex.Unlock()
				}

				// 更新进度
				current := atomic.AddInt32(&count, 1)
				fmt.Printf("测试进度: %d/%d (%.2f%%)\r", current, totalIPs, float64(current)/float64(totalIPs)*100)
			}(ip, group)
		}
	}

	wg.Wait()
	fmt.Println()

	// 打印测试结果统计
	fmt.Printf("测试完成，总IP: %d，成功: %d，成功率: %.2f%%\n",
		totalIPs, totalIPs-int(failCount), 100.0*(float64(totalIPs-int(failCount))/float64(totalIPs)))

	// 计算每个组的平均性能
	for i := range cidrGroups {
		group := &cidrGroups[i]

		if len(group.Results) == 0 {
			continue
		}

		var totalLatency int
		var totalLossRate float64

		for _, result := range group.Results {
			totalLatency += result.AvgLatency
			totalLossRate += result.LossRate

			// 使用第一个有效的数据中心信息
			if group.DataCenter == "" && result.DataCenter != "Unknown" {
				group.DataCenter = result.DataCenter
				group.Region = result.Region
				group.City = result.City
			}
		}

		group.AvgLatency = totalLatency / len(group.Results)
		group.LossRate = totalLossRate / float64(len(group.Results))
	}

	return cidrGroups
}

// 获取数据中心信息
func getDataCenterInfo(ip string, locationMap map[string]location) (string, string, string) {
	maxRetries := 5

	transport := &http.Transport{
		DisableKeepAlives: true, // 禁用 keep-alive
		IdleConnTimeout:   1 * time.Second,
	}

	client := &http.Client{
		Timeout:   1 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for retry := 0; retry <= maxRetries; retry++ {
		// 处理 IPv6 地址
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
		req.Close = true // 确保请求完成后关闭连接

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

	// 所有重试都失败后返回Unknown
	return "Unknown", "", ""
}

// 生成IP文件
func generateIPFile(results []TestResult, ipv4Mode, ipv6Mode, filename string) error {
	// 检查是否至少指定了一种IP类型
	if ipv4Mode == "" && ipv6Mode == "" {
		return fmt.Errorf("必须至少指定 -useip4 或 -useip6 参数")
	}

	var ipList []string
	ipMap := make(map[string]bool) // 用于去重

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
				ip := net.ParseIP(result.IP)
				if ip == nil || ip.To4() == nil {
					continue // 跳过非IPv4
				}

				// 解析CIDR
				_, ipNet, err := net.ParseCIDR(result.CIDR)
				if err != nil {
					continue
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
					if !ipMap[ipStr] {
						ipList = append(ipList, ipStr)
						ipMap[ipStr] = true
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

			// 准备CIDR列表
			type cidrInfo struct {
				ipNet *net.IPNet
			}

			var cidrList []cidrInfo

			// 初始化CIDR信息
			for _, result := range results {
				ip := net.ParseIP(result.IP)
				if ip == nil || ip.To4() == nil {
					continue
				}

				_, ipNet, err := net.ParseCIDR(result.CIDR)
				if err != nil {
					continue
				}

				if ipNet.IP.To4() != nil {
					cidrList = append(cidrList, cidrInfo{
						ipNet: ipNet,
					})
				}
			}

			// 循环生成IP直到达到指定数量
			cidrIndex := 0

			for ipv4Count < targetCount && len(cidrList) > 0 {
				// 获取当前CIDR
				currentCIDR := cidrList[cidrIndex]

				// 使用通用函数生成随机IPv4地址
				ipStr := generateRandomIPv4Address(currentCIDR.ipNet)

				if ipStr != "" && !ipMap[ipStr] {
					ipList = append(ipList, ipStr)
					ipMap[ipStr] = true
					ipv4Count++
				}

				// 移动到下一个CIDR
				cidrIndex = (cidrIndex + 1) % len(cidrList)
			}

			if ipv4Count < targetCount {
				fmt.Printf("警告: 无法生成足够的IPv4地址，已生成 %d 个\n", ipv4Count)
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
				ipNet *net.IPNet
			}

			var cidrList []cidrInfo

			// 初始化CIDR信息
			for _, result := range results {
				ip := net.ParseIP(result.IP)
				if ip == nil || ip.To4() != nil {
					continue
				}

				_, ipNet, err := net.ParseCIDR(result.CIDR)
				if err != nil {
					continue
				}

				if ipNet.IP.To16() != nil {
					cidrList = append(cidrList, cidrInfo{
						ipNet: ipNet,
					})
				}
			}

			// 循环生成IP直到达到指定数量
			cidrIndex := 0

			for ipv6Count < targetCount && len(cidrList) > 0 {
				// 获取当前CIDR
				currentCIDR := cidrList[cidrIndex]

				// 使用通用函数生成随机IPv6地址
				ipStr := generateRandomIPv6Address(currentCIDR.ipNet)

				if ipStr != "" && !ipMap[ipStr] {
					ipList = append(ipList, ipStr)
					ipMap[ipStr] = true
					ipv6Count++
				}

				// 移动到下一个CIDR
				cidrIndex = (cidrIndex + 1) % len(cidrList)
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

// 过滤结果
func filterResults(results []TestResult, coloFilter string, minLatency, maxLatency int, maxLossRate float64, showAll bool) []TestResult {
	var filtered []TestResult

	// 解析数据中心过滤器
	var coloList []string
	if coloFilter != "" {
		coloList = strings.Split(coloFilter, ",")
		for i, colo := range coloList {
			coloList[i] = strings.TrimSpace(colo)
		}
	}

	for _, result := range results {
		// 如果不显示所有结果，则跳过未知数据中心的结果
		if !showAll && result.DataCenter == "Unknown" {
			continue
		}

		// 检查数据中心
		if len(coloList) > 0 {
			match := false
			for _, colo := range coloList {
				if result.DataCenter == colo {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}

		// 检查延迟 - 直接使用 int 值比较
		if result.AvgLatency < minLatency || result.AvgLatency > maxLatency {
			continue
		}

		// 检查丢包率
		if result.LossRate > maxLossRate {
			continue
		}

		filtered = append(filtered, result)
	}

	return filtered
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
	err = writer.Write([]string{"IP&CIDR", "数据中心", "地区", "城市", "平均延迟(ms)", "丢包率(%)"})
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
	fmt.Printf("共测试 %d 个IP\n", len(results))

	// 统计数据中心分布和延迟
	dcMap := make(map[string]struct {
		count        int
		minLatency   int
		maxLatency   int
		totalLatency int
	})

	for _, result := range results {
		dc := result.DataCenter
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
			fmt.Sprintf("%d", stats.maxLatency),
			fmt.Sprintf("%d", avgLatency),
			fmt.Sprintf("%d", stats.minLatency),
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
	resultTable.SetHeader([]string{"IP&CIDR", "地区(数据中心)", "平均延迟", "平均丢包"})
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
