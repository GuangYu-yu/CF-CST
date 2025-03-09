package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
	// 定义命令行参数
	urlFlag := flag.String("url", "", "测速的CIDR链接")
	fileFlag := flag.String("f", "", "指定测速的文件")
	testCount := flag.Int("t", 4, "延迟测速的次数")
	portFlag := flag.Int("tp", 443, "指定测速的端口号")
	ipPerCIDR := flag.Int("ts", 3, "从CIDR内随机选择IP的数量")
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
	for _, group := range cidrGroups {
		if len(group.Results) == 0 {
			continue
		}

		// 使用CIDR作为键，收集所有相同CIDR的测试结果
		for _, result := range group.Results {
			cidrResultMap[result.CIDR] = append(cidrResultMap[result.CIDR], result)
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
			if dataCenter == "" && result.DataCenter != "Unknown" {
				dataCenter = result.DataCenter
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
	filteredResults := filterResults(results, *coloFlag, *minLatency, *maxLatency, *maxLossRate)
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

	fmt.Println("\n测速参数:")
	fmt.Println("  -t int          延迟测试次数 (默认: 4)")
	fmt.Println("  -tp int         测试端口号 (默认: 443)")
	fmt.Println("  -ts int         每个CIDR测试的IP数量 (默认: 3)")
	fmt.Println("  -n int          并发测试线程数量 (默认: 128)")

	fmt.Println("\n筛选参数:")
	fmt.Println("  -colo string    指定数据中心，多个用逗号分隔 (例: HKG,NRT,LAX,SJC)")
	fmt.Println("  -tl int         延迟上限 (默认: 500ms)")
	fmt.Println("  -tll int        延迟下限 (默认: 0ms)")
	fmt.Println("  -tlr float      丢包率上限 (默认: 0.5)")
	fmt.Println("  -p string       输出结果数量 (默认: all)")

	fmt.Println("\n输出选项:")
	fmt.Println("  -nocsv          不生成CSV文件")
	fmt.Println("  -useip4 string  生成IPv4列表")
	fmt.Println("                  - 使用 all: 输出所有IPv4 CIDR的完整IP列表")
	fmt.Println("                  - 使用数字 (如9999): 输出指定数量的不重复IPv4")
	fmt.Println("  -useip6 string  生成IPv6列表")
	fmt.Println("                  - 使用数字 (如9999): 输出指定数量的不重复IPv6")
	fmt.Println("  -iptxt string   指定IP列表输出文件名 (默认: ip.txt)")
	fmt.Println("                  - 使用此参数时必须至少使用 -useip4 或 -useip6")
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

// 全局变量，用于存储IP到CIDR的映射
var ipCIDRMap map[string]string

// 生成随机IPv4地址
func generateRandomIPv4(ipNet *net.IPNet) string {
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
	// 获取网络地址
	ip := ipNet.IP.To16()
	if ip == nil {
		return ""
	}

	// 计算可以随机的位数
	ones, bits := ipNet.Mask.Size()
	randomBits := bits - ones

	// 将IP地址转换为big.Int
	baseIP := big.NewInt(0).SetBytes(ip)

	// 计算掩码
	netMask := big.NewInt(0).Lsh(big.NewInt(1), uint(128-randomBits))
	netMask.Sub(netMask, big.NewInt(1)) // 2^(128-randomBits) - 1
	netMask.Xor(netMask, big.NewInt(0).Lsh(big.NewInt(1), 128))

	// 计算网络地址
	networkAddr := big.NewInt(0).And(baseIP, netMask)

	// 计算最大偏移量
	maxOffset := big.NewInt(0).Lsh(big.NewInt(1), uint(randomBits))

	if maxOffset.Cmp(big.NewInt(1)) <= 0 {
		// /128，只有一个IP，直接返回
		return ip.String()
	}

	// 生成随机偏移量 - 修复这一行
	maxOffsetInt := maxOffset.Int64()
	var randomOffset *big.Int
	if maxOffsetInt > 0 {
		// 对于较小的值，直接使用 Int63n
		if maxOffsetInt <= 1<<63-1 {
			randomOffset = big.NewInt(rand.Int63n(maxOffsetInt))
		} else {
			// 对于较大的值，生成随机字节
			randomBytes := make([]byte, 16)
			for i := range randomBytes {
				randomBytes[i] = byte(rand.Intn(256))
			}
			randomOffset = new(big.Int).SetBytes(randomBytes)
			randomOffset.Mod(randomOffset, maxOffset)
		}
	} else {
		randomOffset = big.NewInt(0)
	}

	// 计算最终IP
	finalIP := big.NewInt(0).Or(networkAddr, randomOffset)

	// 转换回IP地址格式
	ipBytes := finalIP.Bytes()
	for len(ipBytes) < 16 {
		padding := make([]byte, 16-len(ipBytes))
		ipBytes = append(padding, ipBytes...)
	}

	return net.IP(ipBytes).String()
}

// 获取Cloudflare数据中心位置信息
func getLocationMap() (map[string]location, error) {
	// 创建带超时的客户端
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get("https://speed.cloudflare.com/locations")
	if err != nil {
		return nil, fmt.Errorf("无法获取 locations.json: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP请求失败，状态码: %d", resp.StatusCode)
	}

	// 直接从流中解析JSON
	var locations []location
	if err := json.NewDecoder(resp.Body).Decode(&locations); err != nil {
		return nil, fmt.Errorf("无法解析JSON: %v", err)
	}

	// 构造 location 映射，key 为数据中心代码
	locationMap := make(map[string]location)
	for _, loc := range locations {
		locationMap[loc.Iata] = loc
	}

	return locationMap, nil
}

// 测试IP性能
func testIPs(cidrGroups []CIDRGroup, port, testCount, maxThreads int, locationMap map[string]location) []CIDRGroup {
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// 创建任务通道
	type testTask struct {
		ip    string
		group *CIDRGroup
	}

	tasks := make(chan testTask, 1000)

	// 计算总IP数量用于进度显示
	var totalIPs int
	for _, group := range cidrGroups {
		totalIPs += len(group.IPs)
	}

	var count int32

	// 启动工作协程
	for i := 0; i < maxThreads; i++ {
		go func() {
			for task := range tasks {
				// 测试TCP连接
				var successCount int
				var totalLatency time.Duration
				var minLatency, maxLatency time.Duration

				for i := 0; i < testCount; i++ {
					start := time.Now()
					conn, err := net.DialTimeout("tcp", net.JoinHostPort(task.ip, strconv.Itoa(port)), 1*time.Second)
					if err != nil {
						continue
					}
					latency := time.Since(start)
					conn.Close()

					successCount++
					totalLatency += latency

					if minLatency == 0 || latency < minLatency {
						minLatency = latency
					}
					if latency > maxLatency {
						maxLatency = latency
					}
				}

				// 如果所有测试都失败，跳过此IP
				if successCount == 0 {
					wg.Done()
					continue
				}

				// 计算平均延迟和丢包率
				avgLatency := totalLatency / time.Duration(successCount)
				lossRate := float64(testCount-successCount) / float64(testCount)

				// 获取数据中心信息
				dataCenter, region, city := getDataCenterInfo(task.ip, locationMap)

				result := TestResult{
					IP:         task.ip,
					CIDR:       task.group.CIDR,
					DataCenter: dataCenter,
					Region:     region,
					City:       city,
					AvgLatency: int(avgLatency.Milliseconds()), // 直接转换为毫秒整数
					LossRate:   lossRate,
				}

				mutex.Lock()
				task.group.Results = append(task.group.Results, result)
				mutex.Unlock()

				// 更新进度
				current := atomic.AddInt32(&count, 1)
				percentage := float64(current) / float64(totalIPs) * 100
				fmt.Printf("测试进度: %d/%d (%.2f%%)\r", current, totalIPs, percentage)

				wg.Done()
			}
		}()
	}

	// 提交任务
	for i := range cidrGroups {
		group := &cidrGroups[i]
		for _, ip := range group.IPs {
			wg.Add(1)
			tasks <- testTask{ip: ip, group: group}
		}
	}

	// 关闭任务通道并等待所有任务完成
	close(tasks)
	wg.Wait()
	fmt.Println() // 换行，避免进度条覆盖后续输出

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

// 聚合CIDR结果，计算每个CIDR的平均性能
func aggregateCIDRResults(results []TestResult) []TestResult {
	// 创建CIDR到IP结果的映射
	cidrMap := make(map[string][]TestResult)

	// 按CIDR分组
	for _, result := range results {
		cidrMap[result.CIDR] = append(cidrMap[result.CIDR], result)
	}

	// 创建聚合结果
	var aggregatedResults []TestResult

	// 计算每个CIDR的平均性能
	for cidr, ipResults := range cidrMap {
		// 如果只有一个IP，直接使用其结果
		if len(ipResults) == 1 {
			aggregatedResults = append(aggregatedResults, ipResults[0])
			continue
		}

		// 计算平均延迟和丢包率
		var totalLatency int
		var totalLossRate float64
		var dataCenter, region, city string

		for _, result := range ipResults {
			totalLatency += result.AvgLatency
			totalLossRate += result.LossRate

			// 使用第一个有效的数据中心信息
			if dataCenter == "" && result.DataCenter != "Unknown" {
				dataCenter = result.DataCenter
				region = result.Region
				city = result.City
			}
		}

		avgLatency := totalLatency / len(ipResults)
		avgLossRate := totalLossRate / float64(len(ipResults))

		// 创建聚合结果
		aggregatedResults = append(aggregatedResults, TestResult{
			IP:         ipResults[0].IP, // 使用第一个IP作为代表
			CIDR:       cidr,
			DataCenter: dataCenter,
			Region:     region,
			City:       city,
			AvgLatency: avgLatency,
			LossRate:   avgLossRate,
		})
	}

	return aggregatedResults
}

// 从IP获取CIDR
func getCIDRFromIP(ip string) string {
	// 如果在映射中找到对应的CIDR，则返回
	if cidr, ok := ipCIDRMap[ip]; ok {
		return cidr
	}

	// 如果没有找到映射，直接返回原始IP
	return ip
}

// 获取数据中心信息
func getDataCenterInfo(ip string, locationMap map[string]location) (string, string, string) {
	// 先建立 TCP 连接测试可达性
	dialer := &net.Dialer{
		Timeout: 1 * time.Second,
	}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, "80"))
	if err != nil {
		return "Unknown", "", ""
	}
	defer conn.Close()

	// 用自定义 http.Client 重用连接
	client := http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		Timeout: 1 * time.Second,
	}

	requestURL := "http://" + net.JoinHostPort(ip, "80") + "/cdn-cgi/trace"
	req, _ := http.NewRequest("GET", requestURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Close = true

	resp, err := client.Do(req)
	if err != nil {
		return "Unknown", "", ""
	}
	defer resp.Body.Close()

	// 设置读取响应体的超时
	buf := &bytes.Buffer{}
	timeoutChan := time.After(2 * time.Second)
	done := make(chan bool)
	go func() {
		_, _ = io.Copy(buf, resp.Body)
		done <- true
	}()

	select {
	case <-done:
	case <-timeoutChan:
		return "Unknown", "", ""
	}

	bodyStr := buf.String()
	if strings.Contains(bodyStr, "uag=Mozilla/5.0") {
		regex := regexp.MustCompile(`colo=([A-Z]+)`)
		matches := regex.FindStringSubmatch(bodyStr)
		if len(matches) > 1 {
			dataCenter := matches[1]
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
	ipMap := make(map[string]bool) // 用于去重

	// 处理 IPv4
	if ipv4Mode != "" {
		ipv4Count := 0
		ipv4Limit := 300000 // 设置IPv4上限为30万

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
				baseIP := ipNet.IP.To4()
				if baseIP != nil {
					// 生成所有可能的IP
					for i := 0; i < totalIPs && ipv4Count < ipv4Limit; i++ {
						// 创建新IP
						newIP := make(net.IP, 4)
						copy(newIP, baseIP)

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
				ipNet      *net.IPNet
				baseIP     net.IP
				randomBits int
				values     []uint32
				nextIndex  int
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

				ones, _ := ipNet.Mask.Size()
				baseIP := ipNet.IP.To4()
				randomBits := 32 - ones

				if baseIP != nil {
					// 生成所有可能的值
					totalIPs := 1 << uint(randomBits)
					values := make([]uint32, totalIPs)
					for i := uint32(0); i < uint32(totalIPs); i++ {
						values[i] = i
					}
					// 随机打乱序列
					rand.Shuffle(len(values), func(i, j int) {
						values[i], values[j] = values[j], values[i]
					})

					cidrList = append(cidrList, cidrInfo{
						ipNet:      ipNet,
						baseIP:     baseIP,
						randomBits: randomBits,
						values:     values,
						nextIndex:  0,
					})
				}
			}

			// 循环生成IP直到达到指定数量
			cidrIndex := 0
			allExhausted := false

			for ipv4Count < targetCount && !allExhausted {
				allExhausted = true

				for i := 0; i < len(cidrList); i++ {
					currentIndex := (cidrIndex + i) % len(cidrList)
					current := &cidrList[currentIndex]

					// 检查是否还有可用的值
					if current.nextIndex < len(current.values) {
						allExhausted = false

						// 获取下一个随机值
						value := current.values[current.nextIndex]
						current.nextIndex++

						// 创建新IP
						newIP := make(net.IP, 4)
						copy(newIP, current.baseIP)

						// 应用随机值到IP
						for j := 0; j < 4; j++ {
							shift := uint(8 * (3 - j))
							if shift < uint(current.randomBits) {
								randByte := byte((value >> shift) & 0xFF)
								maskByte := current.ipNet.Mask[j]
								newIP[j] = (newIP[j] & maskByte) | (randByte &^ maskByte)
							}
						}

						ipStr := newIP.String()
						if !ipMap[ipStr] {
							ipList = append(ipList, ipStr)
							ipMap[ipStr] = true
							ipv4Count++

							if ipv4Count >= targetCount {
								break
							}
						}
					}
				}

				cidrIndex = (cidrIndex + 1) % len(cidrList)
			}

			if ipv4Count < targetCount {
				fmt.Printf("警告: 无法生成足够的IPv4地址，已生成 %d 个\n", ipv4Count)
			}
		}
	}

	// 处理 IPv6
	if ipv6Mode != "" {
		ipv6Count := 0
		ipv6Limit := 300000 // 设置IPv6上限为30万

		if count, err := strconv.Atoi(ipv6Mode); err == nil && count > 0 {
			targetCount := count
			if targetCount > ipv6Limit {
				targetCount = ipv6Limit
				fmt.Printf("IPv6生成数量已限制为 %d 个\n", ipv6Limit)
			}

			// 准备CIDR列表
			type cidrInfo struct {
				ipNet      *net.IPNet
				baseIP     net.IP
				randomBits int
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

				ones, _ := ipNet.Mask.Size()
				baseIP := ipNet.IP.To16()

				if baseIP != nil {
					cidrList = append(cidrList, cidrInfo{
						ipNet:      ipNet,
						baseIP:     baseIP,
						randomBits: 128 - ones,
					})
				}
			}

			// 循环生成IP直到达到指定数量
			cidrIndex := 0

			for ipv6Count < targetCount && len(cidrList) > 0 {
				// 获取当前CIDR
				currentCIDR := cidrList[cidrIndex]

				// 创建新IP
				newIP := make(net.IP, 16)
				copy(newIP, currentCIDR.baseIP)

				// 生成随机位并应用到IP
				remainingBits := currentCIDR.randomBits
				for k := 0; k < 16; k++ {
					if remainingBits <= 0 {
						break
					}

					bitsInByte := 8
					if remainingBits < 8 {
						bitsInByte = remainingBits
					}

					randByte := byte(rand.Intn(1 << uint(bitsInByte)))
					maskByte := currentCIDR.ipNet.Mask[k]
					newIP[k] = (newIP[k] & maskByte) | (randByte &^ maskByte)

					remainingBits -= bitsInByte
				}

				ipStr := newIP.String()
				if !ipMap[ipStr] {
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
func filterResults(results []TestResult, coloFilter string, minLatency, maxLatency int, maxLossRate float64) []TestResult {
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

	// 统计数据中心分布
	dcMap := make(map[string]int)
	for _, result := range results {
		dcMap[result.DataCenter]++
	}

	fmt.Println("\n数据中心分布:")
	for dc, count := range dcMap {
		fmt.Printf("%s: %d个\n", dc, count)
	}

	// 计算延迟统计
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
	avgLatency := totalLatency / len(results)

	fmt.Printf("\n延迟统计:\n")
	fmt.Printf("最低延迟: %dms\n", minLatency)
	fmt.Printf("最高延迟: %dms\n", maxLatency)
	fmt.Printf("平均延迟: %dms\n", avgLatency)

	// 显示最佳结果
	fmt.Printf("\n最佳结果:\n")
	for i := 0; i < 5 && i < len(results); i++ {
		result := results[i]
		fmt.Printf("%s - %s(%s) - 延迟: %dms, 丢包率: %.1f%%\n",
			result.CIDR,
			result.City,
			result.DataCenter,
			result.AvgLatency,
			result.LossRate*100)
	}
}
