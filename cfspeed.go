package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
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
	AvgLatency time.Duration
	LossRate   float64
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
	ipList := generateRandomIPs(expandedCIDRs, *ipPerCIDR)
	fmt.Printf("共生成 %d 个IP进行测试\n", len(ipList))

	// 如果指定了 -notest 参数，直接生成IP文件并退出
	if *noTest {
		// 创建一个空的结果列表，只包含IP和CIDR信息
		var results []TestResult
		for _, ip := range ipList {
			cidr := getCIDRFromIP(ip)
			results = append(results, TestResult{
				IP:         ip,
				CIDR:       cidr,
				DataCenter: "Unknown",
				Region:     "",
				City:       "",
				AvgLatency: 0,
				LossRate:   0,
			})
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
	results := testIPs(ipList, *portFlag, *testCount, *scanThreads, locationMap)

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
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP请求失败，状态码: %d", resp.StatusCode)
	}

	return parseCIDRList(resp.Body)
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
			fmt.Printf("警告: 无效的CIDR格式 %s: %v\n", cidr, err)
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
				expandedList = append(expandedList, expandIPv4CIDR(ipNet, ones)...)
			}
		} else {
			// IPv6
			ones, _ := ipNet.Mask.Size()
			if ones >= 48 {
				// 已经是/48或更小，直接添加
				expandedList = append(expandedList, cidr)
			} else {
				// 需要拆分为多个/48
				expandedList = append(expandedList, expandIPv6CIDR(ipNet, ones)...)
			}
		}
	}

	return expandedList
}

// 将IPv4 CIDR拆分为多个/24
func expandIPv4CIDR(ipNet *net.IPNet, ones int) []string {
	var result []string
	ip := ipNet.IP.To4()

	// 计算需要拆分的位数
	splitBits := 24 - ones
	count := 1 << uint(splitBits) // 2^splitBits

	// 生成所有/24子网
	for i := 0; i < count; i++ {
		// 创建新的IP
		newIP := make(net.IP, len(ip))
		copy(newIP, ip)

		// 计算子网的第三个字节
		thirdByte := (i >> 8) & 0xFF
		// 计算子网的第四个字节
		fourthByte := i & 0xFF

		if splitBits > 8 {
			newIP[2] = byte(thirdByte)
		}
		if splitBits > 0 {
			newIP[3] = byte(fourthByte)
		}

		// 创建新的CIDR
		result = append(result, fmt.Sprintf("%s/24", newIP.String()))
	}

	return result
}

// 将IPv6 CIDR拆分为多个/48
func expandIPv6CIDR(ipNet *net.IPNet, ones int) []string {
	var result []string
	ip := ipNet.IP.To16()

	// 计算需要拆分的位数
	splitBits := 48 - ones

	// 限制拆分数量，避免生成过多的子网
	if splitBits > 16 {
		fmt.Printf("警告: CIDR %s 拆分为/48会生成过多子网，限制为最多65536个\n", ipNet.String())
		splitBits = 16
	}

	count := 1 << uint(splitBits) // 2^splitBits

	// 生成所有/48子网
	for i := 0; i < count; i++ {
		// 创建新的IP
		newIP := make(net.IP, len(ip))
		copy(newIP, ip)

		// 计算子网的字节
		for j := 0; j < splitBits/8; j++ {
			newIP[6-j] = byte((i >> (j * 8)) & 0xFF)
		}

		// 如果有剩余的位
		if splitBits%8 != 0 {
			mask := byte(0xFF >> (8 - (splitBits % 8)))
			shift := 8 - (splitBits % 8)
			newIP[6-(splitBits/8)] = (newIP[6-(splitBits/8)] & ^mask) | byte((i>>(splitBits/8*8))<<shift)
		}

		// 创建新的CIDR
		result = append(result, fmt.Sprintf("%s/48", newIP.String()))
	}

	return result
}

// 从每个CIDR中随机生成IP
func generateRandomIPs(cidrList []string, ipPerCIDR int) []string {
	rand.Seed(time.Now().UnixNano())
	var ipList []string
	ipToCIDR := make(map[string]string) // 新增：记录IP对应的CIDR

	for _, cidr := range cidrList {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		// 判断是IPv4还是IPv6
		if ipNet.IP.To4() != nil {
			// IPv4
			for i := 0; i < ipPerCIDR; i++ {
				ip := generateRandomIPv4(ipNet)
				ipList = append(ipList, ip)
				ipToCIDR[ip] = cidr // 记录IP来自哪个CIDR
			}
		} else {
			// IPv6
			for i := 0; i < ipPerCIDR; i++ {
				ip := generateRandomIPv6(ipNet)
				ipList = append(ipList, ip)
				ipToCIDR[ip] = cidr // 记录IP来自哪个CIDR
			}
		}
	}

	// 将映射关系保存到全局变量
	ipCIDRMap = ipToCIDR

	return ipList
}

// 全局变量，用于存储IP到CIDR的映射
var ipCIDRMap map[string]string

// 生成随机IPv4地址
func generateRandomIPv4(ipNet *net.IPNet) string {
	ip := ipNet.IP.To4()
	mask := ipNet.Mask

	// 创建新的IP
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)

	// 计算可以随机的位数
	ones, _ := mask.Size()
	randomBits := 32 - ones

	// 生成随机值
	randomValue := rand.Uint32() & ((1 << uint(randomBits)) - 1)

	// 应用随机值到IP的最后几个字节
	for i := 0; i < 4; i++ {
		shift := uint(8 * (3 - i))
		if shift < uint(randomBits) {
			randByte := byte((randomValue >> shift) & 0xFF)
			maskByte := mask[i]
			newIP[i] = (newIP[i] & maskByte) | (randByte &^ maskByte)
		}
	}

	return newIP.String()
}

// 生成随机IPv6地址
func generateRandomIPv6(ipNet *net.IPNet) string {
	ip := ipNet.IP.To16()
	mask := ipNet.Mask

	// 创建新的IP
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)

	// 计算可以随机的位数
	ones, _ := mask.Size()
	randomBits := 128 - ones

	// 生成随机值并应用到IP
	for i := 0; i < 16; i++ {
		if randomBits <= 0 {
			break
		}

		bitsInByte := 8
		if randomBits < 8 {
			bitsInByte = randomBits
		}

		randByte := byte(rand.Intn(1 << uint(bitsInByte)))
		maskByte := mask[i]
		newIP[i] = (newIP[i] & maskByte) | (randByte &^ maskByte)

		randomBits -= bitsInByte
	}

	return newIP.String()
}

// 获取Cloudflare数据中心位置信息
func getLocationMap() (map[string]location, error) {
	// 从 URL 读取 locations.json 文件
	var locations []location

	resp, err := http.Get("https://speed.cloudflare.com/locations")
	if err != nil {
		return nil, fmt.Errorf("无法获取 locations.json: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("无法读取响应体: %v", err)
	}

	err = json.Unmarshal(body, &locations)
	if err != nil {
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
func testIPs(ipList []string, port, testCount, maxThreads int, locationMap map[string]location) []TestResult {
	var results []TestResult
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// 创建信号量控制并发
	semaphore := make(chan struct{}, maxThreads)

	total := len(ipList)
	var count int32

	for _, ip := range ipList {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(ip string) {
			defer func() {
				<-semaphore
				wg.Done()

				// 更新进度
				current := atomic.AddInt32(&count, 1)
				percentage := float64(current) / float64(total) * 100
				fmt.Printf("测试进度: %d/%d (%.2f%%)\r", current, total, percentage)
			}()

			// 测试TCP连接
			var successCount int
			var totalLatency time.Duration
			var minLatency, maxLatency time.Duration

			for i := 0; i < testCount; i++ {
				start := time.Now()
				conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 1*time.Second)
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
				return
			}

			// 计算平均延迟和丢包率
			avgLatency := totalLatency / time.Duration(successCount)
			lossRate := float64(testCount-successCount) / float64(testCount)

			// 获取数据中心信息
			dataCenter, region, city := getDataCenterInfo(ip, locationMap)

			// 确定CIDR
			cidr := getCIDRFromIP(ip)

			mutex.Lock()
			results = append(results, TestResult{
				IP:         ip,
				CIDR:       cidr,
				DataCenter: dataCenter,
				Region:     region,
				City:       city,
				AvgLatency: avgLatency,
				LossRate:   lossRate,
			})
			mutex.Unlock()
		}(ip)
	}

	wg.Wait()
	fmt.Println() // 换行，避免进度条覆盖后续输出

	return results
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

		// 检查延迟
		latencyMs := int(result.AvgLatency.Milliseconds())
		if latencyMs < minLatency || latencyMs > maxLatency {
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
		row := []string{
			result.IP + result.CIDR[len(result.IP):],
			result.DataCenter,
			result.Region,
			result.City,
			fmt.Sprintf("%d", result.AvgLatency.Milliseconds()),
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
	var totalLatency time.Duration
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
	avgLatency := totalLatency / time.Duration(len(results))

	fmt.Printf("\n延迟统计:\n")
	fmt.Printf("最低延迟: %dms\n", minLatency.Milliseconds())
	fmt.Printf("最高延迟: %dms\n", maxLatency.Milliseconds())
	fmt.Printf("平均延迟: %dms\n", avgLatency.Milliseconds())

	// 显示最佳结果
	fmt.Printf("\n最佳结果:\n")
	for i := 0; i < 5 && i < len(results); i++ {
		result := results[i]
		fmt.Printf("%s - %s(%s) - 延迟: %dms, 丢包率: %.1f%%\n",
			result.IP+result.CIDR[len(result.IP):],
			result.City,
			result.DataCenter,
			result.AvgLatency.Milliseconds(),
			result.LossRate*100)
	}
}
