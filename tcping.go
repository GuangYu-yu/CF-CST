package main

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/cheggaaa/pb/v3"
	"golang.org/x/sync/semaphore"
)

// testIPs 测试IP性能
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
						if !shouldIncludeResult(*cidrGroups[i].Result, coloFlag, minLatency, maxLatency, maxLossRate, showAll) {
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

// 格式化时间
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
