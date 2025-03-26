package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/olekukonko/tablewriter"
)

// writeResultsToCSV 将测试结果写入CSV文件
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

// generateIPFile 生成IP列表文件
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

// printResultsSummary 打印结果摘要
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
