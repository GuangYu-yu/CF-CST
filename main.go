package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"time"

	"golang.org/x/sync/semaphore"
)

func init() {
	// 初始化对象池
	initPools()
}

func main() {
	// 解析命令行参数
	args := parseArgs()

	// 添加全局超时控制
	defaultTimeout := 5 * time.Hour

	// 解析超时时间
	globalTimeout, err := time.ParseDuration(args.Timeout)
	if err != nil {
		fmt.Printf("无效的超时时间格式: %s, 使用默认值: %s\n", args.Timeout, defaultTimeout)
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
		runMainProgram(args)
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

func runMainProgram(args CommandArgs) {
	// 限制最大并发数
	if args.ScanThreads > 1024 {
		// 限制最大并发数为1024
		args.ScanThreads = 1024
	}

	// 使用统一的并发控制
	maxConcurrent := args.ScanThreads
	globalSem = semaphore.NewWeighted(int64(maxConcurrent))

	// 显示帮助信息
	if args.Help {
		printHelp()
		return
	}

	// 检查必要参数
	if args.URLFlag == "" && args.FileFlag == "" {
		fmt.Println("错误: 必须指定 -url 或 -f 参数")
		printHelp()
		return
	}

	// 如果使用 -notest 参数，检查是否指定了 -useip4 或 -useip6
	if args.NoTest && args.UseIPv4 == "" && args.UseIPv6 == "" {
		fmt.Println("错误: 使用 -notest 参数时必须至少指定 -useip4 或 -useip6 参数")
		return
	}

	// 获取CIDR列表
	var cidrList []string
	var err error

	if args.URLFlag != "" {
		fmt.Printf("从URL获取CIDR列表: %s\n", args.URLFlag)
		cidrList, err = getCIDRFromURL(args.URLFlag)
	} else {
		fmt.Printf("从文件获取CIDR列表: %s\n", args.FileFlag)
		cidrList, err = getCIDRFromFile(args.FileFlag)
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
	if args.NoTest {
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
		err = generateIPFile(results, args.UseIPv4, args.UseIPv6, args.IPTxtFile)
		if err != nil {
			fmt.Printf("生成IP文件失败: %v\n", err)
		} else {
			fmt.Printf("IP列表已写入: %s\n", args.IPTxtFile)
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
	cidrGroups = testIPs(cidrGroups, args.PortFlag, args.TestCount, args.ScanThreads, args.IPPerCIDR, locationMap,
		&args.ColoFlag, &args.MinLatency, &args.MaxLatency, &args.MaxLossRate, &args.ShowAll)

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
	if args.PrintCount != "all" {
		count, err := strconv.Atoi(args.PrintCount)
		if err == nil && count > 0 {
			// 只有当结果数量大于指定数量时才截取
			if count < len(filteredResults) {
				filteredResults = filteredResults[:count]
			}
			// 否则保持原有结果不变
		}
	}

	// 输出结果
	if !args.NoCSV {
		err = writeResultsToCSV(filteredResults, args.OutFile)
		if err != nil {
			fmt.Printf("写入CSV文件失败: %v\n", err)
		} else {
			fmt.Printf("结果已写入: %s\n", args.OutFile)
		}
	}

	// 输出IP列表
	if args.UseIPv4 != "" || args.UseIPv6 != "" {
		err = generateIPFile(filteredResults, args.UseIPv4, args.UseIPv6, args.IPTxtFile)
		if err != nil {
			fmt.Printf("生成IP文件失败: %v\n", err)
		} else {
			fmt.Printf("IP列表已写入: %s\n", args.IPTxtFile)
		}
	}

	// 打印结果摘要
	printResultsSummary(filteredResults)
}
