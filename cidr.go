package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// 获取共享 CIDR 字符串的函数
func getSharedCIDR(cidr string) string {
	if pooledCIDR, ok := cidrStringPool.Load(cidr); ok {
		return pooledCIDR.(string)
	}
	cidrStringPool.Store(cidr, cidr)
	return cidr
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

// 通用的IPv4地址生成函数
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

// 通用的IPv6地址生成函数
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