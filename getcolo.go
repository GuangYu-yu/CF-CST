package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

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
			loc := &locations[i]
			locationMap[loc.Iata] = loc
		}

		return locationMap, nil
	}

	return nil, lastErr
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
