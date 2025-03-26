package main

import (
	"sync"

	"golang.org/x/sync/semaphore"
)

// TestResult 存储测试结果
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

// CIDRTestData 临时测试数据
type CIDRTestData struct {
	IPs     []string
	Results []TestResult
}

// CIDRResult 最终结果
type CIDRResult struct {
	CIDR       string
	DataCenter string
	Region     string
	City       string
	AvgLatency int
	LossRate   float64
}

// CIDRGroup 测试过程中的结构
type CIDRGroup struct {
	CIDR   string
	Data   *CIDRTestData // 临时数据
	Result *TestResult
}

// location Cloudflare数据中心位置信息
type location struct {
	Iata   string `json:"iata"`
	Region string `json:"region"`
	City   string `json:"city"`
}

// 全局对象池
var (
	globalSem      *semaphore.Weighted
	testDataPool   sync.Pool
	resultPool     sync.Pool
	testResultPool sync.Pool
	cidrStringPool sync.Map // CIDR 字符串池
)

// 初始化对象池
func initPools() {
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

// finalize 计算CIDR组的平均值并生成最终结果
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
