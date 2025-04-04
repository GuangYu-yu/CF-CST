#![allow(dead_code)]
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

// 共享字符串池，用于减少内存使用
static CIDR_STRING_POOL: OnceLock<HashMap<String, String>> = OnceLock::new();

// 对象池，用于减少内存分配
static CIDR_TEST_DATA_POOL: OnceLock<Mutex<Vec<CIDRTestData>>> = OnceLock::new();
static RESULT_POOL: OnceLock<Mutex<Vec<TestResult>>> = OnceLock::new();
static TEST_RESULT_POOL: OnceLock<Mutex<Vec<TestResult>>> = OnceLock::new();

// 位置信息结构体
#[derive(Clone, Debug)]
pub struct Location {
    pub iata: String,
    pub city: String,
    pub region: String,
}

impl Location {
    pub fn new() -> Self {
        Self {
            iata: String::new(),
            city: String::new(),
            region: String::new(),
        }
    }
}

// 测试结果结构体
#[derive(Clone, Debug)]
pub struct TestResult {
    pub ip: String,
    pub cidr: String,
    pub data_center: String,
    pub region: String,
    pub city: String,
    pub avg_latency: i32,
    pub loss_rate: f64,
}

impl TestResult {
    pub fn new() -> Self {
        Self {
            ip: String::new(),
            cidr: String::new(),
            data_center: String::new(),
            region: String::new(),
            city: String::new(),
            avg_latency: 0,
            loss_rate: 0.0,
        }
    }

    pub fn clear(&mut self) {
        self.ip.clear();
        self.cidr.clear();
        self.data_center.clear();
        self.region.clear();
        self.city.clear();
        self.avg_latency = 0;
        self.loss_rate = 0.0;
    }
}

// CIDR测试数据结构体
#[derive(Debug)]
pub struct CIDRTestData {
    pub ips: Vec<String>,
    pub results: Vec<TestResult>,
}

impl CIDRTestData {
    pub fn new() -> Self {
        Self {
            ips: Vec::new(),
            results: Vec::new(),
        }
    }
}

// CIDR组结构体
#[derive(Debug)]
pub struct CIDRGroup {
    pub cidr: String,
    pub data: Option<CIDRTestData>,
    pub result: Option<TestResult>,
}

impl CIDRGroup {
    pub fn new(cidr: String) -> Self {
        Self {
            cidr,
            data: None,
            result: None,
        }
    }

    pub fn finalize(&mut self) {
        if let Some(data) = &self.data {
            if !data.results.is_empty() {
                let mut total_latency = 0;
                let mut total_loss_rate = 0.0;
                
                for result in &data.results {
                    total_latency += result.avg_latency;
                    total_loss_rate += result.loss_rate;
                }
                
                // 从对象池获取结果对象
                let mut result = get_result();
                
                // 填充结果
                result.cidr = self.cidr.clone();
                
                if let Some(first) = data.results.first() {
                    result.data_center = first.data_center.clone();
                    result.region = first.region.clone();
                    result.city = first.city.clone();
                }
                
                result.avg_latency = total_latency / data.results.len() as i32;
                result.loss_rate = total_loss_rate / data.results.len() as f64;
                
                self.result = Some(result);
                
                // 清理临时数据并放回对象池
                if let Some(mut data) = self.data.take() {
                    data.ips.clear();
                    data.results.clear();
                    put_cidr_test_data(data);
                }
            }
        }
    }
}

// 共享状态结构体，用于在线程间共享数据
#[derive(Debug)]
pub struct SharedState {
    pub cidr_groups: Arc<Mutex<Vec<CIDRGroup>>>,
    pub completed: Arc<Mutex<usize>>,
    pub total: usize,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            cidr_groups: Arc::new(Mutex::new(Vec::new())),
            completed: Arc::new(Mutex::new(0)),
            total: 0,
        }
    }
    
    pub fn with_cidr_groups(cidr_groups: Vec<CIDRGroup>) -> Self {
        let total = cidr_groups.len();
        Self {
            cidr_groups: Arc::new(Mutex::new(cidr_groups)),
            completed: Arc::new(Mutex::new(0)),
            total,
        }
    }
    
    pub fn increment_processed_count(&self) -> usize {
        let mut completed = self.completed.lock().unwrap();
        *completed += 1;
        *completed  // 返回当前完成的数量
    }
}

// 初始化对象池
fn init_pools() {
    // 初始化CIDR字符串池
    CIDR_STRING_POOL.get_or_init(|| HashMap::new());
    
    // 初始化CIDR测试数据对象池
    CIDR_TEST_DATA_POOL.get_or_init(|| {
        let mut pool = Vec::with_capacity(1000);
        for _ in 0..1000 {
            pool.push(CIDRTestData::new());
        }
        Mutex::new(pool)
    });
    
    // 初始化结果对象池
    RESULT_POOL.get_or_init(|| {
        let mut pool = Vec::with_capacity(1000);
        for _ in 0..1000 {
            pool.push(TestResult::new());
        }
        Mutex::new(pool)
    });
    
    // 初始化测试结果对象池
    TEST_RESULT_POOL.get_or_init(|| {
        let mut pool = Vec::with_capacity(1000);
        for _ in 0..1000 {
            pool.push(TestResult::new());
        }
        Mutex::new(pool)
    });
}

// 获取或创建CIDR字符串
pub fn get_or_create_cidr_string(cidr: &str) -> String {
    // 确保池已初始化
    if CIDR_STRING_POOL.get().is_none() {
        init_pools();
    }
    
    let pool = CIDR_STRING_POOL.get().unwrap();
    if let Some(existing) = pool.get(cidr) {
        existing.clone()
    } else {
        let string = cidr.to_string();
        // 由于OnceLock中的HashMap是不可变的，我们不能直接修改它
        // 在实际应用中，应该使用Mutex或RwLock包装HashMap
        // 这里简化处理，直接返回新字符串
        string
    }
}

// 获取CIDR测试数据对象
pub fn get_cidr_test_data() -> CIDRTestData {
    // 确保池已初始化
    if CIDR_TEST_DATA_POOL.get().is_none() {
        init_pools();
    }
    
    let mut pool = CIDR_TEST_DATA_POOL.get().unwrap().lock().unwrap();
    pool.pop().unwrap_or_else(CIDRTestData::new)
}

// 归还CIDR测试数据对象到池
pub fn put_cidr_test_data(data: CIDRTestData) {
    // 确保池已初始化
    if CIDR_TEST_DATA_POOL.get().is_none() {
        init_pools();
    }
    
    let mut pool = CIDR_TEST_DATA_POOL.get().unwrap().lock().unwrap();
    pool.push(data);
}

// 获取测试结果对象
pub fn get_test_result() -> TestResult {
    // 确保池已初始化
    if TEST_RESULT_POOL.get().is_none() {
        init_pools();
    }
    
    let mut pool = TEST_RESULT_POOL.get().unwrap().lock().unwrap();
    pool.pop().unwrap_or_else(TestResult::new)
}

// 获取结果对象
pub fn get_result() -> TestResult {
    // 确保池已初始化
    if RESULT_POOL.get().is_none() {
        init_pools();
    }
    
    let mut pool = RESULT_POOL.get().unwrap().lock().unwrap();
    pool.pop().unwrap_or_else(TestResult::new)
}

// 归还结果对象到池
pub fn put_result(result: TestResult) {
    // 确保池已初始化
    if RESULT_POOL.get().is_none() {
        init_pools();
    }
    
    let mut pool = RESULT_POOL.get().unwrap().lock().unwrap();
    pool.push(result);
}