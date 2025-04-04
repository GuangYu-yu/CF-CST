use std::env;
use std::time::Duration;

#[derive(Clone)]  // 添加 Clone trait 派生
pub struct Args {
    pub url: String,
    pub file: String,
    pub test_count: u32,
    pub port: u16,
    pub ip_per_cidr: usize,
    pub colo: String,
    pub max_latency: i32,
    pub min_latency: i32,
    pub max_loss_rate: f64,
    pub scan_threads: usize,
    pub print_count: String,
    pub out_file: String,
    pub no_csv: bool,
    pub use_ipv4: String,
    pub use_ipv6: String,
    pub ip_txt_file: String,
    pub no_test: bool,
    pub show_all: bool,
    pub help: bool,
    pub timeout: String,
    // 添加解析后的超时时间字段
    pub timeout_duration: Option<Duration>,
}

impl Args {
    pub fn new() -> Self {
        Self {
            url: String::new(),
            file: String::new(),
            test_count: 4,
            port: 443,
            ip_per_cidr: 2,
            colo: String::new(),
            max_latency: 500,
            min_latency: 0,
            max_loss_rate: 0.5,
            scan_threads: 128,
            print_count: "all".to_string(),
            out_file: "IP_Speed.csv".to_string(),
            no_csv: false,
            use_ipv4: String::new(),
            use_ipv6: String::new(),
            ip_txt_file: "ip.txt".to_string(),
            no_test: false,
            show_all: false,
            help: false,
            timeout: String::new(),
            timeout_duration: None,
        }
    }

    pub fn parse() -> Self {
        let args: Vec<String> = env::args().collect();
        let mut parsed = Self::new();
        let mut i = 1;  // 跳过程序名
        
        while i < args.len() {
            let arg = &args[i];
            
            // 确保是参数标志，统一处理单破折号和双破折号
            if !arg.starts_with('-') {
                i += 1;
                continue;
            }

            // 去除所有前导破折号
            let name = arg.trim_start_matches('-').to_string();
            
            // 检查是否是无值标志参数
            match name.as_str() {
                "h" => {
                    parsed.help = true;
                    i += 1;
                    continue;
                }
                "nocsv" => {
                    parsed.no_csv = true;
                    i += 1;
                    continue;
                }
                "notest" => {
                    parsed.no_test = true;
                    i += 1;
                    continue;
                }
                "showall" => {
                    parsed.show_all = true;
                    i += 1;
                    continue;
                }
                _ => {}
            }
            
            // 处理带值的参数
            if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                match name.as_str() {
                    "url" => parsed.url = args[i + 1].clone(),
                    "f" => parsed.file = args[i + 1].clone(),
                    "t" => parsed.test_count = args[i + 1].parse().unwrap_or(4),
                    "tp" => parsed.port = args[i + 1].parse().unwrap_or(443),
                    "ts" => parsed.ip_per_cidr = args[i + 1].parse().unwrap_or(2),
                    "colo" => parsed.colo = args[i + 1].clone(),
                    "tl" => parsed.max_latency = args[i + 1].parse().unwrap_or(500),
                    "tll" => parsed.min_latency = args[i + 1].parse().unwrap_or(0),
                    "tlr" => parsed.max_loss_rate = args[i + 1].parse().unwrap_or(0.5),
                    "n" => parsed.scan_threads = args[i + 1].parse().unwrap_or(128),
                    "p" => parsed.print_count = args[i + 1].clone(),
                    "o" => parsed.out_file = args[i + 1].clone(),
                    "useip4" => parsed.use_ipv4 = args[i + 1].clone(),
                    "useip6" => parsed.use_ipv6 = args[i + 1].clone(),
                    "iptxt" => parsed.ip_txt_file = args[i + 1].clone(),
                    "timeout" => {
                        parsed.timeout = args[i + 1].clone();
                        // 解析超时时间
                        parsed.timeout_duration = parse_duration(&args[i + 1]);
                    },
                    _ => {}
                }
                i += 2;  // 跳过参数名和值
            } else {
                i += 1;
            }
        }

        // 限制最大并发数为1024
        if parsed.scan_threads > 1024 {
            parsed.scan_threads = 1024;
        }

        parsed
    }
    
    pub fn validate(&self) -> Result<(), String> {
        // 检查必要参数
        if self.url.is_empty() && self.file.is_empty() {
            return Err("错误: 必须指定 -url 或 -f 参数".to_string());
        }
    
        // 如果使用 -notest 参数，检查是否指定了 -useip4 或 -useip6
        if self.no_test && self.use_ipv4.is_empty() && self.use_ipv6.is_empty() {
            return Err("错误: 使用 -notest 参数时必须至少指定 -useip4 或 -useip6 参数".to_string());
        }
    
        Ok(())
    }
}

// 解析时间字符串为Duration
fn parse_duration(duration_str: &str) -> Option<Duration> {
    // 如果是空字符串，表示不限制时间
    if duration_str.is_empty() {
        return None;
    }
    
    // 尝试使用humantime库解析时间字符串
    match humantime::parse_duration(duration_str) {
        Ok(duration) => Some(duration),
        Err(err) => {
            println!("解析超时时间失败: {}，将不限制运行时间", err);
            None
        }
    }
}

pub fn print_help() {
    println!("\n基本参数:");
    println!("  -url string      测速的CIDR链接");
    println!("  -f string        指定测速的文件路径 (当未设置-url时使用)");
    println!("  -o string        结果文件名 (默认: IP_Speed.csv)");
    println!("  -h               显示帮助信息");
    println!("  -notest          不进行测速，只生成随机IP (需配合 -useip4 或 -useip6 使用)");
    println!("  -showall         使用后显示所有结果，包括未查询到数据中心的结果");
    println!("  -timeout string  程序执行超时退出 (例: 5h0m0s，默认: 不使用)");

    println!("\n测速参数:");
    println!("  -t int           延迟测试次数 (默认: 4)");
    println!("  -tp int          测试端口号 (默认: 443)");
    println!("  -ts int          每个CIDR测试的IP数量 (默认: 2)");
    println!("  -n int           并发测试线程数量 (默认: 128)");
    println!("\n  注意避免 -t 和 -ts 导致测速量过于庞大！");

    println!("\n筛选参数:");
    println!("  -colo string     指定数据中心，多个用逗号分隔 (例: HKG,NRT,LAX,SJC)");
    println!("  -tl int          延迟上限 (默认: 500ms)");
    println!("  -tll int         延迟下限 (默认: 0ms)");
    println!("  -tlr float       丢包率上限 (默认: 0.5)");
    println!("  -p string        输出结果数量 (默认: all)");

    println!("\n输出选项:");
    println!("  -nocsv           不生成CSV文件 (默认: 不使用)");
    println!("  -useip4 string   生成IPv4列表 (默认: 不使用)");
    println!("                   - 使用 all: 输出所有IPv4 CIDR的完整IP列表");
    println!("                   - 使用数字 (如9999): 输出指定数量的不重复IPv4");
    println!("  -useip6 string   生成IPv6列表 (默认: 不使用)");
    println!("                   - 使用数字 (如9999): 输出指定数量的不重复IPv6");
    println!("  -iptxt string    指定IP列表输出文件名 (默认: ip.txt)");
    println!("                   - 使用此参数时必须至少使用 -useip4 或 -useip6");
}