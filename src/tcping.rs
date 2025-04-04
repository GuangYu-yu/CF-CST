use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use std::net::ToSocketAddrs;
use tokio::net::TcpStream;
use tokio::time::{timeout, Instant};
use futures::{stream, StreamExt};
use rand::seq::SliceRandom;
use ipnetwork::IpNetwork;
use std::str::FromStr;
use indicatif::{ProgressBar, ProgressStyle};

use crate::types::{CIDRGroup, CIDRTestData, SharedState, TestResult, Location};
use crate::cidr::{generate_random_ipv4_address, generate_random_ipv6_address};
use crate::pool::execute_with_rate_limit;
use crate::getcolo::get_datacenter_for_ip;

/// 检查测试结果是否符合筛选条件
pub fn should_include_result(
    result: &TestResult,
    colo_flag: &str,
    min_latency: i32,
    max_latency: i32,
    max_loss_rate: f64,
    show_all: bool
) -> bool {
    // 如果不显示所有结果，则跳过未知数据中心的结果
    if !show_all && result.data_center == "Unknown" {
        return false;
    }

    // 检查数据中心
    if !colo_flag.is_empty() {
        // 避免创建中间集合，直接使用迭代器
        let mut match_found = false;
        for colo in colo_flag.split(',') {
            if result.data_center == colo.trim() {
                match_found = true;
                break;
            }
        }
        if !match_found {
            return false;
        }
    }

    // 检查延迟
    if result.avg_latency < min_latency || result.avg_latency > max_latency {
        return false;
    }

    // 检查丢包率
    if result.loss_rate > max_loss_rate {
        return false;
    }

    true
}

/// 执行 TCP 连接测试
async fn tcp_connect(ip: &str, port: u16, timeout_duration: Duration) -> std::io::Result<Duration> {
    let start = Instant::now();
    let socket_addr = format!("{}:{}", ip, port);
    
    // 解析地址 - 避免中间集合，只取第一个地址
    let addr = match socket_addr.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "无法解析地址")),
        },
        Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("地址解析失败: {}", e))),
    };
    
    // 尝试连接
    match timeout(timeout_duration, TcpStream::connect(addr)).await {
        Ok(result) => {
            match result {
                Ok(_) => Ok(start.elapsed()),
                Err(e) => Err(e),
            }
        },
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "连接超时")),
    }
}

pub async fn test_ips(
    cidr_groups: Vec<CIDRGroup>,
    port: u16, 
    test_count: usize, 
    max_threads: usize,  
    ip_per_cidr: usize, 
    location_map: &HashMap<String, Location>,
    colo_flag: &str,
    min_latency: i32,
    max_latency: i32,
    max_loss_rate: f64,
    show_all: bool,
    shared_state: Arc<SharedState>
) -> Vec<CIDRGroup> {
    println!("每个 IP 测试次数: {}", test_count);
    println!("每个 CIDR 测试 IP 数量: {}", ip_per_cidr);
    
    // 创建进度条
    let total_cidrs = cidr_groups.len();
    println!("共有 {} 个 CIDR 需要测试", total_cidrs);
    
    // 创建进度条
    let progress_bar = ProgressBar::new(total_cidrs as u64);
    progress_bar.set_style(ProgressStyle::default_bar()
        .template("{pos}/{len} [{wide_bar}]  [{elapsed_precise}]")
        .unwrap()
        .progress_chars("=> "));
    
    // 启用实时刷新
    progress_bar.enable_steady_tick(std::time::Duration::from_millis(100));
    
    // 并发处理每个 CIDR
    let mut processed_groups = Vec::with_capacity(cidr_groups.len());
    
    // 使用 stream 进行并发处理
    let mut stream = stream::iter(cidr_groups)
        .map(|mut group| {
            let location_map = &location_map; // 使用引用
            let shared_state = shared_state.clone(); // 这个克隆是必要的
            let mut rng = rand::rng(); // 如果不需要共享，可以直接使用
            let progress_bar = &progress_bar; // 使用引用
            let cidr_str = group.cidr.clone(); // 提前克隆一次，避免在循环中多次克隆
            
            async move {
                // 解析 CIDR
                let ip_net = match IpNetwork::from_str(&group.cidr) {
                    Ok(net) => net,
                    Err(_) => {
                        println!("无法解析 CIDR: {}", group.cidr);
                        return group;
                    }
                };
                
                // 创建测试数据 - 预分配容量
                let mut test_data = CIDRTestData {
                    ips: Vec::with_capacity(ip_per_cidr),
                    results: Vec::with_capacity(ip_per_cidr),
                };
                
                // 生成随机 IP - 预分配容量
                let mut ips = Vec::with_capacity(ip_per_cidr * 2); // 预留一些额外空间，因为可能有些IP生成失败
                
                if ip_net.is_ipv4() {
                    for _ in 0..ip_per_cidr {
                        if let Some(ip) = generate_random_ipv4_address(&ip_net) {
                            ips.push(ip);
                        }
                    }
                } else {
                    for _ in 0..ip_per_cidr {
                        if let Some(ip) = generate_random_ipv6_address(&ip_net) {
                            ips.push(ip);
                        }
                    }
                }
                
                // 如果没有生成有效 IP，跳过此 CIDR
                if ips.is_empty() {
                    println!("无法为 CIDR {} 生成有效 IP", group.cidr);
                    return group;
                }
                
                // 打乱 IP 顺序
                ips.shuffle(&mut rng);
                
                // 限制 IP 数量
                if ips.len() > ip_per_cidr {
                    ips.truncate(ip_per_cidr);
                }
                
                test_data.ips = ips.clone();
                
                // 测试每个 IP
                for ip in &ips {
                    // 获取数据中心信息
                    let (datacenter, region, city) = get_datacenter_for_ip(ip, &location_map).await;
                    
                    // 测试连接 - 预分配容量
                    let mut latencies = Vec::with_capacity(test_count);
                    let mut failures = 0;
                    
                    for _ in 0..test_count {
                        match execute_with_rate_limit(|| {
                            let ip = ip.clone();
                            async move {
                                tcp_connect(&ip, port, Duration::from_secs(1)).await
                            }
                        }).await {
                            Ok(duration) => {
                                latencies.push(duration.as_millis() as i32);
                            },
                            Err(_) => {
                                failures += 1;
                            }
                        }
                    }
                    
                    // 计算平均延迟和丢包率
                    let avg_latency = if latencies.is_empty() {
                        0
                    } else {
                        latencies.iter().sum::<i32>() / latencies.len() as i32
                    };
                    
                    let loss_rate = failures as f64 / test_count as f64;
                    
                    // 创建测试结果 - 减少克隆
                    let result = TestResult {
                        ip: ip.to_string(),
                        cidr: cidr_str.clone(), // 使用之前克隆的字符串
                        data_center: datacenter,
                        region,
                        city,
                        avg_latency,
                        loss_rate,
                    };
                    
                    test_data.results.push(result);
                }
                
                // 合并结果
                if !test_data.results.is_empty() {
                    // 按延迟和丢包率排序
                    test_data.results.sort_by(|a, b| {
                        if (a.loss_rate - b.loss_rate).abs() < f64::EPSILON {
                            a.avg_latency.cmp(&b.avg_latency)
                        } else {
                            a.loss_rate.partial_cmp(&b.loss_rate).unwrap()
                        }
                    });
                    
                    // 使用引用而不是克隆
                    if should_include_result(&test_data.results[0], colo_flag, min_latency, max_latency, max_loss_rate, show_all) {
                        group.result = Some(test_data.results[0].clone()); // 这个克隆是必要的
                    }
                }
                
                group.data = Some(test_data);
                
                // 更新进度
                let count = shared_state.increment_processed_count();
                // 每处理一个CIDR就更新进度条
                progress_bar.set_position(count as u64);
                
                group
            }
        })
        .buffer_unordered(max_threads);
    
    // 收集结果
    while let Some(group) = stream.next().await {
        processed_groups.push(group);
    }
    
    // 完成进度条
    progress_bar.finish_with_message("测试完成");
    
    // 过滤出有结果的组
    let filtered_groups: Vec<CIDRGroup> = processed_groups
        .into_iter()
        .filter(|group| group.result.is_some())
        .collect();
    
    println!("测试完成，共有 {} 个 CIDR 符合条件", filtered_groups.len());
    
    filtered_groups
}
