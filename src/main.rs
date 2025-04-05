use std::sync::Arc;
use tokio::time::timeout;
use std::str::FromStr;
use std::collections::HashMap;

mod args;
mod cidr;
mod getcolo;
mod output;
mod tcping;
mod types;
mod pool;

use crate::args::{Args, print_help};
use crate::cidr::{expand_cidrs, get_cidr_from_file, get_cidr_from_url, parse_command_line_cidrs};
use crate::getcolo::get_location_map;
use crate::output::{generate_ip_file, print_results_summary, write_results_to_csv};
use crate::tcping::test_ips;
use crate::types::{CIDRGroup, SharedState, TestResult};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 解析命令行参数
    let args = Args::parse();
    
    // 检查是否设置了超时
    if let Some(timeout_duration) = args.timeout_duration {
        println!("程序将在 {} 秒后自动退出", timeout_duration.as_secs());
        
        // 创建一个任务来运行主程序
        let args_clone = args.clone();
        let program_task = async move {
            run_main_program(args_clone).await;
            Ok::<_, Box<dyn std::error::Error + Send>>(())
        };
        
        // 设置超时
        match timeout(timeout_duration, program_task).await {
            Ok(task_result) => {
                if let Err(e) = task_result {
                    println!("程序执行出错: {}", e);
                }
            }
            Err(_) => {
                // 程序超时
                println!("程序执行超时，强制退出");
                std::process::exit(1);
            }
        }
    } else {
        run_main_program(args).await;
    }
    println!("程序执行完成");
    
    Ok(())
}

async fn run_main_program(args: Args) {

    // 显示帮助信息
    if args.help {
        print_help();
        return;
    }

    // 验证参数
    if let Err(err) = args.validate() {
        println!("{}", err);
        if args.url.is_empty() && args.file.is_empty() && args.cidr.is_empty() {
            print_help();
        }
        return;
    }

    // 获取CIDR列表
    let mut cidr_list = Vec::new();
    
    // 从URL获取CIDR
    if !args.url.is_empty() {
        println!("从URL获取CIDR列表: {}", args.url);
        match get_cidr_from_url(&args.url).await {
            Ok(list) => cidr_list.extend(list),
            Err(e) => {
                println!("从URL获取CIDR列表失败: {}", e);
                // 不立即返回，继续尝试其他来源
            }
        }
    }
    
    // 从文件获取CIDR
    if !args.file.is_empty() {
        println!("从文件获取CIDR列表: {}", args.file);
        match get_cidr_from_file(&args.file) {
            Ok(list) => cidr_list.extend(list),
            Err(e) => {
                println!("从文件获取CIDR列表失败: {}", e);
                // 不立即返回，继续尝试其他来源
            }
        }
    }
    
    // 从命令行参数获取CIDR
    if !args.cidr.is_empty() {
        println!("从命令行参数获取CIDR列表");
        match parse_command_line_cidrs(&args.cidr) {
            Ok(list) => cidr_list.extend(list),
            Err(e) => {
                println!("解析命令行CIDR列表失败: {}", e);
                // 不立即返回，继续尝试其他来源
            }
        }
    }
    
    // 检查是否成功获取到CIDR
    if cidr_list.is_empty() {
        println!("错误: 未能从任何来源获取到有效的CIDR列表");
        return;
    }

    println!("共获取到 {} 个CIDR", cidr_list.len());

    // 处理CIDR列表，将大于/24的IPv4 CIDR拆分为多个/24，将大于/48的IPv6 CIDR拆分为多个/48
    let expanded_cidrs = expand_cidrs(&cidr_list);
    println!("处理后共有 {} 个CIDR", expanded_cidrs.len());

    // 如果指定了 -notest 参数，直接生成IP文件并退出
    if args.no_test {
        let mut results = Vec::new();
        for cidr in &expanded_cidrs {
            if ipnet::IpNet::from_str(cidr).is_ok() {
                results.push(TestResult {
                    ip: String::new(),
                    cidr: cidr.clone(),
                    data_center: String::new(),
                    region: String::new(),
                    city: String::new(),
                    avg_latency: 0,
                    loss_rate: 0.0,
                });
            }
        }

        println!("跳过测速，直接生成IP列表");
        match generate_ip_file(&results, &args.use_ipv4, &args.use_ipv6, &args.ip_txt_file) {
            Ok(_) => println!("IP列表已写入: {}", args.ip_txt_file),
            Err(e) => println!("生成IP文件失败: {}", e),
        }
        return;
    }

    // 获取Cloudflare数据中心位置信息
    let getcolo_location_map = match get_location_map().await {
        Ok(map) => map,
        Err(e) => {
            println!("获取数据中心位置信息失败: {}", e);
            return;
        }
    };
    
    // 转换为 types::Location
    let location_map: HashMap<String, types::Location> = getcolo_location_map
        .iter()
        .map(|(key, value)| {
            (key.clone(), types::Location {
                iata: value.iata.clone(),
                region: value.region.clone(),
                city: value.city.clone(),
            })
        })
        .collect();
    
    // 从每个CIDR中随机选择IP进行测试
    let mut cidr_groups = Vec::with_capacity(expanded_cidrs.len());
    for cidr in &expanded_cidrs {
        cidr_groups.push(CIDRGroup {
            cidr: cidr.clone(),
            data: None,
            result: None,
        });
    }

    // 创建共享状态
    let shared_state = Arc::new(SharedState::new());

    // 转换测试次数
    let test_count = args.test_count.try_into().unwrap_or(4);

    // 添加超时提示信息
    if args.timeout_duration.is_none() {
        println!("程序将不会超时退出");
    }

    // 调用 test_ips 函数并获取处理后的 CIDR 组
    cidr_groups = test_ips(
        cidr_groups,
        args.port,
        test_count,
        args.ip_per_cidr,
        &location_map,
        &args.colo,           // 使用 &str
        args.min_latency,     // 直接传值
        args.max_latency,     // 直接传值
        args.max_loss_rate,   // 直接传值
        args.show_all,        // 直接传值
        shared_state
    ).await;
    
    // 收集已合并的结果
    let mut filtered_results = Vec::new();
    for group in &cidr_groups {
        if let Some(result) = &group.result {
            filtered_results.push(result.clone());
        }
    }

    // 过滤结果
    println!("符合条件的结果: {} 个", filtered_results.len());

    // 排序结果
    filtered_results.sort_by(|a, b| {
        if (a.loss_rate - b.loss_rate).abs() < f64::EPSILON {
            a.avg_latency.cmp(&b.avg_latency)
        } else {
            a.loss_rate.partial_cmp(&b.loss_rate).unwrap()
        }
    });

    // 限制输出数量
    if args.print_count != "all" {
        if let Ok(count) = args.print_count.parse::<usize>() {
            if count > 0 && count < filtered_results.len() {
                filtered_results.truncate(count);
            }
            // 否则保持原有结果不变
        }
    }

    // 输出结果
    if !args.no_csv {
        match write_results_to_csv(&filtered_results, &args.out_file) {
            Ok(_) => println!("结果已写入: {}", args.out_file),
            Err(e) => println!("写入CSV文件失败: {}", e),
        }
    }

    // 输出IP列表
    if !args.use_ipv4.is_empty() || !args.use_ipv6.is_empty() {
        match generate_ip_file(&filtered_results, &args.use_ipv4, &args.use_ipv6, &args.ip_txt_file) {
            Ok(_) => println!("IP列表已写入: {}", args.ip_txt_file),
            Err(e) => println!("生成IP文件失败: {}", e),
        }
    }

    // 打印结果摘要
    print_results_summary(&filtered_results);
}