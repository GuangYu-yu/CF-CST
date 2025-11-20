use std::fs;
use std::fs::File;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::net::IpAddr;

use crate::csv;
use crate::CLOUDFLAREST_RUST;
use crate::{error_println, info_println};

type CidrData = HashMap<String, (Vec<f64>, Vec<f64>, HashSet<String>)>;
type DatacenterStats = HashMap<String, (usize, Vec<f64>, Vec<f64>)>;
type DatacenterCidrs = HashMap<String, HashSet<String>>;

#[derive(Default)]
pub struct ProcessConfig {
    pub output_file: Option<String>,
    pub output_txt: Option<String>,
    pub limit_count: Option<usize>,
    pub select_ipv4: Option<u128>,
    pub select_ipv6: Option<u128>,
    pub ipv4_prefix: u8,
    pub ipv6_prefix: u8,
}

/// 流式处理 CloudflareST 测速结果文件
pub fn process_cloudflare_results(
    temp_result_file: &str,
    config: &ProcessConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    // 初始化数据结构
    let mut cidr_data: CidrData = HashMap::new();
    let mut datacenter_stats: DatacenterStats = HashMap::new();
    let mut datacenter_cidrs: DatacenterCidrs = HashMap::new();

    // 逐行读取结果 CSV
    let file = File::open(temp_result_file)?;
    let reader = BufReader::new(file);
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if i == 0 { continue; } // 跳过表头

        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() < 7 { continue; }

        let ip: IpAddr = match parts[0].trim().parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let loss_rate = parts[3].trim().parse::<f64>().unwrap_or(f64::NAN);
        let latency = parts[4].trim().parse::<f64>().unwrap_or(f64::NAN);
        let datacenter = parts[6].trim();

        // 更新数据中心统计
        let entry = datacenter_stats.entry(datacenter.to_string())
            .or_insert((0, Vec::with_capacity(10), Vec::with_capacity(10)));
        entry.1.push(latency);
        entry.2.push(loss_rate);

        // 使用动态归类逻辑，将IP归类到自定义CIDR
        csv::insert_measurement(
            &mut cidr_data,
            &ip.to_string(),
            latency,
            loss_rate,
            datacenter,
            Some(config.ipv4_prefix),
            Some(config.ipv6_prefix),
        );
        
        // 更新数据中心 CIDR 集合（使用动态归类的CIDR）
        if let Some(bucket) = csv::normalize_ip_to_bucket(&ip.to_string(), Some(config.ipv4_prefix), Some(config.ipv6_prefix)) {
            datacenter_cidrs.entry(datacenter.to_string())
                .or_default()
                .insert(bucket);
        }
    }

    // 更新数据中心 CIDR 数量
    for (dc, cidr_set) in &datacenter_cidrs {
        if let Some(entry) = datacenter_stats.get_mut(dc) {
            entry.0 = cidr_set.len();
        }
    }

    // 生成 CSV/TXT 输出
    generate_outputs(
        &cidr_data,
        config,
    )?;

    // 打印数据中心统计表
    csv::print_datacenter_stats_table(&datacenter_stats);

    Ok(())
}

/// 使用前缀树和统一输出逻辑生成 CSV/TXT 文件
fn generate_outputs(
    cidr_data: &CidrData,
    config: &ProcessConfig,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // 先排序
    let sorted_cidrs = if config.output_file.is_some() || config.output_txt.is_some() {
        csv::process_cidr_data(cidr_data, config.limit_count)
    } else { Vec::new() };

    // 生成 CSV
    if let Some(csv_path) = &config.output_file {
        csv::generate_summary_csv(cidr_data, csv_path, config.limit_count)?;
    }

    // 生成 TXT
    if let Some(txt_path) = &config.output_txt {
        csv::generate_txt_file(
            Some(cidr_data),
            None,
            txt_path,
            config.limit_count,
            config.select_ipv4,
            config.select_ipv6,
        )?;
    }

    // 输出合并的消息
    let files: Vec<&str> = [&config.output_file, &config.output_txt]
        .into_iter()
        .flatten()
        .map(|s| s.as_str())
        .collect();

    if !files.is_empty() {
        info_println(format_args!("已生成结果文件: {}", files.join(" 和 ")));
    }

    Ok(sorted_cidrs)
}

/// 执行 CloudflareST 并处理结果
pub fn execute_cloudflare_st(
    cloudflare_args: &str,
    cidr_file: &str,
    config: &ProcessConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    info_println(format_args!("执行 {}", CLOUDFLAREST_RUST));

    #[cfg(target_os = "windows")] let exe_path = format!(".\\{}", CLOUDFLAREST_RUST);
    #[cfg(any(target_os = "linux", target_os = "macos"))] let exe_path = format!("./{}", CLOUDFLAREST_RUST);

    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let temp_result_file = format!("result_{}.csv", timestamp);

    // 删除旧的 result_*.csv 文件
    for entry in fs::read_dir(".")?.flatten() {
        let path = entry.path();
        if let Some(fname) = path.file_name().and_then(|n| n.to_str())
            && fname.starts_with("result_") && fname.ends_with(".csv") {
            let _ = fs::remove_file(path);
        }
    }

    // 构建并执行命令
    let mut cmd = std::process::Command::new(exe_path);
    cmd.args(["-f", cidr_file, "-dd", "-httping", "-o", &temp_result_file]);
    cmd.args(shell_words::split(cloudflare_args)?);

    match cmd.spawn()?.wait() {
        Ok(status) if status.success() => {
            process_cloudflare_results(
                &temp_result_file,
                config,
            )?;
        },
        Ok(status) => error_println(format_args!("{}执行失败，退出码: {:?}", CLOUDFLAREST_RUST, status.code())),
        Err(e) => error_println(format_args!("执行{}时出错: {}", CLOUDFLAREST_RUST, e)),
    }

    Ok(temp_result_file)
}