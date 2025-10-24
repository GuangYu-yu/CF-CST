use std::fs;
use std::fs::File;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader};
use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use std::net::IpAddr;
use colored::Colorize;
use shell_words;

use crate::csv;

/// 将 IpAddr 转换为 IpNet，IPv4 转换为 /32，IPv6 转换为 /128
fn ip_to_ipnet(ip: IpAddr) -> IpNet {
    match ip {
        IpAddr::V4(addr) => IpNet::new(IpAddr::V4(addr), 32).unwrap(),
        IpAddr::V6(addr) => IpNet::new(IpAddr::V6(addr), 128).unwrap(),
    }
}
/// 流式处理 CloudflareST 测速结果文件
pub fn process_cloudflare_results(
    temp_result_file: &str,
    cidr_file: &str,
    output_file: Option<&str>,
    output_txt: Option<&str>,
    limit_count: Option<usize>,
    select_ipv4: Option<u128>,
    select_ipv6: Option<u128>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 读取 CIDR 文件
    let cidr_entries: Vec<(IpNet, String)> = BufReader::new(File::open(cidr_file)?)
        .lines()
        .filter_map(Result::ok)
        .filter_map(|line| {
            line.split_once('=')
                .and_then(|(cidr, dc)| cidr.trim().parse::<IpNet>().ok().map(|net| (net, dc.trim().to_string())))
        })
        .collect();

    // 构建前缀树
    let mut trie: IpnetTrie<String> = IpnetTrie::new();
    for (net, _) in &cidr_entries {
        trie.insert(*net, net.to_string());
    }

    // 初始化数据结构
    let mut cidr_data: HashMap<String, (Vec<f64>, Vec<f64>, HashSet<String>)> = HashMap::new();
    let mut datacenter_stats: HashMap<String, (usize, Vec<f64>, Vec<f64>)> = HashMap::new();
    let mut datacenter_cidrs: HashMap<String, HashSet<String>> = HashMap::new();

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
        let datacenter = parts[6].trim().to_string();

        // 更新数据中心统计
        let entry = datacenter_stats.entry(datacenter.clone())
            .or_insert((0, Vec::with_capacity(10), Vec::with_capacity(10)));
        entry.1.push(latency);
        entry.2.push(loss_rate);

        // 前缀树匹配 CIDR
        let ip_net = ip_to_ipnet(ip);
        if let Some((_net, cidr_str)) = trie.longest_match(&ip_net) {
            let entry = cidr_data.entry(cidr_str.clone())
                .or_insert((Vec::with_capacity(10), Vec::with_capacity(10), HashSet::new()));
            entry.0.push(latency);
            entry.1.push(loss_rate);
            entry.2.insert(datacenter.clone());

            // 更新数据中心 CIDR 集合
            datacenter_cidrs.entry(datacenter.clone())
                .or_insert_with(HashSet::new)
                .insert(cidr_str.clone());
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
        output_file,
        output_txt,
        limit_count,
        select_ipv4,
        select_ipv6,
    )?;

    // 打印数据中心统计表
    csv::print_datacenter_stats_table(&datacenter_stats);

    Ok(())
}

/// 使用前缀树和统一输出逻辑生成 CSV/TXT 文件
fn generate_outputs(
    cidr_data: &HashMap<String, (Vec<f64>, Vec<f64>, std::collections::HashSet<String>)>,
    output_file: Option<&str>,
    output_txt: Option<&str>,
    limit_count: Option<usize>,
    select_ipv4: Option<u128>,
    select_ipv6: Option<u128>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // 先排序
    let sorted_cidrs = if output_file.is_some() || output_txt.is_some() {
        csv::process_cidr_data(cidr_data, limit_count)
    } else { Vec::new() };

    // 生成 CSV
    if let Some(csv_path) = output_file {
        csv::generate_summary_csv(cidr_data, csv_path, limit_count)?;
    }

    // 生成 TXT
    if let Some(txt_path) = output_txt {
        let (data_ref, sorted_ref) = if output_file.is_some() {
            (None, Some(&sorted_cidrs[..]))
        } else {
            (Some(cidr_data), None)
        };
        csv::generate_txt_file(
            data_ref,
            sorted_ref,
            txt_path,
            limit_count,
            select_ipv4,
            select_ipv6,
        )?;
    }

    // 输出合并的消息
    let files: Vec<&str> = [output_file, output_txt]
        .into_iter()
        .flatten()
        .collect();

    if !files.is_empty() {
        println!("{} 已生成结果文件: {}", "[信息]".cyan().bold(), files.join(" 和 "));
    }

    Ok(sorted_cidrs)
}

/// 执行 CloudflareST 并处理结果
pub fn execute_cloudflare_st(
    cloudflare_args: &str,
    file_name: &str,
    cidr_file: &str,
    output_file: Option<&str>,
    output_txt: Option<&str>,
    limit_count: Option<usize>,
    select_ipv4: Option<u128>,
    select_ipv6: Option<u128>,
) -> Result<String, Box<dyn std::error::Error>> {
    println!("{} 执行 CloudflareST-Rust", "[信息]".cyan().bold());

    #[cfg(target_os = "windows")] let exe_path = format!(".\\{}", file_name);
    #[cfg(any(target_os = "linux", target_os = "macos"))] let exe_path = format!("./{}", file_name);

    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let temp_result_file = format!("result_{}.csv", timestamp);

    // 删除旧的 result_*.csv 文件
    for entry in fs::read_dir(".")?.flatten() {
        let path = entry.path();
        if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
            if fname.starts_with("result_") && fname.ends_with(".csv") {
                let _ = fs::remove_file(path);
            }
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
                cidr_file,
                output_file,
                output_txt,
                limit_count,
                select_ipv4,
                select_ipv6,
            )?;
        },
        Ok(status) => eprintln!("{} CloudflareST执行失败，退出码: {:?}", "[错误]".red().bold(), status.code()),
        Err(e) => eprintln!("{} 执行CloudflareST时出错: {}", "[错误]".red().bold(), e),
    }

    Ok(temp_result_file)
}