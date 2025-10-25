use colored::*;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader, BufWriter, Write},
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
    process::Command,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// 解析CIDR并计算IP数量（自动规范化为标准CIDR格式）
pub fn parse_and_split_cidr(cidr_str: &str, ip_count: u32) -> Vec<String> {
    match normalize_to_cidr(cidr_str) {
        Some(IpNet::V4(v4)) => split_ipv4_cidr(&v4, ip_count),
        Some(IpNet::V6(v6)) => split_ipv6_cidr(&v6, ip_count),
        _ => Vec::new(),
    }
}

/// 自动规范化输入为 CIDR 格式
fn normalize_to_cidr(input: &str) -> Option<IpNet> {
    // IPv4 单 IP
    if let Ok(ipv4) = input.parse::<Ipv4Addr>() {
        let base = Ipv4Addr::from(u32::from(ipv4) & 0xFFFFFF00);
        return Ipv4Net::new(base, 24).ok().map(IpNet::V4);
    }

    // IPv6 单 IP
    if let Ok(ipv6) = input.parse::<Ipv6Addr>() {
        let base = Ipv6Addr::from(u128::from(ipv6) & (!0u128 << (128 - 48)));
        return Ipv6Net::new(base, 48).ok().map(IpNet::V6);
    }

    // IPv4 CIDR
    if let Ok(IpNet::V4(net)) = input.parse::<IpNet>() {
        if net.prefix_len() >= 24 {
            let base = Ipv4Addr::from(u32::from(net.network()) & 0xFFFFFF00);
            return Ipv4Net::new(base, 24).ok().map(IpNet::V4);
        } else {
            return Some(IpNet::V4(net));
        }
    }

    // IPv6 CIDR
    if let Ok(IpNet::V6(net)) = input.parse::<IpNet>() {
        if net.prefix_len() >= 48 {
            let base = Ipv6Addr::from(u128::from(net.network()) & (!0u128 << (128 - 48)));
            return Ipv6Net::new(base, 48).ok().map(IpNet::V6);
        } else {
            return Some(IpNet::V6(net));
        }
    }

    None
}

fn split_ipv4_cidr(network: &Ipv4Net, ip_count: u32) -> Vec<String> {
    let src_prefix = network.prefix_len().max(13);
    if src_prefix >= 24 {
        let base = Ipv4Addr::from(u32::from(network.network()) & 0xFFFFFF00);
        return vec![format!("{}/24={}", base, ip_count)];
    }

    // 不拆分，只计算总量
    let block_count = 1u32 << (24 - src_prefix);
    let total = ip_count * block_count;
    vec![format!("{}/{}={}", network.network(), src_prefix, total)]
}

fn split_ipv6_cidr(network: &Ipv6Net, ip_count: u32) -> Vec<String> {
    let src_prefix = network.prefix_len().max(32);
    if src_prefix >= 48 {
        let base = Ipv6Addr::from(u128::from(network.network()) & (!0u128 << (128 - 48)));
        return vec![format!("{}/48={}", base, ip_count)];
    }

    // 不拆分，只计算总量
    let block_count = 1u128 << (48 - src_prefix as u128);
    let total = ip_count as u128 * block_count;
    vec![format!("{}/{}={}", network.network(), src_prefix, total)]
}

/// 删除旧文件
fn cleanup_old_cidr_files() {
    for entry in fs::read_dir(".").into_iter().flatten().flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if name.starts_with("cidr_split_") && name.ends_with(".txt") {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

/// 写入结果文件
pub fn write_to_temp_file(subnets: &[String]) -> io::Result<String> {
    cleanup_old_cidr_files();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let path = format!("cidr_split_{}.txt", timestamp);
    let mut writer = BufWriter::new(File::create(&path)?);

    for s in subnets {
        writeln!(writer, "{}", s)?;
    }
    writer.flush()?;
    Ok(path)
}

/// 收集多来源 CIDR
pub fn collect_cidr_sources(cidr_text: &str, cidr_url: &str, cidr_file: &str, ip_count: u32) -> Option<String> {
    let mut sources = Vec::new();

    // 文本输入
    sources.extend(cidr_text.split(',').map(str::trim).filter(|s| !s.is_empty()).map(ToString::to_string));

    // URL 来源
    if !cidr_url.is_empty() {
        if let Ok(url_list) = get_cidr_from_url(cidr_url) {
            sources.extend(url_list);
        }
    }

    // 文件来源
    if !cidr_file.is_empty() && Path::new(cidr_file).exists() {
        if let Ok(file_list) = get_cidr_from_file(cidr_file) {
            sources.extend(file_list);
        }
    }

    let mut merged: Vec<String> = merge_cidr_list(&sources);
    merged.sort();

    let subnets: Vec<String> = merged.into_iter().flat_map(|cidr| parse_and_split_cidr(&cidr, ip_count)).collect();

    if subnets.is_empty() {
        eprintln!("\n{} 未找到有效CIDR", "[错误]".red().bold());
        return None;
    }

    match write_to_temp_file(&subnets) {
        Ok(path) => Some(path),
        Err(e) => {
            eprintln!("{} 写入结果失败: {}", "[错误]".red().bold(), e);
            None
        }
    }
}

/// 合并 CIDR
fn merge_cidr_list(cidr_list: &[String]) -> Vec<String> {
    let mut ipv4_networks = Vec::new();
    let mut ipv6_networks = Vec::new();

    for s in cidr_list {
        if let Ok(net) = s.parse::<IpNet>() {
            match net {
                IpNet::V4(v4) => ipv4_networks.push(v4),
                IpNet::V6(v6) => ipv6_networks.push(v6),
            }
        }
    }

    let mut result = Vec::new();

    if !ipv4_networks.is_empty() {
        ipv4_networks.sort();
        for n in Ipv4Net::aggregate(&ipv4_networks) {
            result.push(n.to_string());
        }
    }

    if !ipv6_networks.is_empty() {
        ipv6_networks.sort();
        for n in Ipv6Net::aggregate(&ipv6_networks) {
            result.push(n.to_string());
        }
    }

    result
}

/// 从 URL 获取 CIDR（重试3次）
fn get_cidr_from_url(url: &str) -> io::Result<Vec<String>> {
    for attempt in 1..=3 {
        match Command::new("curl").arg("-s").arg(url).output() {
            Ok(output) if output.status.success() => {
                return Ok(String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .map(str::trim)
                    .filter(|s| !s.is_empty() && !s.starts_with('#') && !s.starts_with("//"))
                    .map(ToString::to_string)
                    .collect());
            }
            Ok(_) | Err(_) if attempt < 3 => {
                eprintln!(
                    "{} curl失败，{}秒后重试 ({}/3)",
                    "[警告]".yellow().bold(),
                    3,
                    attempt
                );
                thread::sleep(Duration::from_secs(3));
            }
            _ => break,
        }
    }
    Ok(Vec::new())
}

/// 从文件读取 CIDR
fn get_cidr_from_file(file_path: &str) -> io::Result<Vec<String>> {
    let reader = BufReader::new(File::open(file_path)?);
    Ok(reader
        .lines()
        .filter_map(Result::ok)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.starts_with('#') && !s.starts_with("//"))
        .collect())
}
