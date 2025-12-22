use std::{
    fs::{self, File},
    io::{self, BufWriter, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    process::Command,
    str::FromStr,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{error_println, warning_println};

fn get_v4_net_addr(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    if prefix >= 32 { return ip; }
    if prefix == 0 { return Ipv4Addr::new(0, 0, 0, 0); }
    let mask = u32::MAX << (32 - prefix);
    Ipv4Addr::from(u32::from(ip) & mask)
}

fn get_v6_net_addr(ip: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    if prefix >= 128 { return ip; }
    if prefix == 0 { return Ipv6Addr::from(0u128); }
    let mask = u128::MAX << (128 - prefix);
    Ipv6Addr::from(u128::from(ip) & mask)
}

/// 手动解析 CIDR 字符串并获取网络地址和前缀长度
fn parse_cidr_manual(cidr_str: &str) -> Option<(String, u8)> {
    let parts: Vec<&str> = cidr_str.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let ip = IpAddr::from_str(parts[0]).ok()?;
    let prefix = parts[1].parse::<u8>().ok()?;

    match ip {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                return None;
            }
            let network_ip = get_v4_net_addr(v4, prefix);
            Some((network_ip.to_string(), prefix))
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return None;
            }
            let network_ip = get_v6_net_addr(v6, prefix);
            Some((network_ip.to_string(), prefix))
        }
    }
}

/// 拆分子网或计算总量
pub fn parse_and_split_cidr(cidr_str: &str, ip_count: u32, v4_p: u8, v6_p: u8) -> Vec<String> { 
    if let Some((addr_str, current_p)) = parse_cidr_manual(cidr_str) {
        if addr_str.contains(':') {
            // IPv6处理
            let target_p = v6_p;
            let min_p = 32;
            let src_prefix = current_p.max(min_p);
            
            if src_prefix >= target_p {
                vec![format!("{}/{}={}", addr_str, target_p, ip_count)]
            } else {
                let block_count = 1u128 << ((target_p as u128) - (src_prefix as u128));
                let total = ip_count as u128 * block_count;
                vec![format!("{}/{}={}", addr_str, src_prefix, total)]
            }
        } else {
            // IPv4处理 - 当需要拆分时，生成多个子网
            let target_p = v4_p;
            let min_p = 13;
            let src_prefix = current_p.max(min_p);
            
            if src_prefix >= target_p {
                vec![format!("{}/{}={}", addr_str, target_p, ip_count)]
            } else {
                // 需要拆分成多个子网
                let mut result = Vec::new();
                let block_count = 1u32 << (target_p - src_prefix);

                // 解析网络地址
                if let Ok(ip) = addr_str.parse::<Ipv4Addr>() {
                    let network_addr = u32::from(get_v4_net_addr(ip, src_prefix));
                    
                    // 生成所有子网
                    for i in 0..block_count {
                        let subnet_addr = network_addr + (i << (32 - target_p));
                        let subnet_ip = Ipv4Addr::from(subnet_addr);
                        result.push(format!("{}/{}={}", subnet_ip, target_p, ip_count));
                    }
                }
                
                result
            }
        }
    } else {
        Vec::new()
    }
}

/// 通用的行处理逻辑：去空格、去空行、去注释
fn clean_lines(content: &str) -> Vec<String> {
    content.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        .map(String::from)
        .collect()
}

/// 规范化输入：支持单IP、CIDR，并自动应用默认前缀
fn normalize_to_cidr(input: &str, v4_p: u8, v6_p: u8) -> Option<String> {
    let input = input.trim();
    if input.is_empty() { return None; }

    // 尝试解析为 CIDR 或 单 IP
    if let Some((addr_str, current_p)) = parse_cidr_manual(input) {
        // 对于已经是CIDR格式的输入，保持原始前缀长度
        Some(format!("{}/{}", addr_str, current_p))
    } else if let Ok(ip) = input.parse::<IpAddr>() {
        // 对于单IP，应用默认前缀长度
        let target_p = match ip {
            IpAddr::V4(_) => v4_p,
            IpAddr::V6(_) => v6_p,
        };
        Some(format!("{}/{}", ip, target_p))
    } else {
        None
    }
}

/// 收集多来源并自动合并重复项
pub fn collect_cidr_sources(
    cidr_text: &str,
    cidr_url: &str,
    cidr_file: &str,
    ip_count: u32,
    ipv4_prefix: Option<u8>,
    ipv6_prefix: Option<u8>,
) -> Option<String> {
    let v4_p = ipv4_prefix?;
    let v6_p = ipv6_prefix?;

    // 1. 汇总所有来源
    let mut raw_sources = Vec::new();
    if !cidr_text.is_empty() {
        raw_sources.extend(cidr_text.split(',').map(|s| s.to_string()));
    }
    if !cidr_url.is_empty() && let Ok(list) = get_cidr_from_url(cidr_url) {
        raw_sources.extend(list);
    }
    if !cidr_file.is_empty() && Path::new(cidr_file).exists() && let Ok(list) = get_cidr_from_file(cidr_file) {
        raw_sources.extend(list);
    }

    // 2. 规范化并去重合并
    let normalized: Vec<String> = raw_sources.into_iter()
        .filter_map(|s| normalize_to_cidr(&s, v4_p, v6_p))
        .map(|n| n.to_string())
        .collect();

    if normalized.is_empty() {
        error_println(format_args!("未找到有效CIDR"));
        return None;
    }

    let mut merged = merge_cidr_list(&normalized);
    merged.sort_unstable();

    // 3. 拆分并生成结果
    let subnets: Vec<String> = merged.into_iter()
        .flat_map(|cidr| parse_and_split_cidr(&cidr, ip_count, v4_p, v6_p))
        .collect();

    if subnets.is_empty() {
        error_println(format_args!("未生成子网"));
        return None;
    }

    write_to_temp_file(&subnets).map(Some).unwrap_or_else(|e| {
        error_println(format_args!("写入结果失败: {}", e));
        None
    })
}

fn merge_cidr_list(cidr_list: &[String]) -> Vec<String> {
    let mut unique_cidrs: Vec<String> = cidr_list.to_vec();
    unique_cidrs.sort_unstable();
    unique_cidrs.dedup();
    unique_cidrs
}

fn get_cidr_from_url(url: &str) -> io::Result<Vec<String>> {
    for attempt in 1..=3 {
        match Command::new("curl").args(["-s", url]).output() {
            Ok(output) if output.status.success() => {
                return Ok(clean_lines(&String::from_utf8_lossy(&output.stdout)));
            }
            Ok(_) | Err(_) if attempt < 3 => {
                warning_println(format_args!("curl失败，3秒后重试 ({}/3)", attempt));
                thread::sleep(Duration::from_secs(3));
            }
            _ => break,
        }
    }
    Ok(Vec::new())
}

fn get_cidr_from_file(file_path: &str) -> io::Result<Vec<String>> {
    let content = std::fs::read_to_string(file_path)?;
    Ok(clean_lines(&content))
}

pub fn write_to_temp_file(subnets: &[String]) -> io::Result<String> {
    cleanup_old_cidr_files();
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let path = format!("cidr_split_{}.txt", ts);
    let mut writer = BufWriter::new(File::create(&path)?);
    for s in subnets { writeln!(writer, "{}", s)?; }
    writer.flush()?;
    Ok(path)
}

fn cleanup_old_cidr_files() {
    if let Ok(entries) = fs::read_dir(".") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str()
                && name.starts_with("cidr_split_") && name.ends_with(".txt") {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}