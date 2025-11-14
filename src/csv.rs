use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufWriter, Write};
use std::fs::File;
use ipnet::{Ipv4Net, Ipv6Net};

type CidrData = HashMap<String, (Vec<f64>, Vec<f64>, HashSet<String>)>;

/// 根据 IP 自动归类为自定义 CIDR（默认 IPv4→/24，IPv6→/48）
pub fn normalize_ip_to_bucket(ip_str: &str, ipv4_prefix: Option<u8>, ipv6_prefix: Option<u8>) -> Option<String> {
    let ipv4_prefix = ipv4_prefix?;
    let ipv6_prefix = ipv6_prefix?;
    
    // IP 地址归类到 CIDR 桶
    if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                // 使用 ipnet 库创建 IPv4 网络
                let network = Ipv4Net::new(ipv4, ipv4_prefix).ok()?;
                return Some(network.to_string());
            }
            std::net::IpAddr::V6(ipv6) => {
                // 使用 ipnet 库创建 IPv6 网络
                let network = Ipv6Net::new(ipv6, ipv6_prefix).ok()?;
                return Some(network.to_string());
            }
        }
    }
    None
}

/// 将 HashSet<String> 转换为管道分隔字符串
fn datacenters_to_string(datacenters: &HashSet<String>) -> String {
    let mut centers: Vec<&str> = datacenters.iter().map(String::as_str).collect();
    centers.sort_unstable(); 
    centers.join("|")
}

/// 打印数据中心统计表
pub fn print_datacenter_stats_table(stats: &HashMap<String, (usize, Vec<f64>, Vec<f64>)>) {
    const COLUMN_PADDING: usize = 3; // 每列额外间距
    const LEADING_SPACES: usize = 1; // 前导空格数量
    const TABLE_HEADERS: [&str; 6] = ["数据中心", "CIDR 数量", "平均延迟", "最小延迟", "最大延迟", "平均丢包"];

    // 初始列宽来自表头
    let header_display_widths = [8, 9, 8, 8, 8, 8];
    let mut column_widths = header_display_widths.to_vec();

    // 预计算每行数据并动态更新列宽
    let rows: Vec<Vec<String>> = stats
        .iter()
        .filter(|(_, (_, lat, _))| !lat.is_empty())
        .map(|(dc, (count, lat, loss))| {
            let lat_len = lat.len() as f64;
            let row = vec![
                dc.clone(),
                count.to_string(),
                format!("{:.2}", lat.iter().sum::<f64>() / lat_len),
                format!("{:.2}", lat.iter().fold(f64::INFINITY, |a, &b| a.min(b))),
                format!("{:.2}", lat.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b))),
                format!("{:.2}", loss.iter().sum::<f64>() / lat_len / 100.0),
            ];

            for (i, field) in row.iter().enumerate() {
                column_widths[i] = column_widths[i].max(field.chars().count());
            }

            row
        })
        .collect();

    // 分割线宽度
    let base_width: usize = {
        let sum_content_widths: usize = column_widths.iter().sum();
        let sum_padding: usize = COLUMN_PADDING * (column_widths.len().saturating_sub(1));
        sum_content_widths + sum_padding + LEADING_SPACES
    };

    let leading = " ".to_string();
    let line = "─".repeat(base_width.saturating_sub(LEADING_SPACES));

    // 输出分割线
    println!("{leading}{line}");

    // 输出表头
    print!("{leading}");
    for (i, header) in TABLE_HEADERS.iter().enumerate() {
        let pad =
            column_widths[i].saturating_sub(header_display_widths[i]) + COLUMN_PADDING;
        print!("\x1b[1;97;100m{}\x1b[0m{}", header, " ".repeat(pad));
    }
    println!();

    // 输出数据行
    for row in &rows {
        print!("{leading}");
        for (i, field) in row.iter().enumerate() {
            let pad =
                column_widths[i].saturating_sub(field.chars().count()) + COLUMN_PADDING;
            print!("{}{}", field, " ".repeat(pad));
        }
        println!();
    }

    // 尾部分割线
    println!("{leading}{line}");
}

/// 根据延迟和丢包计算 CIDR 得分并排序
pub fn process_cidr_data(
    cidr_data: &CidrData,
    limit: Option<usize>,
) -> Vec<String> {
    let mut stats: Vec<(&String, f64, f64, &HashSet<String>)> = Vec::with_capacity(cidr_data.len());
    let mut sum_lat = 0.0;
    let mut sum_loss = 0.0;

    for (cidr, (lat, loss, dc)) in cidr_data {
        let len = lat.len() as f64;
        let avg_lat = lat.iter().sum::<f64>() / len;
        let avg_loss = loss.iter().sum::<f64>() / len;

        sum_lat += avg_lat;
        sum_loss += avg_loss;
        stats.push((cidr, avg_lat, avg_loss, dc));
    }

    let total = stats.len() as f64;
    let avg_lat = sum_lat / total;
    let avg_loss = sum_loss / total;

    let mut scored: Vec<(&String, f64)> = stats
        .iter()
        .map(|(cidr, lat, loss, _)| {
            let s = (avg_lat - *lat) * 0.4 + (avg_loss - *loss) * 0.6;
            (*cidr, s)
        })
        .collect();

    scored.sort_unstable_by(|a, b| b.1.total_cmp(&a.1));

    if let Some(l) = limit {
        scored.truncate(l);
    }

    scored.into_iter().map(|(cidr, _)| cidr.clone()).collect()
}

/// 生成统计结果 CSV 文件
pub fn generate_summary_csv(
    cidr_data: &CidrData,
    output_file: &str,
    limit: Option<usize>,
) -> Result<Vec<String>, std::io::Error> {
    let sorted = process_cidr_data(cidr_data, limit);

    let file = File::create(output_file)?;
    let mut writer = BufWriter::new(file);

    writeln!(writer, "CIDR,数据中心,平均延迟,最小延迟,最大延迟,平均丢包")?;

    for cidr in &sorted {
        if let Some((lat, loss, dc)) = cidr_data.get(cidr) {
            let len = lat.len() as f64;
            let avg_lat = lat.iter().sum::<f64>() / len;
            let min_lat = lat.iter().fold(f64::INFINITY, |a, &b| a.min(b));
            let max_lat = lat.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
            let avg_loss = loss.iter().sum::<f64>() / len;

            writeln!(
                writer, "{},{},{:.2},{:.2},{:.2},{:.2}", 
                cidr, 
                datacenters_to_string(dc), 
                avg_lat,
                min_lat,
                max_lat,
                avg_loss
            )?;
        }
    }

    writer.flush()?;
    Ok(sorted)
}

/// 按 CIDR 分配 IP 数量（自动处理容量限制）
fn distribute_ips(cidrs: &[String], total: u128) -> Vec<(String, u128)> {
    if cidrs.is_empty() || total == 0 {
        return vec![];
    }

    let n = cidrs.len();
    let capacities: Vec<u128> = cidrs.iter().map(|c| {
        // 解析CIDR并计算容量
        parse_cidr_prefix(c)
            .map(|(p, ipv6)| {
                let bits: u32 = if ipv6 { 128 } else { 32 };
                let shift = bits.saturating_sub(p as u32);
                1u128.checked_shl(shift).unwrap_or(u128::MAX)
            })
            .unwrap_or_default()
    }).collect();
    
    let total_capacity: u128 = capacities.iter().sum();
    let total = total.min(total_capacity);

    let base = total / n as u128;
    let extra = total % n as u128;

    cidrs.iter().enumerate().map(|(i, c)| {
        let assigned = base + (i < extra as usize) as u128;
        (c.clone(), assigned.min(capacities[i]))
    }).collect()
}

/// 解析CIDR字符串，返回前缀长度和是否为IPv6
fn parse_cidr_prefix(cidr: &str) -> Option<(u8, bool)> {
    let (ip, prefix) = cidr.split_once('/')?;
    let p = prefix.parse::<u8>().ok()?;
    Some((p, ip.contains(':')))
}

/// 生成 TXT 文件
pub fn generate_txt_file(
    cidr_data: Option<&CidrData>,
    sorted_cidrs: Option<&[String]>,
    output: &str,
    limit: Option<usize>,
    ipv4_total: Option<u128>,
    ipv6_total: Option<u128>,
) -> Result<(), std::io::Error> {
    let sorted = match (cidr_data, sorted_cidrs) {
        (Some(data), None) => process_cidr_data(data, limit),
        (None, Some(list)) => list.to_vec(),
        _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "必须提供CIDR数据")),
    };

    let (ipv4, ipv6): (Vec<_>, Vec<_>) = sorted.into_iter().partition(|c| !c.contains(':'));
    let mut out = String::new();

    let mut append_alloc = |cidrs: &[String], total: Option<u128>| {
        if let Some(t) = total {
            for (cidr, n) in distribute_ips(cidrs, t) {
                if n > 0 {
                    out.push_str(&format!("{}={}\n", cidr, n));
                }
            }
        }
    };

    append_alloc(&ipv4, ipv4_total);
    append_alloc(&ipv6, ipv6_total);

    if ipv4_total.is_none() && ipv6_total.is_none() {
        for c in ipv4.iter().chain(ipv6.iter()) {
            out.push_str(c);
            out.push('\n');
        }
    }

    fs::write(output, out)?;
    Ok(())
}

/// 在数据收集阶段调用此函数，将每个 IP 动态归类为自定义 CIDR
pub fn insert_measurement(
    cidr_data: &mut CidrData,
    ip: &str,
    latency: f64,
    loss: f64,
    datacenter: &str,
    ipv4_prefix: Option<u8>,
    ipv6_prefix: Option<u8>,
) {
    if let Some(bucket) = normalize_ip_to_bucket(ip, ipv4_prefix, ipv6_prefix) {
        let entry = cidr_data.entry(bucket).or_insert((Vec::new(), Vec::new(), HashSet::new()));
        entry.0.push(latency);
        entry.1.push(loss);
        entry.2.insert(datacenter.to_string());
    }
}