use std::collections::{HashMap, HashSet};
use std::fs;
use prettytable::{Table, format, row};
use std::io::{BufWriter, Write};
use std::fs::File;
use std::net::{Ipv4Addr, Ipv6Addr};

/// 根据 IP 自动归类为标准 CIDR（IPv4→/24，IPv6→/48）
pub fn normalize_ip_to_bucket(ip_str: &str) -> Option<String> {
    if let Ok(ipv4) = ip_str.parse::<Ipv4Addr>() {
        let base = u32::from(ipv4) & 0xFFFFFF00;
        return Some(format!("{}/24", Ipv4Addr::from(base)));
    }
    if let Ok(ipv6) = ip_str.parse::<Ipv6Addr>() {
        let base = u128::from(ipv6) & (!0u128 << (128 - 48));
        return Some(format!("{}/48", Ipv6Addr::from(base)));
    }
    None
}

/// 将 HashSet<String> 转换为管道分隔字符串
fn datacenters_to_string(datacenters: &HashSet<String>) -> String {
    let mut centers: Vec<_> = datacenters.iter().cloned().collect();
    centers.sort();
    centers.join("|")
}

/// 打印数据中心统计表
pub fn print_datacenter_stats_table(stats: &HashMap<String, (usize, Vec<f64>, Vec<f64>)>) {
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_CLEAN);
    table.set_titles(row!["数据中心", "CIDR 数量", "平均延迟", "最小延迟", "最大延迟", "平均丢包"]);

    for (dc, (count, lat, loss)) in stats {
        if !lat.is_empty() {
            table.add_row(row![
                dc,
                count,
                format!("{:.2}", average(lat)),
                format!("{:.2}", min_value(lat)),
                format!("{:.2}", max_value(lat)),
                format!("{:.2}", average(loss) / 100.0)
            ]);
        }
    }
    table.printstd();
}

/// 计算平均值
pub fn average(data: &[f64]) -> f64 {
    data.iter().sum::<f64>() / data.len() as f64
}

/// 计算最小值
pub fn min_value(data: &[f64]) -> f64 {
    data.iter().fold(f64::INFINITY, |a, &b| a.min(b))
}

/// 计算最大值
pub fn max_value(data: &[f64]) -> f64 {
    data.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b))
}

/// 根据延迟和丢包计算 CIDR 得分并排序
pub fn process_cidr_data(
    cidr_data: &HashMap<String, (Vec<f64>, Vec<f64>, HashSet<String>)>,
    limit: Option<usize>,
) -> Vec<String> {
    let mut stats: Vec<(&String, f64, f64, &HashSet<String>)> = Vec::with_capacity(cidr_data.len());
    let mut sum_lat = 0.0;
    let mut sum_loss = 0.0;

    for (cidr, (lat, loss, dc)) in cidr_data {
        let avg_lat = average(lat);
        let avg_loss = average(loss);
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
    cidr_data: &HashMap<String, (Vec<f64>, Vec<f64>, HashSet<String>)>,
    output_file: &str,
    limit: Option<usize>,
) -> Result<Vec<String>, std::io::Error> {
    let sorted = process_cidr_data(cidr_data, limit);

    let file = File::create(output_file)?;
    let mut writer = BufWriter::new(file);

    writeln!(writer, "CIDR,数据中心,平均延迟,最小延迟,最大延迟,平均丢包")?;

    for cidr in &sorted {
        if let Some((lat, loss, dc)) = cidr_data.get(cidr) {
            writeln!(
                writer, "{},{},{:.2},{:.2},{:.2},{:.2}", 
                cidr, 
                datacenters_to_string(dc), 
                average(lat),
                min_value(lat),
                max_value(lat),
                average(loss)
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
        if !c.contains('.') { u128::from(u32::MAX) } else { 256 }
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

/// 生成 TXT 文件
pub fn generate_txt_file(
    cidr_data: Option<&HashMap<String, (Vec<f64>, Vec<f64>, HashSet<String>)>>,
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

/// 在数据收集阶段调用此函数，将每个 IP 动态归类为 /24 或 /48 的 CIDR
pub fn insert_measurement(
    cidr_data: &mut HashMap<String, (Vec<f64>, Vec<f64>, HashSet<String>)>,
    ip: &str,
    latency: f64,
    loss: f64,
    datacenter: &str,
) {
    if let Some(bucket) = normalize_ip_to_bucket(ip) {
        let entry = cidr_data.entry(bucket).or_insert((Vec::new(), Vec::new(), HashSet::new()));
        entry.0.push(latency);
        entry.1.push(loss);
        entry.2.insert(datacenter.to_string());
    }
}