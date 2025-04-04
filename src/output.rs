use std::io::{self, Write, BufWriter};
use std::fs::File;
use std::collections::HashMap;
use std::str::FromStr;
use ipnetwork::IpNetwork;
use rand::Rng;
use prettytable::{Table, Row, Cell, format};

use crate::types::TestResult;

/// 将测试结果写入 CSV 文件
pub fn write_results_to_csv(results: &[TestResult], filename: &str) -> io::Result<()> {
    let mut file = File::create(filename)?;
    
    // 写入标题行
    writeln!(file, "CIDR,数据中心,区域,城市,平均延迟,平均丢包")?;
    
    // 写入数据行
    for result in results {
        writeln!(
            file,
            "{},{},{},{},{},{}",
            result.cidr,
            result.data_center,
            result.region,
            result.city,
            result.avg_latency,
            format!("{:.1}", result.loss_rate * 100.0)
        )?;
    }
    
    Ok(())
}

/// 根据测试结果生成 IP 文件
pub fn generate_ip_file(results: &[TestResult], ipv4_mode: &str, ipv6_mode: &str, filename: &str) -> io::Result<()> {
    // 检查是否至少指定了一种IP类型
    if ipv4_mode.is_empty() && ipv6_mode.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "必须至少指定 -useip4 或 -useip6 参数"));
    }

    let mut ip_list = Vec::new();

    // 检查是否有IPv4和IPv6的CIDR
    let mut has_ipv4_cidr = false;
    let mut has_ipv6_cidr = false;

    // 根据需要检查的IP类型进行判断
    let need_check_ipv4 = !ipv4_mode.is_empty();
    let need_check_ipv6 = !ipv6_mode.is_empty();

    for result in results {
        if let Ok(ip_net) = IpNetwork::from_str(&result.cidr) {
            // 分别判断IPv4和IPv6
            if need_check_ipv4 && !has_ipv4_cidr && ip_net.is_ipv4() {
                has_ipv4_cidr = true;
            }

            if need_check_ipv6 && !has_ipv6_cidr && ip_net.is_ipv6() {
                has_ipv6_cidr = true;
            }

            // 如果需要检查的类型都已找到，就可以提前结束检查
            if (!need_check_ipv4 || has_ipv4_cidr) && (!need_check_ipv6 || has_ipv6_cidr) {
                break;
            }
        }
    }

    // 处理 IPv4
    if !ipv4_mode.is_empty() && has_ipv4_cidr {
        let mut ipv4_count = 0;
        let ipv4_limit = 1000000; // 设置IPv4上限为100万

        if ipv4_mode == "all" {
            // 遍历每个CIDR生成所有IP
            for result in results {
                if let Ok(ip_net) = IpNetwork::from_str(&result.cidr) {
                    if !ip_net.is_ipv4() {
                        continue; // 跳过非IPv4
                    }

                    // 获取掩码大小
                    let prefix = ip_net.prefix();
                    let random_bits = 32 - prefix;

                    // 计算该CIDR包含的IP数量
                    let total_ips = 1u32 << random_bits;

                    // 生成该CIDR下的所有IP
                    for i in 0..total_ips {
                        if ipv4_count >= ipv4_limit {
                            break;
                        }

                        // 修复：使用正确的方法获取IP字节
                        let ip_bytes = match ip_net.ip() {
                            std::net::IpAddr::V4(ip) => ip.octets(),
                            _ => continue, // 跳过非IPv4
                        };
                        
                        // 获取掩码字节
                        let mask_bytes = match ip_net.mask() {
                            std::net::IpAddr::V4(ip) => ip.octets(),
                            _ => continue,
                        };
                        
                        // 创建新IP
                        let mut new_ip = [0u8; 4];
                        
                        // 应用值到IP
                        for j in 0..4 {
                            let shift = 8 * (3 - j as u32);
                            if shift < random_bits as u32 {
                                let bit_value = ((i >> shift) & 0xFF) as u8;
                                let mask_byte = mask_bytes[j];
                                new_ip[j] = (ip_bytes[j] & mask_byte) | (bit_value & !mask_byte);
                            } else {
                                new_ip[j] = ip_bytes[j];
                            }
                        }

                        let ip_str = format!("{}.{}.{}.{}", new_ip[0], new_ip[1], new_ip[2], new_ip[3]);
                        ip_list.push(ip_str);
                        ipv4_count += 1;
                    }

                    // 检查是否达到上限
                    if ipv4_count >= ipv4_limit {
                        println!("已达到IPv4生成上限 {} 个", ipv4_limit);
                        break;
                    }
                }
            }
        } else if let Ok(count) = ipv4_mode.parse::<usize>() {
            if count > 0 {
                let mut target_count = count;
                if target_count > ipv4_limit {
                    target_count = ipv4_limit;
                    println!("IPv4生成数量已限制为 {} 个", ipv4_limit);
                }

                // 准备CIDR列表和计算总IP数量
                struct CidrInfo {
                    ip_net: IpNetwork,
                    ip_count: u32,
                }

                let mut cidr_list = Vec::new();
                let mut total_available_ips = 0;

                // 初始化CIDR信息并计算总IP数量
                for result in results {
                    if let Ok(ip_net) = IpNetwork::from_str(&result.cidr) {
                        if !ip_net.is_ipv4() {
                            continue; // 跳过非IPv4
                        }

                        let prefix = ip_net.prefix();
                        let ip_count = 1u32 << (32 - prefix);

                        cidr_list.push(CidrInfo {
                            ip_net,
                            ip_count,
                        });

                        total_available_ips += ip_count;

                        // 一旦总IP数量足够，就可以开始生成随机IP
                        if total_available_ips >= target_count as u32 {
                            break;
                        }
                    }
                }

                // 如果总IP数量不足，则使用所有可用的IP
                if total_available_ips < target_count as u32 {
                    println!("警告: 可用IPv4地址总数({})小于请求数量({})", total_available_ips, target_count);
                    target_count = total_available_ips as usize;
                }

                // 循环生成IP直到达到指定数量
                let mut cidr_index = 0;
                let mut rng = rand::rng();

                while ipv4_count < target_count && !cidr_list.is_empty() {
                    // 获取当前CIDR
                    let current_cidr = &cidr_list[cidr_index];
                    
                    // 使用存储的 ip_count 值
                    let ip_net = current_cidr.ip_net;
                    let random_bits = if current_cidr.ip_count == 1 {
                        0 // 如果只有一个IP (/32)
                    } else {
                        32 - ip_net.prefix()
                    };
                    
                    if random_bits == 0 {
                        // 如果是 /32，直接使用网络地址
                        if let std::net::IpAddr::V4(ip) = ip_net.ip() {
                            ip_list.push(ip.to_string());
                            ipv4_count += 1;
                        }
                    } else {
                        // 获取网络地址的字节
                        let ip_bytes = match ip_net.ip() {
                            std::net::IpAddr::V4(ip) => ip.octets(),
                            _ => {
                                // 移动到下一个CIDR
                                cidr_index = (cidr_index + 1) % cidr_list.len();
                                continue;
                            }
                        };
                        
                        let mask_bytes = match ip_net.mask() {
                            std::net::IpAddr::V4(ip) => ip.octets(),
                            _ => {
                                // 移动到下一个CIDR
                                cidr_index = (cidr_index + 1) % cidr_list.len();
                                continue;
                            }
                        };
                        
                        // 创建新IP
                        let mut new_ip = [0u8; 4];
                        
                        for i in 0..4 {
                            // 保留网络部分
                            new_ip[i] = ip_bytes[i] & mask_bytes[i];
                            
                            // 添加随机主机部分
                            let host_part = rng.random::<u8>() & !mask_bytes[i];
                            new_ip[i] |= host_part;
                        }
                        
                        ip_list.push(format!("{}.{}.{}.{}", new_ip[0], new_ip[1], new_ip[2], new_ip[3]));
                        ipv4_count += 1;
                    }

                    // 移动到下一个CIDR
                    cidr_index = (cidr_index + 1) % cidr_list.len();
                }
            }
        }
    }

    // 处理 IPv6
    if !ipv6_mode.is_empty() && has_ipv6_cidr {
        let mut ipv6_count = 0;
        let ipv6_limit = 1000000; // 设置IPv6上限为100万

        if let Ok(count) = ipv6_mode.parse::<usize>() {
            if count > 0 {
                let mut target_count = count;
                if target_count > ipv6_limit {
                    target_count = ipv6_limit;
                    println!("IPv6生成数量已限制为 {} 个", ipv6_limit);
                }

                // 准备CIDR列表
                struct CidrInfo {
                    ip_net: IpNetwork,
                    mask_size: u8,
                }

                let mut cidr_list = Vec::new();

                let mut has_large_cidr = false;  // 标记是否有/0到/108的大CIDR
                let mut total_small_cidr_ips = 0u64; // 记录/109到/128的CIDR的IP总数

                // 第一次遍历：检查IP数量是否足够
                for result in results {
                    if let Ok(ip_net) = IpNetwork::from_str(&result.cidr) {
                        if !ip_net.is_ipv6() {
                            continue; // 跳过非IPv6
                        }

                        let prefix = ip_net.prefix();
                        // 检查是否有/0到/108的大CIDR
                        if prefix <= 108 {
                            has_large_cidr = true;
                            break;
                        } else {
                            // 计算小CIDR的IP数量并累加
                            let ip_count = 1u64 << (128 - prefix as u64);
                            total_small_cidr_ips += ip_count;
                        }

                        // 如果小CIDR的IP总数已经足够，也可以停止检查
                        if total_small_cidr_ips >= target_count as u64 {
                            break;
                        }
                    }
                }

                // 第二次遍历：收集所有CIDR
                for result in results {
                    if let Ok(ip_net) = IpNetwork::from_str(&result.cidr) {
                        if !ip_net.is_ipv6() {
                            continue;
                        }
                        let prefix = ip_net.prefix();
                        cidr_list.push(CidrInfo {
                            ip_net,
                            mask_size: prefix,
                        });
                    }
                }

                // 如果没有大CIDR且小CIDR的IP总数不足，调整目标数量
                if !has_large_cidr && total_small_cidr_ips < target_count as u64 {
                    println!("警告: 可用IPv6地址总数({})小于请求数量({})", total_small_cidr_ips, target_count);
                    target_count = total_small_cidr_ips as usize;
                }

                // 循环生成IP直到达到指定数量
                let mut cidr_index = 0;
                let mut rng = rand::rng();

                while ipv6_count < target_count && !cidr_list.is_empty() {
                    // 获取当前CIDR
                    let current_cidr = &cidr_list[cidr_index];
                    let ip_net = current_cidr.ip_net;
                    let prefix = current_cidr.mask_size;
                    
                    if prefix == 128 {
                        // 如果是 /128，直接使用网络地址
                        if let std::net::IpAddr::V6(ip) = ip_net.ip() {
                            ip_list.push(ip.to_string());
                            ipv6_count += 1;
                        }
                    } else {
                        // 获取网络地址的字节
                        let ip_bytes = match ip_net.ip() {
                            std::net::IpAddr::V6(ip) => ip.octets(),
                            _ => {
                                // 移动到下一个CIDR
                                cidr_index = (cidr_index + 1) % cidr_list.len();
                                continue;
                            }
                        };
                        
                        let mask_bytes = match ip_net.mask() {
                            std::net::IpAddr::V6(ip) => ip.octets(),
                            _ => {
                                // 移动到下一个CIDR
                                cidr_index = (cidr_index + 1) % cidr_list.len();
                                continue;
                            }
                        };
                        
                        // 创建新IP
                        let mut new_ip = [0u8; 16];
                        
                        for i in 0..16 {
                            // 保留网络部分
                            new_ip[i] = ip_bytes[i] & mask_bytes[i];
                            
                            // 添加随机主机部分
                            let host_part = rng.random::<u8>() & !mask_bytes[i];
                            new_ip[i] |= host_part;
                        }
                        
                        // 转换为IPv6字符串格式
                        let segments = [
                            ((new_ip[0] as u16) << 8) | new_ip[1] as u16,
                            ((new_ip[2] as u16) << 8) | new_ip[3] as u16,
                            ((new_ip[4] as u16) << 8) | new_ip[5] as u16,
                            ((new_ip[6] as u16) << 8) | new_ip[7] as u16,
                            ((new_ip[8] as u16) << 8) | new_ip[9] as u16,
                            ((new_ip[10] as u16) << 8) | new_ip[11] as u16,
                            ((new_ip[12] as u16) << 8) | new_ip[13] as u16,
                            ((new_ip[14] as u16) << 8) | new_ip[15] as u16,
                        ];
                        
                        ip_list.push(format!(
                            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                            segments[0], segments[1], segments[2], segments[3],
                            segments[4], segments[5], segments[6], segments[7]
                        ));
                        ipv6_count += 1;
                    }

                    // 移动到下一个CIDR
                    cidr_index = (cidr_index + 1) % cidr_list.len();
                }

                if ipv6_count > 0 {
                    println!("成功生成 {} 个IPv6地址", ipv6_count);
                }
            }
        }
    }

    // 写入文件
    let file = File::create(filename)?;
    let mut writer = BufWriter::new(file);
    for ip in ip_list {
        writeln!(writer, "{}", ip)?;
    }
    writer.flush()?;
    
    println!("IP列表已写入: {}", filename);
    Ok(())
}

/// 打印测试结果摘要
pub fn print_results_summary(results: &[TestResult]) {
    if results.is_empty() {
        println!("\n未找到符合条件的结果");
        return;
    }

    println!("\n测试结果摘要:");

    // 统计数据中心分布和延迟
    let mut dc_map: HashMap<String, (usize, i32, i32, i32)> = HashMap::new();

    // 统计未知数据中心的数量
    let mut _unknown_count = 0;
    for result in results {
        let dc = &result.data_center;
        if dc == "Unknown" {
            _unknown_count += 1;
        }

        let entry = dc_map.entry(dc.clone()).or_insert((0, result.avg_latency, result.avg_latency, 0));
        
        // 更新计数和总延迟
        entry.0 += 1;
        entry.3 += result.avg_latency;
        
        // 更新最小延迟
        if result.avg_latency < entry.1 {
            entry.1 = result.avg_latency;
        }
        
        // 更新最大延迟
        if result.avg_latency > entry.2 {
            entry.2 = result.avg_latency;
        }
    }

    println!();

    // 创建数据中心统计表格
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(Row::new(vec![
        Cell::new("数据中心"),
        Cell::new("数量").style_spec("r"),
        Cell::new("最高延迟").style_spec("r"),
        Cell::new("平均延迟").style_spec("r"),
        Cell::new("最低延迟").style_spec("r"),
    ]));

    for (dc, (count, min_latency, max_latency, total_latency)) in &dc_map {
        let avg_latency = total_latency / *count as i32;
        table.add_row(Row::new(vec![
            Cell::new(dc),
            Cell::new(&format!("{}", count)).style_spec("r"),
            Cell::new(&format!("{}ms", max_latency)).style_spec("r"),
            Cell::new(&format!("{}ms", avg_latency)).style_spec("r"),
            Cell::new(&format!("{}ms", min_latency)).style_spec("r"),
        ]));
    }
    table.printstd();

    // 计算总体延迟统计
    let mut _total_latency = 0;
    let mut min_latency = results[0].avg_latency;
    let mut max_latency = results[0].avg_latency;
    
    for result in results {
        _total_latency += result.avg_latency;
        if result.avg_latency < min_latency {
            min_latency = result.avg_latency;
        }
        if result.avg_latency > max_latency {
            max_latency = result.avg_latency;
        }
    }

    println!();

    // 显示最佳结果表格
    let mut result_table = Table::new();
    result_table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    result_table.set_titles(Row::new(vec![
        Cell::new("CIDR"),
        Cell::new("城市(数据中心)"),
        Cell::new("平均延迟").style_spec("r"),
        Cell::new("平均丢包").style_spec("r"),
    ]));

    let limit = 10.min(results.len());
    for i in 0..limit {
        let result = &results[i];
        let location_info = format!("{}({})", result.city, result.data_center);
        
        result_table.add_row(Row::new(vec![
            Cell::new(&result.cidr),
            Cell::new(&location_info),
            Cell::new(&format!("{}ms", result.avg_latency)).style_spec("r"),
            Cell::new(&format!("{:.1}%", result.loss_rate * 100.0)).style_spec("r"),
        ]));
    }
    result_table.printstd();

    println!();
}