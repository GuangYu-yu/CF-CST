use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use rand::Rng;
use reqwest::ClientBuilder;
use tokio::time::sleep;
use crate::types::get_or_create_cidr_string;

// 从URL获取CIDR列表
pub async fn get_cidr_from_url(url: &str) -> Result<Vec<String>, String> {
    let max_retries = 10;
    let retry_delay = Duration::from_secs(3);

    let mut last_err = String::from("未知错误");

    // 创建带超时的HTTP客户端
    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(3))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("创建HTTP客户端失败: {}", e))?;

    // 重试逻辑
    for retry in 0..max_retries {
        if retry > 0 {
            println!("第 {} 次重试获取CIDR列表...", retry);
            sleep(retry_delay).await;
            // 每次重试保持延迟时间不变
        }

        match client.get(url).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    last_err = format!("HTTP请求失败，状态码: {}", resp.status());
                    println!("获取失败，准备重试...");
                    continue;
                }

                // 成功获取，解析CIDR列表
                match resp.text().await {
                    Ok(text) => {
                        match parse_cidr_list(&text) {
                            Ok(cidr_list) => {
                                // 检查是否成功获取到CIDR
                                if !cidr_list.is_empty() {
                                    return Ok(cidr_list);
                                }
                                last_err = "获取到的CIDR列表为空".to_string();
                                println!("获取结果为空，准备重试...");
                            }
                            Err(e) => {
                                last_err = format!("解析CIDR列表失败: {}", e);
                                println!("解析失败，准备重试...");
                            }
                        }
                    }
                    Err(e) => {
                        last_err = format!("读取响应内容失败: {}", e);
                        println!("获取失败，准备重试...");
                    }
                }
            }
            Err(e) => {
                last_err = format!("HTTP请求失败: {}", e);
                println!("获取失败，准备重试...");
            }
        }
    }

    // 使用最后一次错误
    Err(last_err)
}

// 从文件获取CIDR列表
pub fn get_cidr_from_file(filename: &str) -> Result<Vec<String>, String> {
    let file = File::open(filename).map_err(|e| format!("打开文件失败: {}", e))?;
    parse_cidr_list_from_reader(BufReader::new(file))
}

fn format_cidr(line: &str) -> String {
    match line.parse::<IpNetwork>() {
        Ok(ip_network) => ip_network.to_string(),
        Err(_) => {
            // 如果解析失败，尝试添加默认掩码
            match line.parse::<IpAddr>() {
                Ok(ip_addr) => match ip_addr {
                    IpAddr::V4(_) => format!("{}/32", ip_addr),
                    IpAddr::V6(_) => format!("{}/128", ip_addr),
                },
                Err(_) => line.to_string(), // 如果仍然解析失败，返回原始字符串
            }
        }
    }
}

// 解析CIDR列表（从字符串）
pub fn parse_cidr_list(content: &str) -> Result<Vec<String>, String> {
    let mut cidr_list = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let cidr = format_cidr(line);
        cidr_list.push(cidr);
    }

    Ok(cidr_list)
}

// 解析CIDR列表（从读取器）
pub fn parse_cidr_list_from_reader<R: io::Read>(reader: BufReader<R>) -> Result<Vec<String>, String> {
    let mut cidr_list = Vec::new();

    for line in reader.lines() {
        let line = line.map_err(|e| format!("读取行失败: {}", e))?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let cidr = format_cidr(line);
        cidr_list.push(cidr);
    }

    Ok(cidr_list)
}

// 扩展CIDR列表
pub fn expand_cidrs(cidr_list: &[String]) -> Vec<String> {
    let mut expanded_list = Vec::new();

    for cidr in cidr_list {
        // 检查是否是有效的CIDR
        let ip_net = match IpNetwork::from_str(cidr) {
            Ok(net) => net,
            Err(_) => continue,
        };

        // 使用共享 CIDR 字符串
        let shared_cidr = get_or_create_cidr_string(cidr);
        expanded_list.push(shared_cidr);

        // 判断是IPv4还是IPv6
        match ip_net {
            IpNetwork::V4(ipv4_net) => {
                let ones = ipv4_net.prefix();
                if ones >= 24 {
                    // 已经是/24或更小，直接添加
                    expanded_list.push(cidr.clone());
                } else {
                    // 需要拆分为多个/24
                    let sub_cidrs = expand_ipv4_cidr(&ipv4_net, ones);
                    expanded_list.extend(sub_cidrs);
                }
            }
            IpNetwork::V6(ipv6_net) => {
                let ones = ipv6_net.prefix();
                if ones >= 48 {
                    // 已经是/48或更小，直接添加
                    expanded_list.push(cidr.clone());
                } else {
                    // 需要拆分为多个/48
                    let sub_cidrs = expand_ipv6_cidr(&ipv6_net, ones);
                    expanded_list.extend(sub_cidrs);
                }
            }
        }
    }

    expanded_list
}

// 将IPv4 CIDR拆分为多个/24
fn expand_ipv4_cidr(ip_net: &Ipv4Network, ones: u8) -> Vec<String> {
    // 如果已经是/24或更小，直接返回
    if ones >= 24 {
        return vec![ip_net.to_string()];
    }

    // 计算需要拆分的子网数量
    let split_bits = 24 - ones;
    let count = 1 << split_bits; // 2^split_bits

    // 将IP地址转换为u32
    let ip = ip_net.network().octets();
    let base_ip = u32::from_be_bytes(ip);

    // 创建掩码
    let mask = 0xffffffff << (32 - ones);

    // 应用掩码获取网络地址
    let base_ip = base_ip & mask;

    let mut result = Vec::with_capacity(count as usize);

    // 生成所有/24子网
    for i in 0..count {
        // 计算新的子网地址
        let new_ip = base_ip | ((i as u32) << 8);

        // 转换回IP地址格式
        let a = ((new_ip >> 24) & 0xFF) as u8;
        let b = ((new_ip >> 16) & 0xFF) as u8;
        let c = ((new_ip >> 8) & 0xFF) as u8;

        // 创建新的CIDR字符串
        let new_cidr = format!("{}.{}.{}.0/24", a, b, c);
        result.push(new_cidr);
    }

    result
}

// 将IPv6 CIDR拆分为多个/48
fn expand_ipv6_cidr(ip_net: &Ipv6Network, ones: u8) -> Vec<String> {
    // 如果已经是/48或更小，直接返回
    if ones >= 48 {
        return vec![ip_net.to_string()];
    }

    // 计算需要拆分的位数
    let mut split_bits = 48 - ones;

    // 限制拆分数量，避免生成过多的子网
    if split_bits > 16 {
        split_bits = 16;
    }

    // 计算需要拆分的子网数量 (2^split_bits)
    let subnet_count = 1 << split_bits;

    // 获取原始 IP 地址的 16 字节表示
    let ip = ip_net.network().octets();

    let mut result = Vec::with_capacity(subnet_count as usize);

    // 生成所有/48子网
    for i in 0..subnet_count {
        // 复制原始 IP 地址
        let mut new_ip = [0u8; 16];
        new_ip.copy_from_slice(&ip);

        // 计算起始字节和位偏移
        let start_byte = (ones / 8) as usize;
        let start_bit = ones % 8;

        // 设置子网索引位
        let mut remaining_bits = split_bits;
        let value = i;

        // 处理第一个字节（可能需要保留部分位）
        if start_bit > 0 {
            // 计算第一个字节可以设置的位数
            let mut bits_in_first_byte = 8 - start_bit;
            if bits_in_first_byte > remaining_bits {
                bits_in_first_byte = remaining_bits;
            }

            // 创建掩码，保留前 start_bit 位
            let mask = 0xFF << (8 - start_bit);

            // 计算要设置的值
            let value_to_set = ((value >> (remaining_bits - bits_in_first_byte)) as u8) << (8 - start_bit - bits_in_first_byte);

            // 设置值，保留前 start_bit 位
            new_ip[start_byte] = (new_ip[start_byte] & mask) | value_to_set;

            remaining_bits -= bits_in_first_byte;
            let mut current_byte = start_byte + 1;

            // 处理完整字节
            while remaining_bits >= 8 {
                new_ip[current_byte] = ((value >> (remaining_bits - 8)) & 0xFF) as u8;
                remaining_bits -= 8;
                current_byte += 1;
            }

            // 处理最后一个不完整字节
            if remaining_bits > 0 {
                let value_to_set = ((value & ((1 << remaining_bits) - 1)) as u8) << (8 - remaining_bits);
                new_ip[current_byte] = value_to_set;
            }
        } else {
            // 起始位是字节边界，处理更简单
            let mut current_byte = start_byte;
            
            // 处理完整字节
            while remaining_bits >= 8 {
                new_ip[current_byte] = ((value >> (remaining_bits - 8)) & 0xFF) as u8;
                remaining_bits -= 8;
                current_byte += 1;
            }

            // 处理最后一个不完整字节
            if remaining_bits > 0 {
                let value_to_set = ((value & ((1 << remaining_bits) - 1)) as u8) << (8 - remaining_bits);
                new_ip[current_byte] = value_to_set;
            }
        }

        // 将 48 位之后的所有位清零
        for j in 6..16 {
            new_ip[j] = 0;
        }

        // 创建新的 /48 CIDR
        let ipv6 = Ipv6Addr::from(new_ip);
        let new_cidr = format!("{}/48", ipv6);
        result.push(new_cidr);
    }

    result
}

// 通用的IPv4地址生成函数
pub fn generate_random_ipv4_address(ip_net: &IpNetwork) -> Option<String> {
    match ip_net {
        IpNetwork::V4(ipv4_net) => {
            // 获取网络地址和掩码
            let ip = ipv4_net.network().octets();
            let ones = ipv4_net.prefix();
            let random_bits = 32 - ones;

            // 将IP地址转换为u32
            let base_ip = u32::from_be_bytes(ip);

            // 创建掩码
            let net_mask = 0xffffffff << random_bits;
            let network_addr = base_ip & net_mask;

            // 计算最大偏移量
            let max_offset = 1u32 << random_bits;

            if max_offset == 1 {
                // /32，只有一个IP，直接返回
                return Some(ipv4_net.network().to_string());
            }

            // 生成随机偏移量
            let random_offset = if max_offset > 2 {
                rand::rng().random_range(1..max_offset as u32) // 避开网络地址，显式转换为u32
            } else {
                1 // /31 的情况，两个地址都可以用
            };

            // 计算最终IP
            let final_ip = network_addr | random_offset;

            // 转换回IP地址格式
            let result = Ipv4Addr::from(final_ip.to_be_bytes());
            Some(result.to_string())
        }
        _ => None,
    }
}

// 通用的IPv6地址生成函数
pub fn generate_random_ipv6_address(ip_net: &IpNetwork) -> Option<String> {
    match ip_net {
        IpNetwork::V6(ipv6_net) => {
            // 获取网络地址
            let ip = ipv6_net.network().octets();
            let ones = ipv6_net.prefix();
            let random_bits = 128 - ones;

            // 创建新IP
            let mut new_ip = [0u8; 16];
            new_ip.copy_from_slice(&ip);

            // 计算需要随机的字节数和位数
            let random_bytes = (random_bits / 8) as usize;
            let remaining_bits = random_bits % 8;

            let mut rng = rand::rng();

            // 完全随机的字节
            for i in 0..16 {
                // 只处理需要随机化的字节
                if i >= 16 - random_bytes {
                    // 生成完全随机的字节
                    let rand_value = rng.random::<u8>();
                    // 保留网络前缀部分
                    let mask_byte = if ones > 0 && i == 16 - random_bytes - 1 && remaining_bits > 0 {
                        0xFF << remaining_bits
                    } else if i < (ones as usize) / 8 {
                        0xFF
                    } else {
                        0
                    };
                    new_ip[i] = (new_ip[i] & mask_byte) | (rand_value & !mask_byte);
                }
            }

            // 处理剩余的不足一个字节的位
            if remaining_bits > 0 {
                let byte_pos = 16 - random_bytes - 1;

                    // 创建位掩码，只修改需要随机的位
                    let bit_mask = 0xFF >> (8 - remaining_bits);
                    // 生成随机值
                    let rand_value = rng.random::<u8>() & bit_mask;
                    // 应用掩码和随机值
                    let mask_byte = 0xFF << remaining_bits;
                    // 保留网络前缀，修改主机部分
                    new_ip[byte_pos] = (new_ip[byte_pos] & mask_byte) | (rand_value & !mask_byte);
            }

            // 检查生成的IP是否为全零地址
            let is_zero = new_ip.iter().all(|&b| b == 0);

            // 如果是全零地址，重新生成
            if is_zero {
                // 简单地将最后一个字节设为1，确保不是全零地址
                new_ip[15] = 1;
            }

            let result = Ipv6Addr::from(new_ip);
            Some(result.to_string())
        }
        _ => None,
    }
}