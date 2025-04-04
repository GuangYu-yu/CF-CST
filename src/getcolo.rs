use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use crate::pool;

// 数据中心位置信息结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub iata: String,
    pub city: String,
    pub region: String,
    #[serde(rename = "cca2")]
    pub country_code: String,
}

// 获取Cloudflare数据中心位置信息
pub async fn get_location_map() -> Result<HashMap<String, Location>, String> {
    // 设置最大重试次数
    let max_retries = 5;
    let retry_delay = Duration::from_secs(2);

    let mut last_err = String::new();

    for retry in 0..max_retries {
        if retry > 0 {
            sleep(retry_delay).await;
        }

        // 创建带超时的客户端
        let client = match Client::builder()
            .timeout(Duration::from_secs(3))
            .build() {
                Ok(client) => client,
                Err(err) => {
                    last_err = format!("无法创建HTTP客户端: {}", err);
                    continue; // 重试
                }
            };

        let resp = match client.get("https://speed.cloudflare.com/locations").send().await {
            Ok(resp) => resp,
            Err(err) => {
                last_err = format!("无法获取 locations.json: {}", err);
                continue; // 重试
            }
        };

        if !resp.status().is_success() {
            last_err = format!("HTTP请求失败，状态码: {}", resp.status());
            continue; // 重试
        }

        // 读取整个响应体
        let body = match resp.bytes().await {
            Ok(body) => body,
            Err(err) => {
                last_err = format!("读取响应体失败: {}", err);
                continue; // 重试
            }
        };

        // 检查响应体是否为空
        if body.is_empty() {
            last_err = "获取到的响应体为空".to_string();
            continue; // 重试
        }

        // 解析JSON
        let locations: Vec<Location> = match serde_json::from_slice(&body) {
            Ok(locations) => locations,
            Err(err) => {
                last_err = format!("无法解析JSON: {}", err);
                continue; // 重试
            }
        };

        // 检查解析后的数据是否为空
        if locations.is_empty() {
            last_err = "解析后的数据中心列表为空".to_string();
            continue; // 重试
        }

        // 构造 location 映射，key 为数据中心代码
        let mut location_map = HashMap::new();
        for location in locations {
            location_map.insert(location.iata.clone(), location);
        }

        return Ok(location_map);
    }

    Err(last_err)
}

// 获取数据中心信息
pub async fn get_datacenter_for_ip(ip: &str, location_map: &HashMap<String, crate::types::Location>) -> (String, String, String) {
    // 使用全局控制器控制并发
    let _permit = match pool::execute_with_rate_limit(|| async {
        let max_retries = 2;
        let retry_delay = Duration::from_millis(800);

        // 创建客户端
        let client = match Client::builder()
            .timeout(Duration::from_millis(1000))
            .redirect(reqwest::redirect::Policy::none())
            .build() {
                Ok(client) => client,
                Err(_) => return Ok::<_, String>(("Unknown".to_string(), "".to_string(), "".to_string())),
            };

        for retry in 0..=max_retries {
            // 添加重试延迟，第一次尝试不延迟
            if retry > 0 {
                sleep(retry_delay).await;
            }

            let host_ip = if !ip.contains('.') {
                format!("[{}]", ip)
            } else {
                ip.to_string()
            };

            // 修复请求构建方式
            let url = format!("http://{}", host_ip);
            let req = match client.head(&url)
                .header("Host", "cloudflare.com")
                .build() {
                    Ok(req) => req,
                    Err(_) => continue,
                };

            let resp = match client.execute(req).await {
                Ok(resp) => resp,
                Err(_) => continue,
            };

            if let Some(cf_ray) = resp.headers().get("cf-ray") {
                if let Ok(cf_ray_str) = cf_ray.to_str() {
                    if let Some(last_dash_index) = cf_ray_str.rfind('-') {
                        let data_center = &cf_ray_str[last_dash_index + 1..];
                        if !data_center.is_empty() {
                            if let Some(loc) = location_map.get(data_center) {
                                return Ok((data_center.to_string(), loc.region.clone(), loc.city.clone()));
                            }
                            return Ok((data_center.to_string(), "".to_string(), "".to_string()));
                        }
                    }
                }
            }
        }

        Ok(("Unknown".to_string(), "".to_string(), "".to_string()))
    }).await {
        Ok(result) => result,
        Err(_) => ("Unknown".to_string(), "".to_string(), "".to_string()),
    };

    _permit
}