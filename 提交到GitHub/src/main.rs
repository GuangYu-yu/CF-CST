use base64::encode;
use clap::{App, Arg};
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::path::Path;
use std::process::exit;

const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100MB 限制

#[derive(Serialize, Deserialize, Debug)]
struct GitHubResponse {
    sha: Option<String>,
    commit: Option<GitHubCommit>,
}

#[derive(Serialize, Deserialize, Debug)]
struct GitHubCommit {
    sha: String,
}

fn main() {
    let matches = App::new("GitHub 文件上传工具")
        .version("0.1.0")
        .author("Trae AI")
        .about("上传文件到 GitHub 仓库")
        .arg(
            Arg::new("file")
                .short('f')
                .long("file")
                .value_name("FILE")
                .help("要上传的文件路径")
                .required(true),
        )
        .arg(
            Arg::new("url")
                .short('u')
                .long("github-url")
                .value_name("URL")
                .help("GitHub raw URL，包含 token")
                .required(true),
        )
        .get_matches();

    let file_path = matches.value_of("file").unwrap();
    let github_url = matches.value_of("url").unwrap();

    let success = upload_to_github(file_path, github_url);
    exit(if success { 0 } else { 1 });
}

fn upload_to_github(file_path: &str, github_url: &str) -> bool {
    println!("开始上传文件 {} 到 GitHub...", file_path);

    // 解析 GitHub URL
    let re = Regex::new(r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/refs/heads/([^/]+)/(.+)\?token=(.+)$").unwrap();
    let captures = match re.captures(github_url) {
        Some(caps) => caps,
        None => {
            println!("错误: GitHub URL 格式不正确");
            println!("正确格式: https://raw.githubusercontent.com/用户名/仓库名/refs/heads/分支名/文件路径?token=访问令牌");
            return false;
        }
    };

    // 提取信息
    let username = captures.get(1).unwrap().as_str();
    let repo_name = captures.get(2).unwrap().as_str();
    let branch = captures.get(3).unwrap().as_str();
    let remote_path = captures.get(4).unwrap().as_str();
    let token = captures.get(5).unwrap().as_str();
    let repo = format!("{}/{}", username, repo_name);

    println!("解析 URL 成功:");
    println!("- 仓库: {}", repo);
    println!("- 分支: {}", branch);
    println!("- 路径: {}", remote_path);

    // 检查文件是否存在
    let path = Path::new(file_path);
    if !path.exists() {
        println!("错误: 文件 {} 不存在", file_path);
        return false;
    }

    // 检查文件大小
    let metadata = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            println!("读取文件元数据失败: {}", e);
            return false;
        }
    };

    let file_size = metadata.len();
    if file_size > MAX_FILE_SIZE {
        println!(
            "错误: 文件大小 ({:.2} MB) 超过限制 (100 MB)",
            file_size as f64 / 1024.0 / 1024.0
        );
        return false;
    }

    // 读取文件内容并进行 base64 编码
    let file_content = match fs::read(path) {
        Ok(content) => content,
        Err(e) => {
            println!("读取文件失败: {}", e);
            return false;
        }
    };
    let encoded_content = encode(&file_content);

    // 创建 HTTP 客户端
    let client = Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("token {}", token)).unwrap(),
    );
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github.v3+json"),
    );
    // 添加 User-Agent 头部
    headers.insert(
        reqwest::header::USER_AGENT,
        HeaderValue::from_static("GitHub-Uploader-Rust/0.1.0"),
    );

    // 检查远程文件是否存在
    let api_url = format!(
        "https://api.github.com/repos/{}/contents/{}",
        repo, remote_path
    );

    let response = match client.get(&api_url).headers(headers.clone()).send() {
        Ok(resp) => resp,
        Err(e) => {
            println!("发送请求失败: {}", e);
            return false;
        }
    };

    let (file_exists, sha) = if response.status().is_success() {
        // 文件存在，获取 SHA
        match response.json::<GitHubResponse>() {
            Ok(data) => {
                println!("远程文件已存在，将进行更新");
                (true, data.sha)
            }
            Err(e) => {
                println!("解析响应失败: {}", e);
                return false;
            }
        }
    } else if response.status().as_u16() == 404 {
        // 文件不存在
        println!("远程文件不存在，将创建新文件");
        (false, None)
    } else {
        println!(
            "检查远程文件失败: {} {}",
            response.status().as_u16(),
            response.status().as_str()
        );
        match response.text() {
            Ok(text) => println!("响应内容: {}", text),
            Err(_) => {}
        }
        return false;
    };

    // 准备请求数据
    let file_name = path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap_or("unknown_file");
    let message = if file_exists {
        format!("更新 {}", file_name)
    } else {
        format!("创建 {}", file_name)
    };

    let mut data = json!({
        "message": message,
        "content": encoded_content,
        "branch": branch
    });

    // 如果文件存在，添加 SHA
    if let Some(sha_value) = sha {
        data["sha"] = json!(sha_value);
    }

    // 发送请求
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("token {}", token)).unwrap(),
    );
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github.v3+json"),
    );
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    // 添加 User-Agent 头部
    headers.insert(
        reqwest::header::USER_AGENT,
        HeaderValue::from_static("GitHub-Uploader-Rust/0.1.0"),
    );

    let response = match client.put(&api_url).headers(headers).json(&data).send() {
        Ok(resp) => resp,
        Err(e) => {
            println!("发送请求失败: {}", e);
            return false;
        }
    };

    if response.status().is_success() {
        match response.json::<GitHubResponse>() {
            Ok(data) => {
                if let Some(commit) = data.commit {
                    println!("文件上传成功! Commit SHA: {}", commit.sha);
                } else {
                    println!("文件上传成功!");
                }
                true
            }
            Err(e) => {
                println!("解析响应失败: {}", e);
                false
            }
        }
    } else {
        println!(
            "上传文件失败 (HTTP 错误): {} {}",
            response.status().as_u16(),
            response.status().as_str()
        );
        match response.text() {
            Ok(text) => println!("响应内容: {}", text),
            Err(_) => {}
        }
        false
    }
}