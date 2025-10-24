use colored::*;
use prettytable::{Cell, Row, Table, format};
use std::collections::HashSet;
use std::env;

#[cfg(target_os = "windows")]
const DEFAULT_EXECUTABLE: &str = "CloudflareST-Rust.exe";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const DEFAULT_EXECUTABLE: &str = "CloudflareST-Rust";

const ALLOWED_CLOUDFLARE_ARGS: &[&str] = &[
    "t", "tp", "colo", "tl", "tll", "tlr", "n", "timeout", "intf", "hu"
];

#[derive(Clone)]
pub struct Args {
    pub file_name: String,
    pub help: bool,
    pub cidr: Option<String>,
    pub cidr_file: Option<String>,
    pub cidr_url: Option<String>,
    pub select_ipv4: Option<u128>,
    pub select_ipv6: Option<u128>,
    pub ip_count: Option<u32>,
    pub cloudflare_args: Option<String>,
    pub output_file: Option<String>,
    pub output_txt: Option<String>,
    pub limit_count: Option<usize>,
    pub skip_cleanup: bool,
}

impl Args {
    pub fn new() -> Self {
        Self {
            file_name: DEFAULT_EXECUTABLE.to_string(),
            help: false,
            cidr: Some("".to_string()),
            cidr_file: Some("".to_string()),
            cidr_url: Some("".to_string()),
            select_ipv4: None,
            select_ipv6: None,
            ip_count: Some(2),
            cloudflare_args: Some("".to_string()),
            output_file: Some("CIDR-Result.csv".to_string()),
            output_txt: Some("ip.txt".to_string()),
            limit_count: None,
            skip_cleanup: false,
        }
    }

    pub fn parse() -> Self {
        let args: Vec<String> = env::args().collect();
        let mut parsed = Self::new();
        let vec = Self::parse_args_to_vec(&args);

        for (k, v_opt) in vec {
            match k.as_str() {
                "h" | "help" => parsed.help = true,
                "f" => parsed.file_name = v_opt.unwrap_or(parsed.file_name),
                "cidr" => parsed.cidr = v_opt,
                "cf" => parsed.cidr_file = v_opt,
                "cu" => parsed.cidr_url = v_opt,
                "s4" => parsed.select_ipv4 = v_opt.and_then(|v| v.parse::<u128>().ok()),
                "s6" => parsed.select_ipv6 = v_opt.and_then(|v| v.parse::<u128>().ok()),
                "ic" => parsed.ip_count = v_opt.and_then(|v| v.parse::<u32>().ok().map(|num| num.clamp(1, 256))),
                "ca" => {
                    if let Some(v) = v_opt {
                        let validated_args = Self::validate_allowed_args(&v, ALLOWED_CLOUDFLARE_ARGS);
                        parsed.cloudflare_args = Some(validated_args);
                    }
                }
                "o" => parsed.output_file = v_opt,
                "ot" => parsed.output_txt = v_opt,
                "lc" => parsed.limit_count = v_opt.and_then(|v| v.parse().ok()),
                "sc" => parsed.skip_cleanup = true,
                _ => {
                    print_help();
                    println!("{} 无效的参数: {}", "[错误]".red().bold(), k);
                    std::process::exit(1);
                }
            }
        }

        parsed
    }

    fn parse_args_to_vec(args: &[String]) -> Vec<(String, Option<String>)> {
        let mut vec = Vec::new();
        let mut iter = args.iter().skip(1).peekable();

        while let Some(arg) = iter.next() {
            if arg.starts_with('-') {
                let key = arg.trim_start_matches('-').to_string();
                // 统一使用 peek 判断是否有下一个值
                let value = if let Some(next) = iter.peek() {
                    if key == "ca" || !next.starts_with('-') {
                        Some(iter.next().unwrap().to_string())
                    } else {
                        None
                    }
                } else {
                    None
                };
                vec.push((key, value));
            }
        }

        vec
    }

    fn validate_allowed_args(input: &str, allowed: &[&str]) -> String {
        let allowed_set: HashSet<_> = allowed.iter().cloned().collect();

        for part in input.split_whitespace() {
            if part.starts_with('-') {
                let key = part.trim_start_matches('-');
                if !allowed_set.contains(key) {
                    eprintln!("{} 尝试传递不允许的参数: -{}", "[错误]".red().bold(), key);
                    std::process::exit(1);
                }
            }
        }

        input.to_string()
    }
}

pub fn parse_args() -> Args {
    let args = Args::parse();
    let mut errors = Vec::new();

    if args.help {
        print_help();
        std::process::exit(0);
    }

    if !std::path::Path::new(&args.file_name).exists() {
        errors.push("错误: 指定的测速程序 file_name 不存在".to_string());
    }

    if let Some(cidr_file) = &args.cidr_file {
        if !cidr_file.is_empty() && !std::path::Path::new(cidr_file).exists() {
            errors.push("错误: 指定的文件不存在".to_string());
        }
    }

    if args.cidr.is_none() && args.cidr_file.is_none() && args.cidr_url.is_none() {
        errors.push("错误: 必须指定一个或多个 CIDR 来源参数 (-cidr, -cf 或 -cu)".to_string());
    }

    if !errors.is_empty() {
        for err in &errors {
            eprintln!("{}", err.red().bold());
        }
        std::process::exit(1);
    }

    args
}

pub fn print_help() {
    println!("{}", "# CF-CST".bold().blue());

    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_CLEAN);

    macro_rules! add_arg {
        ($name:expr, $desc:expr, $default:expr) => {
            table.add_row(Row::new(vec![
                Cell::new(&format!(" {:<12}", $name.green())),
                Cell::new(&format!("{:<16}", $desc)),
                Cell::new(&format!("{:<10}", $default.dimmed())),
            ]));
        };
    }

    add_arg!("-f", "指定 CloudflareST-Rust 可执行文件名", DEFAULT_EXECUTABLE);
    add_arg!("-cidr", "指定要解析的地址", "无");
    add_arg!("-cf", "从指定文件获取列表", "无");
    add_arg!("-cu", "从URL远程获取列表", "无");
    add_arg!("-ic", "从每个CIDR中分别随机选择用于测速的 IP 数量", "2");
    add_arg!("-s4", "为 IPv4 CIDR 附加数量后缀", "无");
    add_arg!("-s6", "为 IPv6 CIDR 附加数量后缀", "无");
    add_arg!("-ca", &format!("可传递给测速程序的参数: {}", ALLOWED_CLOUDFLARE_ARGS.join(" ")), "无");
    add_arg!("-o", "指定输出 csv 文件名", "CIDR-Result.csv");
    add_arg!("-ot", "指定输出 txt 文件名", "ip.txt");
    add_arg!("-lc", "指定写入文件的条目数量", "无限制");
    add_arg!("-sc", "跳过删除临时文件 (cidr_split_*.txt, result_*.csv)", "false");

    table.printstd();
}