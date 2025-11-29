use std::collections::HashSet;
use std::env;
use crate::CLOUDFLAREST_RUST;
use crate::error_println;

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
    pub ipv4_prefix: u8,
    pub ipv6_prefix: u8,
}

impl Args {
    pub fn new() -> Self {
        Self {
            file_name: CLOUDFLAREST_RUST.to_owned(),
            help: false,
            cidr: Some("".to_string()),
            cidr_file: Some("".to_string()),
            cidr_url: Some("".to_string()),
            select_ipv4: None,
            select_ipv6: None,
            ip_count: Some(2),
            cloudflare_args: Some("".to_string()),
            output_file: Some("CIDR-Result.csv".to_owned()),
            output_txt: Some("ip.txt".to_owned()),
            limit_count: None,
            skip_cleanup: false,
            ipv4_prefix: 24,
            ipv6_prefix: 48,
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
                "v4p" => parsed.ipv4_prefix = v_opt.and_then(|v| v.parse::<u8>().ok()).unwrap_or(parsed.ipv4_prefix),
                "v6p" => parsed.ipv6_prefix = v_opt.and_then(|v| v.parse::<u8>().ok()).unwrap_or(parsed.ipv6_prefix),
                _ => {
                    print_help();
                    error_and_exit(format_args!("无效的参数: {}", k));
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
                let key = arg.trim_start_matches('-').to_owned();
                // 统一使用 peek 判断是否有下一个值
                let value = if let Some(next) = iter.peek() {
                    if key == "ca" || !next.starts_with('-') {
                        Some(iter.next().unwrap().to_owned())
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
                    error_and_exit(format_args!("尝试传递不允许的参数: -{}", key));
                }
            }
        }

        input.to_owned()
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
        errors.push(format!("指定的测速程序 {} 不存在", &args.file_name));
    }

    if let Some(cidr_file) = &args.cidr_file
        && !cidr_file.is_empty() && !std::path::Path::new(cidr_file).exists() {
        errors.push(String::from("指定的文件不存在"));
    }

    if args.cidr.is_none() && args.cidr_file.is_none() && args.cidr_url.is_none() {
        errors.push(String::from("必须指定一个或多个 CIDR 来源参数 (-cidr, -cf 或 -cu)"));
    }

    if !errors.is_empty() {
        for err in &errors {
            error_println(format_args!("{}", err));
        }
        std::process::exit(1);
    }

    args
}

// 计算显示宽度
fn approximate_display_width_no_color(s: &str) -> usize {
    let mut width = 0;
    let mut in_escape = false; 

    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
            continue;
        }
        if in_escape {
            if c == 'm' || c.is_alphabetic() {
                in_escape = false;
            }
            continue;
        }
        // 非 ASCII (中文) 宽度为 2，ASCII 宽度为 1
        width += if c.is_ascii() { 1 } else { 2 };
    }
    width
}

// 格式化和打印单个参数行
fn print_arg_row(name: &str, desc: &str, default: &str) {
    // 固定的列宽
    const COL_NAME_WIDTH: usize = 9;
    const COL_DESC_WIDTH: usize = 35;
    const COL_DEFAULT_WIDTH: usize = 10;

    // 1. 格式化参数名：绿色 (\x1b[32m)
    let name_colored = format!("\x1b[32m{}\x1b[0m", name);
    let name_display_width = approximate_display_width_no_color(&name_colored);
    let name_padding = COL_NAME_WIDTH.saturating_sub(name_display_width);
    
    // 2. 格式化描述 (默认颜色)
    let desc_display_width = approximate_display_width_no_color(desc);
    let desc_padding = COL_DESC_WIDTH.saturating_sub(desc_display_width);

    // 3. 格式化默认值：暗淡色 (\x1b[2m)
    let default_colored = format!("\x1b[2m{}\x1b[0m", default);
    let default_display_width = approximate_display_width_no_color(&default_colored);
    let default_padding = COL_DEFAULT_WIDTH.saturating_sub(default_display_width);

    // 4. 打印整行 (左侧增加 1 个空格作为缩进)
    println!(
        " {}{}{}{}{}{}",
        name_colored,
        " ".repeat(name_padding),
        desc,
        " ".repeat(desc_padding),
        default_colored,
        " ".repeat(default_padding)
    );
}

pub fn print_help() {
    print_arg_row("-f", "指定测速使用的可执行程序文件名", CLOUDFLAREST_RUST);
    print_arg_row("-cidr", "指定要解析的 CIDR 地址", "无");
    print_arg_row("-cf", "从指定文件获取 CIDR 列表", "无");
    print_arg_row("-cu", "从URL远程获取 CIDR 列表", "无");
    print_arg_row("-ic", "每个 CIDR 随机选取的 IP 数量", "2");
    print_arg_row("-s4", "为 IPv4 CIDR 附加数量后缀", "无");
    print_arg_row("-s6", "为 IPv6 CIDR 附加数量后缀", "无");
    print_arg_row("-ca", "向测速程序传递一些参数", "无");
    print_arg_row("-o", "指定输出 CSV 文件名", "CIDR-Result.csv");
    print_arg_row("-ot", "指定输出 TXT 文件名", "ip.txt");
    print_arg_row("-lc", "限制写入文件的条目数量", "无限制");
    print_arg_row("-sc", "跳过删除临时文件", "false");
    print_arg_row("v4p", "IPv4 CIDR 前缀长度", "24");
    print_arg_row("v6p", "IPv6 CIDR 前缀长度", "48");
}

// 打印错误信息并退出程序
pub fn error_and_exit(args: std::fmt::Arguments<'_>) -> ! {
    error_println(args);
    std::process::exit(1);
}