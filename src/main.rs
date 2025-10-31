use colored::Colorize;
use std::fs;

// 定义统一的错误、信息和警告输出函数
pub fn error_println(args: std::fmt::Arguments<'_>) {
    eprintln!("{} {}", "[错误]".red().bold(), args);
}

pub fn info_println(args: std::fmt::Arguments<'_>) {
    println!("{} {}", "[信息]".cyan().bold(), args);
}

pub fn warning_println(args: std::fmt::Arguments<'_>) {
    println!("{} {}", "[警告]".yellow().bold(), args);
}

// CloudflareST-Rust 全局常量，根据平台不同设置不同的值
#[cfg(target_os = "windows")]
pub const CLOUDFLAREST_RUST: &str = "CloudflareST-Rust.exe";

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub const CLOUDFLAREST_RUST: &str = "CloudflareST-Rust";

mod args;
mod cidr;
mod csv;
mod test;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "# CF-CST".bold().blue());
    let args = args::parse_args();

    // 检查是否提供 CIDR 来源
    let has_cidr_source = args.cidr.as_deref().map_or(false, |s| !s.is_empty())
        || args.cidr_url.as_deref().map_or(false, |s| !s.is_empty())
        || args.cidr_file.as_deref().map_or(false, |s| !s.is_empty());

    if !has_cidr_source {
        info_println(format_args!("没有提供 CIDR 来源"));
        return Ok(());
    }

    let ip_count = args.ip_count.unwrap();

    // 收集 CIDR 来源
    if let Some(temp_cidr_file) = cidr::collect_cidr_sources(
        args.cidr.as_deref().unwrap(),
        args.cidr_url.as_deref().unwrap(),
        args.cidr_file.as_deref().unwrap(),
        ip_count,
    ) {
        use test::execute_cloudflare_st;
        // 无论是否提供 cloudflare_args 都执行测速，如果没有提供则使用空字符串
        let cloudflare_args = args.cloudflare_args.as_deref().unwrap();
        let temp_result_file = execute_cloudflare_st(
            cloudflare_args,
            &temp_cidr_file,
            args.output_file.as_deref(),
            args.output_txt.as_deref(),
            args.limit_count,
            args.select_ipv4,
            args.select_ipv6,
        )?;

        // 清理临时文件
        if !args.skip_cleanup {
            for file_path in [&temp_cidr_file, &temp_result_file] {
                fs::remove_file(file_path).ok();
            }
        } else {
            info_println(format_args!("跳过临时文件清理"));
        }
    }

    info_println(format_args!("CIDR 测速完毕"));
    Ok(())
}