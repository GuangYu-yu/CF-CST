use colored::Colorize;
use std::fs;

mod args;
mod cidr;
mod csv;
mod test;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = args::parse_args();
    println!("{}", "# CF-CST".blue());

    // 检查是否提供 CIDR 来源
    let has_cidr_source = args.cidr.as_deref().map_or(false, |s| !s.is_empty())
        || args.cidr_url.as_deref().map_or(false, |s| !s.is_empty())
        || args.cidr_file.as_deref().map_or(false, |s| !s.is_empty());

    if !has_cidr_source {
        println!("{} 没有提供 CIDR 来源", "[信息]".cyan().bold());
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
            &args.file_name,
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
            println!("{} 跳过临时文件清理", "[信息]".cyan().bold());
        }
    }

    println!("{} CIDR 测速完毕", "[信息]".cyan().bold());
    Ok(())
}