use clap::{Parser, Subcommand};
use cmd::reset;
use colored::Colorize;
use std::fmt;
use util::{log_error, log_info, syslog};
mod cmd;

const BANNER: &str = r" 

 █████ ██    ████████████   ████████  █████ ███    █████████  
██   ████    ██   ██   ██   ████   ████   ██████  ██████   ██ 
█████████    ██   ██   █████████████ █████████ ████ ████████  
██   ████    ██   ██   ██   ████   ████   ████  ██  ████      
██   ██ ██████    ██   ██   ████   ████   ████      ████

by 34n0@immerda.ch";

#[derive(Debug)]
struct ArCliError {
    message: String,
}

impl fmt::Display for ArCliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", "error:".red().bold(), self.message)
    }
}

#[derive(Debug)]
struct ArCliSuccess {
    message: String,
}

impl fmt::Display for ArCliSuccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", "success:".green().bold(), self.message)
    }
}

#[derive(Debug)]
struct ArCliInfo {
    message: String,
}

impl fmt::Display for ArCliInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", "info:".yellow().bold(), self.message)
    }
}

#[derive(Debug)]
enum ArCliResult {
    Success(Option<ArCliSuccess>),
    Info(ArCliInfo),
    Error(ArCliError),
}

impl fmt::Display for ArCliResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArCliResult::Success(Some(ref success)) => write!(f, "{success}"),
            ArCliResult::Success(None) => Ok(()),
            ArCliResult::Error(ref error) => write!(f, "{error}"),
            ArCliResult::Info(ref info) => write!(f, "{info}"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    arg_required_else_help = true,
    author = "34n0",
    about = &BANNER,
)]

struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(about = "Reset a locked PAM user")]
    Reset {
        #[clap(long, short)]
        user: String,
    },
}

fn main() {
    syslog::init_cli_log().unwrap_or_else(|e| println!("{e:?}: Error initializing cli log:"));

    let cli_res = match Cli::parse().command {
        Some(Command::Reset { user }) => reset::user(&user),
        _ => ArCliResult::Success(None),
    };

    match &cli_res {
        ArCliResult::Success(res) => {
            if let Some(res) = res {
                log_info!("{}", &res.message);
            }
        }
        ArCliResult::Error(res) => {
            log_error!("{}", &res.message);
        }
        ArCliResult::Info(_) => (),
    }

    println!("{cli_res}");
}
