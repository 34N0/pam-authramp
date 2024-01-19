use clap::{Parser, Subcommand};
use cmd::reset;
use util::{log_error, log_info, syslog};
mod cmd;

const BANNER: &str = r" 

 █████ ██    ████████████   ████████  █████ ███    █████████  
██   ████    ██   ██   ██   ████   ████   ██████  ██████   ██ 
█████████    ██   ██   █████████████ █████████ ████ ████████  
██   ████    ██   ██   ██   ████   ████   ████  ██  ████      
██   ██ ██████    ██   ██   ████   ████   ████      ████";

#[derive(Debug)]
struct ArCliError {
    message: String,
}

type ArCliResult = Result<Option<String>, ArCliError>;

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
    #[command(about = "Audit the PAM authramp log")]
    Audit,
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
        _ => Ok(None),
    };

    match cli_res {
        Ok(res) => {
            if let Some(res) = res {
                log_info!("{}", &res);
                println!("{}", &res);
            }
        }
        Err(e) => {
            log_error!("{}", &e.message);
            println!("{}", &e.message);
        }
    }
}
