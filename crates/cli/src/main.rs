use clap::{Parser, command};


#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short)]
    name: String,
}

fn main() {
    let args = Args::parse();

    println!("{args:?}");
}