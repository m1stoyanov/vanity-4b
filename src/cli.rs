use gumdrop::Options;

// CLI Options
#[derive(Debug, Options, Clone)]
pub struct Opts {
    pub help: bool,
    #[options(help = "Desired pattern, e.g., \"0x01234\"", required, short = "x", meta = "")]
    pub pattern: String,
    #[options(
        help = "Function name, e.g., \"checkAddressInfo\"",
        required,
        short = "f",
        meta = ""
    )]
    pub fn_name: String,
    #[options(
        help = "Optional function parameters e.g., \"address,address,uint256\"",
        short = "p",
        meta = ""
    )]
    pub fn_parameters: Option<String>,
    #[options(
        help = "Number of threads to use (default: number of physical cores)",
        short = "t",
        meta = ""
    )]
    pub num_threads: Option<usize>,
}
