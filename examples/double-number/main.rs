//! Tiny local project for trying the Henosis evidence workflow.
use std::{fs, io, thread, time::{Duration, Instant}};

fn main() -> io::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--pause") {
        fs::write("started.marker", "started\n")?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while !std::path::Path::new("release.marker").exists() {
            if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "release marker not found"));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    let input = fs::read_to_string("input.txt")?;
    let number: i64 = input.trim().parse().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let factor = if std::env::args().nth(1).as_deref() == Some("--factor-env") {
        if std::env::var_os("HENOSIS_UNSELECTED").is_some() {
            return Err(io::Error::other("unselected environment variable was inherited"));
        }
        std::env::var("HENOSIS_DEMO_FACTOR").map_err(io::Error::other)?
            .parse::<i64>().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
    } else { 2 };
    let result = number.checked_mul(factor).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "overflow"))?;
    fs::write("result.txt", format!("{result}\n"))?;
    if std::env::args().nth(1).as_deref() == Some("--pause") {
        fs::write("finished.marker", "finished\n")?;
    }
    Ok(())
}
