//! Log output on standard error.
//!
//! Under systemd, standard error goes to the journal, which adds its own timestamps and
//! reads a leading `<N>` as the syslog priority of the line (`SyslogLevelPrefix=`, on by
//! default). So when standard error is the journal stream, lines carry that prefix and
//! no timestamp. Otherwise they are formatted for a terminal or a file.
//!
//! Messages that dependencies emit through the `log` crate, such as netlink-proto's
//! decoding errors, are forwarded as well.

use std::fmt;
use std::fs;
use std::io::{self, IsTerminal};
use std::os::unix::fs::MetadataExt;

use tracing::level_filters::LevelFilter;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

/// Installs the global logger. Call once, at startup.
///
/// # Panics
///
/// Panics if a global logger is already installed.
pub fn init() {
    let builder = tracing_subscriber::fmt()
        .with_max_level(LevelFilter::INFO)
        .with_writer(io::stderr);
    if stderr_is_journal() {
        let format = tracing_subscriber::fmt::format()
            .without_time()
            .with_ansi(false);
        builder
            .with_ansi(false)
            .event_format(SyslogPrefix(format))
            .finish()
            .init();
    } else {
        builder
            .with_ansi(io::stderr().is_terminal())
            .finish()
            .init();
    }
}

/// Whether standard error is connected to the journal. systemd sets `JOURNAL_STREAM` to
/// `<device>:<inode>` of the journal stream it connects. Comparing that with standard
/// error rules out a variable inherited by a process whose output was redirected.
fn stderr_is_journal() -> bool {
    let Ok(stream) = std::env::var("JOURNAL_STREAM") else {
        return false;
    };
    let Ok(stderr) = fs::metadata("/proc/self/fd/2") else {
        return false;
    };
    stream == format!("{}:{}", stderr.dev(), stderr.ino())
}

/// Syslog priority of a level, as used by the `<N>` prefix.
const fn priority(level: Level) -> u8 {
    match level {
        Level::ERROR => 3,
        Level::WARN => 4,
        Level::INFO => 6,
        Level::DEBUG | Level::TRACE => 7,
    }
}

/// Prepends `<N>` to every line produced by the inner format.
struct SyslogPrefix<F>(F);

impl<S, N, F> FormatEvent<S, N> for SyslogPrefix<F>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
    F: FormatEvent<S, N>,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        write!(writer, "<{}>", priority(*event.metadata().level()))?;
        self.0.format_event(ctx, writer, event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_levels_to_syslog_priorities() {
        assert_eq!(priority(Level::ERROR), 3);
        assert_eq!(priority(Level::WARN), 4);
        assert_eq!(priority(Level::INFO), 6);
        assert_eq!(priority(Level::DEBUG), 7);
        assert_eq!(priority(Level::TRACE), 7);
    }
}
