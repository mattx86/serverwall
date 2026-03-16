use chrono::{DateTime, TimeDelta, Utc};
use serverwall_core::config::schema::RetryConfig;

/// Manages retry scheduling for queued messages.
pub struct RetryScheduler {
    /// Parsed retry intervals (durations).
    intervals: Vec<TimeDelta>,
    /// Maximum age before a message is considered expired.
    max_age: TimeDelta,
    /// Maximum number of delivery attempts.
    max_attempts: u32,
}

impl RetryScheduler {
    /// Build a scheduler from the relay retry configuration.
    pub fn new(config: &RetryConfig) -> Self {
        let intervals: Vec<TimeDelta> = config
            .intervals
            .iter()
            .filter_map(|s| parse_duration(s))
            .collect();

        let max_age = parse_duration(&config.max_age).unwrap_or_else(|| TimeDelta::days(5));

        Self {
            intervals,
            max_age,
            max_attempts: config.max_attempts,
        }
    }

    /// Return the next retry time for the given attempt number, or `None` if
    /// the maximum number of attempts has been exceeded.
    pub fn next_retry_time(&self, attempt: u32) -> Option<DateTime<Utc>> {
        if attempt >= self.max_attempts {
            return None;
        }

        let delay = if (attempt as usize) < self.intervals.len() {
            self.intervals[attempt as usize]
        } else {
            // After exhausting the explicit list, repeat the last interval
            self.intervals
                .last()
                .copied()
                .unwrap_or_else(|| TimeDelta::hours(1))
        };

        Some(Utc::now() + delay)
    }

    /// Check whether a message created at `created` has exceeded `max_age`.
    pub fn is_expired(&self, created: DateTime<Utc>) -> bool {
        Utc::now() - created > self.max_age
    }
}

/// Parse a simple duration string such as "5m", "2h", "1d", "30s".
fn parse_duration(s: &str) -> Option<TimeDelta> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (num_str, unit) = s.split_at(s.len() - 1);
    let value: i64 = num_str.parse().ok()?;

    match unit {
        "s" => TimeDelta::try_seconds(value),
        "m" => TimeDelta::try_minutes(value),
        "h" => TimeDelta::try_hours(value),
        "d" => TimeDelta::try_days(value),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("5m"), TimeDelta::try_minutes(5));
        assert_eq!(parse_duration("2h"), TimeDelta::try_hours(2));
        assert_eq!(parse_duration("1d"), TimeDelta::try_days(1));
        assert_eq!(parse_duration("30s"), TimeDelta::try_seconds(30));
        assert!(parse_duration("").is_none());
        assert!(parse_duration("abc").is_none());
    }

    #[test]
    fn test_next_retry_time() {
        let config = RetryConfig {
            intervals: vec!["5m".into(), "10m".into(), "1h".into()],
            max_age: "5d".into(),
            max_attempts: 5,
        };
        let sched = RetryScheduler::new(&config);

        // Attempt 0, 1, 2 use explicit intervals
        assert!(sched.next_retry_time(0).is_some());
        assert!(sched.next_retry_time(2).is_some());
        // Attempt 3 falls back to last interval
        assert!(sched.next_retry_time(3).is_some());
        // Attempt 5 exceeds max_attempts
        assert!(sched.next_retry_time(5).is_none());
    }

    #[test]
    fn test_is_expired() {
        let config = RetryConfig {
            intervals: vec!["5m".into()],
            max_age: "1h".into(),
            max_attempts: 10,
        };
        let sched = RetryScheduler::new(&config);

        let recent = Utc::now() - TimeDelta::minutes(30);
        assert!(!sched.is_expired(recent));

        let old = Utc::now() - TimeDelta::hours(2);
        assert!(sched.is_expired(old));
    }
}
