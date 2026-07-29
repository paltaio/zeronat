//! Paces how often a PPPoE shell dials again after discovery gave up or a
//! session died before it had served.
//!
//! Neither loop is timed on its own. A datapath that gave up or has been
//! released emits nothing until the shell resets it, and an access concentrator
//! that answers a dial through PADS and then tears the session down answers the
//! next dial as fast as it is sent, so the wait here is the only thing keeping a
//! station off the segment. It runs on the shell's negotiation tick and doubles
//! per dial that fails to produce a session that lasts.

use std::time::Duration;

use tokio::time::Instant;

/// Negotiation ticks a shell waits before the first redial. An access
/// concentrator that stops serving usually starts again on its own, so a shell
/// that gave up keeps dialing at a falling rate rather than stopping.
pub const REDIAL_TICKS: u32 = 3;
/// Ceiling the redial wait doubles up to. A shell that bounces its channel
/// while every session is down starts the ladder over before it climbs this
/// far, so the top rungs are reached only where the shell keeps the channel.
const REDIAL_TICKS_MAX: u32 = 60;
/// How long a session has to stay up to count as having served. A session that
/// held this long proves the segment hands out sessions that last, so its drop
/// is a link flap: the shell dials again at once and the ladder starts over.
pub const SESSION_HELD: Duration = Duration::from_secs(20);

/// Whether the session that came up at `up_since` held long enough to serve.
pub fn held(up_since: Option<Instant>) -> bool {
    up_since.is_some_and(|since| since.elapsed() >= SESSION_HELD)
}

/// The wait pacing one session's next dial.
pub struct Redial {
    /// Ticks left before the next dial, or `None` when no dial is pending.
    wait: Option<u32>,
    /// Ticks the next wait is armed for.
    next: u32,
}

impl Default for Redial {
    fn default() -> Self {
        Redial {
            wait: None,
            next: REDIAL_TICKS,
        }
    }
}

impl Redial {
    /// Start the wait after a failed dial and report how long it is, or `None`
    /// when a wait is already running.
    pub fn arm(&mut self) -> Option<u32> {
        if self.wait.is_some() {
            return None;
        }
        let ticks = self.next;
        self.wait = Some(ticks);
        self.next = (self.next * 2).min(REDIAL_TICKS_MAX);
        Some(ticks)
    }

    /// Count one tick off the wait, reporting whether it is time to dial.
    pub fn due(&mut self) -> bool {
        let Some(left) = self.wait else {
            return false;
        };
        let left = left - 1;
        self.wait = (left > 0).then_some(left);
        left == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_redial_wait_doubles_up_to_the_ceiling() {
        let mut redial = Redial::default();
        let mut waits = Vec::new();
        for _ in 0..7 {
            let ticks = redial.arm().expect("a wait is already running");
            waits.push(ticks);
            for left in (0..ticks).rev() {
                assert_eq!(redial.due(), left == 0, "the wait dialed with {left} left");
            }
        }
        assert_eq!(waits, [3, 6, 12, 24, 48, 60, 60]);
    }

    #[tokio::test(start_paused = true)]
    async fn only_a_session_that_stayed_up_counts_as_held() {
        assert!(!held(None), "a session that never came up cannot have held");
        let up = Instant::now();
        assert!(!held(Some(up)), "a session that just came up has not held");
        tokio::time::advance(SESSION_HELD).await;
        assert!(held(Some(up)), "a session up for the full window has held");
    }
}
