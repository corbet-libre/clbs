use super::*;
use std::time::Duration;

#[test]
fn wall_clock_conversion_refuses_before_epoch_and_preserves_seconds() {
    assert_eq!(unix_seconds(SystemTime::UNIX_EPOCH), Ok(0));
    let before = SystemTime::UNIX_EPOCH - Duration::from_nanos(1);
    assert_eq!(unix_seconds(before), Err(Error::Clock));
    let after = SystemTime::UNIX_EPOCH + Duration::from_millis(2500);
    assert_eq!(unix_seconds(after), Ok(2));
    assert!(SystemClock.now().unwrap() > 0);
}
