use std::sync::Mutex;

pub struct ProgressCounter {
    current: Mutex<u64>,
    total: u64,
}
impl ProgressCounter {
    pub fn new(total: u64) -> Self {
        Self {
            current: Mutex::new(0),
            total,
        }
    }

    pub fn increment(&self) {
        let mut current = self.current.lock().unwrap_or_else(|e| e.into_inner());
        *current += 1;
    }
    pub fn get_current(&self) -> u64 {
        let current = self.current.lock().unwrap_or_else(|e| e.into_inner());
        *current
    }
    pub fn get_total(&self) -> u64 {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let counter = ProgressCounter::new(100);
        assert_eq!(counter.get_current(), 0);
        assert_eq!(counter.get_total(), 100);
    }

    #[test]
    fn test_increment() {
        let counter = ProgressCounter::new(10);
        assert_eq!(counter.get_current(), 0);
        counter.increment();
        assert_eq!(counter.get_current(), 1);
        counter.increment();
        assert_eq!(counter.get_current(), 2);
    }

    #[test]
    fn test_get_current_and_total() {
        let counter = ProgressCounter::new(50);
        assert_eq!(counter.get_current(), 0);
        assert_eq!(counter.get_total(), 50);
        counter.increment();
        assert_eq!(counter.get_current(), 1);
        assert_eq!(counter.get_total(), 50);
    }
}
