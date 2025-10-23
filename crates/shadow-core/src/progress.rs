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
        let mut current = self.current.lock().unwrap();
        *current += 1;
    }
    pub fn get_current(&self) -> u64 {
        let current = self.current.lock().unwrap();
        *current
    }
    pub fn get_total(&self) -> u64 {
        self.total
    }
}
