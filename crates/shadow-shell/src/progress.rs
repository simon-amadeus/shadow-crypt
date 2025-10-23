use crate::display_progress;

pub struct ProgressCounter {
    current: std::sync::Mutex<u64>,
    total: u64,
}
impl ProgressCounter {
    pub fn new(total: u64) -> Self {
        Self {
            current: std::sync::Mutex::new(0),
            total,
        }
    }

    pub fn increment(&self) {
        let mut current = self.current.lock().unwrap();
        *current += 1;
        display_progress(*current, self.total);
    }
}
