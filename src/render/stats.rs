use web_time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct FrameStats {
    sample_started_at: Instant,
    last_frame_at: Instant,
    sample_duration: Duration,
    frames_in_sample: u32,
    fps: f32,
    delta_seconds: f32,
}

impl Default for FrameStats {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameStats {
    pub fn new() -> Self {
        let now = Instant::now();

        Self {
            sample_started_at: now,
            last_frame_at: now,
            sample_duration: Duration::from_millis(500),
            frames_in_sample: 0,
            fps: 0.0,
            delta_seconds: 0.0,
        }
    }

    pub fn with_sample_duration(sample_duration: Duration) -> Self {
        Self {
            sample_duration,
            ..Self::new()
        }
    }

    pub fn tick(&mut self) -> bool {
        let now = Instant::now();
        self.delta_seconds = (now - self.last_frame_at).as_secs_f32();
        self.last_frame_at = now;
        self.frames_in_sample += 1;

        let elapsed = now - self.sample_started_at;
        if elapsed < self.sample_duration {
            return false;
        }

        self.fps = self.frames_in_sample as f32 / elapsed.as_secs_f32().max(f32::EPSILON);
        self.frames_in_sample = 0;
        self.sample_started_at = now;
        true
    }

    pub fn fps(&self) -> f32 {
        self.fps
    }

    pub fn delta_seconds(&self) -> f32 {
        self.delta_seconds
    }
}
