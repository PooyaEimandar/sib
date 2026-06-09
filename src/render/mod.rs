pub mod bind_group;
pub mod buffer;
pub mod camera;
pub mod context;
pub mod render_pass;
pub mod runner;
pub mod shader;
pub mod stats;
pub mod text;
pub mod texture;

#[cfg(target_arch = "wasm32")]
pub(crate) mod web;

pub use bytemuck;
pub use context::{Frame, RenderContext, RenderError, RenderResult};
pub use glam;
pub use runner::{Example, ExampleSettings, run};
pub use stats::FrameStats;
pub use wgpu;
pub use winit;
