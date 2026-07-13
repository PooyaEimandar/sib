use crate::render::runner::ExampleSettings;
use std::{error::Error, fmt, sync::Arc};
use wgpu::CurrentSurfaceTexture;
use winit::{dpi::PhysicalSize, event_loop::OwnedDisplayHandle, window::Window};

pub type RenderResult<T> = Result<T, RenderError>;

#[derive(Debug)]
pub enum RenderError {
    Message(String),
    Source(Box<dyn Error + Send + Sync>),
}

impl RenderError {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub fn source(error: impl Error + Send + Sync + 'static) -> Self {
        Self::Source(Box::new(error))
    }
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(message) => write!(f, "{message}"),
            Self::Source(error) => write!(f, "{error}"),
        }
    }
}

impl Error for RenderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Message(_) => None,
            Self::Source(error) => Some(error.as_ref()),
        }
    }
}

impl From<winit::error::EventLoopError> for RenderError {
    fn from(error: winit::error::EventLoopError) -> Self {
        Self::source(error)
    }
}

impl From<winit::error::OsError> for RenderError {
    fn from(error: winit::error::OsError) -> Self {
        Self::source(error)
    }
}

impl From<wgpu::CreateSurfaceError> for RenderError {
    fn from(error: wgpu::CreateSurfaceError) -> Self {
        Self::source(error)
    }
}

impl From<wgpu::RequestAdapterError> for RenderError {
    fn from(error: wgpu::RequestAdapterError) -> Self {
        Self::source(error)
    }
}

impl From<wgpu::RequestDeviceError> for RenderError {
    fn from(error: wgpu::RequestDeviceError) -> Self {
        Self::source(error)
    }
}

pub struct RenderContext {
    pub instance: wgpu::Instance,
    pub adapter: wgpu::Adapter,
    pub device: wgpu::Device,
    pub queue: wgpu::Queue,
    pub surface: wgpu::Surface<'static>,
    pub surface_config: wgpu::SurfaceConfiguration,
    pub window: Arc<Window>,
    pub size: PhysicalSize<u32>,
}

pub struct Frame {
    pub surface_texture: wgpu::SurfaceTexture,
    pub view: wgpu::TextureView,
}

impl RenderContext {
    pub async fn new(
        window: Arc<Window>,
        display_handle: OwnedDisplayHandle,
        settings: &ExampleSettings,
    ) -> RenderResult<Self> {
        let mut size = window.inner_size();
        #[cfg(target_arch = "wasm32")]
        {
            if let Some(viewport_size) = crate::render::web::viewport_physical_size() {
                size = viewport_size;
            } else if size.width <= 1 || size.height <= 1 {
                size = settings.initial_size;
            }
            let _ = window.request_inner_size(size);
        }
        size.width = size.width.max(1);
        size.height = size.height.max(1);

        let instance = wgpu::Instance::new(
            wgpu::InstanceDescriptor::new_with_display_handle_from_env(Box::new(display_handle)),
        );
        let surface = instance.create_surface(window.clone())?;
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: settings.power_preference,
                compatible_surface: Some(&surface),
                force_fallback_adapter: settings.force_fallback_adapter,
                ..Default::default()
            })
            .await?;

        let (device, queue) = adapter
            .request_device(&wgpu::DeviceDescriptor {
                label: Some("sib render device"),
                required_features: settings.required_features,
                required_limits: settings
                    .required_limits
                    .clone()
                    .using_resolution(adapter.limits()),
                experimental_features: wgpu::ExperimentalFeatures::disabled(),
                memory_hints: settings.memory_hints.clone(),
                trace: wgpu::Trace::Off,
            })
            .await?;

        let surface_config = surface
            .get_default_config(&adapter, size.width, size.height)
            .ok_or_else(|| RenderError::message("adapter does not support this window surface"))?;
        surface.configure(&device, &surface_config);

        Ok(Self {
            instance,
            adapter,
            device,
            queue,
            surface,
            surface_config,
            window,
            size,
        })
    }

    pub fn aspect_ratio(&self) -> f32 {
        self.surface_config.width as f32 / self.surface_config.height.max(1) as f32
    }

    pub fn gpu_device_info(&self) -> String {
        let info = self.adapter.get_info();
        let name = if info.name.trim().is_empty() {
            "unknown GPU"
        } else {
            info.name.as_str()
        };

        format!("{name} ({:?}, {:?})", info.backend, info.device_type)
    }

    pub fn resize(&mut self, new_size: PhysicalSize<u32>) {
        #[cfg(target_arch = "wasm32")]
        let new_size = {
            if let Some(viewport_size) = crate::render::web::viewport_physical_size() {
                viewport_size
            } else if (new_size.width <= 1 || new_size.height <= 1)
                && (self.surface_config.width > 1 && self.surface_config.height > 1)
            {
                return;
            } else {
                new_size
            }
        };

        let width = new_size.width.max(1);
        let height = new_size.height.max(1);

        if self.surface_config.width == width && self.surface_config.height == height {
            return;
        }

        self.size = PhysicalSize::new(width, height);
        self.surface_config.width = width;
        self.surface_config.height = height;
        self.surface.configure(&self.device, &self.surface_config);
    }

    pub fn recreate_surface(&mut self) -> RenderResult<()> {
        self.surface = self.instance.create_surface(self.window.clone())?;
        self.surface.configure(&self.device, &self.surface_config);
        Ok(())
    }

    pub fn acquire_frame(&mut self) -> RenderResult<Option<Frame>> {
        let surface_texture = match self.surface.get_current_texture() {
            CurrentSurfaceTexture::Success(texture) => texture,
            CurrentSurfaceTexture::Suboptimal(texture) => {
                drop(texture);
                self.surface.configure(&self.device, &self.surface_config);
                return Ok(None);
            }
            CurrentSurfaceTexture::Timeout | CurrentSurfaceTexture::Occluded => return Ok(None),
            CurrentSurfaceTexture::Outdated => {
                self.surface.configure(&self.device, &self.surface_config);
                return Ok(None);
            }
            CurrentSurfaceTexture::Lost => {
                self.recreate_surface()?;
                return Ok(None);
            }
            CurrentSurfaceTexture::Validation => {
                return Err(RenderError::message(
                    "surface texture acquisition failed validation",
                ));
            }
        };

        let view = surface_texture
            .texture
            .create_view(&wgpu::TextureViewDescriptor::default());

        Ok(Some(Frame {
            surface_texture,
            view,
        }))
    }

    pub fn submit(&self, encoder: wgpu::CommandEncoder) {
        self.queue.submit(std::iter::once(encoder.finish()));
    }
}
