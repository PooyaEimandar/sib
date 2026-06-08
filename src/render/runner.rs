use std::{mem, sync::Arc};
use winit::{
    application::ApplicationHandler,
    dpi::PhysicalSize,
    event::WindowEvent,
    event_loop::{ActiveEventLoop, ControlFlow, EventLoop, OwnedDisplayHandle},
    window::{Window, WindowAttributes, WindowId},
};

#[cfg(target_arch = "wasm32")]
use winit::dpi::Size;

#[cfg(target_arch = "wasm32")]
use winit::event_loop::EventLoopProxy;

#[cfg(target_arch = "wasm32")]
use winit::platform::web::{EventLoopExtWebSys, WindowAttributesExtWebSys};

use crate::render::{RenderContext, RenderError, RenderResult};

#[derive(Clone, Debug)]
pub struct ExampleSettings {
    pub title: String,
    pub initial_size: PhysicalSize<u32>,
    pub power_preference: wgpu::PowerPreference,
    pub force_fallback_adapter: bool,
    pub required_features: wgpu::Features,
    pub required_limits: wgpu::Limits,
    pub memory_hints: wgpu::MemoryHints,
}

impl Default for ExampleSettings {
    fn default() -> Self {
        Self {
            title: "sib render example".to_owned(),
            initial_size: PhysicalSize::new(1280, 720),
            power_preference: wgpu::PowerPreference::HighPerformance,
            force_fallback_adapter: false,
            required_features: wgpu::Features::empty(),
            required_limits: wgpu::Limits::downlevel_defaults(),
            memory_hints: wgpu::MemoryHints::MemoryUsage,
        }
    }
}

pub trait Example: 'static {
    fn settings(&self) -> ExampleSettings {
        ExampleSettings::default()
    }

    fn init(&mut self, _context: &mut RenderContext) -> RenderResult<()> {
        Ok(())
    }

    fn resize(&mut self, _context: &mut RenderContext, _size: PhysicalSize<u32>) {}

    fn input(&mut self, _context: &mut RenderContext, _event: &WindowEvent) -> bool {
        false
    }

    fn update(&mut self, _context: &mut RenderContext) {}

    fn render(
        &mut self,
        context: &mut RenderContext,
        view: &wgpu::TextureView,
        encoder: &mut wgpu::CommandEncoder,
    ) -> RenderResult<()>;
}

pub fn run(example: impl Example) -> RenderResult<()> {
    #[cfg(not(target_arch = "wasm32"))]
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .try_init();

    #[cfg(target_arch = "wasm32")]
    console_error_panic_hook::set_once();

    let event_loop = EventLoop::<RenderEvent>::with_user_event().build()?;
    event_loop.set_control_flow(ControlFlow::Poll);

    #[cfg(not(target_arch = "wasm32"))]
    {
        let mut application = Application::new(example);
        event_loop.run_app(&mut application)?;

        if let Some(error) = application.error {
            Err(error)
        } else {
            Ok(())
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        let application = Application::new(example, event_loop.create_proxy());
        event_loop.spawn_app(application);
        Ok(())
    }
}

struct Initialized {
    context: RenderContext,
    example: Box<dyn Example>,
}

enum RenderEvent {
    Initialized(RenderResult<Initialized>),
}

enum AppState {
    New,
    Initializing,
    Running {
        context: RenderContext,
        example: Box<dyn Example>,
    },
    Failed,
}

struct Application {
    settings: ExampleSettings,
    state: AppState,
    pending_example: Option<Box<dyn Example>>,
    error: Option<RenderError>,
    #[cfg(target_arch = "wasm32")]
    proxy: EventLoopProxy<RenderEvent>,
}

impl Application {
    #[cfg(not(target_arch = "wasm32"))]
    fn new(example: impl Example) -> Self {
        let settings = example.settings();

        Self {
            settings,
            state: AppState::New,
            pending_example: Some(Box::new(example)),
            error: None,
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn new(example: impl Example, proxy: EventLoopProxy<RenderEvent>) -> Self {
        let settings = example.settings();

        Self {
            settings,
            state: AppState::New,
            pending_example: Some(Box::new(example)),
            error: None,
            proxy,
        }
    }

    fn fail(&mut self, event_loop: &ActiveEventLoop, error: RenderError) {
        self.error = Some(error);
        self.state = AppState::Failed;
        event_loop.exit();
    }

    fn request_redraw(&self) {
        if let AppState::Running { context, .. } = &self.state {
            context.window.request_redraw();
        }
    }

    fn window_attributes(&self) -> WindowAttributes {
        #[cfg(target_arch = "wasm32")]
        {
            let initial_size = crate::render::web::viewport_logical_size()
                .map(Size::from)
                .unwrap_or_else(|| self.settings.initial_size.into());

            Window::default_attributes()
                .with_title(self.settings.title.clone())
                .with_inner_size(initial_size)
                .with_append(true)
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            Window::default_attributes()
                .with_title(self.settings.title.clone())
                .with_inner_size(self.settings.initial_size)
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn initialize(
        &mut self,
        event_loop: &ActiveEventLoop,
        window: Arc<Window>,
        display_handle: OwnedDisplayHandle,
    ) {
        let mut context =
            match pollster::block_on(RenderContext::new(window, display_handle, &self.settings)) {
                Ok(context) => context,
                Err(error) => {
                    self.fail(event_loop, error);
                    return;
                }
            };

        let Some(mut example) = self.pending_example.take() else {
            self.fail(
                event_loop,
                RenderError::message("application resumed without an example"),
            );
            return;
        };

        if let Err(error) = example.init(&mut context) {
            self.fail(event_loop, error);
            return;
        }

        self.state = AppState::Running { context, example };
        self.request_redraw();
    }

    #[cfg(target_arch = "wasm32")]
    fn initialize(
        &mut self,
        event_loop: &ActiveEventLoop,
        window: Arc<Window>,
        display_handle: OwnedDisplayHandle,
    ) {
        let Some(mut example) = self.pending_example.take() else {
            self.fail(
                event_loop,
                RenderError::message("application resumed without an example"),
            );
            return;
        };

        let proxy = self.proxy.clone();
        let settings = self.settings.clone();
        self.state = AppState::Initializing;

        wasm_bindgen_futures::spawn_local(async move {
            let result = async {
                let mut context = RenderContext::new(window, display_handle, &settings).await?;
                example.init(&mut context)?;
                Ok(Initialized { context, example })
            }
            .await;

            let _ = proxy.send_event(RenderEvent::Initialized(result));
        });
    }

    fn accept_initialized(
        &mut self,
        event_loop: &ActiveEventLoop,
        initialized: RenderResult<Initialized>,
    ) {
        match initialized {
            Ok(Initialized { context, example }) => {
                self.state = AppState::Running { context, example };
                self.request_redraw();
            }
            Err(error) => self.fail(event_loop, error),
        }
    }
}

impl ApplicationHandler<RenderEvent> for Application {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if !matches!(self.state, AppState::New) {
            return;
        }

        let window = match event_loop.create_window(self.window_attributes()) {
            Ok(window) => Arc::new(window),
            Err(error) => {
                self.fail(event_loop, error.into());
                return;
            }
        };

        let display_handle = event_loop.owned_display_handle();
        self.initialize(event_loop, window, display_handle);
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: RenderEvent) {
        match event {
            RenderEvent::Initialized(result) => self.accept_initialized(event_loop, result),
        }
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        event: WindowEvent,
    ) {
        let AppState::Running { context, example } = &mut self.state else {
            return;
        };

        if example.input(context, &event) {
            return;
        }

        match event {
            WindowEvent::CloseRequested => event_loop.exit(),
            WindowEvent::Resized(size) => {
                context.resize(size);
                example.resize(context, size);
                context.window.request_redraw();
            }
            WindowEvent::RedrawRequested => {
                example.update(context);

                let Some(frame) = (match context.acquire_frame() {
                    Ok(frame) => frame,
                    Err(error) => {
                        self.fail(event_loop, error);
                        return;
                    }
                }) else {
                    context.window.request_redraw();
                    return;
                };

                let mut encoder =
                    context
                        .device
                        .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                            label: Some("sib render frame encoder"),
                        });

                if let Err(error) = example.render(context, &frame.view, &mut encoder) {
                    self.fail(event_loop, error);
                    return;
                }

                context.submit(encoder);
                frame.surface_texture.present();
                context.window.request_redraw();
            }
            WindowEvent::Destroyed => {
                self.state = AppState::Failed;
            }
            _ => {}
        }
    }

    fn suspended(&mut self, _event_loop: &ActiveEventLoop) {
        if matches!(self.state, AppState::Running { .. }) {
            let AppState::Running { example, .. } = mem::replace(&mut self.state, AppState::Failed)
            else {
                return;
            };
            self.pending_example = Some(example);
            self.state = AppState::New;
        }
    }

    fn about_to_wait(&mut self, _event_loop: &ActiveEventLoop) {
        self.request_redraw();
    }
}
