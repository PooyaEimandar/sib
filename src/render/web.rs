use winit::dpi::{LogicalSize, PhysicalSize};

pub(crate) fn viewport_logical_size() -> Option<LogicalSize<f64>> {
    let window = web_sys::window()?;
    let (width, height) = if let Some(viewport) = window.visual_viewport() {
        (viewport.width(), viewport.height())
    } else {
        (
            window.inner_width().ok()?.as_f64()?,
            window.inner_height().ok()?.as_f64()?,
        )
    };

    if width.is_finite() && height.is_finite() && width > 0.0 && height > 0.0 {
        Some(LogicalSize::new(width, height))
    } else {
        None
    }
}

pub(crate) fn viewport_physical_size() -> Option<PhysicalSize<u32>> {
    let window = web_sys::window()?;
    let scale_factor = window.device_pixel_ratio().max(1.0);
    let size = viewport_logical_size()?;

    Some(PhysicalSize::new(
        physical_extent(size.width, scale_factor),
        physical_extent(size.height, scale_factor),
    ))
}

fn physical_extent(logical_extent: f64, scale_factor: f64) -> u32 {
    (logical_extent * scale_factor)
        .round()
        .clamp(1.0, u32::MAX as f64) as u32
}
