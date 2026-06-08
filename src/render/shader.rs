use std::borrow::Cow;

pub fn wgsl_module(
    device: &wgpu::Device,
    label: impl Into<Option<&'static str>>,
    source: &'static str,
) -> wgpu::ShaderModule {
    device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: label.into(),
        source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(source)),
    })
}
