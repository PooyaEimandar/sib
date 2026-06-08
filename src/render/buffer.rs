use bytemuck::Pod;
use wgpu::util::DeviceExt;

pub fn buffer_from_data<T: Pod>(
    device: &wgpu::Device,
    label: impl Into<Option<&'static str>>,
    data: &[T],
    usage: wgpu::BufferUsages,
) -> wgpu::Buffer {
    device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: label.into(),
        contents: bytemuck::cast_slice(data),
        usage,
    })
}

pub fn vertex_buffer<T: Pod>(
    device: &wgpu::Device,
    label: impl Into<Option<&'static str>>,
    vertices: &[T],
) -> wgpu::Buffer {
    buffer_from_data(device, label, vertices, wgpu::BufferUsages::VERTEX)
}

pub fn index_buffer<T: Pod>(
    device: &wgpu::Device,
    label: impl Into<Option<&'static str>>,
    indices: &[T],
) -> wgpu::Buffer {
    buffer_from_data(device, label, indices, wgpu::BufferUsages::INDEX)
}

pub fn uniform_buffer<T: Pod>(
    device: &wgpu::Device,
    label: impl Into<Option<&'static str>>,
    data: &T,
) -> wgpu::Buffer {
    buffer_from_data(
        device,
        label,
        std::slice::from_ref(data),
        wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
    )
}
