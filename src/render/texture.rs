use crate::render::{RenderError, RenderResult};

pub const DEPTH_FORMAT: wgpu::TextureFormat = wgpu::TextureFormat::Depth32Float;

#[derive(Clone, Debug)]
pub struct ImageRgba8 {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

impl ImageRgba8 {
    pub fn new(width: u32, height: u32, rgba: Vec<u8>) -> RenderResult<Self> {
        validate_rgba_len(width, height, rgba.len())?;
        Ok(Self {
            width,
            height,
            rgba,
        })
    }
}

pub struct Texture {
    pub texture: wgpu::Texture,
    pub view: wgpu::TextureView,
    pub sampler: wgpu::Sampler,
    pub size: wgpu::Extent3d,
    pub format: wgpu::TextureFormat,
}

impl Texture {
    pub fn depth(device: &wgpu::Device, config: &wgpu::SurfaceConfiguration) -> Self {
        let size = wgpu::Extent3d {
            width: config.width,
            height: config.height,
            depth_or_array_layers: 1,
        };
        let texture = device.create_texture(&wgpu::TextureDescriptor {
            label: Some("depth texture"),
            size,
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: DEPTH_FORMAT,
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT | wgpu::TextureUsages::TEXTURE_BINDING,
            view_formats: &[],
        });
        let view = texture.create_view(&wgpu::TextureViewDescriptor::default());
        let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            label: Some("depth sampler"),
            address_mode_u: wgpu::AddressMode::ClampToEdge,
            address_mode_v: wgpu::AddressMode::ClampToEdge,
            address_mode_w: wgpu::AddressMode::ClampToEdge,
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            mipmap_filter: wgpu::MipmapFilterMode::Nearest,
            compare: Some(wgpu::CompareFunction::LessEqual),
            ..Default::default()
        });

        Self {
            texture,
            view,
            sampler,
            size,
            format: DEPTH_FORMAT,
        }
    }

    pub fn from_rgba8_2d(
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        label: impl Into<Option<&'static str>>,
        image: &ImageRgba8,
    ) -> RenderResult<Self> {
        Self::from_rgba8_layers(
            device,
            queue,
            label,
            image.width,
            image.height,
            &[image.rgba.as_slice()],
            wgpu::TextureViewDimension::D2,
        )
    }

    pub fn from_rgba8_cube(
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        label: impl Into<Option<&'static str>>,
        faces: &[ImageRgba8],
    ) -> RenderResult<Self> {
        if faces.len() != 6 {
            return Err(RenderError::message(format!(
                "cubemap expected 6 faces, got {}",
                faces.len()
            )));
        }

        let (width, height) = shared_extent("cubemap", faces)?;
        let layers = faces
            .iter()
            .map(|face| face.rgba.as_slice())
            .collect::<Vec<_>>();

        Self::from_rgba8_layers(
            device,
            queue,
            label,
            width,
            height,
            &layers,
            wgpu::TextureViewDimension::Cube,
        )
    }

    pub fn from_rgba8_array(
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        label: impl Into<Option<&'static str>>,
        images: &[ImageRgba8],
    ) -> RenderResult<Self> {
        let (width, height) = shared_extent("texture array", images)?;
        let layers = images
            .iter()
            .map(|image| image.rgba.as_slice())
            .collect::<Vec<_>>();

        Self::from_rgba8_layers(
            device,
            queue,
            label,
            width,
            height,
            &layers,
            wgpu::TextureViewDimension::D2Array,
        )
    }

    fn from_rgba8_layers(
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        label: impl Into<Option<&'static str>>,
        width: u32,
        height: u32,
        layers: &[&[u8]],
        view_dimension: wgpu::TextureViewDimension,
    ) -> RenderResult<Self> {
        if layers.is_empty() {
            return Err(RenderError::message("texture has no RGBA layers"));
        }

        for (index, layer) in layers.iter().enumerate() {
            validate_rgba_len(width, height, layer.len()).map_err(|error| {
                RenderError::message(format!("invalid texture layer {index}: {error}"))
            })?;
        }

        let layer_count = layers.len() as u32;
        let size = wgpu::Extent3d {
            width,
            height,
            depth_or_array_layers: layer_count,
        };
        let format = wgpu::TextureFormat::Rgba8UnormSrgb;
        let label = label.into();
        let texture = device.create_texture(&wgpu::TextureDescriptor {
            label,
            size,
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format,
            usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
            view_formats: &[],
        });

        for (layer_index, rgba) in layers.iter().enumerate() {
            queue.write_texture(
                wgpu::TexelCopyTextureInfo {
                    texture: &texture,
                    mip_level: 0,
                    origin: wgpu::Origin3d {
                        x: 0,
                        y: 0,
                        z: layer_index as u32,
                    },
                    aspect: wgpu::TextureAspect::All,
                },
                rgba,
                wgpu::TexelCopyBufferLayout {
                    offset: 0,
                    bytes_per_row: Some(width * 4),
                    rows_per_image: Some(height),
                },
                wgpu::Extent3d {
                    width,
                    height,
                    depth_or_array_layers: 1,
                },
            );
        }

        let view = texture.create_view(&wgpu::TextureViewDescriptor {
            label,
            format: Some(format),
            dimension: Some(view_dimension),
            aspect: wgpu::TextureAspect::All,
            base_mip_level: 0,
            mip_level_count: Some(1),
            base_array_layer: 0,
            array_layer_count: Some(layer_count),
            usage: Some(wgpu::TextureUsages::TEXTURE_BINDING),
        });
        let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            label,
            address_mode_u: wgpu::AddressMode::ClampToEdge,
            address_mode_v: wgpu::AddressMode::ClampToEdge,
            address_mode_w: wgpu::AddressMode::ClampToEdge,
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            mipmap_filter: wgpu::MipmapFilterMode::Nearest,
            ..Default::default()
        });

        Ok(Self {
            texture,
            view,
            sampler,
            size,
            format,
        })
    }
}

fn shared_extent(label: &str, images: &[ImageRgba8]) -> RenderResult<(u32, u32)> {
    let first = images
        .first()
        .ok_or_else(|| RenderError::message(format!("{label} has no images")))?;
    let width = first.width;
    let height = first.height;

    for (index, image) in images.iter().enumerate() {
        if image.width != width || image.height != height {
            return Err(RenderError::message(format!(
                "{label} image {index} has size {}x{}, expected {width}x{height}",
                image.width, image.height
            )));
        }
    }

    Ok((width, height))
}

fn validate_rgba_len(width: u32, height: u32, actual_len: usize) -> RenderResult<()> {
    let expected_len = width
        .checked_mul(height)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(|| RenderError::message("RGBA image dimensions overflow"))?
        as usize;

    if actual_len != expected_len {
        return Err(RenderError::message(format!(
            "RGBA image has {actual_len} bytes, expected {expected_len}"
        )));
    }

    Ok(())
}
