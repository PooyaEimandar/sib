pub fn begin_color_depth<'encoder>(
    encoder: &'encoder mut wgpu::CommandEncoder,
    label: impl Into<Option<&'static str>>,
    color_view: &'encoder wgpu::TextureView,
    depth_view: Option<&'encoder wgpu::TextureView>,
    clear_color: wgpu::Color,
    clear_depth: f32,
) -> wgpu::RenderPass<'encoder> {
    let depth_stencil_attachment = depth_view.map(|view| wgpu::RenderPassDepthStencilAttachment {
        view,
        depth_ops: Some(wgpu::Operations {
            load: wgpu::LoadOp::Clear(clear_depth),
            store: wgpu::StoreOp::Store,
        }),
        stencil_ops: None,
    });

    encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
        label: label.into(),
        color_attachments: &[Some(wgpu::RenderPassColorAttachment {
            view: color_view,
            depth_slice: None,
            resolve_target: None,
            ops: wgpu::Operations {
                load: wgpu::LoadOp::Clear(clear_color),
                store: wgpu::StoreOp::Store,
            },
        })],
        depth_stencil_attachment,
        timestamp_writes: None,
        occlusion_query_set: None,
        multiview_mask: None,
    })
}

pub fn begin_color_load<'encoder>(
    encoder: &'encoder mut wgpu::CommandEncoder,
    label: impl Into<Option<&'static str>>,
    color_view: &'encoder wgpu::TextureView,
) -> wgpu::RenderPass<'encoder> {
    encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
        label: label.into(),
        color_attachments: &[Some(wgpu::RenderPassColorAttachment {
            view: color_view,
            depth_slice: None,
            resolve_target: None,
            ops: wgpu::Operations {
                load: wgpu::LoadOp::Load,
                store: wgpu::StoreOp::Store,
            },
        })],
        depth_stencil_attachment: None,
        timestamp_writes: None,
        occlusion_query_set: None,
        multiview_mask: None,
    })
}
