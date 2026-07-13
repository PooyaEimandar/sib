use bytemuck::{Pod, Zeroable};
use glam::{Mat4, Vec3};

#[derive(Clone, Copy, Debug)]
pub struct Camera {
    pub eye: Vec3,
    pub target: Vec3,
    pub up: Vec3,
    pub aspect: f32,
    pub fovy_radians: f32,
    pub znear: f32,
    pub zfar: f32,
}

impl Camera {
    pub fn new(eye: Vec3, target: Vec3, aspect: f32) -> Self {
        Self {
            eye,
            target,
            up: Vec3::Y,
            aspect,
            fovy_radians: 45.0_f32.to_radians(),
            znear: 0.1,
            zfar: 256.0,
        }
    }

    pub fn view_projection_matrix(&self) -> Mat4 {
        // Right-handed view * projection. The `directx` projection variant has NDC Z in
        // [0, 1] — the depth range wgpu/Metal/D3D expect — so no extra OpenGL->wgpu clip
        // remap is needed (the old clip matrix double-remapped depth into [0.5, 1.0]).
        let proj = glam::camera::rh::proj::directx::perspective(
            self.fovy_radians,
            self.aspect,
            self.znear,
            self.zfar,
        );
        let view = glam::camera::rh::view::look_at_mat4(self.eye, self.target, self.up);
        proj * view
    }

    pub fn uniform(&self) -> CameraUniform {
        CameraUniform {
            view_projection: self.view_projection_matrix().to_cols_array_2d(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct CameraUniform {
    pub view_projection: [[f32; 4]; 4],
}
