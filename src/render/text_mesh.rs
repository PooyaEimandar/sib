use crate::render::{RenderError, RenderResult};
use bytemuck::{Pod, Zeroable};
use glyphon::{Attrs, Buffer, Family, FontSystem, Metrics, Shaping, Wrap, cosmic_text::Align};
use skrifa::{
    FontRef, GlyphId, MetadataProvider,
    instance::{LocationRef, Size},
    outline::{DrawSettings, OutlinePen},
};

#[derive(Clone, Copy, Debug)]
pub enum TextMeshFamily {
    SansSerif,
    Serif,
    Monospace,
    Name(&'static str),
}

impl TextMeshFamily {
    fn to_glyphon(self) -> Family<'static> {
        match self {
            Self::SansSerif => Family::SansSerif,
            Self::Serif => Family::Serif,
            Self::Monospace => Family::Monospace,
            Self::Name(name) => Family::Name(name),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TextMeshOptions {
    pub font_size: f32,
    pub line_height: f32,
    pub layout_width: Option<f32>,
    pub layout_height: Option<f32>,
    pub depth: f32,
    pub stroke_width: f32,
    pub curve_steps: usize,
    pub family: TextMeshFamily,
    pub shaping: Shaping,
    pub align: Option<Align>,
    pub wrap: Wrap,
    pub center: bool,
}

impl Default for TextMeshOptions {
    fn default() -> Self {
        Self {
            font_size: 1.0,
            line_height: 1.25,
            layout_width: None,
            layout_height: None,
            depth: 0.1,
            stroke_width: 0.035,
            curve_steps: 8,
            family: TextMeshFamily::SansSerif,
            shaping: Shaping::Advanced,
            align: None,
            wrap: Wrap::None,
            center: true,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct TextMeshVertex {
    pub position: [f32; 3],
    pub normal: [f32; 3],
    pub color: [f32; 4],
}

impl TextMeshVertex {
    pub const ATTRIBUTES: [wgpu::VertexAttribute; 3] =
        wgpu::vertex_attr_array![0 => Float32x3, 1 => Float32x3, 2 => Float32x4];

    pub fn layout() -> wgpu::VertexBufferLayout<'static> {
        wgpu::VertexBufferLayout {
            array_stride: std::mem::size_of::<Self>() as wgpu::BufferAddress,
            step_mode: wgpu::VertexStepMode::Vertex,
            attributes: &Self::ATTRIBUTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TextMeshBounds {
    pub min: [f32; 3],
    pub max: [f32; 3],
}

impl TextMeshBounds {
    pub fn center(self) -> [f32; 3] {
        [
            (self.min[0] + self.max[0]) * 0.5,
            (self.min[1] + self.max[1]) * 0.5,
            (self.min[2] + self.max[2]) * 0.5,
        ]
    }

    pub fn width(self) -> f32 {
        self.max[0] - self.min[0]
    }

    pub fn height(self) -> f32 {
        self.max[1] - self.min[1]
    }

    pub fn depth(self) -> f32 {
        self.max[2] - self.min[2]
    }
}

#[derive(Clone, Debug, Default)]
pub struct TextMesh {
    pub vertices: Vec<TextMeshVertex>,
    pub indices: Vec<u32>,
    pub bounds: TextMeshBounds,
}

impl TextMesh {
    pub fn from_font_bytes(
        font_data: &[u8],
        text: &str,
        color: [f32; 4],
        options: TextMeshOptions,
    ) -> RenderResult<Self> {
        let font = FontRef::new(font_data)
            .map_err(|e| RenderError::message(format!("invalid font: {e}")))?;
        let units_per_em = font
            .metrics(Size::unscaled(), LocationRef::default())
            .units_per_em as f32;
        if units_per_em <= 0.0 {
            return Err(RenderError::message("font has invalid units_per_em"));
        }
        let outline_glyphs = font.outline_glyphs();
        let mut font_system = FontSystem::new_with_fonts(std::iter::empty());
        font_system.db_mut().load_font_data(font_data.to_vec());

        let font_size = options.font_size.max(0.001);
        let line_height = options.line_height.max(font_size);
        let mut buffer = Buffer::new(&mut font_system, Metrics::new(font_size, line_height));
        buffer.set_size(options.layout_width, options.layout_height);
        buffer.set_wrap(options.wrap);
        buffer.set_text(
            text,
            &Attrs::new().family(options.family.to_glyphon()),
            options.shaping,
            options.align,
        );
        buffer.shape_until_scroll(&mut font_system, false);

        let mut mesh = Self::default();
        let curve_steps = options.curve_steps.max(1);
        let stroke_width = options.stroke_width.max(0.001);
        let depth = options.depth.max(0.001);

        for run in buffer.layout_runs() {
            for glyph in run.glyphs {
                let Some(outline) = outline_glyphs.get(GlyphId::from(glyph.glyph_id)) else {
                    continue;
                };
                let mut collector = OutlineCollector::new(curve_steps);
                if outline
                    .draw(
                        DrawSettings::unhinted(Size::unscaled(), LocationRef::default()),
                        &mut collector,
                    )
                    .is_err()
                {
                    continue;
                }

                let scale = glyph.font_size / units_per_em;
                let origin_x = glyph.x + glyph.font_size * glyph.x_offset;
                let origin_y = -(run.line_y + glyph.y - glyph.font_size * glyph.y_offset);

                for contour in collector.finish() {
                    let contour = contour
                        .into_iter()
                        .map(|point| Point2 {
                            x: origin_x + point.x * scale,
                            y: origin_y + point.y * scale,
                        })
                        .collect::<Vec<_>>();

                    for segment in contour.windows(2) {
                        add_segment_prism(
                            &mut mesh,
                            segment[0],
                            segment[1],
                            stroke_width,
                            depth,
                            color,
                        )?;
                    }
                }
            }
        }

        if mesh.vertices.is_empty() {
            return Err(RenderError::message("text mesh produced no vertices"));
        }

        mesh.recalculate_bounds();
        if options.center {
            let center = mesh.bounds.center();
            mesh.translate([-center[0], -center[1], 0.0]);
        }

        Ok(mesh)
    }

    pub fn translate(&mut self, offset: [f32; 3]) {
        for vertex in &mut self.vertices {
            vertex.position[0] += offset[0];
            vertex.position[1] += offset[1];
            vertex.position[2] += offset[2];
        }
        self.recalculate_bounds();
    }

    pub fn append(&mut self, other: &Self, offset: [f32; 3]) -> RenderResult<()> {
        let base_index = u32::try_from(self.vertices.len())
            .map_err(|_| RenderError::message("text mesh vertex count exceeds u32"))?;

        self.vertices
            .extend(other.vertices.iter().copied().map(|mut vertex| {
                vertex.position[0] += offset[0];
                vertex.position[1] += offset[1];
                vertex.position[2] += offset[2];
                vertex
            }));
        self.indices
            .extend(other.indices.iter().map(|index| base_index + index));
        self.recalculate_bounds();

        Ok(())
    }

    pub fn recalculate_bounds(&mut self) {
        let Some(first) = self.vertices.first() else {
            self.bounds = TextMeshBounds::default();
            return;
        };

        let mut min = first.position;
        let mut max = first.position;
        for vertex in &self.vertices {
            for axis in 0..3 {
                min[axis] = min[axis].min(vertex.position[axis]);
                max[axis] = max[axis].max(vertex.position[axis]);
            }
        }
        self.bounds = TextMeshBounds { min, max };
    }
}

#[derive(Clone, Copy, Debug)]
struct Point2 {
    x: f32,
    y: f32,
}

impl Point2 {
    fn distance_squared(self, other: Self) -> f32 {
        let dx = self.x - other.x;
        let dy = self.y - other.y;
        dx * dx + dy * dy
    }
}

struct OutlineCollector {
    contours: Vec<Vec<Point2>>,
    current: Vec<Point2>,
    first: Option<Point2>,
    last: Option<Point2>,
    curve_steps: usize,
}

impl OutlineCollector {
    fn new(curve_steps: usize) -> Self {
        Self {
            contours: Vec::new(),
            current: Vec::new(),
            first: None,
            last: None,
            curve_steps,
        }
    }

    fn finish(mut self) -> Vec<Vec<Point2>> {
        self.finish_current();
        self.contours
    }

    fn finish_current(&mut self) {
        if self.current.len() >= 2 {
            self.contours.push(std::mem::take(&mut self.current));
        } else {
            self.current.clear();
        }
        self.first = None;
        self.last = None;
    }

    fn push_point(&mut self, point: Point2) {
        let is_duplicate = self
            .last
            .map(|last| last.distance_squared(point) <= 0.000_001)
            .unwrap_or(false);

        if !is_duplicate {
            self.current.push(point);
            self.last = Some(point);
        }
    }
}

impl OutlinePen for OutlineCollector {
    fn move_to(&mut self, x: f32, y: f32) {
        self.finish_current();
        let point = Point2 { x, y };
        self.first = Some(point);
        self.push_point(point);
    }

    fn line_to(&mut self, x: f32, y: f32) {
        self.push_point(Point2 { x, y });
    }

    fn quad_to(&mut self, x1: f32, y1: f32, x: f32, y: f32) {
        let Some(start) = self.last else {
            self.line_to(x, y);
            return;
        };

        for step in 1..=self.curve_steps {
            let t = step as f32 / self.curve_steps as f32;
            let mt = 1.0 - t;
            self.push_point(Point2 {
                x: mt * mt * start.x + 2.0 * mt * t * x1 + t * t * x,
                y: mt * mt * start.y + 2.0 * mt * t * y1 + t * t * y,
            });
        }
    }

    fn curve_to(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, x: f32, y: f32) {
        let Some(start) = self.last else {
            self.line_to(x, y);
            return;
        };

        for step in 1..=self.curve_steps {
            let t = step as f32 / self.curve_steps as f32;
            let mt = 1.0 - t;
            self.push_point(Point2 {
                x: mt * mt * mt * start.x
                    + 3.0 * mt * mt * t * x1
                    + 3.0 * mt * t * t * x2
                    + t * t * t * x,
                y: mt * mt * mt * start.y
                    + 3.0 * mt * mt * t * y1
                    + 3.0 * mt * t * t * y2
                    + t * t * t * y,
            });
        }
    }

    fn close(&mut self) {
        if let (Some(first), Some(last)) = (self.first, self.last)
            && first.distance_squared(last) > 0.000_001
        {
            self.push_point(first);
        }
        self.finish_current();
    }
}

fn add_segment_prism(
    mesh: &mut TextMesh,
    start: Point2,
    end: Point2,
    stroke_width: f32,
    depth: f32,
    color: [f32; 4],
) -> RenderResult<()> {
    let dx = end.x - start.x;
    let dy = end.y - start.y;
    let length = (dx * dx + dy * dy).sqrt();
    if length <= 0.000_1 {
        return Ok(());
    }

    let half_width = stroke_width * 0.5;
    let half_depth = depth * 0.5;
    let dir = [dx / length, dy / length];
    let side = [-dir[1] * half_width, dir[0] * half_width];
    let front_z = half_depth;
    let back_z = -half_depth;

    let f0a = [start.x + side[0], start.y + side[1], front_z];
    let f0b = [start.x - side[0], start.y - side[1], front_z];
    let f1a = [end.x + side[0], end.y + side[1], front_z];
    let f1b = [end.x - side[0], end.y - side[1], front_z];
    let b0a = [start.x + side[0], start.y + side[1], back_z];
    let b0b = [start.x - side[0], start.y - side[1], back_z];
    let b1a = [end.x + side[0], end.y + side[1], back_z];
    let b1b = [end.x - side[0], end.y - side[1], back_z];

    push_quad(mesh, f0a, f0b, f1b, f1a, [0.0, 0.0, 1.0], color)?;
    push_quad(mesh, b0b, b0a, b1a, b1b, [0.0, 0.0, -1.0], color)?;
    push_quad(
        mesh,
        f0a,
        f1a,
        b1a,
        b0a,
        [side[0] / half_width, side[1] / half_width, 0.0],
        color,
    )?;
    push_quad(
        mesh,
        f1b,
        f0b,
        b0b,
        b1b,
        [-side[0] / half_width, -side[1] / half_width, 0.0],
        color,
    )?;
    push_quad(mesh, f0b, f0a, b0a, b0b, [-dir[0], -dir[1], 0.0], color)?;
    push_quad(mesh, f1a, f1b, b1b, b1a, [dir[0], dir[1], 0.0], color)?;

    Ok(())
}

fn push_quad(
    mesh: &mut TextMesh,
    a: [f32; 3],
    b: [f32; 3],
    c: [f32; 3],
    d: [f32; 3],
    normal: [f32; 3],
    color: [f32; 4],
) -> RenderResult<()> {
    let base = u32::try_from(mesh.vertices.len())
        .map_err(|_| RenderError::message("text mesh vertex count exceeds u32"))?;
    mesh.vertices.extend([
        TextMeshVertex {
            position: a,
            normal,
            color,
        },
        TextMeshVertex {
            position: b,
            normal,
            color,
        },
        TextMeshVertex {
            position: c,
            normal,
            color,
        },
        TextMeshVertex {
            position: d,
            normal,
            color,
        },
    ]);
    mesh.indices
        .extend([base, base + 1, base + 2, base, base + 2, base + 3]);

    Ok(())
}
