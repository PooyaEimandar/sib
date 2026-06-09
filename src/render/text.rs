use crate::render::{RenderContext, RenderError, RenderResult};

pub use glyphon::{Attrs, Family, Metrics, Shaping, TextBounds, Wrap, cosmic_text::Align};

pub type TextItemId = usize;

#[derive(Clone, Copy, Debug)]
pub enum TextFamily {
    SansSerif,
    Serif,
    Monospace,
    Name(&'static str),
}

impl TextFamily {
    fn to_glyphon(self) -> glyphon::Family<'static> {
        match self {
            Self::SansSerif => glyphon::Family::SansSerif,
            Self::Serif => glyphon::Family::Serif,
            Self::Monospace => glyphon::Family::Monospace,
            Self::Name(name) => glyphon::Family::Name(name),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TextStyle {
    pub font_size: f32,
    pub line_height: f32,
    pub color: [u8; 4],
    pub family: TextFamily,
    pub shaping: glyphon::Shaping,
    pub align: Option<glyphon::cosmic_text::Align>,
}

impl Default for TextStyle {
    fn default() -> Self {
        Self {
            font_size: 18.0,
            line_height: 24.0,
            color: [255, 255, 255, 255],
            family: TextFamily::SansSerif,
            shaping: glyphon::Shaping::Advanced,
            align: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TextPlacement {
    pub left: f32,
    pub top: f32,
    pub width: f32,
    pub height: f32,
    pub scale: f32,
}

impl Default for TextPlacement {
    fn default() -> Self {
        Self {
            left: 16.0,
            top: 16.0,
            width: 480.0,
            height: 120.0,
            scale: 1.0,
        }
    }
}

struct TextItem {
    buffer: glyphon::Buffer,
    left: f32,
    top: f32,
    scale: f32,
    bounds: glyphon::TextBounds,
    color: glyphon::Color,
}

impl TextItem {
    fn new(
        font_system: &mut glyphon::FontSystem,
        text: &str,
        style: TextStyle,
        placement: TextPlacement,
    ) -> Self {
        let metrics = glyphon::Metrics::new(style.font_size, style.line_height);
        let mut buffer = glyphon::Buffer::new(font_system, metrics);
        buffer.set_size(
            font_system,
            Some(placement.width.max(1.0)),
            Some(placement.height.max(1.0)),
        );
        buffer.set_wrap(font_system, glyphon::Wrap::Word);
        buffer.set_text(
            font_system,
            text,
            &glyphon::Attrs::new().family(style.family.to_glyphon()),
            style.shaping,
            style.align,
        );
        buffer.shape_until_scroll(font_system, false);

        Self {
            buffer,
            left: placement.left,
            top: placement.top,
            scale: placement.scale,
            bounds: bounds_for(placement),
            color: glyphon::Color::rgba(
                style.color[0],
                style.color[1],
                style.color[2],
                style.color[3],
            ),
        }
    }
}

pub struct TextOverlay {
    font_system: glyphon::FontSystem,
    cache: glyphon::Cache,
    swash_cache: glyphon::SwashCache,
    viewport: glyphon::Viewport,
    atlas: glyphon::TextAtlas,
    renderer: glyphon::TextRenderer,
    items: Vec<TextItem>,
}

impl TextOverlay {
    pub fn new(context: &RenderContext) -> RenderResult<Self> {
        Self::from_font_system(context, glyphon::FontSystem::new())
    }

    pub fn with_font_data(
        context: &RenderContext,
        fonts: impl IntoIterator<Item = impl Into<Vec<u8>>>,
    ) -> RenderResult<Self> {
        let mut font_system = glyphon::FontSystem::new_with_fonts(std::iter::empty());
        for font in fonts {
            font_system.db_mut().load_font_data(font.into());
        }

        Self::from_font_system(context, font_system)
    }

    pub fn add_font_data(&mut self, font: impl Into<Vec<u8>>) {
        self.font_system.db_mut().load_font_data(font.into());
    }

    pub fn clear(&mut self) {
        self.items.clear();
    }

    pub fn add_text(
        &mut self,
        text: &str,
        style: TextStyle,
        placement: TextPlacement,
    ) -> TextItemId {
        let id = self.items.len();
        self.items
            .push(TextItem::new(&mut self.font_system, text, style, placement));
        id
    }

    pub fn update_text(
        &mut self,
        id: TextItemId,
        text: &str,
        style: TextStyle,
        placement: TextPlacement,
    ) -> RenderResult<()> {
        let replacement = TextItem::new(&mut self.font_system, text, style, placement);
        let item = self
            .items
            .get_mut(id)
            .ok_or_else(|| RenderError::message(format!("text item {id} does not exist")))?;
        *item = replacement;
        Ok(())
    }

    pub fn prepare(&mut self, context: &RenderContext) -> RenderResult<()> {
        self.viewport.update(
            &context.queue,
            glyphon::Resolution {
                width: context.surface_config.width,
                height: context.surface_config.height,
            },
        );

        let text_areas = self
            .items
            .iter()
            .map(|item| glyphon::TextArea {
                buffer: &item.buffer,
                left: item.left,
                top: item.top,
                scale: item.scale,
                bounds: item.bounds,
                default_color: item.color,
                custom_glyphs: &[],
            })
            .collect::<Vec<_>>();

        self.renderer
            .prepare(
                &context.device,
                &context.queue,
                &mut self.font_system,
                &mut self.atlas,
                &self.viewport,
                text_areas,
                &mut self.swash_cache,
            )
            .map_err(RenderError::source)
    }

    pub fn render(&self, pass: &mut wgpu::RenderPass<'_>) -> RenderResult<()> {
        self.renderer
            .render(&self.atlas, &self.viewport, pass)
            .map_err(RenderError::source)
    }

    pub fn trim(&mut self) {
        self.atlas.trim();
    }

    fn from_font_system(
        context: &RenderContext,
        font_system: glyphon::FontSystem,
    ) -> RenderResult<Self> {
        let cache = glyphon::Cache::new(&context.device);
        let swash_cache = glyphon::SwashCache::new();
        let viewport = glyphon::Viewport::new(&context.device, &cache);
        let mut atlas = glyphon::TextAtlas::new(
            &context.device,
            &context.queue,
            &cache,
            context.surface_config.format,
        );
        let renderer = glyphon::TextRenderer::new(
            &mut atlas,
            &context.device,
            wgpu::MultisampleState::default(),
            None,
        );

        Ok(Self {
            font_system,
            cache,
            swash_cache,
            viewport,
            atlas,
            renderer,
            items: Vec::new(),
        })
    }
}

fn bounds_for(placement: TextPlacement) -> glyphon::TextBounds {
    glyphon::TextBounds {
        left: placement.left.floor() as i32,
        top: placement.top.floor() as i32,
        right: (placement.left + placement.width).ceil() as i32,
        bottom: (placement.top + placement.height).ceil() as i32,
    }
}
