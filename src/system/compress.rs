use bytes::Bytes;

pub async fn encode_brotli<T: AsRef<[u8]>>(
    input: T,
    buffer_size: usize,
    q: u32,
    lgwin: u32,
) -> anyhow::Result<Bytes> {
    let mut out = vec![];
    let mut encoder =
        brotli::CompressorReader::new(std::io::Cursor::new(input.as_ref()), buffer_size, q, lgwin);
    std::io::copy(&mut encoder, &mut out)?;
    Ok(Bytes::from(out))
}

pub async fn encode_zstd<T: AsRef<[u8]>>(input: T, level: i32) -> anyhow::Result<Bytes> {
    let mut out = vec![];
    zstd::stream::copy_encode(std::io::Cursor::new(input.as_ref()), &mut out, level)?;
    Ok(Bytes::from(out))
}

pub async fn encode_gzip<T: AsRef<[u8]>>(input: T) -> anyhow::Result<Bytes> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let mut out = vec![];
    let mut encoder = GzEncoder::new(&mut out, Compression::default());
    std::io::copy(&mut std::io::Cursor::new(input.as_ref()), &mut encoder)?;
    encoder.finish()?;
    Ok(Bytes::from(out))
}
