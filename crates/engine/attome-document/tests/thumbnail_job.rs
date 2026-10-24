//! Z6-T6: a thumbnail of one image. The scaling and encoding run without
//! an object store or a database; `thumbnail::process` adds only the read,
//! the write and the session column around them.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_document::files::is_owned_file_key;
use attome_document::thumbnail::{
    THUMB_SIZE, ThumbnailError, is_thumbnailable, make_thumbnail, thumbnail_key,
};
use image::{ImageFormat, Rgb, RgbImage};
use uuid::Uuid;

fn encoded(width: u32, height: u32, format: ImageFormat) -> Vec<u8> {
    let img = RgbImage::from_fn(width, height, |x, y| {
        Rgb([(x % 256) as u8, (y % 256) as u8, 128])
    });
    let mut out = std::io::Cursor::new(Vec::new());
    img.write_to(&mut out, format)
        .expect("encode the test image");
    out.into_inner()
}

fn decoded_size(png: &[u8]) -> (u32, u32) {
    let img = image::load_from_memory_with_format(png, ImageFormat::Png).expect("a PNG");
    (img.width(), img.height())
}

#[test]
fn a_wide_jpeg_scales_to_320_on_its_longer_side() {
    let jpeg = encoded(1000, 500, ImageFormat::Jpeg);
    let png = make_thumbnail(&jpeg, "image/jpeg").expect("a thumbnail");
    assert_eq!(decoded_size(&png), (THUMB_SIZE, 160));
}

#[test]
fn a_small_png_is_not_scaled_up() {
    let small = encoded(100, 60, ImageFormat::Png);
    let png = make_thumbnail(&small, "image/png; charset=binary").expect("a thumbnail");
    assert_eq!(decoded_size(&png), (100, 60));
}

#[test]
fn only_images_get_thumbnails() {
    assert!(is_thumbnailable("image/webp"));
    assert!(!is_thumbnailable("application/pdf"));
    assert_eq!(
        make_thumbnail(b"%PDF-1.7", "application/pdf"),
        Err(ThumbnailError::Unsupported)
    );
    assert!(matches!(
        make_thumbnail(b"not a png", "image/png"),
        Err(ThumbnailError::Unreadable(_))
    ));
}

#[test]
fn the_thumbnail_lives_under_the_record_prefix() {
    let record = Uuid::now_v7();
    let original = format!("contact/{record}/photo/{}", Uuid::now_v7());
    let key = thumbnail_key(&original);
    assert!(key.ends_with(".thumb.png"));
    assert!(is_owned_file_key("contact", record, "photo", &key));
}
