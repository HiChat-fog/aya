#![allow(clippy::print_stdout, reason = "xtask is a CLI tool")]
#![allow(clippy::use_debug, reason = "debug output aids troubleshooting")]

use std::{
    fs,
    io::{Cursor, Read as _},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, anyhow, bail};

use crate::{
    http::{HttpClient, url_file_name},
    ubuntu_mainline::{
        KernelArchitecture, KernelPackage, KernelPackageContents, directory_listing_urls, one,
        parse_efi_zboot_header, unpack_ubuntu_mainline_image_package,
        unpack_ubuntu_mainline_modules_package,
    },
};

// Ubuntu Mainline does not publish riscv64 packages; the ports archive ships
// the linux-riscv kernel for riscv64 instead. The pool is flat across Ubuntu
// releases.
// https://wiki.ubuntu.com/Kernel/RiscV
const UBUNTU_PORTS_LINUX_RISCV_POOL_URL: &str =
    "https://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux-riscv/";

const UBUNTU_PORTS_IMAGE_PACKAGE_PREFIX: &str = "linux-image-unsigned-";
const UBUNTU_PORTS_MODULES_PACKAGE_PREFIX: &str = "linux-modules-";

// riscv64 raw Image header magic:
// https://github.com/torvalds/linux/blob/v6.18/arch/riscv/include/asm/image.h#L12-L25
const RISCV64_IMAGE_MAGIC_OFFSET: usize = 0x30;
const RISCV64_IMAGE_MAGIC: &[u8; 5] = b"RISCV";

struct UbuntuPortsKernelUrls {
    base: String,
    image: String,
    modules: String,
}

fn ubuntu_ports_kernel_urls(
    client: &HttpClient,
    version: &str,
    architecture: KernelArchitecture,
) -> Result<UbuntuPortsKernelUrls> {
    let pool_html = client
        .get_text(UBUNTU_PORTS_LINUX_RISCV_POOL_URL)
        .context("failed to list the Ubuntu ports linux-riscv pool")?;

    // Unlike Mainline, the pool is flat across Ubuntu releases, so the
    // requested version must select exactly one generic image and modules
    // package. Anything else means the version argument or the filename rules
    // are not precise enough.
    let architecture = architecture.as_str();
    let package_suffix = format!("_{architecture}.deb");
    let image_prefix = format!("{UBUNTU_PORTS_IMAGE_PACKAGE_PREFIX}{version}-generic_");
    let modules_prefix = format!("{UBUNTU_PORTS_MODULES_PACKAGE_PREFIX}{version}-generic_");

    let mut image_matches = Vec::new();
    let mut modules_matches = Vec::new();
    for url in directory_listing_urls(&pool_html, UBUNTU_PORTS_LINUX_RISCV_POOL_URL) {
        let Ok(file_name) = url_file_name(url.as_ref()) else {
            continue;
        };
        if !file_name.ends_with(&package_suffix) {
            continue;
        }
        if file_name.starts_with(&image_prefix) {
            image_matches.push(url.into_owned());
        } else if file_name.starts_with(&modules_prefix) {
            modules_matches.push(url.into_owned());
        }
    }

    let image = one(image_matches.as_slice())
        .with_context(|| format!("failed to resolve the Ubuntu ports image package for {version}"))?
        .clone();
    let modules = one(modules_matches.as_slice())
        .with_context(|| {
            format!("failed to resolve the Ubuntu ports modules package for {version}")
        })?
        .clone();

    let image_file_name = url_file_name(&image)?;
    let (image_package_name, _) = image_file_name
        .split_once('_')
        .ok_or_else(|| anyhow!("unexpected Ubuntu ports image package URL: {image}"))?;
    let base = image_package_name
        .strip_prefix(UBUNTU_PORTS_IMAGE_PACKAGE_PREFIX)
        .ok_or_else(|| anyhow!("unexpected Ubuntu ports image package URL: {image}"))?
        .to_owned();

    Ok(UbuntuPortsKernelUrls {
        base,
        image,
        modules,
    })
}

// QEMU's -kernel path is not a full EFI boot path and fails on EFI zboot
// images before the kernel starts; the arm64 runner deals with the same
// problem, see `maybe_extract_qemu_arm64_image` in ubuntu_mainline.rs. Ubuntu
// ports riscv64 vmlinuz files are EFI zboot images with a zstd payload, so
// extract the embedded raw riscv64 Image and pass that to QEMU instead.
fn maybe_extract_qemu_riscv64_image(path: &Path) -> Result<PathBuf> {
    let image = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let Some(zboot_header) = parse_efi_zboot_header(&image)? else {
        return Ok(path.to_path_buf());
    };
    if zboot_header.compression != "zstd" {
        bail!(
            "unsupported EFI zboot compression {:?} in {}",
            zboot_header.compression,
            path.display()
        );
    }

    let mut decoder = zstd::stream::read::Decoder::new(Cursor::new(zboot_header.payload))
        .with_context(|| {
            format!(
                "failed to create zstd decoder for EFI zboot payload from {}",
                path.display()
            )
        })?
        .single_frame();
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).with_context(|| {
        format!(
            "failed to decompress EFI zboot payload from {}",
            path.display()
        )
    })?;
    if decompressed
        .get(RISCV64_IMAGE_MAGIC_OFFSET..RISCV64_IMAGE_MAGIC_OFFSET + RISCV64_IMAGE_MAGIC.len())
        != Some(RISCV64_IMAGE_MAGIC.as_slice())
    {
        bail!(
            "decompressed EFI zboot payload from {} is not a raw riscv64 Image",
            path.display()
        );
    }

    let output = path.with_file_name(format!(
        "Image-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("vmlinuz-"))
            .unwrap_or("riscv64")
    ));
    fs::write(&output, decompressed).with_context(|| {
        format!(
            "failed to write extracted riscv64 Image {}",
            output.display()
        )
    })?;
    println!(
        "extracted {} from {} EFI zboot zstd payload",
        output.display(),
        path.display()
    );
    Ok(output)
}

pub(crate) fn download_ubuntu_ports_kernel_packages(
    client: &HttpClient,
    cache_dir: &Path,
    extraction_root: &Path,
    architecture: KernelArchitecture,
    versions: &[String],
) -> Result<Vec<KernelPackage>> {
    let output_dir = cache_dir
        .join("ubuntu-ports-kernels")
        .join(architecture.as_str());
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;

    let mut packages = Vec::new();
    for (index, version) in versions.iter().enumerate() {
        let urls = ubuntu_ports_kernel_urls(client, version, architecture)
            .with_context(|| format!("failed to resolve Ubuntu ports kernel {version}"))?;
        // ETag caching still revalidates each package over the network, so VM
        // runs require network access even when these files already exist.
        let image = client.download_to_dir(&urls.image, &output_dir)?;
        let modules = client.download_to_dir(&urls.modules, &output_dir)?;

        // Ports package layouts match Mainline: linux-image-unsigned provides
        // vmlinuz, while linux-modules provides config, System.map, and the
        // module tree.
        let contents = unpack_ubuntu_mainline_image_package(
            &image,
            &extraction_root.join(format!("kernel-archive-{index}-image")),
            KernelPackageContents::default(),
        )
        .with_context(|| format!("failed to unpack image package for {}", urls.base))?;
        let contents = unpack_ubuntu_mainline_modules_package(
            &modules,
            &extraction_root.join(format!("kernel-archive-{index}-modules")),
            contents,
        )
        .with_context(|| format!("failed to unpack modules package for {}", urls.base))?;

        let kernel_image = maybe_extract_qemu_riscv64_image(
            one(contents.kernel_images.as_slice())
                .with_context(|| format!("kernel image for {}", urls.base))?,
        )?;

        packages.push(KernelPackage {
            kernel_image,
            config: one(contents.configs.as_slice())
                .with_context(|| format!("config for {}", urls.base))?
                .clone(),
            modules_dir: one(contents.modules_dirs.as_slice())
                .with_context(|| format!("modules directory for {}", urls.base))?
                .clone(),
            system_map: one(contents.system_maps.as_slice())
                .with_context(|| format!("System.map for {}", urls.base))?
                .clone(),
            base: PathBuf::from(&urls.base),
        });
    }

    Ok(packages)
}
