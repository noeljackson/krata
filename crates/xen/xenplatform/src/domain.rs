use std::sync::Arc;

use crate::{
    boot::BootDomain, elfloader::ElfImageLoader, error::Error, sys::XEN_PAGE_SHIFT, ImageLoader,
    RuntimePlatform, RuntimePlatformType,
};
use log::warn;
use uuid::Uuid;
use xencall::XenCall;

use crate::error::Result;

pub const XEN_EXTRA_MEMORY_KB: u64 = 2048;

pub struct PlatformDomainManager {
    call: XenCall,
}

impl PlatformDomainManager {
    pub async fn new(call: XenCall) -> Result<PlatformDomainManager> {
        Ok(PlatformDomainManager { call })
    }

    fn max_memory_kb(resources: &PlatformResourcesConfig) -> u64 {
        (resources.max_memory_mb * 1024) + XEN_EXTRA_MEMORY_KB
    }

    async fn create_base_domain(
        &self,
        config: &PlatformDomainConfig,
        platform: &RuntimePlatform,
    ) -> Result<u32> {
        let mut domain = platform.create_domain(config.options.iommu);
        domain.handle = config.uuid.into_bytes();
        domain.max_vcpus = config.resources.max_vcpus;
        // Per-domain resource limits — cap grant table and event channel allocation.
        // 8 grant frames = 4096 entries (guests need ~4: console, xenstore, VBD, VIF).
        // 16 maptrack frames for dom0 grant mappings.
        // 128 event channels (guests need ~4: console, xenstore, VBD, VIF).
        domain.max_grant_frames = 8;
        domain.max_maptrack_frames = 16;
        domain.max_evtchn_port = 128;
        let domid = self.call.create_domain(domain).await?;
        Ok(domid)
    }

    async fn configure_domain_resources(
        &self,
        domid: u32,
        config: &PlatformDomainConfig,
    ) -> Result<()> {
        self.call
            .set_max_vcpus(domid, config.resources.max_vcpus)
            .await?;
        self.call
            .set_max_mem(
                domid,
                PlatformDomainManager::max_memory_kb(&config.resources),
            )
            .await?;
        Ok(())
    }

    async fn create_internal(
        &self,
        domid: u32,
        config: &PlatformDomainConfig,
        mut platform: RuntimePlatform,
    ) -> Result<BootDomain> {
        self.configure_domain_resources(domid, config).await?;
        let kernel = config.kernel.clone();
        let loader = tokio::task::spawn_blocking(move || match kernel.format {
            KernelFormat::ElfCompressed => ElfImageLoader::load(kernel.data),
            KernelFormat::ElfUncompressed => Ok(ElfImageLoader::new(kernel.data)),
        })
        .await
        .map_err(Error::AsyncJoinError)??;
        let loader = ImageLoader::Elf(loader);
        let mut domain = platform
            .initialize(
                domid,
                self.call.clone(),
                &loader,
                &config.kernel,
                &config.resources,
                &config.boot_resources,
            )
            .await?;
        platform.boot(domid, self.call.clone(), &mut domain).await?;
        Ok(domain)
    }

    pub async fn create(&self, config: PlatformDomainConfig) -> Result<PlatformDomainInfo> {
        let platform = config.platform.create();
        let domid = self.create_base_domain(&config, &platform).await?;
        let domain = match self.create_internal(domid, &config, platform).await {
            Ok(domain) => domain,
            Err(error) => {
                if let Err(destroy_fail) = self.call.destroy_domain(domid).await {
                    warn!(
                        "failed to destroy failed domain {}: {}",
                        domid, destroy_fail
                    );
                }
                return Err(error);
            }
        };
        Ok(PlatformDomainInfo {
            domid,
            store_evtchn: domain.store_evtchn,
            store_mfn: domain.store_mfn,
            console_evtchn: domain.console_evtchn,
            console_mfn: domain.console_mfn,
            boot_resources: domain.boot_resources,
        })
    }

    /// Restore a domain from a checkpoint stream.
    ///
    /// Creates an empty domain, then loads its memory state from the checkpoint
    /// via xc_domain_restore. The checkpoint fd must point to a raw xc migration
    /// stream (NOT an xl-wrapped file -- the caller must strip the xl header).
    ///
    /// Returns PlatformDomainInfo with the new domid and store/console MFNs
    /// from the checkpoint's shared_info page.
    pub async fn restore(
        &self,
        config: PlatformRestoreConfig,
        checkpoint_fd: i32,
    ) -> Result<PlatformDomainInfo> {
        let platform = config.platform.create();

        // Create empty domain (same base setup as create path)
        let mut domain = platform.create_domain(config.options.iommu);
        domain.handle = config.uuid.into_bytes();
        domain.max_vcpus = config.resources.max_vcpus;
        domain.max_grant_frames = 8;
        domain.max_maptrack_frames = 16;
        domain.max_evtchn_port = 128;
        let domid = self.call.create_domain(domain).await?;

        // Set resources -- restore needs generous max_mem because
        // xc_domain_restore allocates P2M table pages beyond the
        // checkpoint's memory footprint.
        self.call
            .set_max_vcpus(domid, config.resources.max_vcpus)
            .await?;
        let restore_max_mem_kb = config.resources.max_memory_mb * 1024 * 2;
        self.call.set_max_mem(domid, restore_max_mem_kb).await?;

        // Allocate event channels for xenstore and console
        let store_evtchn = self.call.evtchn_alloc_unbound(domid, 0).await?;
        let console_evtchn = self.call.evtchn_alloc_unbound(domid, 0).await?;

        // Load checkpoint memory into the domain
        let result = match xencall::restore::restore_domain(
            domid,
            checkpoint_fd,
            store_evtchn,
            console_evtchn,
        ) {
            Ok(result) => result,
            Err(err) => {
                warn!("xc_domain_restore failed for domain {}: {}", domid, err);
                let _ = self.call.destroy_domain(domid).await;
                return Err(Error::GenericError(format!("domain restore failed: {err}")));
            }
        };

        // NOTE: gnttab_seed is NOT needed here. xc_domain_restore() seeds
        // the grant table internally (xc_dom_gnttab_seed in stream_complete).
        // Double-seeding corrupts the grant table and can crash the host.

        // Reset the xenstore ring page. The checkpoint contains stale ring
        // state (pending requests/responses from the old session). If
        // xenstored connects via introduce_domain before the ring is clean,
        // it processes stale data and the resulting events crash the guest
        // kernel (NULL deref in multi_cpu_stop during PV resume).
        //
        // Zero the ring indices and connection field so the guest and
        // xenstored start from a clean state after introduce_domain.
        self.reset_xenstore_ring(domid, result.store_mfn).await?;

        Ok(PlatformDomainInfo {
            domid,
            store_evtchn,
            store_mfn: result.store_mfn,
            console_evtchn,
            console_mfn: result.console_mfn,
            boot_resources: PlatformBootResourcesInfo::default(),
        })
    }

    /// Reset the xenstore shared ring page to a clean state.
    ///
    /// Maps the page via privcmd, zeros the ring indices and connection
    /// field, then unmaps. This prevents xenstored from processing stale
    /// checkpoint data when introduce_domain is called.
    async fn reset_xenstore_ring(&self, domid: u32, store_mfn: u64) -> Result<()> {
        use std::sync::atomic::{fence, Ordering};

        let page_size = 1u64 << XEN_PAGE_SHIFT;
        let addr = self
            .call
            .mmap(0, page_size)
            .await
            .ok_or(Error::MmapFailed)?;

        self.call
            .mmap_batch(domid, 1, addr, vec![store_mfn])
            .await?;

        // xenstore_domain_interface layout:
        //   char req[1024];          // offset 0
        //   char rsp[1024];          // offset 1024
        //   uint32_t req_cons;       // offset 2048
        //   uint32_t req_prod;       // offset 2052
        //   uint32_t rsp_cons;       // offset 2056
        //   uint32_t rsp_prod;       // offset 2060
        //   uint32_t server_features;// offset 2064
        //   uint32_t connection;     // offset 2068
        //   uint32_t error;          // offset 2072
        unsafe {
            let base = addr as *mut u8;
            // Zero ring data buffers
            std::ptr::write_bytes(base, 0, 2048);
            // Zero indices + control fields (28 bytes from offset 2048)
            std::ptr::write_bytes(base.add(2048), 0, 28);
        }
        fence(Ordering::Release);

        unsafe {
            libc::munmap(addr as *mut std::ffi::c_void, page_size as usize);
        }
        Ok(())
    }

    pub async fn destroy(&self, domid: u32) -> Result<()> {
        self.call.destroy_domain(domid).await?;
        Ok(())
    }
}

/// Configuration for restoring a domain from a checkpoint.
/// Same as PlatformDomainConfig but without kernel data.
#[derive(Clone, Debug)]
pub struct PlatformRestoreConfig {
    pub uuid: Uuid,
    pub platform: RuntimePlatformType,
    pub resources: PlatformResourcesConfig,
    pub options: PlatformOptions,
}

#[derive(Clone, Debug)]
pub struct PlatformDomainConfig {
    pub uuid: Uuid,
    pub platform: RuntimePlatformType,
    pub resources: PlatformResourcesConfig,
    pub kernel: PlatformKernelConfig,
    pub options: PlatformOptions,
    pub boot_resources: PlatformBootResourcesConfig,
}

#[derive(Clone, Debug)]
pub struct PlatformKernelConfig {
    pub data: Arc<Vec<u8>>,
    pub format: KernelFormat,
    pub initrd: Option<Arc<Vec<u8>>>,
    pub cmdline: String,
}

#[derive(Clone, Debug)]
pub struct PlatformResourcesConfig {
    pub max_vcpus: u32,
    pub assigned_vcpus: u32,
    pub max_memory_mb: u64,
    pub assigned_memory_mb: u64,
}

#[derive(Clone, Debug)]
pub struct PlatformOptions {
    pub iommu: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PlatformBootResourcesConfig {
    pub ninepfs: PlatformNinepfsBootResourcesConfig,
}

#[derive(Clone, Debug)]
pub struct PlatformNinepfsBootResourcesConfig {
    pub share_count: u32,
    pub rings_per_share: u32,
}

impl Default for PlatformNinepfsBootResourcesConfig {
    fn default() -> Self {
        Self {
            share_count: 0,
            rings_per_share: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub enum KernelFormat {
    ElfUncompressed,
    ElfCompressed,
}

#[derive(Clone, Debug)]
pub struct PlatformDomainInfo {
    pub domid: u32,
    pub store_evtchn: u32,
    pub store_mfn: u64,
    pub console_evtchn: u32,
    pub console_mfn: u64,
    pub boot_resources: PlatformBootResourcesInfo,
}

#[derive(Clone, Debug, Default)]
pub struct PlatformBootResourcesInfo {
    pub ninepfs: Vec<PlatformNinepfsShareResources>,
}

#[derive(Clone, Debug)]
pub struct PlatformNinepfsShareResources {
    pub rings: Vec<PlatformNinepfsRingResource>,
}

#[derive(Clone, Debug)]
pub struct PlatformNinepfsRingResource {
    pub grant_index: u64,
    pub intf_gref: u32,
    pub evtchn: u32,
}
