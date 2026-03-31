fn main() {
    // Only link Xen guest libraries when the feature is enabled.
    // The restore module uses dlopen at runtime instead of link-time binding.
    // This keeps krata-xencall compilable on non-Xen hosts.
}
