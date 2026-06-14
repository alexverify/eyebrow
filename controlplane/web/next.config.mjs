/**
 * Static export so the dashboard ships embedded in the assay Go binary
 * (go:embed) and serves on loopback with no Node runtime.
 * @type {import('next').NextConfig}
 */
const nextConfig = {
  output: "export",
  trailingSlash: true,
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
}

export default nextConfig
