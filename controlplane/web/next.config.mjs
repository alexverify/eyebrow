/**
 * Static export: `next build` emits a plain HTML/JS/CSS site to out/, which the
 * Go binary embeds (go:embed) and serves on loopback. No Node at runtime; the
 * backend is the Go /api/* endpoints, so SSR and Next API routes are unused.
 * @type {import('next').NextConfig}
 */
const nextConfig = {
  output: "export",
  images: { unoptimized: true },
  // Assets are served from the binary root, so keep relative asset paths.
  trailingSlash: true,
};

export default nextConfig;
