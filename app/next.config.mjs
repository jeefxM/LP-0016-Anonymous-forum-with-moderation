/** @type {import('next').NextConfig} */
const nextConfig = {
  // The SDK ships ESM with explicit .js specifiers; let Next transpile it.
  transpilePackages: ["@logos-forum/moderation-sdk"],
  webpack: (config) => {
    // @waku / libp2p reference node builtins that don't exist in the browser.
    // The light node doesn't use them at runtime, so stub them out.
    config.resolve.fallback = {
      ...config.resolve.fallback,
      fs: false,
      net: false,
      tls: false,
    };
    return config;
  },
};

export default nextConfig;
