import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The app reads the artifact bundle from ../artifacts at build time (Server Components).
  // Nothing here imports analysis code — the only contract is the JSON/Parquet on disk.
  webpack: (config) => {
    // vega-canvas optionally requires the native `canvas` package for server rendering.
    // We render Vega client-side as SVG, so stub it out to silence the resolve warning.
    config.resolve.alias = { ...config.resolve.alias, canvas: false };
    return config;
  },
};

export default nextConfig;
