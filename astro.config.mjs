import { defineConfig } from "astro/config";

import react from "@astrojs/react";

// https://astro.build/config
export default defineConfig({
  site: "https://rigidity.github.io",
  base: "chia-encoder-util",
  integrations: [react()]
});