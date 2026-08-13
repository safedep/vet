import { defineConfig } from "tsdown";

export default defineConfig({
  entry: ["src/bin.ts"],
  format: ["cjs"],
  clean: true,
  minify: true,
});
