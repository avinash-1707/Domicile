// @ts-check
import { defineConfig } from 'astro/config';

// https://astro.build/config
export default defineConfig({
  site: 'https://domicile.avnsh.me',
  build: {
    // one page: inline the stylesheet so first paint needs no extra request
    inlineStylesheets: 'always',
  },
});
