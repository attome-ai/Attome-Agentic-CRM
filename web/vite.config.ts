import { defineConfig } from 'vite';

export default defineConfig({
  resolve: {
    dedupe: [
      '@angular/animations',
      '@angular/common',
      '@angular/compiler',
      '@angular/core',
      '@angular/forms',
      '@angular/platform-browser',
      '@angular/router',
      'rxjs',
    ],
  },
});
