import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';

export const collections = {
  spec: defineCollection({
    loader: glob({
      pattern: '**/*.md',
      base: './src/content/spec',
    }),
  }),
  registry: defineCollection({
    loader: glob({
      pattern: '**/*.md',
      base: './src/content/registry',
    }),
  }),
};
