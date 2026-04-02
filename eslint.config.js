import tsParser from "@typescript-eslint/parser";

export default [
  {
    ignores: [
      "dist/**",
      "node_modules/**",
      "*.tgz",
      "vitest.config.ts.timestamp-*.mjs",
    ],
  },
  {
    files: ["typescript/**/*.ts"],
    languageOptions: {
      parser: tsParser,
      ecmaVersion: "latest",
      sourceType: "module",
    },
    rules: {
      "no-constant-condition": ["error", { checkLoops: false }],
      "no-unreachable": "error",
    },
  },
];
