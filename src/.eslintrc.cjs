module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  plugins: ['@typescript-eslint/eslint-plugin', 'prettier'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:prettier/recommended',
  ],
  env: {
    node: true,
    es2021: true,
  },
  rules: {
    'prettier/prettier': 'error',
    // It's good practice to avoid 'any', but we need it for mocking and WebAuthn extensions.
    // Let's set it to a warning instead of a hard error.
    '@typescript-eslint/no-explicit-any': 'warn',
  },
};