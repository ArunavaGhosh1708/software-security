import tsParser from '/opt/eslint/node_modules/@typescript-eslint/parser/dist/index.js';
export default [{
  files: ['**/*.{js,jsx,ts,tsx,mjs,cjs}'],
  languageOptions: {parser: tsParser, ecmaVersion: 'latest', sourceType: 'module', parserOptions: {ecmaFeatures: {jsx:true}}},
  rules: {'no-eval':'error','no-implied-eval':'error','no-new-func':'error','no-debugger':'warn','no-unreachable':'error','no-constant-condition':'warn'}
}];
