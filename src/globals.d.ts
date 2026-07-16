/**
 * Compile-time globals injected by Bun's --define flag.
 */
export {};

declare global {
  var __PACKAGE_VERSION__: string | undefined;
}
