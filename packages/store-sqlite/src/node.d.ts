// The few Node.js built-ins this package uses, declared here so the repository
// needs no `@types/node`. Not emitted.
declare module "node:fs" {
  export function mkdirSync(path: string, options?: { recursive?: boolean }): unknown;
  export function readFileSync(path: string, encoding: "utf8"): string;
  export function realpathSync(path: string): string;
  export function renameSync(oldPath: string, newPath: string): void;
  export function unlinkSync(path: string): void;
  export function writeFileSync(path: string, data: string, options?: { mode?: number }): void;
}
declare module "node:path" {
  export function basename(path: string): string;
  export function dirname(path: string): string;
  export function join(...paths: string[]): string;
  export function resolve(...paths: string[]): string;
}
declare const process: { readonly pid: number; readonly platform: string };
