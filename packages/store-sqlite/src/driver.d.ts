// Ambient declaration so `import("better-sqlite3")` type-checks without the
// driver's own types. The adapter types the connection itself (`Database` in
// deployment.ts). Not emitted.
declare module "better-sqlite3" {
  const DatabaseConstructor: unknown;
  export default DatabaseConstructor;
}
