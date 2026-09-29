// Environment recorded with every result (#74 comparability rules): Node.js,
// OS/arch, CPU, and runner. Package and core versions live on each side, the
// PII mode and corpus version at the top level of the result.

import { arch, cpus, platform, release, totalmem } from "node:os";

function runnerOf(env) {
  if (env.GITHUB_ACTIONS === "true") {
    const parts = ["github-actions", env.RUNNER_OS, env.RUNNER_ARCH, env.ImageOS, env.ImageVersion].filter(
      (part) => typeof part === "string" && part.length > 0,
    );
    return parts.join("/");
  }
  if (env.CI === "true") return "ci";
  return "local";
}

export function captureEnvironment(env = process.env) {
  const cpuList = cpus();
  return {
    node: process.versions.node,
    v8: process.versions.v8,
    platform: platform(),
    arch: arch(),
    osRelease: release(),
    cpuModel: cpuList[0]?.model?.trim() ?? "unknown",
    cpuCount: cpuList.length,
    totalMemoryBytes: totalmem(),
    runner: runnerOf(env),
  };
}
