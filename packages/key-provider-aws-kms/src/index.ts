/**
 * `@redact-secret/key-provider-aws-kms`: an optional `KeyProvider` over AWS
 * KMS for the persistent vault (docs/specs/persistent-vault.md §6). The AWS
 * SDK is a peer dependency of this package and of no other.
 */
export type { DataKeyCacheOptions } from "./cache.js";
export { CACHE_MAX_AGE_CEILING_MS, CACHE_MAX_ENTRIES_CEILING } from "./cache.js";
export { CONTEXT_DIGEST_KEY, CONTEXT_VERSION, CONTEXT_VERSION_KEY } from "./context.js";
export type {
  AwsKmsKey,
  AwsKmsKeyProvider,
  AwsKmsKeyProviderOptions,
  AwsKmsKeyProviderStats,
  AwsKmsKeyState,
  KmsClientLike,
  KmsCommand,
} from "./provider.js";
export {
  AWS_KMS_KEY_PROVIDER_PROFILE,
  createAwsKmsKeyProvider,
  DEFAULT_CALL_TIMEOUT_MS,
  KEY_REF_PREFIX,
} from "./provider.js";
