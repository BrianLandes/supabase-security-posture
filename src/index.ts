export {
  type Config,
  ConfigError,
  loadConfig,
  parseConfig,
  RULE_IDS,
  type RuleId,
  TABLE_KINDS,
} from './config.js';
export { generateConfig } from './init.js';
export { type Format, render } from './report.js';
export { type CheckOptions, type CheckResult, check, configKey, type Finding, RULE_DESCRIPTIONS } from './rules.js';
export { SNAPSHOT_SQL, type Snapshot, SnapshotError, takeSnapshot } from './snapshot.js';
