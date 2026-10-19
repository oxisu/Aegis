/**
 * 界面版本号。
 *
 * ⚠ 这是同一个数字的第 3 处拷贝：
 *   1. 仓库根 `VERSION`（权威）；
 *   2. `ui/package.json` 的 `version`；
 *   3. 这里。
 * CI 的「版本号一致性」作业目前只查 1 与 2，所以改版本号时**三处一起改**，
 * 别指望 CI 报错来提醒。
 */

export const UI_VERSION = '0.1.0-alpha.2';
