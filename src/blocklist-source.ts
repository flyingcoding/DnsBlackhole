import { t } from "./i18n";

/**
 * 规则来源标记里清单 ID 的前缀，与后端 `config::FILTER_SOURCE_PREFIX` 对应。
 *
 * 统计和查询日志都按清单 ID 关联，改名只换显示名、不影响历史归属。
 * 内置来源（自定义规则、重绑定防护等）没有 ID，标记就是原文。
 */
const FILTER_SOURCE_PREFIX = "f:";

/** 取出来源标记里的清单 ID；内置来源返回 null。 */
export function filterIdFromSource(source: string): string | null {
  return source.startsWith(FILTER_SOURCE_PREFIX)
    ? source.slice(FILTER_SOURCE_PREFIX.length)
    : null;
}

/**
 * 把来源标记显示成人能看懂的名字。
 *
 * 清单按 ID 查当前名称；内置来源原样显示；查不到的清单说明已经被删掉了，
 * 历史记录仍然保留，只是没有名字可用。
 */
export function blocklistSourceLabel(
  source: string,
  filterNames: ReadonlyMap<string, string>,
): string {
  const id = filterIdFromSource(source);
  if (id === null) {
    return source;
  }
  return filterNames.get(id) ?? t("已删除的清单");
}
