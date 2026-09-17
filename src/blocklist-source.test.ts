import { describe, expect, it } from "vitest";

import { blocklistSourceLabel, filterIdFromSource } from "./blocklist-source";

const names = new Map([
  ["custom-1758012345-123", "AdGuard DNS Filter｜综合广告"],
  ["hagezi-tif", "HaGeZi TIF｜恶意威胁"],
]);

describe("filterIdFromSource", () => {
  it("取出清单 ID", () => {
    expect(filterIdFromSource("f:hagezi-tif")).toBe("hagezi-tif");
  });

  it("内置来源没有 ID", () => {
    expect(filterIdFromSource("自定义规则")).toBeNull();
    expect(filterIdFromSource("DNS Rebinding Protection")).toBeNull();
  });
});

describe("blocklistSourceLabel", () => {
  it("清单按 ID 显示当前名称，改名后自动跟随", () => {
    expect(blocklistSourceLabel("f:custom-1758012345-123", names)).toBe(
      "AdGuard DNS Filter｜综合广告",
    );
  });

  it("内置来源原样显示", () => {
    expect(blocklistSourceLabel("DNS Rebinding Protection", names)).toBe(
      "DNS Rebinding Protection",
    );
    expect(blocklistSourceLabel("自定义规则", names)).toBe("自定义规则");
  });

  it("清单已删除时给出兜底说明，而不是暴露 ID", () => {
    const label = blocklistSourceLabel("f:removed-list", names);
    expect(label).not.toContain("removed-list");
    expect(label).toBeTruthy();
  });

  it("升级前遗留的按名称记录的来源原样显示", () => {
    // 迁移时匹配不上的旧名没有 f: 前缀，当作内置来源原样展示即可。
    expect(blocklistSourceLabel("1Hosts Xtra（激进广告与隐私拦截）", names)).toBe(
      "1Hosts Xtra（激进广告与隐私拦截）",
    );
  });
});
