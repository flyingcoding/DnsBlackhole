import { describe, expect, it } from "vitest";

import { passwordIssue } from "./login";

describe("Web 管理密码校验", () => {
  it("按 Unicode 字符计算最小长度", () => {
    expect(passwordIssue("密码密码密码密码", "密码密码密码密码")).toBeNull();
    expect(passwordIssue("密码密码密码", "密码密码密码")).toContain("至少需要 8 个字符");
  });

  it("按 UTF-8 字节限制最大长度", () => {
    const password = "密".repeat(43);
    expect(passwordIssue(password, password)).toContain("不能超过 128 字节");
  });

  it("拒绝控制字符和不一致的确认密码", () => {
    expect(passwordIssue("valid\npassword", "valid\npassword")).toContain("不能包含控制字符");
    expect(passwordIssue("valid-password", "different-password")).toContain("不一致");
  });
});
