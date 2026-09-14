import {
  changeWebAdminPassword,
  getWebAuthState,
  loginWebAdmin,
  logoutWebAdmin,
  setWebAuthRejectionHandler,
  setupWebAdminPassword,
  WebAuthError,
  type WebAuthRejection,
} from "./api";
import { query } from "./dom";
import { escapeHtml } from "./format";
import { t } from "./i18n";

/**
 * Web 管理后台的登录门禁。
 *
 * 只在 Web 模式装配：桌面版由操作系统认证本地用户，不引入登录流程。
 * 前端是同一份 dist，靠运行时判断决定装不装，不做两份构建。
 */

type GateMode = "setup" | "login";

type GateOptions = {
  /** 会话在使用过程中失效时展示的说明。 */
  notice?: string;
  /** 登录成功后的动作。首屏是继续启动，中途失效是整页重载。 */
  onAuthenticated: () => void;
};

export type WebAuthControlHooks = {
  showMessage: (text: string, isError: boolean) => void;
  confirmAction: (options: {
    title: string;
    message: string;
    confirmLabel: string;
    danger?: boolean;
  }) => Promise<boolean>;
};

const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_BYTES = 128;

let gateVisible = false;

/**
 * 首屏门禁：已登录直接返回 true；否则渲染登录或首次设置页，
 * 等到认证成功才 resolve，让启动流程接着跑。
 *
 * 读取认证状态本身失败时停在可重试的错误页，不能直接启动：否则后续受保护
 * 请求只会连续失败，而且首次失败时还没有装好统一的认证拒绝处理器。
 */
export async function ensureWebAuthenticated(): Promise<boolean> {
  installRejectionHandler();
  while (true) {
    try {
      const state = await getWebAuthState();
      if (state.authenticated) {
        return true;
      }
      await new Promise<void>((resolve) => {
        showGate(state.passwordConfigured ? "login" : "setup", {
          onAuthenticated: resolve,
        });
      });
      return true;
    } catch (error) {
      console.error("读取 Web 管理认证状态失败", error);
      await waitForAuthStateRetry(error);
    }
  }
}

/** 装配顶栏登出与设置页的改密码入口。只在 Web 模式调用。 */
export function installWebAuthControls(hooks: WebAuthControlHooks): void {
  const logoutButton = query<HTMLButtonElement>("#web_auth_logout_btn");
  const form = query<HTMLFormElement>("#web_auth_password_form");
  const current = query<HTMLInputElement>("#web_auth_current_password");
  const next = query<HTMLInputElement>("#web_auth_new_password");
  const confirm = query<HTMLInputElement>("#web_auth_confirm_password");

  logoutButton.addEventListener("click", async () => {
    const confirmed = await hooks.confirmAction({
      title: t("退出登录"),
      message: t("将结束当前浏览器的管理会话，需要重新输入密码才能继续管理。"),
      confirmLabel: t("退出登录"),
    });
    if (!confirmed) {
      return;
    }
    try {
      await logoutWebAdmin();
    } catch (error) {
      console.error("退出登录失败", error);
    }
    window.location.reload();
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const issue = passwordIssue(next.value, confirm.value);
    if (issue) {
      hooks.showMessage(issue, true);
      return;
    }
    const submit = query<HTMLButtonElement>("#web_auth_password_submit");
    submit.disabled = true;
    submit.classList.add("loading");
    try {
      await changeWebAdminPassword(current.value, next.value);
      form.reset();
      hooks.showMessage(t("管理密码已更新，其它设备上的会话已失效"), false);
    } catch (error) {
      hooks.showMessage(
        t("修改管理密码失败：{p0}", { p0: errorText(error) }),
        true,
      );
    } finally {
      submit.disabled = false;
      submit.classList.remove("loading");
    }
  });
}

/** 会话中途失效时统一回到门禁。注册在 api.ts 的 401/403 出口上。 */
function installRejectionHandler(): void {
  setWebAuthRejectionHandler((error) => {
    showGate(gateModeFor(error.reason), {
      notice: error.message,
      // 中途失效时页面上的数据已经是旧的，重新登录后整页重载最省心也最不容易出错。
      onAuthenticated: () => window.location.reload(),
    });
  });
}

function gateModeFor(reason: WebAuthRejection): GateMode {
  return reason === "setup_required" ? "setup" : "login";
}

function waitForAuthStateRetry(error: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    try {
      showConnectionGate(errorText(error), resolve);
    } catch (renderError) {
      reject(renderError);
    }
  });
}

function showConnectionGate(message: string, onRetry: () => void): void {
  if (gateVisible) {
    return;
  }
  gateVisible = true;
  document.documentElement.dataset.webAuthGate = "unavailable";
  const host = document.createElement("div");
  host.className = "auth-gate";
  host.innerHTML = `
    <section class="auth-gate-card" aria-labelledby="auth_gate_title">
      <div class="auth-gate-brand">
        <strong>DnsBlackhole</strong>
        <span>${escapeHtml(t("Web 管理后台"))}</span>
      </div>
      <h1 id="auth_gate_title">${escapeHtml(t("暂时无法连接管理服务"))}</h1>
      <p class="auth-gate-hint">${escapeHtml(t("浏览器无法读取认证状态。请检查服务状态和网络连接，然后重试。"))}</p>
      <p class="auth-gate-notice" role="alert">${escapeHtml(message)}</p>
      <button class="primary" id="auth_gate_retry" type="button">${escapeHtml(t("重试"))}</button>
    </section>
  `;
  document.body.appendChild(host);
  const retry = host.querySelector<HTMLButtonElement>("#auth_gate_retry");
  if (!retry) {
    host.remove();
    gateVisible = false;
    delete document.documentElement.dataset.webAuthGate;
    throw new Error("Web 认证错误页缺少重试按钮");
  }
  retry.addEventListener("click", () => {
    host.remove();
    gateVisible = false;
    delete document.documentElement.dataset.webAuthGate;
    onRetry();
  });
  retry.focus();
}

function showGate(mode: GateMode, options: GateOptions): void {
  if (gateVisible) {
    return;
  }
  gateVisible = true;
  document.documentElement.dataset.webAuthGate = mode;
  const host = document.createElement("div");
  host.className = "auth-gate";
  host.innerHTML = gateMarkup(mode, options.notice);
  document.body.appendChild(host);

  const form = host.querySelector<HTMLFormElement>("form");
  const password = host.querySelector<HTMLInputElement>("#auth_gate_password");
  const confirm = host.querySelector<HTMLInputElement>("#auth_gate_confirm");
  const submit = host.querySelector<HTMLButtonElement>("#auth_gate_submit");
  const errorLine = host.querySelector<HTMLParagraphElement>("#auth_gate_error");
  if (!form || !password || !submit || !errorLine) {
    host.remove();
    gateVisible = false;
    delete document.documentElement.dataset.webAuthGate;
    throw new Error("Web 认证门禁结构不完整");
  }
  password.focus();

  const showError = (text: string) => {
    errorLine.textContent = text;
    errorLine.classList.remove("hidden");
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorLine.classList.add("hidden");
    if (mode === "setup") {
      const issue = passwordIssue(password.value, confirm?.value ?? "");
      if (issue) {
        showError(issue);
        return;
      }
    } else if (!password.value) {
      showError(t("请输入管理密码"));
      return;
    }
    submit.disabled = true;
    submit.classList.add("loading");
    form.setAttribute("aria-busy", "true");
    try {
      if (mode === "setup") {
        await setupWebAdminPassword(password.value);
      } else {
        await loginWebAdmin(password.value);
      }
      host.remove();
      gateVisible = false;
      delete document.documentElement.dataset.webAuthGate;
      options.onAuthenticated();
    } catch (error) {
      if (error instanceof WebAuthError && error.reason === "already_configured") {
        host.remove();
        gateVisible = false;
        delete document.documentElement.dataset.webAuthGate;
        showGate("login", {
          notice: error.message,
          onAuthenticated: options.onAuthenticated,
        });
        return;
      }
      showError(errorText(error));
      password.value = "";
      if (confirm) {
        confirm.value = "";
      }
      password.focus();
    } finally {
      submit.disabled = false;
      submit.classList.remove("loading");
      form.removeAttribute("aria-busy");
    }
  });
}

function gateMarkup(mode: GateMode, notice?: string): string {
  const setup = mode === "setup";
  const title = setup ? t("设置管理密码") : t("登录 DnsBlackhole");
  const hint = setup
    ? t("这个管理页面在局域网内可达，任何能访问它的设备都能改配置、停 DNS、看全部查询记录。请先设置一个管理密码。")
    : t("请输入管理密码以继续管理这台 DnsBlackhole。");
  const noticeLine = notice
    ? `<p class="auth-gate-notice" role="status">${escapeHtml(notice)}</p>`
    : "";
  const confirmField = setup
    ? `
        <label class="field">
          <span>${escapeHtml(t("再次输入以确认"))}</span>
          <input id="auth_gate_confirm" type="password" autocomplete="new-password" maxlength="${MAX_PASSWORD_BYTES}" spellcheck="false" required />
        </label>`
    : "";
  return `
    <form class="auth-gate-card" novalidate>
      <div class="auth-gate-brand">
        <strong>DnsBlackhole</strong>
        <span>${escapeHtml(t("Web 管理后台"))}</span>
      </div>
      <h1>${escapeHtml(title)}</h1>
      <p class="auth-gate-hint">${escapeHtml(hint)}</p>
      ${noticeLine}
      <label class="field">
        <span>${escapeHtml(t("管理密码"))}</span>
        <input
          id="auth_gate_password"
          type="password"
          autocomplete="${setup ? "new-password" : "current-password"}"
          maxlength="${MAX_PASSWORD_BYTES}"
          spellcheck="false"
          required
          ${setup ? 'aria-describedby="auth_gate_password_hint"' : ""}
        />
        ${setup ? `<small id="auth_gate_password_hint">${escapeHtml(t("至少 {p0} 个字符，最多 {p1} 字节。", { p0: MIN_PASSWORD_LENGTH, p1: MAX_PASSWORD_BYTES }))}</small>` : ""}
      </label>
      ${confirmField}
      <p class="auth-gate-error hidden" id="auth_gate_error" role="alert"></p>
      <button class="primary" id="auth_gate_submit" type="submit">
        ${escapeHtml(setup ? t("设置并进入") : t("登录"))}
      </button>
      <p class="auth-gate-foot">${escapeHtml(
        setup
          ? t("也可以在这台机器上执行 dnsblackhole-service web-auth set-password 来设置。")
          : t("忘记密码时在这台机器上执行 dnsblackhole-service web-auth reset 清除后重设。"),
      )}</p>
    </form>
  `;
}

export function passwordIssue(password: string, confirm: string): string | null {
  if ([...password].length < MIN_PASSWORD_LENGTH) {
    return t("管理密码至少需要 {p0} 个字符", { p0: MIN_PASSWORD_LENGTH });
  }
  if (new TextEncoder().encode(password).length > MAX_PASSWORD_BYTES) {
    return t("管理密码不能超过 {p0} 字节", { p0: MAX_PASSWORD_BYTES });
  }
  if (/[\u0000-\u001f\u007f-\u009f]/u.test(password)) {
    return t("管理密码不能包含控制字符");
  }
  if (password !== confirm) {
    return t("两次输入的密码不一致");
  }
  return null;
}

function errorText(error: unknown): string {
  if (error instanceof WebAuthError || error instanceof Error) {
    return error.message;
  }
  return String(error);
}
