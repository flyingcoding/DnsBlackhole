//! Web 管理后台的身份认证。
//!
//! 只服务 Linux 的 Web 管理形态：Web 是这个形态的唯一管理入口，且默认监听
//! `0.0.0.0:3000`。没有密码等于任何局域网设备都能改配置、停 DNS、读完整查询日志。
//! 桌面版不引入登录（操作系统已经认证了本地用户），所以整个模块挂在 `web-admin`
//! feature 上，`argon2` / `getrandom` 也不进 desktop 构建。
//!
//! 分层：`Host` 白名单与 `Origin` 校验保留在 [`crate::web_admin`]，认证是叠加的一层，
//! 不是替换。CSRF 由 `SameSite=Strict` 与 `Origin` 校验双保险。

use std::{
    fmt::Write as _,
    fs,
    net::IpAddr,
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{self, PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{dns::SecurityEventType, service_core::AppState};

/// Argon2id 参数，取 OWASP 的推荐档（m=19 MiB、t=2、p=1）。
///
/// 单次校验耗时用按需测试实测：
///   `cargo test --release --lib measures_argon2_verify_cost -- --ignored --nocapture`
///
/// 实测记录：
/// - amd64：**12.0 ms**（2026-09-09，Ubuntu 26.04 验证机，VMware 4 vCPU / 3.3 GiB RAM，
///   release 构建）。登录路径上这个开销可以忽略，限速阈值不用为它让步。
/// - arm64 低配设备（树莓派 / ARM NAS）：**待实测**；以后正式支持 arm64 镜像时
///   一并验证。过慢时下调 `ARGON2_MEMORY_KIB` 而不是 `ARGON2_TIME_COST`——
///   减少迭代次数对离线爆破的抗性损失更大。
const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
const ARGON2_TIME_COST: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;

/// 参数在编译期就校验一遍：非法组合直接编译不过，运行期没有 unwrap。
const ARGON2_PARAMS: Params = match Params::new(
    ARGON2_MEMORY_KIB,
    ARGON2_TIME_COST,
    ARGON2_PARALLELISM,
    None,
) {
    Ok(params) => params,
    Err(_) => panic!("Argon2id 参数常量必须合法"),
};

/// 盐长度取 RustCrypto 的推荐值。
const SALT_BYTES: usize = 16;

/// 会话 Cookie 名。
pub(crate) const SESSION_COOKIE: &str = "dnsblackhole_session";

/// 会话 token 字节数，走 OS CSPRNG。
const SESSION_TOKEN_BYTES: usize = 32;

/// 会话绝对上限：不管有没有活动，超过就要重新登录。不做可配置项，也不做“记住我”。
const SESSION_ABSOLUTE_LIFETIME: Duration = Duration::from_secs(12 * 3600);

/// 并发会话上限，超出淘汰最旧的一个。
const MAX_SESSIONS: usize = 16;

/// 密码长度下限（按字符计，避免多字节密码被额外惩罚）与字节上限。
const MIN_PASSWORD_CHARS: usize = 8;
const MAX_PASSWORD_BYTES: usize = 128;

/// 密码文件的大小上限：正常只有一行，超过就是挂错了文件。
const MAX_PASSWORD_FILE_BYTES: u64 = 4 * 1024;

/// 单 IP 连续失败到这个次数后开始锁定。
const LOCKOUT_AFTER_FAILURES: u32 = 5;
/// 锁定基准时长，之后按 2 的幂退避到上限。
const LOCKOUT_BASE: Duration = Duration::from_secs(15);
const LOCKOUT_MAX: Duration = Duration::from_secs(15 * 60);
/// 限速表容量上限：伪造源地址不能把内存撑爆。
const MAX_TRACKED_CLIENTS: usize = 1024;
/// 空闲多久的失败记录可以回收。
const ATTEMPT_RETENTION: Duration = Duration::from_secs(3600);

/// 全局失败上限：分布式撞库会换 IP，单 IP 限速拦不住。
const GLOBAL_FAILURE_WINDOW: Duration = Duration::from_secs(300);
const GLOBAL_FAILURE_LIMIT: u32 = 100;
const GLOBAL_LOCKOUT: Duration = Duration::from_secs(60);

/// 认证失败的原因。调用方（`web_admin` 的中间件与处理器）负责映射成 HTTP 状态码。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuthFailure {
    /// 尚未设置管理密码，只能先走首次设置。
    SetupRequired,
    /// 已经设置过密码，不能再走首次设置。
    AlreadyConfigured,
    /// 未登录或会话已过期。
    Unauthenticated,
    /// 密码错误。
    InvalidPassword,
    /// 登录被限速锁定，附带剩余秒数。
    Locked { retry_after_seconds: u64 },
    /// 输入不满足要求（密码太短之类）。
    Invalid(String),
    /// 内部错误（读写数据库、哈希计算失败）。
    Internal(String),
}

impl AuthFailure {
    /// 给前端的机器可读原因码。前端只靠它区分“去设置密码”和“去登录”。
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::SetupRequired => "setup_required",
            Self::AlreadyConfigured => "already_configured",
            Self::Unauthenticated => "unauthenticated",
            Self::InvalidPassword => "invalid_password",
            Self::Locked { .. } => "locked",
            Self::Invalid(_) => "invalid_request",
            Self::Internal(_) => "internal_error",
        }
    }

    pub(crate) fn message(&self) -> String {
        match self {
            Self::SetupRequired => {
                "尚未设置 Web 管理密码，请先访问管理页面完成首次设置".to_string()
            }
            Self::AlreadyConfigured => "已设置过 Web 管理密码，请直接登录".to_string(),
            Self::Unauthenticated => "请先登录 Web 管理后台".to_string(),
            Self::InvalidPassword => "密码错误".to_string(),
            Self::Locked {
                retry_after_seconds,
            } => format!("登录失败次数过多，请在 {retry_after_seconds} 秒后重试"),
            Self::Invalid(message) => message.clone(),
            Self::Internal(message) => message.clone(),
        }
    }
}

/// `web-auth status` 与前端首屏都读这个。
#[derive(Debug, Clone, Serialize)]
pub(crate) struct WebAuthStatus {
    /// 是否已设置管理密码。
    pub(crate) configured: bool,
    /// 密码最近一次写入的 Unix 秒。
    pub(crate) updated_at: Option<u64>,
    /// 当前有效会话数（未过期的）。
    pub(crate) active_sessions: usize,
}

/// 密码变更的来源，只用于安全事件的 reason 文本。
#[derive(Debug, Clone, Copy)]
pub(crate) enum PasswordOrigin {
    /// Web 首次设置页
    WebSetup,
    /// Web 修改密码
    WebChange,
    /// 本机 CLI `web-auth set-password`
    LocalCli,
    /// 本机 CLI `web-auth reset`
    LocalReset,
    /// 容器首启的 `--admin-password-file`
    PasswordFile,
}

impl PasswordOrigin {
    fn reason(self) -> &'static str {
        match self {
            Self::WebSetup => "首次设置管理密码",
            Self::WebChange => "通过 Web 修改管理密码",
            Self::LocalCli => "通过本机 CLI 设置管理密码",
            Self::LocalReset => "通过本机 CLI 重置管理密码",
            Self::PasswordFile => "通过 --admin-password-file 设置管理密码",
        }
    }

    /// 本机 CLI 与密码文件都发生在运行 DnsBlackhole 的那台机器上，
    /// 事件的来源客户端记 `127.0.0.1`；具体是哪条路径由 reason 文本区分。
    fn client_ip(self) -> Option<IpAddr> {
        match self {
            Self::WebSetup | Self::WebChange => None,
            Self::LocalCli | Self::LocalReset | Self::PasswordFile => {
                Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
            }
        }
    }
}

/// 会话表里的一条记录。key 是 `sha256(token)`：日志或内存转储里拿到它不能直接复用。
struct SessionEntry {
    key: [u8; 32],
    created_at: Instant,
    last_seen_at: Instant,
}

#[derive(Default)]
struct CredentialCache {
    loaded: bool,
    password_hash: Option<String>,
    updated_at: Option<u64>,
}

struct ClientAttempts {
    failures: u32,
    locked_until: Option<Instant>,
    last_failure_at: Instant,
}

#[derive(Default)]
struct RateLimitState {
    clients: Vec<(IpAddr, ClientAttempts)>,
    global_failures: u32,
    global_window_started_at: Option<Instant>,
    global_locked_until: Option<Instant>,
}

/// 认证状态挂在 [`AppState`] 上：CLI 走 RPC 改密码时也要能清掉进程内的会话。
///
/// 会话只在内存里，**进程重启后需要重新登录**。这是有意取舍：持久化会话要额外管
/// 失效、轮换与存储加密，对家庭局域网场景收益不足。
pub(crate) struct WebAuthState {
    credential: Mutex<CredentialCache>,
    sessions: Mutex<Vec<SessionEntry>>,
    rate_limit: Mutex<RateLimitState>,
}

impl WebAuthState {
    pub(crate) fn new() -> Self {
        Self {
            credential: Mutex::new(CredentialCache::default()),
            sessions: Mutex::new(Vec::new()),
            rate_limit: Mutex::new(RateLimitState::default()),
        }
    }
}

/// 中间件的判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuthOutcome {
    Authorized,
    Rejected(AuthFailure),
}

/// 判断一个请求能否访问管理接口，通过时顺带刷新会话的空闲计时。
pub(crate) fn authorize(state: &AppState, cookie_header: Option<&str>) -> AuthOutcome {
    match credential_hash(state) {
        Ok(None) => return AuthOutcome::Rejected(AuthFailure::SetupRequired),
        Ok(Some(_)) => {}
        Err(error) => return AuthOutcome::Rejected(AuthFailure::Internal(error)),
    }
    let Some(token) = cookie_header.and_then(session_token_from_cookies) else {
        return AuthOutcome::Rejected(AuthFailure::Unauthenticated);
    };
    if touch_session(state, &token_key(&token)) {
        AuthOutcome::Authorized
    } else {
        AuthOutcome::Rejected(AuthFailure::Unauthenticated)
    }
}

/// 首次设置：只在还没有密码时可用。成功后直接返回新会话的 token。
pub(crate) fn setup_password(
    state: &AppState,
    client: IpAddr,
    password: &str,
) -> Result<String, AuthFailure> {
    create_initial_password(state, password, PasswordOrigin::WebSetup, Some(client))?;
    let token = issue_session(state)?;
    Ok(token)
}

fn create_initial_password(
    state: &AppState,
    password: &str,
    origin: PasswordOrigin,
    client: Option<IpAddr>,
) -> Result<(), AuthFailure> {
    validate_password(password)?;
    let phc = hash_password(password).map_err(AuthFailure::Internal)?;
    let mut cache = state
        .web_auth
        .credential
        .lock()
        .map_err(|_| AuthFailure::Internal("写入 Web 管理凭据缓存失败".to_string()))?;
    load_credential_cache(state, &mut cache).map_err(AuthFailure::Internal)?;
    if cache.password_hash.is_some() {
        return Err(AuthFailure::AlreadyConfigured);
    }
    let Some(updated_at) = state
        .database
        .create_web_admin_credential(&phc)
        .map_err(AuthFailure::Internal)?
    else {
        // 数据库唯一键是最终裁决者。理论上只有另一个进程错误地同时使用同一数据目录
        // 才会走到这里；重新加载缓存，保证当前进程也立即进入“已设置”状态。
        let stored = state
            .database
            .web_admin_credential()
            .map_err(AuthFailure::Internal)?;
        cache.password_hash = stored.as_ref().map(|item| item.password_hash.clone());
        cache.updated_at = stored.as_ref().map(|item| item.updated_at);
        cache.loaded = true;
        return Err(AuthFailure::AlreadyConfigured);
    };
    cache.loaded = true;
    cache.password_hash = Some(phc);
    cache.updated_at = Some(updated_at);
    drop(cache);
    record_event(
        state,
        SecurityEventType::WebAuthPasswordChanged,
        client.or_else(|| origin.client_ip()),
        origin.reason().to_string(),
    );
    Ok(())
}

/// 登录。失败会计入限速与安全事件。
pub(crate) fn login(
    state: &AppState,
    client: IpAddr,
    password: &str,
) -> Result<String, AuthFailure> {
    let Some(stored) = credential_hash(state).map_err(AuthFailure::Internal)? else {
        return Err(AuthFailure::SetupRequired);
    };
    check_lockout(state, client)?;
    // 已保存的密码不可能超过这个上限或含控制字符。先拒绝明显无效输入，
    // 避免把数 MiB 的请求体交给 Argon2；失败仍照常计入限速。
    if password.len() > MAX_PASSWORD_BYTES || password.chars().any(char::is_control) {
        return reject_login(state, client);
    }
    if !verify_password(&stored, password).map_err(AuthFailure::Internal)? {
        return reject_login(state, client);
    }
    clear_failures(state, client)?;
    let token = issue_session(state)?;
    record_event(
        state,
        SecurityEventType::WebAuthLogin,
        Some(client),
        "Web 管理登录成功".to_string(),
    );
    Ok(token)
}

/// 修改密码：校验当前密码，成功后使除本会话之外的全部会话失效。
pub(crate) fn change_password(
    state: &AppState,
    client: IpAddr,
    cookie_header: Option<&str>,
    current_password: &str,
    new_password: &str,
) -> Result<(), AuthFailure> {
    validate_password(new_password)?;
    let phc = hash_password(new_password).map_err(AuthFailure::Internal)?;
    // 校验旧密码与写入新密码必须在同一把凭据锁内完成，避免两个并发修改都用旧密码
    // 通过校验，随后互相覆盖。数据库写入与缓存更新也保持一个临界区。
    let mut cache = state
        .web_auth
        .credential
        .lock()
        .map_err(|_| AuthFailure::Internal("写入 Web 管理凭据缓存失败".to_string()))?;
    load_credential_cache(state, &mut cache).map_err(AuthFailure::Internal)?;
    let Some(stored) = cache.password_hash.as_deref() else {
        return Err(AuthFailure::SetupRequired);
    };
    if !verify_password(stored, current_password).map_err(AuthFailure::Internal)? {
        drop(cache);
        record_event(
            state,
            SecurityEventType::WebAuthFailed,
            Some(client),
            "修改 Web 管理密码时当前密码错误".to_string(),
        );
        return Err(AuthFailure::InvalidPassword);
    }
    let updated_at = state
        .database
        .save_web_admin_credential(&phc)
        .map_err(AuthFailure::Internal)?;
    cache.password_hash = Some(phc);
    cache.updated_at = Some(updated_at);
    drop(cache);
    record_event(
        state,
        SecurityEventType::WebAuthPasswordChanged,
        Some(client),
        PasswordOrigin::WebChange.reason().to_string(),
    );
    let keep = cookie_header
        .and_then(session_token_from_cookies)
        .map(|token| token_key(&token));
    retain_only_session(state, keep.as_ref())?;
    Ok(())
}

/// 登出：删掉服务端会话。Cookie 由调用方清除。
pub(crate) fn logout(state: &AppState, cookie_header: Option<&str>) {
    if let Some(token) = cookie_header.and_then(session_token_from_cookies) {
        remove_session(state, &token_key(&token));
    }
}

pub(crate) fn invalidate_sessions(state: &AppState) -> Result<(), AuthFailure> {
    retain_only_session(state, None)
}

/// 本机路径设置密码：CLI 的 `web-auth set-password` 与容器的 `--admin-password-file`。
/// 会清掉全部会话——改了密码就不该让旧浏览器继续用着。
pub(crate) fn set_password_locally(
    state: &AppState,
    password: &str,
    origin: PasswordOrigin,
) -> Result<(), AuthFailure> {
    store_password(state, password, origin, None)?;
    retain_only_session(state, None)?;
    Ok(())
}

/// 清除密码与全部会话，作为忘记密码时的本机恢复路径。返回是否确实清掉了已设置的密码。
pub(crate) fn reset_password(state: &AppState) -> Result<bool, AuthFailure> {
    let mut cache = state
        .web_auth
        .credential
        .lock()
        .map_err(|_| AuthFailure::Internal("写入 Web 管理凭据缓存失败".to_string()))?;
    let removed = state
        .database
        .clear_web_admin_credential()
        .map_err(AuthFailure::Internal)?;
    cache.loaded = true;
    cache.password_hash = None;
    cache.updated_at = None;
    drop(cache);
    retain_only_session(state, None)?;
    if removed {
        record_event(
            state,
            SecurityEventType::WebAuthPasswordChanged,
            PasswordOrigin::LocalReset.client_ip(),
            PasswordOrigin::LocalReset.reason().to_string(),
        );
    }
    Ok(removed)
}

pub(crate) fn status(state: &AppState) -> Result<WebAuthStatus, AuthFailure> {
    let hash = credential_hash(state).map_err(AuthFailure::Internal)?;
    let updated_at = state
        .web_auth
        .credential
        .lock()
        .map_err(|_| AuthFailure::Internal("读取 Web 管理凭据缓存失败".to_string()))?
        .updated_at;
    Ok(WebAuthStatus {
        configured: hash.is_some(),
        updated_at,
        active_sessions: active_session_count(state),
    })
}

/// 首启读取挂载的密码文件（配合 Docker secret）。
///
/// 不提供环境变量方式：`docker inspect` 能看到环境变量。
/// 已经设置过密码时忽略该文件，避免容器重启把用户在界面上改过的密码顶回去。
///
/// 读取或校验失败时返回错误。调用方可以继续运行 DNS，但不得启动 Web 管理后台，
/// 否则显式要求预设密码的部署会意外退回到可被抢占的首次设置状态。
pub(crate) fn apply_password_file(state: &AppState, path: &Path) -> Result<(), String> {
    match credential_hash(state) {
        Ok(Some(_)) => {
            eprintln!(
                "已存在 Web 管理密码，忽略 --admin-password-file：{}",
                path.display()
            );
            return Ok(());
        }
        Ok(None) => {}
        Err(error) => return Err(format!("读取 Web 管理凭据失败：{error}")),
    }
    let password = read_password_file(path).map_err(|error| {
        format!(
            "读取 --admin-password-file 失败（{}）：{error}",
            path.display()
        )
    })?;
    match create_initial_password(state, &password, PasswordOrigin::PasswordFile, None) {
        Ok(()) => {}
        Err(AuthFailure::AlreadyConfigured) => {
            eprintln!(
                "已存在 Web 管理密码，忽略 --admin-password-file：{}",
                path.display()
            );
            return Ok(());
        }
        Err(failure) => {
            return Err(format!(
                "--admin-password-file 内容不可用（{}）：{}",
                path.display(),
                failure.message()
            ));
        }
    }
    eprintln!("已从 {} 设置 Web 管理密码", path.display());
    Ok(())
}

fn read_password_file(path: &Path) -> Result<String, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("无法读取文件信息：{error}"))?;
    if !metadata.is_file() {
        return Err("密码文件必须指向普通文件".to_string());
    }
    if metadata.len() > MAX_PASSWORD_FILE_BYTES {
        return Err(format!(
            "密码文件超过 {MAX_PASSWORD_FILE_BYTES} 字节，已拒绝读取"
        ));
    }
    let content =
        fs::read_to_string(path).map_err(|error| format!("密码文件必须是 UTF-8 文本：{error}"))?;
    // 只去掉行尾换行：密码本身可能以空格开头或结尾。
    Ok(content.trim_end_matches(['\n', '\r']).to_string())
}

/// 启动时给出的醒目提示，Server DEB 与容器日志里都要能看到。
pub(crate) fn log_startup_state(state: &AppState, listen: &str) {
    match credential_hash(state) {
        Ok(Some(_)) => eprintln!("Web 管理认证：已设置管理密码"),
        Ok(None) => {
            eprintln!("========================================================");
            eprintln!("尚未设置 Web 管理密码。");
            eprintln!("请立即访问 http://{listen} 完成设置：在此之前除首次设置页外");
            eprintln!("的全部管理接口都会被拒绝，DNS 解析不受影响。");
            eprintln!("也可以在本机执行：dnsblackhole-service web-auth set-password");
            eprintln!("========================================================");
        }
        Err(error) => eprintln!("[错误] 检查 Web 管理凭据失败：{error}"),
    }
}

// ---------------------------------------------------------------------------
// 凭据
// ---------------------------------------------------------------------------

/// 取密码哈希，首次访问时从数据库懒加载。加载后内存即为快路径，写入时同步更新。
fn credential_hash(state: &AppState) -> Result<Option<String>, String> {
    let mut cache = state
        .web_auth
        .credential
        .lock()
        .map_err(|_| "读取 Web 管理凭据缓存失败".to_string())?;
    load_credential_cache(state, &mut cache)?;
    Ok(cache.password_hash.clone())
}

fn load_credential_cache(state: &AppState, cache: &mut CredentialCache) -> Result<(), String> {
    if cache.loaded {
        return Ok(());
    }
    let stored = state.database.web_admin_credential()?;
    cache.password_hash = stored.as_ref().map(|item| item.password_hash.clone());
    cache.updated_at = stored.as_ref().map(|item| item.updated_at);
    cache.loaded = true;
    Ok(())
}

fn store_password(
    state: &AppState,
    password: &str,
    origin: PasswordOrigin,
    client: Option<IpAddr>,
) -> Result<(), AuthFailure> {
    validate_password(password)?;
    let phc = hash_password(password).map_err(AuthFailure::Internal)?;
    // 先取得缓存锁再落库，避免数据库已更新但缓存锁失败时继续用旧密码。
    // 所有凭据路径都遵循 credential -> database 的锁顺序。
    let mut cache = state
        .web_auth
        .credential
        .lock()
        .map_err(|_| AuthFailure::Internal("写入 Web 管理凭据缓存失败".to_string()))?;
    let updated_at = state
        .database
        .save_web_admin_credential(&phc)
        .map_err(AuthFailure::Internal)?;
    cache.loaded = true;
    cache.password_hash = Some(phc);
    cache.updated_at = Some(updated_at);
    drop(cache);
    record_event(
        state,
        SecurityEventType::WebAuthPasswordChanged,
        client.or_else(|| origin.client_ip()),
        origin.reason().to_string(),
    );
    Ok(())
}

fn validate_password(password: &str) -> Result<(), AuthFailure> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(AuthFailure::Invalid(format!(
            "管理密码至少需要 {MIN_PASSWORD_CHARS} 个字符"
        )));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(AuthFailure::Invalid(format!(
            "管理密码不能超过 {MAX_PASSWORD_BYTES} 字节"
        )));
    }
    if password.chars().any(char::is_control) {
        return Err(AuthFailure::Invalid("管理密码不能包含控制字符".to_string()));
    }
    Ok(())
}

fn hasher() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, ARGON2_PARAMS)
}

fn hash_password(password: &str) -> Result<String, String> {
    let mut salt = [0u8; SALT_BYTES];
    getrandom::fill(&mut salt).map_err(|error| format!("生成密码盐失败：{error}"))?;
    hasher()
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| format!("计算密码哈希失败：{error}"))
}

/// 用存储的 PHC 字符串校验密码。参数以哈希里记录的为准，所以调整常量不会让旧密码失效。
fn verify_password(stored: &str, password: &str) -> Result<bool, String> {
    let parsed =
        PasswordHash::new(stored).map_err(|error| format!("解析已存密码哈希失败：{error}"))?;
    match hasher().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(password_hash::Error::PasswordInvalid) => Ok(false),
        Err(error) => Err(format!("校验管理密码失败：{error}")),
    }
}

// ---------------------------------------------------------------------------
// 会话
// ---------------------------------------------------------------------------

fn token_key(token: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(token.as_bytes());
    digest.finalize().into()
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for index in 0..32 {
        diff |= left[index] ^ right[index];
    }
    diff == 0
}

fn issue_session(state: &AppState) -> Result<String, AuthFailure> {
    let mut raw = [0u8; SESSION_TOKEN_BYTES];
    getrandom::fill(&mut raw)
        .map_err(|error| AuthFailure::Internal(format!("生成会话 token 失败：{error}")))?;
    let mut token = String::with_capacity(SESSION_TOKEN_BYTES * 2);
    for byte in raw {
        let _ = write!(token, "{byte:02x}");
    }
    let idle = idle_timeout(state);
    let now = Instant::now();
    let mut sessions = state
        .web_auth
        .sessions
        .lock()
        .map_err(|_| AuthFailure::Internal("访问会话表失败".to_string()))?;
    prune_sessions(&mut sessions, idle, now);
    if sessions.len() >= MAX_SESSIONS {
        // 队首是最早创建的：淘汰最旧的会话，不让一台设备反复登录把别人挤没。
        sessions.remove(0);
    }
    sessions.push(SessionEntry {
        key: token_key(&token),
        created_at: now,
        last_seen_at: now,
    });
    Ok(token)
}

fn touch_session(state: &AppState, key: &[u8; 32]) -> bool {
    let idle = idle_timeout(state);
    let now = Instant::now();
    let Ok(mut sessions) = state.web_auth.sessions.lock() else {
        return false;
    };
    prune_sessions(&mut sessions, idle, now);
    let mut matched = None;
    // 不提前 break：命中与否的耗时不随 token 内容变化。
    for (index, session) in sessions.iter().enumerate() {
        if constant_time_eq(&session.key, key) {
            matched = Some(index);
        }
    }
    match matched {
        Some(index) => {
            sessions[index].last_seen_at = now;
            true
        }
        None => false,
    }
}

fn remove_session(state: &AppState, key: &[u8; 32]) {
    if let Ok(mut sessions) = state.web_auth.sessions.lock() {
        sessions.retain(|session| !constant_time_eq(&session.key, key));
    }
}

/// `keep` 为 `None` 时清空全部会话。
fn retain_only_session(state: &AppState, keep: Option<&[u8; 32]>) -> Result<(), AuthFailure> {
    let mut sessions = state
        .web_auth
        .sessions
        .lock()
        .map_err(|_| AuthFailure::Internal("访问会话表失败".to_string()))?;
    match keep {
        Some(key) => sessions.retain(|session| constant_time_eq(&session.key, key)),
        None => sessions.clear(),
    }
    Ok(())
}

fn active_session_count(state: &AppState) -> usize {
    let idle = idle_timeout(state);
    let now = Instant::now();
    match state.web_auth.sessions.lock() {
        Ok(mut sessions) => {
            prune_sessions(&mut sessions, idle, now);
            sessions.len()
        }
        Err(_) => 0,
    }
}

fn prune_sessions(sessions: &mut Vec<SessionEntry>, idle: Duration, now: Instant) {
    sessions.retain(|session| {
        now.duration_since(session.created_at) <= SESSION_ABSOLUTE_LIFETIME
            && now.duration_since(session.last_seen_at) <= idle
    });
}

fn idle_timeout(state: &AppState) -> Duration {
    let minutes = state
        .current_config()
        .map(|config| config.web_admin_session_idle_minutes)
        .unwrap_or(60);
    Duration::from_secs(u64::from(minutes) * 60)
}

/// 生成 `Set-Cookie` 的值。
///
/// 不带 `Max-Age`：会话 Cookie 随浏览器关闭失效，服务端也不做“记住我”。
pub(crate) fn session_cookie(token: &str, secure: bool) -> String {
    let mut cookie = format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub(crate) fn cleared_session_cookie(secure: bool) -> String {
    let mut cookie = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub(crate) fn secure_cookie_enabled(state: &AppState) -> bool {
    state
        .current_config()
        .map(|config| config.web_admin_secure_cookie)
        .unwrap_or(false)
}

fn session_token_from_cookies(header: &str) -> Option<String> {
    header
        .split(';')
        .filter_map(|part| part.split_once('='))
        .find(|(name, _)| name.trim() == SESSION_COOKIE)
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

// ---------------------------------------------------------------------------
// 登录限速
// ---------------------------------------------------------------------------

fn check_lockout(state: &AppState, client: IpAddr) -> Result<(), AuthFailure> {
    let now = Instant::now();
    let mut limit = state
        .web_auth
        .rate_limit
        .lock()
        .map_err(|_| AuthFailure::Internal("访问 Web 登录限速状态失败".to_string()))?;
    if let Some(until) = limit.global_locked_until {
        if now < until {
            return Err(AuthFailure::Locked {
                retry_after_seconds: remaining_seconds(until, now),
            });
        }
        limit.global_locked_until = None;
    }
    if let Some((_, attempts)) = limit.clients.iter().find(|(ip, _)| *ip == client)
        && let Some(until) = attempts.locked_until
        && now < until
    {
        return Err(AuthFailure::Locked {
            retry_after_seconds: remaining_seconds(until, now),
        });
    }
    Ok(())
}

fn reject_login(state: &AppState, client: IpAddr) -> Result<String, AuthFailure> {
    let locked_for = record_failure(state, client)?;
    record_event(
        state,
        SecurityEventType::WebAuthFailed,
        Some(client),
        "Web 管理登录密码错误".to_string(),
    );
    if let Some(locked_for) = locked_for {
        record_event(
            state,
            SecurityEventType::WebAuthLocked,
            Some(client),
            format!("Web 管理登录连续失败，已锁定 {locked_for} 秒"),
        );
        return Err(AuthFailure::Locked {
            retry_after_seconds: locked_for,
        });
    }
    Err(AuthFailure::InvalidPassword)
}

/// 记录一次失败，返回本次是否触发锁定（以及锁定秒数）。
fn record_failure(state: &AppState, client: IpAddr) -> Result<Option<u64>, AuthFailure> {
    let now = Instant::now();
    let mut limit = state
        .web_auth
        .rate_limit
        .lock()
        .map_err(|_| AuthFailure::Internal("访问 Web 登录限速状态失败".to_string()))?;
    // 全局窗口：一段时间内的失败总数超限就整体短暂锁定。
    match limit.global_window_started_at {
        Some(started) if now.duration_since(started) <= GLOBAL_FAILURE_WINDOW => {
            limit.global_failures = limit.global_failures.saturating_add(1);
        }
        _ => {
            limit.global_window_started_at = Some(now);
            limit.global_failures = 1;
        }
    }
    let mut locked_for = None;
    if limit.global_failures >= GLOBAL_FAILURE_LIMIT {
        limit.global_locked_until = Some(now + GLOBAL_LOCKOUT);
        limit.global_failures = 0;
        limit.global_window_started_at = Some(now);
        locked_for = Some(GLOBAL_LOCKOUT.as_secs());
    }

    evict_stale_attempts(&mut limit, now);
    let entry = match limit.clients.iter_mut().find(|(ip, _)| *ip == client) {
        Some((_, attempts)) => attempts,
        None => {
            limit.clients.push((
                client,
                ClientAttempts {
                    failures: 0,
                    locked_until: None,
                    last_failure_at: now,
                },
            ));
            let index = limit.clients.len() - 1;
            &mut limit.clients[index].1
        }
    };
    entry.failures = entry.failures.saturating_add(1);
    entry.last_failure_at = now;
    if entry.failures >= LOCKOUT_AFTER_FAILURES {
        let steps = entry.failures - LOCKOUT_AFTER_FAILURES;
        let lock = LOCKOUT_BASE
            .saturating_mul(1u32 << steps.min(16))
            .min(LOCKOUT_MAX);
        entry.locked_until = Some(now + lock);
        locked_for = Some(lock.as_secs());
    }
    Ok(locked_for)
}

fn clear_failures(state: &AppState, client: IpAddr) -> Result<(), AuthFailure> {
    let mut limit = state
        .web_auth
        .rate_limit
        .lock()
        .map_err(|_| AuthFailure::Internal("访问 Web 登录限速状态失败".to_string()))?;
    limit.clients.retain(|(ip, _)| *ip != client);
    Ok(())
}

fn evict_stale_attempts(limit: &mut RateLimitState, now: Instant) {
    limit.clients.retain(|(_, attempts)| {
        attempts.locked_until.is_some_and(|until| now < until)
            || now.duration_since(attempts.last_failure_at) <= ATTEMPT_RETENTION
    });
    while limit.clients.len() >= MAX_TRACKED_CLIENTS {
        // 满了就丢最早失败的那条：留着仍在锁定期内的记录更有价值。
        let oldest = limit
            .clients
            .iter()
            .enumerate()
            .min_by_key(|(_, (_, attempts))| attempts.last_failure_at)
            .map(|(index, _)| index);
        match oldest {
            Some(index) => {
                limit.clients.remove(index);
            }
            None => break,
        }
    }
}

fn remaining_seconds(until: Instant, now: Instant) -> u64 {
    until.saturating_duration_since(now).as_secs().max(1)
}

// ---------------------------------------------------------------------------
// 安全事件
// ---------------------------------------------------------------------------

fn record_event(
    state: &AppState,
    event_type: SecurityEventType,
    client: Option<IpAddr>,
    reason: String,
) {
    let client_ip = client
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).to_string());
    state.record_web_admin_security_event(event_type, client_ip, reason);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::AppConfig, database::Database, service_core::AppState};
    use std::{
        net::Ipv4Addr,
        sync::{Arc, Barrier},
        thread,
    };

    fn test_state() -> Arc<AppState> {
        let database = Arc::new(Database::open_in_memory().expect("内存库应能打开"));
        let dir = std::env::temp_dir().join("dnsblackhole-web-auth-test");
        Arc::new(AppState::new(
            AppConfig::default(),
            database,
            dir.clone(),
            dir,
        ))
    }

    fn client() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))
    }

    #[test]
    fn rejects_everything_until_password_is_configured() {
        let state = test_state();
        assert_eq!(
            authorize(&state, None),
            AuthOutcome::Rejected(AuthFailure::SetupRequired)
        );
        assert_eq!(
            login(&state, client(), "whatever-long"),
            Err(AuthFailure::SetupRequired)
        );
    }

    #[test]
    fn setup_then_login_then_logout_round_trip() {
        let state = test_state();
        let token = setup_password(&state, client(), "correct-horse").expect("首次设置应成功");
        let cookie = format!("{SESSION_COOKIE}={token}");
        assert_eq!(authorize(&state, Some(&cookie)), AuthOutcome::Authorized);

        // 已设置密码后不能再走首次设置
        assert_eq!(
            setup_password(&state, client(), "another-password"),
            Err(AuthFailure::AlreadyConfigured)
        );

        logout(&state, Some(&cookie));
        assert_eq!(
            authorize(&state, Some(&cookie)),
            AuthOutcome::Rejected(AuthFailure::Unauthenticated)
        );

        let second = login(&state, client(), "correct-horse").expect("登录应成功");
        assert_eq!(
            authorize(&state, Some(&format!("{SESSION_COOKIE}={second}"))),
            AuthOutcome::Authorized
        );
    }

    #[test]
    fn concurrent_first_setup_has_exactly_one_winner() {
        let state = test_state();
        let barrier = Arc::new(Barrier::new(2));
        let workers = ["first-password", "second-password"].map(|password| {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                (password, setup_password(&state, client(), password))
            })
        });
        let [first, second] = workers.map(|worker| worker.join().expect("设置线程不应异常"));
        let outcomes = [first, second];
        assert_eq!(
            outcomes.iter().filter(|(_, result)| result.is_ok()).count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|(_, result)| matches!(result, Err(AuthFailure::AlreadyConfigured)))
                .count(),
            1
        );
        let winner = outcomes
            .iter()
            .find_map(|(password, result)| result.is_ok().then_some(*password))
            .expect("应有唯一胜者");
        login(&state, client(), winner).expect("最终保存的密码应属于唯一胜者");
    }

    #[test]
    fn wrong_password_is_rejected_and_counted() {
        let state = test_state();
        setup_password(&state, client(), "correct-horse").expect("首次设置应成功");
        retain_only_session(&state, None).expect("应能清空会话");
        for _ in 0..(LOCKOUT_AFTER_FAILURES - 1) {
            assert_eq!(
                login(&state, client(), "wrong-password"),
                Err(AuthFailure::InvalidPassword)
            );
        }
        let failure = login(&state, client(), "wrong-password").expect_err("第 5 次应触发锁定");
        assert!(matches!(failure, AuthFailure::Locked { .. }));
        // 锁定期内即使密码正确也不放行
        assert!(matches!(
            login(&state, client(), "correct-horse"),
            Err(AuthFailure::Locked { .. })
        ));
        let events = state
            .database
            .recent_security_events(64)
            .expect("应能读取安全事件");
        assert!(
            events
                .iter()
                .any(|event| event.event_type == SecurityEventType::WebAuthFailed)
        );
        assert!(
            events
                .iter()
                .any(|event| event.event_type == SecurityEventType::WebAuthLocked)
        );
    }

    #[test]
    fn oversized_login_input_is_rejected_and_counted() {
        let state = test_state();
        setup_password(&state, client(), "correct-horse").expect("首次设置应成功");
        assert_eq!(
            login(&state, client(), &"x".repeat(MAX_PASSWORD_BYTES + 1)),
            Err(AuthFailure::InvalidPassword)
        );
        let events = state
            .database
            .recent_security_events(64)
            .expect("应能读取安全事件");
        assert!(
            events
                .iter()
                .any(|event| event.event_type == SecurityEventType::WebAuthFailed)
        );
    }

    #[test]
    fn successful_login_clears_failure_counter() {
        let state = test_state();
        setup_password(&state, client(), "correct-horse").expect("首次设置应成功");
        for _ in 0..(LOCKOUT_AFTER_FAILURES - 1) {
            let _ = login(&state, client(), "wrong-password");
        }
        login(&state, client(), "correct-horse").expect("登录应成功");
        for _ in 0..(LOCKOUT_AFTER_FAILURES - 1) {
            assert_eq!(
                login(&state, client(), "wrong-password"),
                Err(AuthFailure::InvalidPassword)
            );
        }
    }

    #[test]
    fn idle_and_absolute_timeouts_expire_sessions() {
        let state = test_state();
        let token = setup_password(&state, client(), "correct-horse").expect("首次设置应成功");
        let key = token_key(&token);
        let idle = Duration::from_secs(600);

        let mut sessions = vec![SessionEntry {
            key,
            created_at: Instant::now(),
            last_seen_at: Instant::now() - idle - Duration::from_secs(1),
        }];
        prune_sessions(&mut sessions, idle, Instant::now());
        assert!(sessions.is_empty(), "空闲超时应清掉会话");

        let mut sessions = vec![SessionEntry {
            key,
            created_at: Instant::now() - SESSION_ABSOLUTE_LIFETIME - Duration::from_secs(1),
            last_seen_at: Instant::now(),
        }];
        prune_sessions(&mut sessions, idle, Instant::now());
        assert!(sessions.is_empty(), "绝对上限应清掉会话");
    }

    #[test]
    fn concurrent_sessions_are_capped() {
        let state = test_state();
        setup_password(&state, client(), "correct-horse").expect("首次设置应成功");
        let mut tokens = Vec::new();
        for _ in 0..(MAX_SESSIONS + 4) {
            tokens.push(login(&state, client(), "correct-horse").expect("登录应成功"));
        }
        assert_eq!(active_session_count(&state), MAX_SESSIONS);
        let oldest = &tokens[0];
        assert_eq!(
            authorize(&state, Some(&format!("{SESSION_COOKIE}={oldest}"))),
            AuthOutcome::Rejected(AuthFailure::Unauthenticated),
            "最旧的会话应已被淘汰"
        );
        let newest = tokens.last().expect("应有会话");
        assert_eq!(
            authorize(&state, Some(&format!("{SESSION_COOKIE}={newest}"))),
            AuthOutcome::Authorized
        );
    }

    #[test]
    fn changing_password_keeps_only_the_current_session() {
        let state = test_state();
        let first = setup_password(&state, client(), "correct-horse").expect("首次设置应成功");
        let second = login(&state, client(), "correct-horse").expect("第二个会话应能登录");
        let second_cookie = format!("{SESSION_COOKIE}={second}");
        change_password(
            &state,
            client(),
            Some(&second_cookie),
            "correct-horse",
            "battery-staple",
        )
        .expect("修改密码应成功");
        assert_eq!(
            authorize(&state, Some(&second_cookie)),
            AuthOutcome::Authorized
        );
        assert_eq!(
            authorize(&state, Some(&format!("{SESSION_COOKIE}={first}"))),
            AuthOutcome::Rejected(AuthFailure::Unauthenticated)
        );
        assert_eq!(
            login(&state, client(), "correct-horse"),
            Err(AuthFailure::InvalidPassword)
        );
        login(&state, client(), "battery-staple").expect("新密码应能登录");
    }

    #[test]
    fn change_password_requires_the_current_one() {
        let state = test_state();
        let token = setup_password(&state, client(), "correct-horse").expect("首次设置应成功");
        let cookie = format!("{SESSION_COOKIE}={token}");
        assert_eq!(
            change_password(&state, client(), Some(&cookie), "wrong", "battery-staple"),
            Err(AuthFailure::InvalidPassword)
        );
        login(&state, client(), "correct-horse").expect("旧密码仍然有效");
    }

    #[test]
    fn reset_clears_password_and_sessions() {
        let state = test_state();
        let token = setup_password(&state, client(), "correct-horse").expect("首次设置应成功");
        assert!(reset_password(&state).expect("重置应成功"));
        assert_eq!(
            authorize(&state, Some(&format!("{SESSION_COOKIE}={token}"))),
            AuthOutcome::Rejected(AuthFailure::SetupRequired)
        );
        assert!(!reset_password(&state).expect("重复重置应成功但无变化"));
        // 重置后可以重新走首次设置
        setup_password(&state, client(), "battery-staple").expect("重置后应能再次设置");
    }

    #[test]
    fn short_or_control_character_passwords_are_rejected() {
        let state = test_state();
        assert!(matches!(
            setup_password(&state, client(), "short"),
            Err(AuthFailure::Invalid(_))
        ));
        assert!(matches!(
            setup_password(&state, client(), "with\nnewline"),
            Err(AuthFailure::Invalid(_))
        ));
        assert!(matches!(
            setup_password(&state, client(), &"x".repeat(MAX_PASSWORD_BYTES + 1)),
            Err(AuthFailure::Invalid(_))
        ));
        // 多字节密码按字符计数，8 个汉字应通过
        setup_password(&state, client(), "密码密码密码密码").expect("多字节密码应通过");
    }

    #[test]
    fn cookie_parser_picks_the_session_cookie() {
        assert_eq!(
            session_token_from_cookies("theme=dark; dnsblackhole_session=abc123; other=1"),
            Some("abc123".to_string())
        );
        assert_eq!(session_token_from_cookies("theme=dark"), None);
        assert_eq!(session_token_from_cookies("dnsblackhole_session="), None);
    }

    #[test]
    fn cookie_attributes_follow_the_secure_switch() {
        assert_eq!(
            session_cookie("abc", false),
            "dnsblackhole_session=abc; HttpOnly; SameSite=Strict; Path=/"
        );
        assert!(session_cookie("abc", true).ends_with("; Secure"));
        assert!(cleared_session_cookie(false).contains("Max-Age=0"));
    }

    #[test]
    fn enabling_secure_cookie_invalidates_existing_sessions() {
        let state = test_state();
        let token = setup_password(&state, client(), "correct-horse").expect("首次设置应成功");
        let cookie = format!("{SESSION_COOKIE}={token}");
        assert_eq!(authorize(&state, Some(&cookie)), AuthOutcome::Authorized);

        let mut config = state.current_config().expect("应能读取配置");
        config.enabled = false;
        config.web_admin_secure_cookie = true;
        crate::service_core::save_config_blocking(Arc::clone(&state), config)
            .expect("应能开启 Secure Cookie");

        assert_eq!(
            authorize(&state, Some(&cookie)),
            AuthOutcome::Rejected(AuthFailure::Unauthenticated)
        );
    }

    #[test]
    fn stored_hash_is_argon2id_and_never_the_plaintext() {
        let phc = hash_password("correct-horse").expect("应能计算哈希");
        assert!(phc.starts_with("$argon2id$v=19$"));
        assert!(!phc.contains("correct-horse"));
        assert!(verify_password(&phc, "correct-horse").expect("校验应成功"));
        assert!(!verify_password(&phc, "correct-horsf").expect("校验应成功"));
        // 同一个密码两次哈希的盐不同
        let other = hash_password("correct-horse").expect("应能计算哈希");
        assert_ne!(phc, other);
    }

    #[test]
    fn password_file_trims_only_trailing_newlines() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "dnsblackhole-admin-password-{}.txt",
            std::process::id()
        ));
        fs::write(&path, " correct horse \r\n").expect("应能写入临时密码文件");
        assert_eq!(
            read_password_file(&path).expect("应能读取"),
            " correct horse "
        );
        fs::remove_file(&path).expect("应能清理临时文件");
    }

    #[test]
    fn password_file_errors_are_returned_without_configuring_a_password() {
        let state = test_state();
        let path = std::env::temp_dir().join(format!(
            "dnsblackhole-missing-admin-password-{}.txt",
            std::process::id()
        ));
        let error = apply_password_file(&state, &path).expect_err("不存在的密码文件应返回错误");
        assert!(error.contains("读取 --admin-password-file 失败"));
        assert!(!status(&state).expect("应能读取认证状态").configured);
    }

    /// Argon2id 单次校验耗时。默认跳过，手动执行：
    ///   cargo test --release --lib measures_argon2_verify_cost -- --ignored --nocapture
    #[test]
    #[ignore = "性能测试：实测 Argon2id 单次校验耗时"]
    fn measures_argon2_verify_cost() {
        let phc = hash_password("correct-horse").expect("应能计算哈希");
        let rounds = 10;
        let started = Instant::now();
        for _ in 0..rounds {
            assert!(verify_password(&phc, "correct-horse").expect("校验应成功"));
        }
        let each = started.elapsed() / rounds;
        println!(
            "Argon2id m={ARGON2_MEMORY_KIB} KiB t={ARGON2_TIME_COST} p={ARGON2_PARALLELISM}：单次校验 {:.1} ms",
            each.as_secs_f64() * 1000.0
        );
    }
}
