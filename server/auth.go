package server

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"antifox/db"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash" // Old single-user password (only used for the first-boot migration to rbac_users)
	// defaultSessionTTL is the default session (JWT) length — and also the "idle timeout" window:
	// With active use the backend renews it on a sliding basis (see requireAuth); idle longer than this and the token expires, requiring a fresh login.
	// Overridable with the auth.session_ttl_minutes setting (minutes).
	defaultSessionTTL = 60 * time.Minute
	sessionTTLKey     = "auth.session_ttl_minutes"
	keyChars          = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

type ctxKey int

const accessCtxKey ctxKey = 1

// adminRunCtxKey marks an agent run started by an admin session (so agent tools can tell whether they are in
// an admin context, and apply the same containment to high-risk tools like update_mcp as the HTTP layer).
const adminRunCtxKey ctxKey = 2

func ctxIsAdmin(ctx context.Context) bool {
	v, _ := ctx.Value(adminRunCtxKey).(bool)
	return v
}

// authClaims carries the user id (Subject) + username + the password version at signing (token_version).
// Ver makes "password change / deactivation kicks you offline" work: at verification it is compared against the current token_version in the DB, and a mismatch is rejected.
type authClaims struct {
	Username string `json:"usr"`
	Ver      int    `json:"ver"`
	jwt.RegisteredClaims
}

// CurrentAccess takes the current logged-in user's RBAC authorization profile from the request context (injected by requireAuth).
func CurrentAccess(r *http.Request) *db.RBACAccess {
	acc, _ := r.Context().Value(accessCtxKey).(*db.RBACAccess)
	return acc
}

// loadOrCreateJWTKey reads / generates the 32-byte HS256 signing key.
func loadOrCreateJWTKey(dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, jwtKeyFilename)
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] New JWT key written to %s", path)
	return buf, nil
}

// sessionTTL reads the session-length (minutes) setting, falling back to the default when unset / invalid.
func (s *Server) sessionTTL() time.Duration {
	if s.m != nil && s.m.pg != nil {
		if m := s.m.pg.GetInt(sessionTTLKey, 0); m > 0 {
			return time.Duration(m) * time.Minute
		}
	}
	return defaultSessionTTL
}

// signJWT issues an HS256 token with the default session TTL (tests use this).
func signJWT(key []byte, userID, username string) (string, error) {
	return signJWTTTL(key, userID, username, 0, defaultSessionTTL)
}

// signJWTTTL issues an HS256 token that expires after ttl, stamped with the user's
// current token_version (ver) so a later password change / disable invalidates it.
func signJWTTTL(key []byte, userID, username string, ver int, ttl time.Duration) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, authClaims{
		Username: username,
		Ver:      ver,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}).SignedString(key)
}

// parseJWT validates and returns the claims.
func parseJWT(tokenStr string, key []byte) (*authClaims, bool) {
	var c authClaims
	t, err := jwt.ParseWithClaims(tokenStr, &c, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	})
	if err != nil || !t.Valid {
		return nil, false
	}
	return &c, true
}

// extractToken reads the JWT from Authorization: Bearer, antifox_token cookie, or ?token=.
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("antifox_token"); err == nil && c.Value != "" {
		return c.Value
	}
	return r.URL.Query().Get("token")
}

// requireAuth verifies the JWT + resolves the user/permissions into the context. /api/auth/* and /api/health are exempt.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" {
			h.ServeHTTP(w, r)
			return
		}
		claims, ok := parseJWT(extractToken(r), s.jwtKey)
		if !ok {
			writeErr(w, 401, "Unauthorized or token expired")
			return
		}
		// Authorization resolution is now deny-by-default: any anomaly (empty subject / DB unavailable / query failure / empty profile)
		// is rejected across the board, never let through — avoiding "old tokens stay valid after account deletion" or "silent pass-through when the DB flaps".
		if strings.TrimSpace(claims.Subject) == "" {
			writeErr(w, 401, "Login session has expired; please log in again")
			return
		}
		if s.m == nil || s.m.pg == nil {
			writeErr(w, 503, "Authorization service is temporarily unavailable")
			return
		}
		acc, err := s.m.pg.ResolveRBACAccess(claims.Subject)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeErr(w, 401, "Login session has expired; please log in again")
			} else {
				log.Printf("[auth] Authorization query failed: %v", err)
				writeErr(w, 503, "Authorization service is temporarily unavailable")
			}
			return
		}
		if acc == nil {
			log.Printf("[auth] Authorization query returned an empty profile")
			writeErr(w, 503, "Authorization service is temporarily unavailable")
			return
		}
		if !acc.User.Enabled {
			writeErr(w, 403, "Account is deactivated")
			return
		}
		// Token version check: after a password change / deactivation, token_version increments, and an old token carrying a stale Ver
		// is invalid, forcing a fresh login.
		if claims.Ver != acc.User.TokenVersion {
			writeErr(w, 401, "Login session has expired; please log in again")
			return
		}
		// Forced password change at first login: first-boot seeding uses a weak default password, so must_change_password users are rejected everywhere except /api/auth/*
		// (already exempted at the top of this function, including the password-change endpoint) until they change their password, after which they can use the platform normally.
		if acc.User.MustChangePassword {
			writeErr(w, 403, "You must change your password at first login")
			return
		}
		// Sliding renewal (= idle timeout): once a token is past halfway and still in active use, a new token is issued and sent back via
		// the X-Refresh-Token response header for the frontend to store in place; idle beyond the session length and it expires naturally, requiring a fresh login.
		if claims.ExpiresAt != nil {
			ttl := s.sessionTTL()
			if rem := time.Until(claims.ExpiresAt.Time); rem > 0 && rem < ttl/2 {
				if fresh, err := signJWTTTL(s.jwtKey, claims.Subject, claims.Username, acc.User.TokenVersion, ttl); err == nil {
					w.Header().Set("Access-Control-Expose-Headers", "X-Refresh-Token")
					w.Header().Set("X-Refresh-Token", fresh)
				}
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), accessCtxKey, acc))
		// Permission enforcement. Safety valves: unmapped routes pass through; admin (full access) is never blocked; the rbac.enforce switch defaults to true.
		if s.m.pg.GetBool("rbac.enforce", true) {
			if perm := permissionForRequest(r.Method, r.URL.Path); perm != "" && !acc.Permissions[perm] {
				writeErr(w, 403, "Insufficient permissions: "+perm)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

// bootstrapRBAC migrates the old single-user password into the built-in admin on first boot, and seeds roles/permissions (idempotent).
func (s *Server) bootstrapRBAC() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	legacyHash, _, _ := s.m.pg.GetSetting(authPassKey)
	// Migration path: the old single-user password may be a weak default, so after migrating it into admin, the first login forces a password change.
	if err := s.m.pg.BootstrapRBAC(legacyHash, true); err != nil {
		log.Printf("[rbac] bootstrap failed: %v", err)
		return
	}
	if strings.TrimSpace(legacyHash) != "" {
		log.Printf("[rbac] Multi-user permissions ready (old password migrated to the built-in admin)")
	} else {
		log.Printf("[rbac] Multi-user permissions ready")
	}
}

// GET /api/auth/status — whether the platform is initialized (has platform users).
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	needs, err := pg.RBACNeedsBootstrap()
	if err != nil {
		writeErr(w, 500, "Query failed")
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": !needs})
}

// POST /api/auth/init — set the admin password on first boot (creates the built-in admin).
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ip := clientIP(r)
	// fail-closed: if the initialization-guard query errors, reject across the board — never treat a query failure as "not initialized" and allow setting
	// a password (otherwise a query failure could be used to reset the admin password).
	needs, err := pg.RBACNeedsBootstrap()
	if err != nil {
		pg.RecordAudit("", "auth", "init", "fail", ip, "Initialization-guard query failed (rejected)", nil)
		writeErr(w, 503, "Service is temporarily unavailable")
		return
	}
	if !needs {
		pg.RecordAudit("", "auth", "init", "fail", ip, "Platform is already initialized; refusing to set the password again", nil)
		writeErr(w, 403, "Already initialized")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "Bad request format")
		return
	}
	if msg := validatePasswordStrength(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "Password encryption failed")
		return
	}
	// Setup wizard: the user just chose their own password after passing the strength check, so don't force another password change (otherwise the whole site gets stuck on 403 after init).
	if err := pg.BootstrapRBAC(string(hash), false); err != nil {
		writeErr(w, 500, "Initialization failed: "+err.Error())
		return
	}
	_ = pg.SetSetting(authPassKey, string(hash)) // Kept for compatibility
	ver := 0
	if u, e := pg.GetRBACUserByID("admin"); e == nil && u != nil {
		ver = u.TokenVersion
	}
	tok, err := signJWTTTL(s.jwtKey, "admin", "admin", ver, s.sessionTTL())
	if err != nil {
		writeErr(w, 500, "Token generation failed")
		return
	}
	pg.RecordAudit("admin", "auth", "init", "success", ip, "First-boot admin password initialization", nil)
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password — change the current logged-in user's password.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	claims, ok := parseJWT(extractToken(r), s.jwtKey)
	if !ok {
		writeErr(w, 401, "Unauthorized")
		return
	}
	u, err := pg.GetRBACUserByID(claims.Subject)
	if err != nil {
		writeErr(w, 401, "User does not exist")
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "Bad request format")
		return
	}
	if msg := validatePasswordStrength(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	ip := clientIP(r)
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.OldPassword)); err != nil {
		pg.RecordAudit(u.Username, "auth", "change_password", "fail", ip, "Current password is incorrect", nil)
		writeErr(w, 401, "Current password is incorrect")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "Password encryption failed")
		return
	}
// UpdateRBACUserPassword increments token_version itself, invalidating all old tokens including the token in this request.
	if err := pg.UpdateRBACUserPassword(u.ID, string(newHash)); err != nil {
		writeErr(w, 500, "Save failed: "+err.Error())
		return
	}
	pg.RecordAudit(u.Username, "auth", "change_password", "success", ip, "Password changed successfully", nil)
	// Issue the caller a fresh token with the new version, avoiding "you get kicked out right after changing your password"; old tokens on other devices still become invalid.
	fresh := ""
	if nu, e := pg.GetRBACUserByID(u.ID); e == nil && nu != nil {
		fresh, _ = signJWTTTL(s.jwtKey, nu.ID, nu.Username, nu.TokenVersion, s.sessionTTL())
	}
	writeJSON(w, 200, map[string]any{"ok": true, "token": fresh})
}

// POST /api/auth/login — verify username/password and return a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "Bad request format")
		return
	}
	ip := clientIP(r)
	// Lockout counts are merged by normalized (lowercase) username: account matching is case-insensitive, so the lockout bucket must use the same key,
	// otherwise an attacker could rotate case variants like Admin/aDmin/ADMIN and count separately for each, bypassing account-level lockout.
	uname := strings.ToLower(strings.TrimSpace(req.Username))
	// Brute-force protection: check lockout status on both IP + account dimensions. A hit returns 429 directly, without doing any
	// password comparison (bcrypt itself is CPU-heavy; blocking first also eases "a flood of attempts saturating CPU/connections").
	if locked, retry := s.loginLimiter.locked(ip, uname); locked {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
		pg.RecordAudit(uname, "auth", "login_locked", "fail", ip,
			fmt.Sprintf("Brute-force lockout triggered, %ds of cooldown remaining", int(retry.Seconds())), nil)
		writeErr(w, 429, fmt.Sprintf("Too many attempts; the account/source is temporarily locked, please try again in %d seconds", int(retry.Seconds())))
		return
	}
	u, err := pg.GetRBACUserByUsername(req.Username)
	if err != nil || u == nil || !u.Enabled {
		reason := "Incorrect username or password"
		if u != nil && !u.Enabled {
			reason = "Account is deactivated"
		}
		s.registerLoginFailure(pg, ip, uname)
		pg.RecordAudit(uname, "auth", "login_failed", "fail", ip, reason, nil)
		log.Printf("[auth] Login failed user=%q ip=%s reason=%s", uname, ip, reason)
		writeErr(w, 401, reason)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
		s.registerLoginFailure(pg, ip, u.Username)
		pg.RecordAudit(u.Username, "auth", "login_failed", "fail", ip, "Wrong password", nil)
		log.Printf("[auth] Login failed user=%q ip=%s reason=Wrong password", u.Username, ip)
		writeErr(w, 401, "Incorrect username or password")
		return
	}
	tok, err := signJWTTTL(s.jwtKey, u.ID, u.Username, u.TokenVersion, s.sessionTTL())
	if err != nil {
		writeErr(w, 500, "Token generation failed")
		return
	}
	s.loginLimiter.reset(ip, u.Username) // A successful login resets the failure count for that IP+account
	pg.RecordAudit(u.Username, "auth", "login", "success", ip, "Login succeeded", nil)
	log.Printf("[auth] Login succeeded user=%q ip=%s", u.Username, ip)
	// must_change_password makes the frontend jump straight to password change after login; the backend requireAuth also blocks.
	writeJSON(w, 200, map[string]any{"token": tok, "must_change_password": u.MustChangePassword})
}

// registerLoginFailure records one failure in the limiter; if it happens to trigger a lockout, it writes an audit entry so it shows up on the logs page.
func (s *Server) registerLoginFailure(pg *db.DB, ip, username string) {
	if s.loginLimiter.fail(ip, username, s.loginPolicy()) {
		pg.RecordAudit(username, "auth", "login_locked", "fail", ip, "Failure count exceeded the threshold; temporarily locked", nil)
		log.Printf("[auth] Brute-force lockout user=%q ip=%s", username, ip)
	}
}

// validatePasswordStrength returns an empty string = pass, otherwise = the reason given to the user.
// Rules: 8–128 characters long, at least two character classes (letters / digits / symbols), and not a single repeated character.
func validatePasswordStrength(pw string) string {
	if len(pw) < 8 {
		return "Password must be at least 8 characters"
	}
	if len(pw) > 128 {
		return "Password is too long (at most 128 characters)"
	}
	var hasLetter, hasDigit, hasOther bool
	allSame := true
	for i, r := range pw {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasOther = true
		}
		if i > 0 && rune(pw[i]) != rune(pw[0]) {
			allSame = false
		}
	}
	if allSame {
		return "Password must not be a single repeated character"
	}
	classes := 0
	for _, b := range []bool{hasLetter, hasDigit, hasOther} {
		if b {
			classes++
		}
	}
	if classes < 2 {
		return "Password must contain at least two character classes (letters / digits / symbols)"
	}
	return ""
}

// clientIP extracts the client IP. Forwarding headers X-Real-IP / X-Forwarded-For are only trusted when the request comes from a trusted proxy (loopback / internal network, e.g. an nginx reverse proxy);
// otherwise the direct source RemoteAddr is used, so clients cannot forge forwarding headers
// to bypass source-level rate limiting / lockout. Under a trusted proxy: X-Real-IP (overriding) takes priority, then X-Forwarded-For
// takes the last one (proxies append hop by hop, so the one closest to us is the real source; the client-controllable prefix is ignored).
func clientIP(r *http.Request) string {
	remote := remoteAddrIP(r.RemoteAddr)
	if isTrustedProxyIP(remote) {
		if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
			return xr
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	return remote
}

// remoteAddrIP takes the IP part from net/http's RemoteAddr. net.SplitHostPort handles
// IPv6 correctly ("[::1]:port" → "::1", dropping the brackets, which LastIndexByte can't do); without a port, strip the brackets as a fallback.
func remoteAddrIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr)); err == nil {
		return host
	}
	return strings.Trim(strings.TrimSpace(remoteAddr), "[]")
}

// trustedProxyNets is the trusted reverse-proxy range, loopback only by default (127.0.0.0/8 + ::1).
// ⚠️ The whole private network is not trusted by default — otherwise, in an internal-network/VPN deployment, any private-network client could forge forwarding headers to bypass source-level
// lockout. When the reverse proxy is not on loopback, declare its range explicitly with the auth.trusted_proxies setting (see SetTrustedProxies).
var trustedProxyNets = loopbackProxyNets()

func loopbackProxyNets() []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range []string{"127.0.0.0/8", "::1/128"} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

// SetTrustedProxies rebuilds the trusted-proxy set from loopback + extra CIDRs/IPs (comma- or whitespace-separated); invalid entries are ignored,
// empty input = loopback only. Loaded once at startup by the server from settings (read-only after that, no concurrent writes).
func SetTrustedProxies(list string) {
	nets := loopbackProxyNets()
	for _, f := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if f == "" {
			continue
		}
		if !strings.Contains(f, "/") { // Bare IP → single-host mask
			if ip := net.ParseIP(f); ip != nil {
				if ip.To4() != nil {
					f += "/32"
				} else {
					f += "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(f); err == nil {
			nets = append(nets, n)
		}
	}
	trustedProxyNets = nets
}

// isTrustedProxyIP checks whether the direct source is a trusted reverse proxy (inside trustedProxyNets). Only forwarding headers set by a trusted proxy
// are believed — direct sources (public / undeclared private networks) never have their forwarding headers trusted, ruling out forged bypasses of rate limits.
func isTrustedProxyIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range trustedProxyNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}
