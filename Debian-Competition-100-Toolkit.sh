#!/usr/bin/env bash
# Debian competition hardening toolkit
# Based on user-provided scoring list. Review README and keep required services.
# Run: sudo bash Debian-Competition-100-Toolkit.sh
# Optional: sudo bash Debian-Competition-100-Toolkit.sh --audit
# Optional: sudo bash Debian-Competition-100-Toolkit.sh --all
set -u -o pipefail
umask 077

if (( EUID != 0 )); then echo 'Run with: sudo bash Debian-Competition-100-Toolkit.sh'; exit 1; fi
BACKUP="/root/debian-competition-backups-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
LOG="$BACKUP/changes.log"
: > "$LOG"

say() { printf '\n\033[1;34m%s\033[0m\n' "$*"; printf '%s %s\n' "$(date -Is)" "$*" >> "$LOG"; }
warn() { printf '\033[1;33mWARNING: %s\033[0m\n' "$*"; printf 'WARN: %s\n' "$*" >> "$LOG"; }
ask() { local answer; read -r -p "$1 [y/N]: " answer || return 1; [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]; }
keep() { local f="$1"; if [[ -e "$f" ]]; then local dest="$BACKUP${f}"; mkdir -p "$(dirname "$dest")"; cp -a -- "$f" "$dest"; fi; }
installed() { dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null | grep -qx installed; }
set_key() {
  local file="$1" key="$2" value="$3"
  [[ -f "$file" ]] || touch "$file"
  keep "$file"
  # Only replace setting lines; preserve other config content and comments.
  sed -i -E "/^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*=/d" "$file"
  printf '%s = %s\n' "$key" "$value" >> "$file"
}

f1_accounts() {
  say '1/18: Unauthorized and hidden accounts: thaos, raedric, devil, concelhaut (8 pts)'
  keep /etc/passwd; keep /etc/shadow; keep /etc/group; keep /etc/gshadow
  for user in thaos raedric devil concelhaut; do
    if ! id "$user" >/dev/null 2>&1; then echo "Already absent: $user"; continue; fi
    if [[ "$user" == "${SUDO_USER:-not-the-user}" || "$user" == "$(logname 2>/dev/null || echo none)" ]]; then warn "Refusing to remove active administrator $user"; continue; fi
    echo "Account: $user; UID: $(id -u "$user"); groups: $(id -nG "$user" 2>/dev/null || true)"
    if [[ "$(id -u "$user")" == '0' ]]; then warn "UID 0 account: check manually before removal"; continue; fi
    if ask "Remove $user and their home directory?"; then
      pkill -u "$user" 2>/dev/null || true
      userdel -r "$user" 2>&1 || warn "Could not fully remove $user"
    fi
  done
}

f2_passwords() {
  say '2/18: Set passwords for hiravias and root (4 pts)'
  for user in hiravias root; do
    if id "$user" >/dev/null 2>&1; then
      passwd -S "$user" || true
      if ask "Set a new strong password for $user (interactive)?"; then passwd "$user" || warn "Password change failed for $user"; fi
    else warn "Account not found: $user"; fi
  done
}

f3_password_policy() {
  say '3/18: yescrypt, lockout, minimum age and length (8 pts)'
  keep /etc/login.defs; keep /etc/pam.d/common-password
  sed -i -E 's/^[[:space:]]*#?[[:space:]]*ENCRYPT_METHOD[[:space:]]+.*/ENCRYPT_METHOD YESCRYPT/; s/^[[:space:]]*#?[[:space:]]*PASS_MIN_DAYS[[:space:]]+.*/PASS_MIN_DAYS 1/; s/^[[:space:]]*#?[[:space:]]*PASS_MIN_LEN[[:space:]]+.*/PASS_MIN_LEN 12/' /etc/login.defs
  grep -q '^ENCRYPT_METHOD ' /etc/login.defs || echo 'ENCRYPT_METHOD YESCRYPT' >> /etc/login.defs
  grep -q '^PASS_MIN_DAYS ' /etc/login.defs || echo 'PASS_MIN_DAYS 1' >> /etc/login.defs
  grep -q '^PASS_MIN_LEN ' /etc/login.defs || echo 'PASS_MIN_LEN 12' >> /etc/login.defs
  if [[ -f /etc/pam.d/common-password ]]; then
    python3 - <<'PY'
from pathlib import Path
import re
p=Path('/etc/pam.d/common-password')
lines=p.read_text().splitlines(keepends=True)
out=[]
for line in lines:
    if not line.lstrip().startswith('#') and 'pam_unix.so' in line:
        line=re.sub(r'\s+(?:sha512|md5|yescrypt)\b','',line.rstrip('\n'))+' yescrypt\n'
        line=re.sub(r'\s+nullok\b','',line)
    out.append(line)
p.write_text(''.join(out))
PY
  fi
  if ! installed libpam-pwquality; then
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y libpam-pwquality || warn 'Could not install libpam-pwquality'
  fi
  if installed libpam-pwquality; then
    set_key /etc/security/pwquality.conf minlen 12
    set_key /etc/security/pwquality.conf enforce_for_root 1
    if ! grep -Eq '^[^#]*pam_pwquality\.so' /etc/pam.d/common-password; then
      keep /etc/pam.d/common-password
      sed -i '/^[[:space:]]*password.*pam_unix\.so/i password requisite pam_pwquality.so retry=3' /etc/pam.d/common-password
    fi
  fi
  # PAM faillock is security-critical: only modify a standard simple Debian PAM stack.
  set_key /etc/security/faillock.conf deny 5
  set_key /etc/security/faillock.conf fail_interval 900
  set_key /etc/security/faillock.conf unlock_time 900
  if find /usr/lib /lib -name pam_faillock.so -print -quit 2>/dev/null | grep -q .; then
    if grep -q 'pam_faillock.so' /etc/pam.d/common-auth; then
      echo 'pam_faillock already configured; inspect: grep -n faillock /etc/pam.d/common-*'
    elif command -v pam-auth-update >/dev/null 2>&1; then
      if ask 'Enable Debian pam_faillock using managed PAM profiles? Keep this session open for verification'; then
        keep /etc/pam.d/common-auth; keep /etc/pam.d/common-account
        mkdir -p /usr/share/pam-configs
        cat > /usr/share/pam-configs/competition_faillock_notify <<'PROFILE'
Name: Competition - faillock check and count reset
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
        requisite       pam_faillock.so preauth silent
Account-Type: Primary
Account:
        required        pam_faillock.so
PROFILE
        cat > /usr/share/pam-configs/competition_faillock_fail <<'PROFILE'
Name: Competition - deny failed authentication after threshold
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
        [default=die]   pam_faillock.so authfail
PROFILE
        DEBIAN_FRONTEND=noninteractive pam-auth-update --enable competition_faillock_notify competition_faillock_fail || warn 'pam-auth-update failed; inspect /etc/pam.d/common-auth'
        warn 'Test a NEW login before closing this session. Revert if needed using pam-auth-update --remove competition_faillock_notify competition_faillock_fail.'
      fi
    else warn 'pam-auth-update missing; PAM lockout skipped'; fi
  else warn 'pam_faillock.so absent; install libpam-modules'; fi
  echo 'Password aging defaults affect newly created accounts. Existing user aging can be adjusted individually with chage -m 1 USER.'
}

f4_kernel_logging() {
  say '4/18: Log impossible-address kernel packets to /var/log/kern.log (2 pts)'
  echo 'net.ipv4.conf.all.log_martians = 1' > /etc/sysctl.d/91-competition-martians.conf
  echo 'net.ipv4.conf.default.log_martians = 1' >> /etc/sysctl.d/91-competition-martians.conf
  sysctl -p /etc/sysctl.d/91-competition-martians.conf || true
  if ! installed rsyslog; then DEBIAN_FRONTEND=noninteractive apt-get install -y rsyslog || warn 'rsyslog unavailable'; fi
  if installed rsyslog; then
    cat > /etc/rsyslog.d/30-competition-kernel.conf <<'EOF'
kern.*                          -/var/log/kern.log
EOF
    systemctl enable --now rsyslog || true
    systemctl restart rsyslog || true
  fi
}

f5_gdm() {
  say '5/18: Hide user list on GDM login screen (2 pts)'
  mkdir -p /etc/dconf/db/gdm.d /etc/dconf/profile
  if [[ ! -f /etc/dconf/profile/gdm ]]; then
    cat > /etc/dconf/profile/gdm <<'PROFILE'
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
PROFILE
  fi
  keep /etc/dconf/db/gdm.d/01-competition-login
  cat > /etc/dconf/db/gdm.d/01-competition-login <<'EOF'
[org/gnome/login-screen]
disable-user-list=true
EOF
  if command -v dconf >/dev/null 2>&1; then dconf update || warn 'dconf update failed'; else warn 'dconf unavailable'; fi
  echo 'Log out and back in to see the greeter change. Do not restart GDM during a competition session.'
}

f6_sudo_auth() {
  say '6/18: Require password for sudo (2 pts)'
  command -v visudo >/dev/null 2>&1 || { warn 'visudo missing'; return; }
  local file
  for file in /etc/sudoers /etc/sudoers.d/*; do
    [[ -f "$file" ]] || continue
    if grep -Eq 'NOPASSWD:|!authenticate' "$file"; then
      echo "Relevant sudo rules in $file:"
      grep -nE 'NOPASSWD:|!authenticate' "$file" || true
      if ask "Replace NOPASSWD: and Defaults !authenticate in $file?"; then
        keep "$file"
        sed -i -e 's/NOPASSWD:/PASSWD:/g' -e '/^[[:space:]]*Defaults.*!authenticate/d' "$file"
        if ! visudo -cf /etc/sudoers; then cp -a "$BACKUP$file" "$file"; warn "Invalid sudoers syntax; reverted $file"; fi
      fi
    fi
  done
  visudo -cf /etc/sudoers || true
}

f7_system_shells() {
  say '7/18: Disable interactive shells for unauthorized system accounts (2 pts)'
  echo 'System UID < 1000 with interactive shells (excluding root):'
  awk -F: '$3 < 1000 && $1!="root" && $7 ~ /(bash|zsh|fish|\/sh)$/ {print $1, "UID=" $3, "shell=" $7}' /etc/passwd
  echo 'postgres and other service identities may require their configured shell for administration.'
  if ask 'Change these accounts to /usr/sbin/nologin one by one?'; then
    while IFS=: read -r user _ uid _ _ _ shell; do
      if (( uid < 1000 )) && [[ "$user" != root ]] && [[ "$shell" =~ (bash|zsh|fish|/sh)$ ]]; then
        if ask "Set $user ($shell) shell to nologin?"; then usermod -s /usr/sbin/nologin "$user" || true; fi
      fi
    done < /etc/passwd
  fi
}

f8_firewall() {
  say '8/18: Enable UFW and block port 9473 (7 pts)'
  if ! command -v ufw >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get install -y ufw || { warn 'UFW install failed'; return; }; fi
  # Preserve port 22 for remote SSH clients if a server is running.
  if systemctl is-active --quiet ssh 2>/dev/null; then
    warn 'SSH service active: preserving its configured listening ports before enabling UFW.'
    while read -r port; do
      [[ "$port" =~ ^[0-9]+$ ]] && ufw allow "${port}/tcp" || true
    done < <(/usr/sbin/sshd -T 2>/dev/null | awk '$1=="port" {print $2}')
  fi
  ufw default deny incoming
  ufw default allow outgoing
  ufw deny 9473/tcp
  ufw deny 9473/udp
  ufw --force enable
  ufw status verbose
  warn 'If PostgreSQL clients connect remotely, preserve only the required database-access rules.'
}

f9_grub() {
  say '9/18: Restrict permissions on /boot/grub/grub.cfg (4 pts)'
  if [[ -f /boot/grub/grub.cfg ]]; then chown root:root /boot/grub/grub.cfg; chmod 600 /boot/grub/grub.cfg; stat -c '%a %U:%G %n' /boot/grub/grub.cfg; else warn 'GRUB configuration not found'; fi
}

f10_dmesg() {
  say '10/18: Prevent unprivileged dmesg access (4 pts)'
  echo 'kernel.dmesg_restrict = 1' > /etc/sysctl.d/90-competition-dmesg.conf
  sysctl -p /etc/sysctl.d/90-competition-dmesg.conf || true
}

f11_services() {
  say '11/18: Stop and disable apache2 and smbd (4 pts)'
  for service in apache2 smbd; do
    if systemctl list-unit-files "${service}.service" --no-legend 2>/dev/null | grep -q .; then
      systemctl disable --now "$service" || warn "Could not disable $service"
    else echo "$service not installed as a service"; fi
  done
  warn 'Only do this because your Debian scoring checklist marks these services as unwanted.'
}

f12_updates() {
  say '12/18: Install Debian security updates and newer kernel (4 pts)'
  if ! ask 'Run apt update, upgrade, and install linux-image-amd64? This may take time and require a reboot'; then return; fi
  apt-get update || { warn 'apt update failed'; return; }
  DEBIAN_FRONTEND=noninteractive apt-get upgrade -y || warn 'Some packages did not upgrade'
  DEBIAN_FRONTEND=noninteractive apt-get install -y linux-image-amd64 || warn 'Kernel metapackage install failed'
  echo 'Running kernel:'; uname -r
  echo 'Installed kernel packages:'; dpkg-query -W 'linux-image*' 2>/dev/null | tail -12 || true
  warn 'Kernel updates may not score until the VM is safely rebooted.'
}

f13_mp3() {
  say '13/18: Find prohibited MP3 files (2 pts)'
  local found="$BACKUP/mp3-files.txt"
  find /home /root /opt /tmp /var/tmp /media /var/www -type f -iname '*.mp3' -print 2>/dev/null | tee "$found"
  if [[ ! -s "$found" ]]; then warn 'No MP3 files found in common user-content locations'; return; fi
  if ask 'Permanently remove the MP3 files listed above?'; then
    while IFS= read -r f; do [[ -f "$f" ]] && rm -f -- "$f"; done < "$found"
  fi
}

f14_software() {
  say '14/18: Remove hydra, Discord and cmospwd (6 pts)'
  local pkgs=() pkg
  for pkg in hydra hydra-gtk discord cmospwd; do installed "$pkg" && pkgs+=("$pkg"); done
  if (( ${#pkgs[@]} > 0 )); then
    printf 'Installed packages: %s\n' "${pkgs[*]}"
    if ask 'Purge these unwanted packages?'; then DEBIAN_FRONTEND=noninteractive apt-get purge -y "${pkgs[@]}"; fi
  fi
  if command -v flatpak >/dev/null 2>&1 && flatpak list --app --columns=application 2>/dev/null | grep -qx com.discordapp.Discord; then
    if ask 'Uninstall Discord Flatpak?'; then flatpak uninstall -y com.discordapp.Discord; fi
  fi
  if command -v snap >/dev/null 2>&1 && snap list discord >/dev/null 2>&1; then
    if ask 'Uninstall Discord snap?'; then snap remove discord; fi
  fi
  for d in /opt/discord /usr/share/discord; do
    if [[ -d "$d" ]]; then
      if ask "Remove manually installed Discord directory $d?"; then rm -rf -- "$d"; fi
    fi
  done
  echo 'Additional installed locations:'
  command -v hydra || true; command -v discord || true; command -v cmospwd || true
}

f15_backdoor() {
  say '15/18: Quarantine kworker.py Python backdoor (4 pts)'
  local bad='/var/cache/.adra/kworker.py' pid comm
  for p in /proc/[0-9]*; do
    pid="${p##*/}"
    [[ "$pid" == "$$" || "$pid" == "${PPID}" ]] && continue
    if tr '\0' '\n' < "$p/cmdline" 2>/dev/null | grep -Fxq "$bad"; then
      comm=$(cat "$p/comm" 2>/dev/null || true)
      echo "Stopping suspicious process PID=$pid ($comm)"
      kill "$pid" 2>/dev/null || true
    fi
  done
  if [[ -f "$bad" ]]; then
    mkdir -p "$BACKUP/malware-quarantine"
    mv -v -- "$bad" "$BACKUP/malware-quarantine/kworker.py"
    chmod 600 "$BACKUP/malware-quarantine/kworker.py"
  else echo 'Backdoor file already absent'; fi
  echo 'Check references/persistence to the old path:'
  grep -rlF -- "$bad" /etc/cron* /etc/systemd/system /var/spool/cron 2>/dev/null || true
  warn 'Any persistence entries printed above must be examined and removed separately.'
}

f16_postgresql() {
  say '16/18: PostgreSQL SSL + authenticated connections (10 pts)'
  if ! command -v pg_lsclusters >/dev/null 2>&1; then warn 'No Debian PostgreSQL clusters found'; return; fi
  local ver cluster status conf hba
  while read -r ver cluster status; do
    [[ -n "$ver" ]] || continue
    conf="/etc/postgresql/$ver/$cluster/postgresql.conf"
    hba="/etc/postgresql/$ver/$cluster/pg_hba.conf"
    [[ -f "$conf" && -f "$hba" ]] || continue
    echo "Cluster: $ver/$cluster status=$status"
    keep "$conf"; keep "$hba"
    if [[ -f /etc/ssl/certs/ssl-cert-snakeoil.pem && -f /etc/ssl/private/ssl-cert-snakeoil.key ]]; then
      if getent group ssl-cert >/dev/null; then usermod -aG ssl-cert postgres || true; fi
      pg_conftool "$ver" "$cluster" set ssl on
      pg_conftool "$ver" "$cluster" set ssl_cert_file /etc/ssl/certs/ssl-cert-snakeoil.pem
      pg_conftool "$ver" "$cluster" set ssl_key_file /etc/ssl/private/ssl-cert-snakeoil.key
    else
      warn 'Debian snakeoil certificate missing; creating unique PostgreSQL certificate and key.'
      local certdir="/etc/postgresql/$ver/$cluster/competition-tls"
      mkdir -p "$certdir"
      openssl req -x509 -newkey rsa:3072 -nodes -days 365 -subj "/CN=$(hostname)" \
          -keyout "$certdir/server.key" -out "$certdir/server.crt" || { warn 'TLS cert generation failed'; continue; }
      chown postgres:postgres "$certdir/server.key" "$certdir/server.crt"
      chmod 600 "$certdir/server.key"; chmod 644 "$certdir/server.crt"
      pg_conftool "$ver" "$cluster" set ssl on
      pg_conftool "$ver" "$cluster" set ssl_cert_file "$certdir/server.crt"
      pg_conftool "$ver" "$cluster" set ssl_key_file "$certdir/server.key"
    fi
    pg_conftool "$ver" "$cluster" set password_encryption scram-sha-256
    echo "Existing HBA auth rules in $hba:"
    grep -E '^[[:space:]]*(local|host|hostssl|hostnossl)[[:space:]]' "$hba" || true
    if grep -Eq '^[[:space:]]*(local|host|hostssl|hostnossl)[[:space:]].*[[:space:]]trust([[:space:]#]|$)' "$hba"; then
      warn 'TRUST permits password-free database logins; replacing it with SCRAM requires passwords on affected roles.'
      if ask "Change TRUST entries to scram-sha-256 in $hba? (May break app connections without passwords)"; then
        sed -i -E '/^[[:space:]]*(local|host|hostssl|hostnossl)[[:space:]]/s/[[:space:]]trust([[:space:]#]|$)/ scram-sha-256\1/' "$hba"
      fi
    fi
    if ask "Restart PostgreSQL cluster $ver/$cluster to apply SSL and authentication settings?"; then
      pg_ctlcluster "$ver" "$cluster" restart || warn "PostgreSQL failed to restart; restore backups if necessary"
      if [[ "$(pg_ctlcluster "$ver" "$cluster" status 2>/dev/null || true)" == *'server is running'* ]]; then
        su -s /bin/sh postgres -c "psql -Atqc 'SHOW ssl;'" 2>/dev/null || true
      fi
    fi
    echo "Review DB authentication with: sudo -u postgres psql -c 'TABLE pg_hba_file_rules;'"
  done < <(pg_lsclusters --no-header 2>/dev/null | awk '{print $1, $2, $4}')
}

f17_ssh() {
  say '17/18: Disable SSH root login and user-provided environment (8 pts)'
  if ! command -v sshd >/dev/null 2>&1 && [[ ! -x /usr/sbin/sshd ]]; then warn 'OpenSSH server not installed'; return; fi
  mkdir -p /etc/ssh/sshd_config.d
  local f='/etc/ssh/sshd_config.d/00-competition-hardening.conf'
  keep "$f"
  cat > "$f" <<'EOF'
PermitRootLogin no
PermitUserEnvironment no
PermitEmptyPasswords no
EOF
  if /usr/sbin/sshd -t; then
    systemctl reload ssh 2>/dev/null || systemctl restart ssh || true
    /usr/sbin/sshd -T | grep -Ei 'permitrootlogin|permituserenvironment|permitemptypasswords' || true
  else
    warn 'sshd syntax check failed: restoring previous drop-in if it existed'
    if [[ -f "$BACKUP$f" ]]; then cp -a "$BACKUP$f" "$f"; else rm -f "$f"; fi
  fi
}

f18_chrome() {
  say '18/18: Block Chrome pop-ups and enable automatic HTTPS upgrades (8 pts)'
  local file='/etc/opt/chrome/policies/managed/competition-security.json'
  mkdir -p "$(dirname "$file")"
  keep "$file"
  python3 - "$file" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
try: obj=json.loads(p.read_text()) if p.exists() else {}
except (ValueError,OSError): obj={}
obj['DefaultPopupsSetting']=2
obj['HttpsUpgradesEnabled']=True
p.write_text(json.dumps(obj,indent=2)+'\n')
PY
  chmod 644 "$file"
  echo 'Chrome: restart browser, then open chrome://policy and click Reload policies.'
  echo 'Policy file:'; cat "$file"
}

audit() {
  say 'READ-ONLY AUDIT: does not alter settings'
  echo 'OS:'; grep '^PRETTY_NAME=' /etc/os-release || true
  echo 'Accounts:'; for u in thaos raedric devil concelhaut hiravias root; do id "$u" 2>/dev/null || true; done
  echo 'Password status:'; for u in hiravias root; do passwd -S "$u" 2>/dev/null || true; done
  echo 'Kernel:'; uname -r
  echo 'Firewall:'; command -v ufw >/dev/null && ufw status verbose || true
  echo 'dmesg restricted:'; sysctl kernel.dmesg_restrict || true
  echo 'GRUB permissions:'; stat -c '%a %U:%G %n' /boot/grub/grub.cfg 2>/dev/null || true
  echo 'Sudoers password bypass:'; grep -RnsE 'NOPASSWD:|!authenticate' /etc/sudoers /etc/sudoers.d 2>/dev/null || true
  echo 'PAM policies:'; grep -nE 'pam_faillock|pam_pwquality|pam_unix' /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password 2>/dev/null || true
  echo 'Password defaults:'; grep -E '^ENCRYPT_METHOD|^PASS_MIN_DAYS|^PASS_MIN_LEN' /etc/login.defs || true
  echo 'Services:'; systemctl is-enabled apache2 smbd ssh postgresql 2>/dev/null || true
  echo 'Malware:'; ls -l /var/cache/.adra/kworker.py 2>/dev/null || true
  echo 'PG clusters:'; command -v pg_lsclusters >/dev/null && pg_lsclusters || true
  echo 'SSH effective:'; [[ -x /usr/sbin/sshd ]] && /usr/sbin/sshd -T 2>/dev/null | grep -Ei 'permitrootlogin|permituserenvironment' || true
  echo 'Chrome policy:'; cat /etc/opt/chrome/policies/managed/competition-security.json 2>/dev/null || true
  echo "Backup/log location (if any changes are made): $BACKUP"
}

run_one() {
  case "$1" in
    1) f1_accounts;; 2) f2_passwords;; 3) f3_password_policy;; 4) f4_kernel_logging;;
    5) f5_gdm;; 6) f6_sudo_auth;; 7) f7_system_shells;; 8) f8_firewall;;
    9) f9_grub;; 10) f10_dmesg;; 11) f11_services;; 12) f12_updates;;
    13) f13_mp3;; 14) f14_software;; 15) f15_backdoor;; 16) f16_postgresql;;
    17) f17_ssh;; 18) f18_chrome;; a|A) audit;; *) warn 'Invalid selection';;
  esac
}

all_fixes() {
  warn 'This changes operating-system settings. Check the README. Continue only if you have VM console access and a backup/snapshot.'
  if ! ask 'Proceed through all 18 groups, with confirmations for destructive steps?'; then return; fi
  local i
  for i in {1..18}; do
    run_one "$i" || warn "Group $i returned nonzero: review output"
  done
  say 'All groups processed. Run the scoring report, examine errors, and verify SSH, login, PostgreSQL, and the workstation GUI.'
  echo "Backups: $BACKUP"
}

menu() {
  while true; do
    cat <<'MENU'

========== DEBIAN COMPETITION TOOLKIT ==========
 1  Unauthorized/hidden accounts (4 checks)
 2  Blank passwords: hiravias and root (2 checks)
 3  Password hash / lockout / age / length (4 checks)
 4  Kernel log packets with impossible addresses
 5  GDM hide user list
 6  Require sudo password
 7  System accounts use non-login shells
 8  UFW enabled + block TCP/UDP 9473
 9  Restrict /boot/grub/grub.cfg
10  Restrict unprivileged dmesg
11  Disable Apache2 and Samba smbd
12  Kernel + security package updates
13  Find/delete prohibited MP3 files
14  Remove Hydra, Discord, cmospwd
15  Quarantine fake kworker.py backdoor
16  PostgreSQL SSL and auth
17  SSH root login + user environment
18  Chrome popups + HTTPS upgrades
 a  Read-only security audit
 0  ALL GROUPS (interactive)
 q  Quit
===============================================
MENU
    read -r -p 'Choose: ' choice || break
    case "$choice" in q|Q) break;; 0) all_fixes;; *) run_one "$choice";; esac
  done
  echo "Backups and log: $BACKUP"
}

case "${1:-}" in
  --audit) audit;;
  --all) all_fixes;;
  --help|-h) echo 'Run: sudo bash SCRIPT [--audit|--all]. No argument opens the menu.';;
  '') menu;;
  *) echo 'Unknown flag; use --help'; exit 2;;
esac
