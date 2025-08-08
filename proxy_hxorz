#!/usr/bin/env bash
# proxy_hxorz - Dev Proxy Accelerator (Xget Mirrors)
# Author: you
set -euo pipefail

############################################################
# ASCII Banner
############################################################
print_ascii_banner() {
cat <<'EOF'
██████╗ ██████╗  ██████╗ ██╗  ██╗██╗  ██╗ ██████╗ ██╗  ██╗
██╔══██╗██╔══██╗██╔═══██╗██║  ██║╚██╗██╔╝██╔═══██╗██║ ██╔╝
██████╔╝██████╔╝██║   ██║███████║ ╚███╔╝ ██║   ██║█████╔╝
██╔═══╝ ██╔══██╗██║   ██║██╔══██║ ██╔██╗ ██║   ██║██╔═██╗
██║     ██║  ██║╚██████╔╝██║  ██║██╔╝ ██╗╚██████╔╝██║  ██╗
╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
             proxy_hxorz · Dev Proxy Accelerator
                     (Xget Mirror Config)
EOF
}

############################################################
# Globals & Helpers
############################################################
XGET_BASE_DEFAULT="https://hxorz.cn"
XGET_BASE="${XGET_BASE_DEFAULT}"
DRY_RUN="${1:-}"
SUMMARY=()

say()  { printf "\033[1;32m[+] %s\033[0m\n" "$*"; }
warn() { printf "\033[1;33m[!] %s\033[0m\n" "$*"; }
err()  { printf "\033[1;31m[-] %s\033[0m\n" "$*"; }

confirm() {
  local msg="${1:-继续?}"
  read -r -p "$msg [y/N]: " ans || true
  [[ "${ans:-}" =~ ^[Yy]$ ]]
}

backup_write() {
  local path="$1"; shift
  local content="$*"
  local dir; dir="$(dirname "$path")"
  [[ -d "$dir" ]] || mkdir -p "$dir"
  if [[ "$DRY_RUN" == "--dry-run" ]]; then
    warn "DRY-RUN: would write $path"
    return 0
  fi
  if [[ -f "$path" ]]; then
    cp -f "$path" "$path.bak.$(date +%Y%m%d%H%M%S)"
  fi
  printf "%s" "$content" > "$path"
}

append_unique() {
  local path="$1" line="$2"
  if [[ "$DRY_RUN" == "--dry-run" ]]; then
    warn "DRY-RUN: would ensure line in $path: $line"
    return 0
  fi
  mkdir -p "$(dirname "$path")"
  touch "$path"
  grep -Fqx "$line" "$path" || echo "$line" >> "$path"
}

############################################################
# Config modules
############################################################

cfg_git() {
  command -v git >/dev/null 2>&1 || { warn "Git 未安装，跳过"; return; }
  say "配置 Git url.insteadOf（HTTPS）"
  mapfile -t maps < <(cat <<EOF
${XGET_BASE}/gh/|https://github.com/
${XGET_BASE}/gl/|https://gitlab.com/
${XGET_BASE}/gitea/|https://gitea.com/
${XGET_BASE}/codeberg/|https://codeberg.org/
${XGET_BASE}/sf/|https://sourceforge.net/
EOF
)
  for m in "${maps[@]}"; do
    left="${m%%|*}"; right="${m##*|}"
    if [[ "$DRY_RUN" == "--dry-run" ]]; then
      warn "DRY-RUN: git config --global url.\"$left\".insteadOf \"$right\""
    else
      git config --global "url.$left.insteadOf" "$right"
    fi
  done
  SUMMARY+=("Git: https -> ${XGET_BASE}/(gh|gl|gitea|codeberg|sf)")

  if confirm "是否将 SSH/ssh:///git:// 形式也重定向到镜像（可能影响私有仓库 SSH 拉取）？"; then
    local ssh_maps=(
      "ssh://git@github.com/|${XGET_BASE}/gh/"
      "git@github.com:|${XGET_BASE}/gh/"
      "git://github.com/|${XGET_BASE}/gh/"
    )
    for m in "${ssh_maps[@]}"; do
      right="${m%%|*}"; left="${m##*|}"
      if [[ "$DRY_RUN" == "--dry-run" ]]; then
        warn "DRY-RUN: git config --global url.\"$left\".insteadOf \"$right\""
      else
        git config --global "url.$left.insteadOf" "$right"
      fi
    done
    SUMMARY+=("Git: 追加 SSH/git:// -> ${XGET_BASE}/gh/")
  fi
}

cfg_npm() {
  command -v npm >/dev/null 2>&1 || { warn "npm 未安装，跳过"; return; }
  say "配置 npm registry"
  if [[ "$DRY_RUN" == "--dry-run" ]]; then
    warn "DRY-RUN: npm config set registry ${XGET_BASE}/npm/"
  else
    npm config set registry "${XGET_BASE}/npm/"
  fi
  SUMMARY+=("npm: registry=${XGET_BASE}/npm/")
}

cfg_pip() {
  say "配置 pip 源"
  local pip_conf="$HOME/.pip/pip.conf"
  local host; host="$(echo "$XGET_BASE" | awk -F/ '{print $3}')"
  backup_write "$pip_conf" "\
[global]
index-url = ${XGET_BASE}/pypi/simple/
trusted-host = ${host}
"
  SUMMARY+=("pip: $pip_conf -> index-url=${XGET_BASE}/pypi/simple/")
}

cfg_conda() {
  say "配置 conda 源（如未安装可忽略）"
  local condarc="$HOME/.condarc"
  backup_write "$condarc" "\
default_channels:
  - ${XGET_BASE}/conda/pkgs/main
  - ${XGET_BASE}/conda/pkgs/r
  - ${XGET_BASE}/conda/pkgs/msys2
channel_alias: ${XGET_BASE}/conda/community
channel_priority: strict
show_channel_urls: true
"
  SUMMARY+=("conda: $condarc -> 使用 ${XGET_BASE}/conda/*")
}

cfg_maven() {
  say "配置 Maven Central 镜像"
  local m2="$HOME/.m2/settings.xml"
  backup_write "$m2" "\
<settings>
  <mirrors>
    <mirror>
      <id>xget-maven-central</id>
      <mirrorOf>central</mirrorOf>
      <name>Xget Maven Central Mirror</name>
      <url>${XGET_BASE}/maven/maven2</url>
    </mirror>
  </mirrors>
</settings>
"
  SUMMARY+=("Maven: $m2 -> mirror=${XGET_BASE}/maven/maven2")
}

cfg_gradle() {
  say "配置 Gradle 镜像"
  local init="$HOME/.gradle/init.gradle"
  backup_write "$init" "\
allprojects {
  repositories {
    maven { url '${XGET_BASE}/maven/maven2' }
  }
}
settingsEvaluated { settings ->
  settings.pluginManagement {
    repositories {
      maven { url '${XGET_BASE}/gradle/m2' }
      gradlePluginPortal()
    }
  }
}
"
  SUMMARY+=("Gradle: $init -> maven=${XGET_BASE}/maven/maven2, plugins=${XGET_BASE}/gradle/m2")
}

cfg_go() {
  command -v go >/dev/null 2>&1 || { warn "Go 未安装，跳过"; return; }
  say "配置 Go 模块代理"
  if [[ "$DRY_RUN" == "--dry-run" ]]; then
    warn "DRY-RUN: go env -w GOPROXY=${XGET_BASE}/golang,direct"
    warn "DRY-RUN: go env -w GOSUMDB=off"
  else
    go env -w GOPROXY="${XGET_BASE}/golang,direct"
    go env -w GOSUMDB=off
  fi
  SUMMARY+=("Go: GOPROXY=${XGET_BASE}/golang,direct; GOSUMDB=off")
}

cfg_rubygems() {
  command -v gem >/dev/null 2>&1 || { warn "RubyGems 未安装，跳过"; return; }
  say "配置 RubyGems 与 Bundler 镜像（保留 rubygems.org）"
  if [[ "$DRY_RUN" == "--dry-run" ]]; then
    warn "DRY-RUN: gem sources --add ${XGET_BASE}/rubygems/ || true"
    warn "DRY-RUN: bundle config mirror.https://rubygems.org ${XGET_BASE}/rubygems/ (若已安装 bundler)"
  else
    gem sources --add "${XGET_BASE}/rubygems/" >/dev/null 2>&1 || true
    if command -v bundle >/dev/null 2>&1; then
      bundle config mirror.https://rubygems.org "${XGET_BASE}/rubygems/"
    fi
  fi
  SUMMARY+=("RubyGems: 增加镜像=${XGET_BASE}/rubygems/；Bundler mirror 已配置（如安装）")
}

cfg_cargo() {
  say "配置 Cargo 镜像（Rust）"
  local c="$HOME/.cargo/config.toml"
  backup_write "$c" "\
[source.crates-io]
replace-with = \"xget\"

[source.xget]
registry = \"${XGET_BASE}/crates/\"
"
  SUMMARY+=("Cargo: $c -> crates=${XGET_BASE}/crates/")
}

cfg_nuget() {
  command -v dotnet >/dev/null 2>&1 || { warn "dotnet 未安装，跳过 NuGet"; return; }
  say "配置 NuGet 源"
  if [[ "$DRY_RUN" == "--dry-run" ]]; then
    warn "DRY-RUN: dotnet nuget add source ${XGET_BASE}/nuget/v3/index.json -n xget || true"
  else
    dotnet nuget add source "${XGET_BASE}/nuget/v3/index.json" -n xget >/dev/null 2>&1 || true
  fi
  SUMMARY+=("NuGet: 源=${XGET_BASE}/nuget/v3/index.json (name=xget)")
}

cfg_r() {
  say "配置 R 的 CRAN 镜像"
  local rp="$HOME/.Rprofile"
  append_unique "$rp" "options(repos = c(CRAN = \"${XGET_BASE}/cran/\"))"
  append_unique "$rp" "options(download.file.method = \"libcurl\")"
  SUMMARY+=("R: $rp -> CRAN=${XGET_BASE}/cran/")
}

cfg_containerd() {
  say "配置 containerd 注册表镜像 (ghcr.io / gcr.io) - 使用 certs.d/hosts.toml"
  confirm "需要在 /etc/containerd/certs.d/ 写入 hosts.toml 并重启 containerd 吗？(sudo)" || { warn "跳过 containerd"; return; }
  if ! command -v sudo >/dev/null 2>&1; then warn "无 sudo，跳过"; return; fi

  local ghcr_dir="/etc/containerd/certs.d/ghcr.io"
  local gcr_dir="/etc/containerd/certs.d/gcr.io"
  local ghcr_hosts="$ghcr_dir/hosts.toml"
  local gcr_hosts="$gcr_dir/hosts.toml"

  mk_hosts() {
    local dir="$1" hosts="$2" upstream="$3" mirror="$4"
    sudo mkdir -p "$dir"
    if [[ "$DRY_RUN" == "--dry-run" ]]; then
      warn "DRY-RUN: would write $hosts"
      return 0
    fi
    if [[ -f "$hosts" ]]; then
      sudo cp -f "$hosts" "$hosts.bak.$(date +%Y%m%d%H%M%S)"
    fi
    sudo tee "$hosts" >/dev/null <<EOF
server = "https://$upstream"

[host."$mirror"]
  capabilities = ["pull", "resolve"]
EOF
  }

  mk_hosts "$ghcr_dir" "$ghcr_hosts" "ghcr.io" "${XGET_BASE}/cr/ghcr"
  mk_hosts "$gcr_dir" "$gcr_hosts" "gcr.io"  "${XGET_BASE}/cr/gcr"

  if [[ "$DRY_RUN" != "--dry-run" ]]; then
    sudo systemctl restart containerd || true
  fi
  SUMMARY+=("containerd: certs.d hosts.toml -> ${XGET_BASE}/cr/(ghcr|gcr)")
}

cfg_apt() {
  say "替换 APT 源为 Xget（Ubuntu/Debian）"
  confirm "将 /etc/apt/sources.list 切到 ${XGET_BASE} 吗？(sudo)" || { warn "跳过 APT"; return; }
  if ! command -v sudo >/dev/null 2>&1; then warn "无 sudo，跳过"; return; fi

  local codename=""
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    codename="${VERSION_CODENAME:-}"
  fi
  if [[ -z "$codename" ]]; then
    read -r -p "未识别到发行版代号，请手动输入（例如：focal/jammy/bookworm）： " codename
  fi
  if [[ -z "$codename" ]]; then
    err "无法确定发行版代号，取消 APT 配置"; return
  fi

  local content="\
# Xget APT 源（自动识别：$codename）
deb ${XGET_BASE}/ubuntu/ubuntu ${codename} main restricted universe multiverse
deb ${XGET_BASE}/ubuntu/ubuntu ${codename}-updates main restricted universe multiverse
"

  if [[ "$DRY_RUN" == "--dry-run" ]]; then
    warn "DRY-RUN: would write /etc/apt/sources.list"
  else
    sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak.$(date +%Y%m%d%H%M%S) || true
    echo "$content" | sudo tee /etc/apt/sources.list >/dev/null
    sudo apt -y update || true
  fi
  SUMMARY+=("APT: sources.list -> ${XGET_BASE}/ubuntu/ubuntu (${codename})")
}

############################################################
# Menu (interactive)
############################################################

main_menu() {
  clear
  print_ascii_banner
  echo
  echo "镜像基址（默认：${XGET_BASE_DEFAULT}）可自定义；支持 --dry-run 预演写入。"
  read -r -p "镜像基址（回车使用默认）： " base_in || true
  if [[ -n "${base_in:-}" ]]; then XGET_BASE="${base_in}"; fi
  XGET_BASE="${XGET_BASE%/}"
  if ! [[ "$XGET_BASE" =~ ^https?://[^/]+$ ]]; then
    err "镜像基址格式不合法（示例：https://hxorz.cn） -> 当前：$XGET_BASE"
    exit 1
  fi
  say "使用镜像基址：${XGET_BASE}"
  echo

  echo "请选择要配置的模块（可多选，用空格分隔；输入 A 全选）："
  echo " 1) Git"
  echo " 2) npm"
  echo " 3) pip"
  echo " 4) conda"
  echo " 5) Maven"
  echo " 6) Gradle"
  echo " 7) Go"
  echo " 8) RubyGems"
  echo " 9) Cargo (Rust)"
  echo "10) NuGet (dotnet)"
  echo "11) R (CRAN)"
  echo "12) containerd（需 sudo）"
  echo "13) APT（需 sudo，Ubuntu/Debian）"
  echo

  read -r -p "你的选择: " choice || true

  declare -a SEL=()
  if [[ "$choice" =~ ^[Aa]$ ]]; then
    SEL=(1 2 3 4 5 6 7 8 9 10 11 12 13)
  else
    for tok in $choice; do
      [[ "$tok" =~ ^[0-9]+$ ]] && SEL+=("$tok")
    done
  fi

  if [[ ${#SEL[@]} -eq 0 ]]; then
    err "未选择任何模块，退出。"; exit 1
  fi

  say "开始配置（${DRY_RUN:---实际写入---}）..."
  for n in "${SEL[@]}"; do
    case "$n" in
      1) cfg_git ;;
      2) cfg_npm ;;
      3) cfg_pip ;;
      4) cfg_conda ;;
      5) cfg_maven ;;
      6) cfg_gradle ;;
      7) cfg_go ;;
      8) cfg_rubygems ;;
      9) cfg_cargo ;;
      10) cfg_nuget ;;
      11) cfg_r ;;
      12) cfg_containerd ;;
      13) cfg_apt ;;
      *) warn "未知选项: $n，跳过" ;;
    esac
  done

  echo
  say "配置完成，摘要："
  for s in "${SUMMARY[@]}"; do
    echo " - $s"
  done

  cat <<'TIP'

验证建议：
1) Git: git config --global --get-regexp '^url\..*\.insteadof'
2) npm: npm config get registry
3) pip: python -m pip config list
4) conda: conda config --show | egrep 'default_channels|channel_alias|channel_priority'
5) Maven: grep -A2 '<mirror>' ~/.m2/settings.xml
6) Gradle: 查看 ~/.gradle/init.gradle
7) Go: go env | egrep 'GOPROXY|GOSUMDB'
8) RubyGems: gem sources -l && (bundle config list | grep mirror || true)
9) Cargo: cat ~/.cargo/config.toml
10) NuGet: dotnet nuget list source
11) R: R -q -e 'getOption("repos")'
12) containerd: cat /etc/containerd/certs.d/ghcr.io/hosts.toml; 用 docker/podman/crictl 拉取 ghcr.io 测试
13) APT: sudo apt update
TIP
}

main_menu
