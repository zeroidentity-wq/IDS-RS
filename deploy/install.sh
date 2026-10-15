#!/usr/bin/env bash
# =============================================================================
# Instaleaza IDS-RS ca serviciu systemd pe RHEL 9. Ruleaza ca root, fara
# acces la internet:
#
#   sudo ./install.sh                                    (din arhiva package.sh)
#   sudo deploy/install.sh target/rhel9/release/ids-rs   (din repo)
#
# Idempotent: poate fi rulat din nou la upgrade. Nu suprascrie config-urile
# existente din /etc/ids-rs si nu porneste nicio instanta.
# =============================================================================
set -euo pipefail

deploy_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# In arhiva, binarul si example.toml stau langa script; in repo, binarul se
# da ca argument, iar config-ul exemplu este config.toml din radacina.
binary=${1:-$deploy_dir/ids-rs}
example_config=$deploy_dir/example.toml
[[ -f $example_config ]] || example_config=$deploy_dir/../config.toml

if [[ ! -f $binary ]]; then
    echo "utilizare: $0 [cale catre binarul ids-rs compilat pentru RHEL 9]" >&2
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "Ruleaza ca root (sudo)." >&2
    exit 1
fi

# Un binar compilat pe o distributie mai noua cere un glibc pe care RHEL 9
# nu il are ("GLIBC_2.38 not found") si nu porneste deloc.
if ! "$binary" --help >/dev/null 2>&1; then
    echo "Binarul $binary nu ruleaza pe acest sistem:" >&2
    "$binary" --help >&2 || true
    echo "Compileaza-l pentru RHEL 9 cu deploy/build-rhel9.sh." >&2
    exit 1
fi

getent group ids-rs >/dev/null || groupadd --system ids-rs
id ids-rs >/dev/null 2>&1 ||
    useradd --system --gid ids-rs --home-dir /var/lib/ids-rs --no-create-home \
        --shell /sbin/nologin --comment "IDS-RS service" ids-rs

# `install` creeaza fisiere noi, cu contextul SELinux implicit al destinatiei
# (un `mv` din /home ar pastra user_home_t si systemd nu l-ar putea executa).
install -m 0755 -o root -g root "$binary" /usr/local/bin/ids-rs
install -m 0644 -o root -g root "$deploy_dir/systemd/ids-rs@.service" \
    /etc/systemd/system/ids-rs@.service

# Config-urile pot contine parola SMTP si token-ul dashboard-ului.
install -d -m 0750 -o root -g ids-rs /etc/ids-rs
if [[ ! -e /etc/ids-rs/example.toml ]]; then
    install -m 0640 -o root -g ids-rs "$example_config" /etc/ids-rs/example.toml
fi

if command -v restorecon >/dev/null; then
    restorecon -F /usr/local/bin/ids-rs /etc/systemd/system/ids-rs@.service
    restorecon -RF /etc/ids-rs
fi

systemctl daemon-reload

cat <<'EOF'
IDS-RS instalat. Pentru o instanta noua (ex: "fortigate"):

  cp /etc/ids-rs/example.toml /etc/ids-rs/fortigate.toml
  chown root:ids-rs /etc/ids-rs/fortigate.toml && chmod 0640 /etc/ids-rs/fortigate.toml
  # editeaza: listen_port, trusted_senders, parser/[custom_parser], web_dashboard.port
  ids-rs test-parser /etc/ids-rs/fortigate.toml sample.log
  firewall-cmd --permanent --add-port=<listen_port>/udp && firewall-cmd --reload
  systemctl enable --now ids-rs@fortigate
  journalctl -u ids-rs@fortigate -f
EOF
