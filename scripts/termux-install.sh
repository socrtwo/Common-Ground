#!/data/data/com.termux/files/usr/bin/bash
# Common Ground - install on Termux (Android).
# Usage:  bash scripts/termux-install.sh        (from a clone of the repository)
#   or:   curl -sLO https://raw.githubusercontent.com/socrtwo/Common-Ground/main/scripts/termux-install.sh
#         bash termux-install.sh                (clones into ~/Common-Ground first)
set -euo pipefail

echo "==> Installing packages"
# python-cryptography comes from the Termux repository so pip does not try
# to compile it on the device.
pkg install -y git python python-cryptography

if [ -f src/app.py ]; then
  ROOT=$(pwd)
elif [ -f ../src/app.py ]; then
  ROOT=$(cd .. && pwd)
else
  ROOT="$HOME/Common-Ground"
  if [ ! -d "$ROOT/.git" ]; then
    echo "==> Cloning into $ROOT"
    git clone https://github.com/socrtwo/Common-Ground.git "$ROOT"
  fi
fi

echo "==> Installing Flask"
pip install flask

echo "==> Self-test (protocol walkthrough)"
(cd "$ROOT/src" && python3 demo_verification.py)

cat <<MSG

Installed. To run the forum:
  cd $ROOT/src
  ADMIN_KEY=choose-16-or-more-chars python3 app.py
then open http://127.0.0.1:5000 in the phone's browser.
MSG
