#!/bin/sh
set -e

echo "INTXXX install_name_tool $@"

exec install_name_tool "$@"
