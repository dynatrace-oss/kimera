# Copyright 2025 Dynatrace LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

UNKNOWN_STATE = "UNKNOWN (no probe tool)"

# Emitted once per script and called by every probe that touches the network, so that
# "we proved this is closed" is never confused with "we had no tool to test it".
# POSIX sh only — exec_in_pod runs scripts under /bin/sh.
PROBE_PRELUDE = f"""\
kimera_port_open() {{
    if command -v nc >/dev/null 2>&1; then
        if nc -z -w "$3" "$1" "$2" >/dev/null 2>&1; then echo OPEN; else echo CLOSED; fi
    elif command -v bash >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
        if timeout "$3" bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1; then
            echo OPEN
        else
            echo CLOSED
        fi
    else
        echo "{UNKNOWN_STATE}"
    fi
}}

kimera_resolve() {{
    if command -v nslookup >/dev/null 2>&1; then
        nslookup "$1" 2>/dev/null | awk '/^Address: /{{print $2}}' | tail -1
    elif command -v getent >/dev/null 2>&1; then
        getent hosts "$1" 2>/dev/null | awk '{{print $1}}' | head -1
    else
        return 2
    fi
}}

kimera_tcp_send() {{
    if command -v nc >/dev/null 2>&1; then
        nc -w "$3" "$1" "$2" 2>/dev/null
    elif command -v bash >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
        timeout "$3" bash -c '
            exec 3<>/dev/tcp/"$0"/"$1" || exit 1
            cat >&3
            cat <&3
        ' "$1" "$2" 2>/dev/null
    else
        return 2
    fi
}}

kimera_http_reachable() {{
    if command -v curl >/dev/null 2>&1; then
        _code=$(curl -sk -o /dev/null -w "%{{http_code}}" -m "$2" "$1" 2>/dev/null)
    elif command -v wget >/dev/null 2>&1; then
        _code=$(wget -q -O /dev/null -T "$2" -S "$1" 2>&1 \\
                | awk '/^  HTTP\\//{{print $2}}' | tail -1)
    else
        echo "{UNKNOWN_STATE}"
        return 2
    fi
    if [ -n "$_code" ] && [ "$_code" != "000" ] && [ "$_code" != "0" ]; then
        echo "REACHABLE (HTTP $_code)"
    else
        echo UNREACHABLE
    fi
}}

kimera_http_get() {{
    _url=$1
    _tmo=$2
    shift 2
    if command -v curl >/dev/null 2>&1; then
        for _h in "$@"; do set -- "$@" -H "$_h"; shift; done
        curl -sk -m "$_tmo" "$@" "$_url" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        for _h in "$@"; do set -- "$@" --header="$_h"; shift; done
        # Without --content-on-error GNU wget discards the body of a 4xx/5xx, which is the
        # response that matters most. BusyBox wget rejects the flag, so retry without it.
        _out=$(wget -q -O- --timeout="$_tmo" --no-check-certificate \\
               --content-on-error "$@" "$_url" 2>/dev/null)
        if [ -z "$_out" ]; then
            _out=$(wget -q -O- --timeout="$_tmo" --no-check-certificate "$@" "$_url" 2>/dev/null)
        fi
        printf %s "$_out"
    else
        return 2
    fi
}}

kimera_http_post() {{
    _url=$1
    _tmo=$2
    _body=$3
    shift 3
    if command -v curl >/dev/null 2>&1; then
        for _h in "$@"; do set -- "$@" -H "$_h"; shift; done
        curl -sk -m "$_tmo" -X POST -d "$_body" "$@" "$_url" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        for _h in "$@"; do set -- "$@" --header="$_h"; shift; done
        wget -q -O- --timeout="$_tmo" --no-check-certificate \\
            --post-data="$_body" "$@" "$_url" 2>/dev/null
    else
        return 2
    fi
}}
"""
