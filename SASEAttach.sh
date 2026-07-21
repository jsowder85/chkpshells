#!/bin/bash
#
# create_sase_vpn.sh
#
# Configures one or more route-based SASE site-to-site VPN tunnels
# on a Check Point / Spark gateway using numbered VTIs (Virtual Tunnel
# Interfaces) and BGP for route exchange, then runs each Gaia clish command
# in expert mode via: clish -c "COMMAND"
#
# Values collected from the user:
#   0. How many SASE gateways to build tunnels to (1-50)
#   Collected ONCE, shared across ALL tunnels:
#     1. Local BGP AS number (defaults to 65000 if left blank)
#     2. SASE BGP AS number (defaults to 64512 if left blank, per Check Point's
#        SASE Admin Guide; shared by all SASE peers)
#     3. Public IP of the locally managed Spark gateway (local)          -> ike-v2-gateway-id-override
#   Collected for EACH SASE gateway:
#     4. Public IP of that SASE gateway (remote peer)                    -> remote-site-ip-address / ike-v2-peer-id
#     5. Pre-Shared Secret Key (can differ per gateway)                  -> auth password
#     6. VTI remote IP (Check Point SASE Gateway Internal IP)               -> vpn tunnel "remote"
#     7. Local VTI IP address for this tunnel (a sensible default is     -> vpn tunnel "local" / interface address
#        suggested based on the remote VTI IP, but can be overridden)
#
# The ike-v2-global-gateway-id is auto-discovered from the running
# configuration (`show configuration`) since it is unique per gateway, and is
# shared across all tunnels. VTI numbers start at 10 (or continue from the
# highest existing VTI if this script has been run before) and increment by
# one per tunnel. VPN site names follow SASE<n>, continuing from the
# highest existing SASE<n> site if any already exist, so re-running
# this script to add more gateways will not collide with earlier tunnels.
# The inbound route filter policy ID starts at 512 on Spark systems and
# also continues from the highest existing policy ID found.
#
# The VPN site name for each tunnel always matches the "peer" name used in
# its corresponding "add vpn tunnel" command.
#
# A log file is created immediately (before any prompts) and is updated
# throughout the run - including on unexpected failures - so there is
# always a record of what happened, even if the script is interrupted or
# hits an unhandled error partway through. Pre-shared secrets are never
# written to the log in plaintext.
#
# Everything else in the commands is left exactly as provided.
#
# ---------------------------------------------------------------------------
# REVISION LOG
# Only major/functional changes are documented here going forward. Small
# regression fixes, wording tweaks, and minor test corrections are tracked
# as dot releases without a full entry.
#
#   1.0 - Initial release. Route-based site-to-site VPN with numbered VTIs
#         and BGP, --revert rollback support, dynamic-routing detection,
#         host-object-restricted BGP access rule, and selectable route
#         advertisement (all interfaces, specific interfaces, or manual
#         CIDR networks).
#   1.1 - Corrected the default SASE BGP AS number to 64512 (previously
#         64515), matching Check Point's official SASE Admin Guide. The
#         route advertisement interface list now also excludes any
#         interface backing an Internet/WAN connection, so a WAN uplink
#         can never accidentally be redistributed to the SASE gateway(s).
#   1.2 - Reworked the post-run health check into a live, auto-refreshing
#         dashboard: "vpn tu tlist" and "show bgp peers" now run in the
#         background every 30 seconds, showing a simple color-coded
#         UP/DOWN status per tunnel and per BGP peer instead of raw
#         command output. Monitoring stops automatically once everything
#         is green (printing the full raw output once as confirmation),
#         and if 5 minutes pass without that happening, the user is asked
#         whether to keep monitoring. Persistent storage (log file and
#         rollback manifest) now defaults to /storage/sase_vpn, the
#         partition that survives a reboot on Spark appliances.
#   1.3 - Health check dashboard now refreshes every 10 seconds (was 30).
#         Added a new "--healthcheck [manifest]" flag to run just the live
#         dashboard on its own, without repeating the creation flow -
#         loads the same rollback manifest used by --revert to know which
#         tunnels/peers to check (the manifest now also records each SASE
#         gateway's public IP for this purpose). The rollback command
#         reminder is now also reprinted immediately after execution
#         completes, not just before, so it's harder to miss/scroll past.
#   1.4 - Added a new "--auto \"ANSWER;ANSWER;...\"" flag that runs the
#         entire normal creation flow non-interactively by feeding a
#         single semicolon-separated answer string into stdin, in the
#         same order prompts would normally appear. This does not bypass
#         any validation or confirmation step - it only supplies the
#         answers, so the exact same checks still apply. Also fixed the
#         on-screen step count/summary to consistently report at the same
#         high-level grouped level in both the creation and --revert flows
#         (previously the summary could show a different, confusing total
#         than the steps actually listed), and replaced a screen-clearing
#         call in the health check dashboard with a plain separator so
#         earlier configuration output is no longer wiped from view.
#   1.5 - Full review pass over user input validation. Fixed: an extremely
#         long numeric string (e.g. a mistyped AS number or gateway count)
#         could trigger a confusing raw bash arithmetic error instead of a
#         clean validation message; IPv4 addresses with leading zeros in an
#         octet (e.g. "01.2.3.4") were incorrectly accepted, which is
#         ambiguous across different parsers; the suggested default local
#         VTI IP could come out identical to the remote VTI IP when the
#         remote address ended in .0 or .255, causing the script's own
#         suggested default to fail its own duplicate-IP check. Also added
#         stronger validation of --revert/--healthcheck manifest files
#         (consistent array lengths, a present/numeric policy ID) so a
#         corrupted or hand-edited manifest fails with a clear message
#         instead of a generic error. None of these required restarting
#         the script - every fix re-prompts in place.
#   1.6 - Added a "--help" / "-h" flag that lists every available flag
#         (--auto, --revert, --healthcheck, --help) with a description of
#         what each one does, checked before anything else so it works
#         regardless of what other flags might otherwise be expected.
#   1.7 - Added a check for whether the appliance is centrally managed -
#         either 'set maas mode "enable"' (Smart-1 Cloud) or
#         'set security-management mode centrally-managed' (an SMS or
#         MDM) in the "show configuration" output - since this script
#         does not support centrally-managed appliances. The
#         configuration is now pulled, and this check run, as the very
#         first thing in the main flow (before the gateway-count prompt
#         or any other input), so a centrally-managed appliance is caught
#         and the script exits immediately without asking anything else.
#   1.8 - Made the centrally-managed detection tolerant of minor
#         formatting differences (extra whitespace, optional quoting)
#         instead of requiring an exact literal match, and added
#         diagnostic logging of the captured configuration size plus a
#         breadcrumb if "maas" or "centrally-managed" appears anywhere
#         but doesn't match the expected pattern - to make it possible to
#         pinpoint a mismatch from the log alone if this is ever reported
#         not to trigger again.
#   1.9 - The centrally-managed check still wasn't triggering on a real
#         Smart-1 Cloud appliance even with the broadest possible search
#         (case-insensitive "maas" with no other constraints), despite
#         the line being confirmed present via the same clish command run
#         manually. "show configuration" is now captured to a file FIRST,
#         and the centrally-managed check runs directly against that file
#         rather than a bash variable - command substitution can silently
#         lose data (e.g. truncating at an embedded NUL byte, which
#         Smart-1 Cloud connection data could plausibly contain) in ways
#         a file write does not. The log now also records the file's line
#         /byte count alongside the variable's, so a future mismatch
#         between the two would be immediately visible as confirmation.
# ---------------------------------------------------------------------------

set -euo pipefail

# ---------------------------------------------------------------------------
# Terminal colors (safe no-ops if the terminal doesn't support them)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_RESET='\033[0m'
    C_BOLD='\033[1m'
    C_CYAN='\033[0;36m'
    C_GREEN='\033[0;32m'
    C_RED='\033[0;31m'
    C_YELLOW='\033[0;33m'
else
    C_RESET=''; C_BOLD=''; C_CYAN=''; C_GREEN=''; C_RED=''; C_YELLOW=''
fi

# ---------------------------------------------------------------------------
# Set up the persistent log file FIRST, before any prompts run, so that
# even a failure during input collection (or an unexpected bug) leaves a
# diagnostic trail rather than nothing at all.
#
# /storage is the partition that survives a reboot on Spark appliances, so
# it's used as the primary location - this matters not just for the log,
# but for the rollback manifest written alongside it, since --revert needs
# to be able to find that manifest even after the box has been rebooted.
# /var/log and /var/tmp are only used as a fallback if /storage is somehow
# unavailable, and are NOT guaranteed to survive a reboot.
# ---------------------------------------------------------------------------
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_CANDIDATES=("/storage/sase_vpn" "/var/log/sase_vpn" "/var/tmp/sase_vpn")
LOG_DIR=""
LOG_DIR_IS_PERSISTENT=false
for candidate in "${LOG_CANDIDATES[@]}"; do
    if mkdir -p "$candidate" 2>/dev/null; then
        LOG_DIR="$candidate"
        [[ "$candidate" == "/storage/sase_vpn" ]] && LOG_DIR_IS_PERSISTENT=true
        break
    fi
done
if [[ -z "$LOG_DIR" ]]; then
    # Last resort so a run is never completely unlogged
    LOG_DIR="/tmp"
fi
LOG_FILE="${LOG_DIR}/sase_vpn_${TIMESTAMP}.log"
: > "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/sase_vpn_${TIMESTAMP}.log"

if [[ "$LOG_DIR_IS_PERSISTENT" != true ]]; then
    echo -e "${C_YELLOW}Warning: /storage/sase_vpn was not available - using ${LOG_DIR} instead,"
    echo -e "which may not survive a reboot. The rollback manifest for this run may not"
    echo -e "be found later by --revert if this appliance is rebooted before then.${C_RESET}"
    echo
fi

# Appends a timestamped line to the log file. Safe to call before PSKS
# exists (sanitize_for_log only runs on command strings, not here).
log_msg() {
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$LOG_FILE"
}

# Redacts every collected PSK value out of a command string before logging.
# PSKS may not be populated yet when this is defined - that's fine, it's
# only evaluated at call time.
sanitize_for_log() {
    local text="$1"
    local secret
    for secret in "${PSKS[@]:-}"; do
        [[ -n "$secret" ]] && text="${text//${secret}/********}"
    done
    echo "$text"
}

# Captures unexpected/unhandled failures anywhere in the script and makes
# sure they are visible to the user and recorded in the log, instead of a
# bare bash error with no context.
on_unexpected_error() {
    local exit_code=$? line_no=$1
    log_msg "FATAL: unexpected error at line ${line_no} (exit code ${exit_code}). Last command: ${BASH_COMMAND}"
    echo
    echo -e "${C_RED}${C_BOLD}An unexpected error occurred (line ${line_no}, exit code ${exit_code}).${C_RESET}"
    echo -e "${C_RED}Details have been recorded in: ${LOG_FILE}${C_RESET}"
    exit "$exit_code"
}
trap 'on_unexpected_error $LINENO' ERR

CLISH_TIMEOUT=45
if ! command -v timeout >/dev/null 2>&1; then
    # Fall back to no timeout if the utility isn't available on this system
    timeout() { shift; "$@"; }
fi

# ---------------------------------------------------------------------------
# Runs all commands for a group sequentially in the background, writing one
# result line per command to outfile as "status<TAB>encoded_output" (real
# newlines in output are encoded as literal "\n" so each result stays on a
# single line). Lets the caller show a spinner while this runs. Each
# individual command is capped at CLISH_TIMEOUT seconds so a hung clish
# call can't freeze the whole script indefinitely.
# ---------------------------------------------------------------------------
run_group() {
    trap - ERR
    local start="$1" end="$2" outfile="$3"
    local j cmd output status encoded attempt src_name fallback_cmd fb_output fb_status
    : > "$outfile"
    for ((j = start; j <= end; j++)); do
        cmd="${COMMANDS[$j]}"

        for attempt in 1 2 3 4 5; do
            if output="$(timeout "${CLISH_TIMEOUT}" clish -c "${cmd}" 2>&1)"; then
                status=0
            else
                status=$?
                if [ "$status" -eq 124 ]; then
                    output="${output}"$'\n'"[TIMEOUT] Command did not complete within ${CLISH_TIMEOUT} seconds."
                fi
            fi

            # A dependency this command relies on (e.g. a bgp-policy, BGP
            # peer, VTI tunnel, or VPN site just created by a previous
            # command) may not be immediately visible yet on some systems.
            # If we see this class of error, pause and retry (up to 5
            # attempts total, 10 seconds apart) before giving up.
            if [[ "$attempt" -lt 5 ]] && [[ "$output" == *"There is no"*"with id"* || "$output" == *"does not exist"* || "$output" == *"not configured"* ]]; then
                log_msg "Retry ${attempt}/5 for dependency-not-ready error on: ${cmd} - waiting 10s. Output: ${output}"
                sleep 10
                continue
            fi
            break
        done

        # The BGP access rule may already exist even though our earlier
        # detection missed it (e.g. a concurrent run, or a naming/formatting
        # variant our check didn't match). Rather than fail outright, fall
        # back to adding this gateway's host object as a source on the
        # existing rule instead - the practical goal either way.
        if [[ "$cmd" == *"add access-rule"*"SASE_BGP_ALLOW"* ]] && [[ "$output" == *"already exists"* ]] && [[ "$cmd" =~ source\ \"([^\"]+)\" ]]; then
            src_name="${BASH_REMATCH[1]}"
            fallback_cmd="set access-rule type incoming-internal-and-vpn name \"SASE_BGP_ALLOW\" add source \"${src_name}\""
            if fb_output="$(timeout "${CLISH_TIMEOUT}" clish -c "${fallback_cmd}" 2>&1)"; then
                fb_status=0
            else
                fb_status=$?
            fi
            output="[INFO] Access rule \"SASE_BGP_ALLOW\" already exists - added ${src_name} as a source instead.${fb_output:+ ${fb_output}}"
            status=$fb_status
        fi

        encoded="${output//$'\n'/\\n}"
        printf '%s\t%s\n' "$status" "$encoded" >> "$outfile"

        # After creating an inbound-route-filter bgp-policy, give it a flat
        # 30-second settle window before the next command (which configures
        # it further) runs. This step has repeatedly needed longer than
        # expected to register on some appliances.
        case "$cmd" in
            *"based-on-as as "*" on")
                sleep 30
                ;;
        esac

        # After adding a VTI tunnel or VPN site, or turning on a BGP AS group
        # or BGP peer, give it a flat 10-second settle window before the next
        # command (which immediately configures/references it) runs. This is
        # a fixed wait rather than actively re-querying the system, since
        # re-querying was too slow on some systems.
        if [[ "$cmd" == *"add vpn tunnel"* || "$cmd" == *"add vpn site name"* ]]; then
            sleep 10
        elif [[ "$cmd" == *"peer "*" on" && "$cmd" != *"multihop"* && "$cmd" != *"graceful-restart"* ]]; then
            sleep 10
        elif [[ "$cmd" == *"remote-as "*" on" && "$cmd" != *"peer"* ]]; then
            sleep 10
        fi
    done
}

SPINNER_CHARS='|/-\'

# ---------------------------------------------------------------------------
# Collapses consecutive commands sharing the same STEP_GROUPS label into a
# single on-screen reporting step, then executes everything currently in
# COMMANDS/DESCRIPTIONS/STEP_GROUPS with a spinner and full logging. Used by
# both the normal creation flow and the --revert flow.
# ---------------------------------------------------------------------------
execute_command_groups() {
    TOTAL=${#COMMANDS[@]}
    FAIL_COUNT=0
    GROUP_FAIL_COUNT=0

    GROUP_TITLES=()
    GROUP_STARTS=()
    GROUP_ENDS=()
    local prev_group="" label i gi
    for i in "${!STEP_GROUPS[@]}"; do
        label="${STEP_GROUPS[$i]}"
        if [[ "$label" != "$prev_group" ]]; then
            GROUP_TITLES+=("$label")
            GROUP_STARTS+=("$i")
            prev_group="$label"
        fi
    done
    NUM_GROUPS=${#GROUP_TITLES[@]}
    for ((gi = 0; gi < NUM_GROUPS; gi++)); do
        if [ $((gi + 1)) -lt "$NUM_GROUPS" ]; then
            GROUP_ENDS+=("$(( ${GROUP_STARTS[$((gi + 1))]} - 1 ))")
        else
            GROUP_ENDS+=("$((TOTAL - 1))")
        fi
    done

    echo -e "${C_BOLD}Applying configuration (${NUM_GROUPS} steps)...${C_RESET}"
    echo

    local group_step title start end RESULTS_FILE worker_pid si ch group_fail idx r_status r_encoded cmd desc log_cmd output
    for ((gi = 0; gi < NUM_GROUPS; gi++)); do
        group_step=$((gi + 1))
        title="${GROUP_TITLES[$gi]}"
        start="${GROUP_STARTS[$gi]}"
        end="${GROUP_ENDS[$gi]}"

        echo -e "${C_CYAN}[${group_step}/${NUM_GROUPS}]${C_RESET} ${title}"

        RESULTS_FILE="$(mktemp)"
        run_group "$start" "$end" "$RESULTS_FILE" &
        worker_pid=$!

        si=0
        while kill -0 "$worker_pid" 2>/dev/null; do
            ch="${SPINNER_CHARS:$si:1}"
            printf "\r        %s working..." "$ch"
            si=$(( (si + 1) % ${#SPINNER_CHARS} ))
            sleep 0.15 2>/dev/null || sleep 1
        done
        wait "$worker_pid" 2>/dev/null || true
        printf "\r\033[K"

        group_fail=0
        idx=$start
        while IFS=$'\t' read -r r_status r_encoded; do
            cmd="${COMMANDS[$idx]}"
            desc="${DESCRIPTIONS[$idx]}"
            log_cmd="$(sanitize_for_log "$cmd")"
            output="${r_encoded//\\n/$'\n'}"

            {
                echo "[$((idx + 1))/$TOTAL] $desc"
                echo "COMMAND: clish -c \"${log_cmd}\""
                echo "$output"
                echo "----------------------------------------------------------------"
            } >> "$LOG_FILE"

            if [[ "$output" == "[INFO]"* ]]; then
                echo -e "        ${C_CYAN}${output}${C_RESET}"
            elif [[ -n "$output" ]] && [[ "$output" == *"Could not"* || "$output" == *"Error"* || "$output" == *"error"* || "$r_status" -ne 0 ]]; then
                group_fail=$((group_fail + 1))
                FAIL_COUNT=$((FAIL_COUNT + 1))
                echo -e "        ${C_RED}[FAIL] ${desc}${C_RESET}"
                echo "$output" | sed 's/^/            /'
            fi
            idx=$((idx + 1))
        done < "$RESULTS_FILE"
        rm -f "$RESULTS_FILE"

        if [ "$group_fail" -eq 0 ]; then
            echo -e "        ${C_GREEN}[OK] done${C_RESET}"
        else
            GROUP_FAIL_COUNT=$((GROUP_FAIL_COUNT + 1))
            echo -e "        ${C_YELLOW}[WARN] completed with ${group_fail} issue(s) - see above${C_RESET}"
        fi
    done

    echo
    if [[ "$FAIL_COUNT" -eq 0 ]]; then
        echo -e "${C_GREEN}${C_BOLD}=== Operation complete (${NUM_GROUPS}/${NUM_GROUPS} steps succeeded) ===${C_RESET}"
    else
        echo -e "${C_YELLOW}${C_BOLD}=== Operation finished with ${GROUP_FAIL_COUNT} issue(s) out of ${NUM_GROUPS} steps ===${C_RESET}"
    fi

    {
        echo "Run finished $(date)"
        echo "Result: ${TOTAL} total steps, $((TOTAL - FAIL_COUNT)) succeeded, ${FAIL_COUNT} reported issues"
    } >> "$LOG_FILE"

    echo -e "${C_BOLD}Full command output has been saved to:${C_RESET} ${LOG_FILE}"
}

# ---------------------------------------------------------------------------
# Live, auto-refreshing health check dashboard. Uses the global GW_COUNT,
# SITE_NAMES, SASE_GW_IPS, and VTI_REMOTE_IPS arrays to know which tunnels
# and BGP peers to check - these are populated either by a fresh creation
# run, or (for --healthcheck) loaded from a rollback manifest. Requires
# LOG_FILE to already be set up.
#
# "vpn tu tlist" and "show bgp peers" are re-run in the background every 10
# seconds, and a simple per-tunnel / per-peer status line is redrawn from
# their output - rather than dumping the raw command output every cycle.
# Press Ctrl+C to stop at any time.
#
# If every tunnel and peer goes green, monitoring stops automatically and
# the full raw output of both commands is shown once as final confirmation.
# If 5 minutes pass without everything being healthy, the user is asked
# whether to keep monitoring, since everything should normally be up by then.
# ---------------------------------------------------------------------------
run_health_check_dashboard() {
    # sed doesn't interpret "\033"-style escapes the way echo -e/printf do,
    # so real ESC bytes are generated here first, then used directly
    # wherever a color needs to be embedded into text coming from clish
    # output (this also naturally no-ops when colors are disabled, since
    # C_GREEN/C_YELLOW/C_RESET are empty strings in that case).
    local REAL_GREEN REAL_YELLOW REAL_RESET
    REAL_GREEN="$(printf '%b' "${C_GREEN}")"
    REAL_YELLOW="$(printf '%b' "${C_YELLOW}")"
    REAL_RESET="$(printf '%b' "${C_RESET}")"

    local HEALTHCHECK_STOPPED=false
    local HEALTHCHECK_ALL_GREEN=false
    local HEALTHCHECK_START_TIME
    HEALTHCHECK_START_TIME=$(date +%s)
    trap 'HEALTHCHECK_STOPPED=true' SIGINT

    local TU_TMPFILE BGP_TMPFILE TU_BGPID BGP_BGPID si ch
    local VPN_TU_OUTPUT BGP_PEERS_OUTPUT
    local ALL_TUNNELS_UP ALL_PEERS_UP i site gw_ip remote_vti peer_state
    local HEALTHCHECK_ELAPSED HEALTHCHECK_CONTINUE s

    while [[ "$HEALTHCHECK_STOPPED" != true ]]; do
        # Gather both commands' output in the background so the dashboard
        # can show a "collecting..." spinner rather than appearing to hang.
        TU_TMPFILE="$(mktemp)"
        BGP_TMPFILE="$(mktemp)"
        ( clish -c "vpn tu tlist" > "$TU_TMPFILE" 2>&1 ) &
        TU_BGPID=$!
        ( clish -c "show bgp peers" > "$BGP_TMPFILE" 2>&1 ) &
        BGP_BGPID=$!

        si=0
        while kill -0 "$TU_BGPID" 2>/dev/null || kill -0 "$BGP_BGPID" 2>/dev/null; do
            [[ "$HEALTHCHECK_STOPPED" == true ]] && break
            ch="${SPINNER_CHARS:$si:1}"
            printf "\r%s Collecting current status..." "$ch"
            si=$(( (si + 1) % ${#SPINNER_CHARS} ))
            sleep 0.2
        done
        wait "$TU_BGPID" 2>/dev/null || true
        wait "$BGP_BGPID" 2>/dev/null || true
        printf "\r\033[K"

        VPN_TU_OUTPUT="$(cat "$TU_TMPFILE" 2>/dev/null)"
        BGP_PEERS_OUTPUT="$(cat "$BGP_TMPFILE" 2>/dev/null)"
        rm -f "$TU_TMPFILE" "$BGP_TMPFILE"

        log_msg "Health check cycle: refreshed vpn tu tlist / show bgp peers status."

        echo
        echo -e "${C_BOLD}$(printf '=%.0s' $(seq 1 60))${C_RESET}"
        echo -e "${C_BOLD}=== SASE Configuration Health Check ===${C_RESET}"
        echo "Last updated: $(date '+%Y-%m-%d %H:%M:%S')  (refreshes every 10s - Ctrl+C to stop)"
        echo

        ALL_TUNNELS_UP=true
        echo -e "${C_BOLD}--- VPN Tunnel Status ---${C_RESET}"
        for ((i = 0; i < GW_COUNT; i++)); do
            site="${SITE_NAMES[$i]}"
            gw_ip="${SASE_GW_IPS[$i]}"
            if tunnel_is_up "$VPN_TU_OUTPUT" "$gw_ip"; then
                printf "  %-12s (%s): %sUP%s\n" "$site" "$gw_ip" "$REAL_GREEN" "$REAL_RESET"
            else
                printf "  %-12s (%s): %sDOWN%s\n" "$site" "$gw_ip" "$REAL_YELLOW" "$REAL_RESET"
                ALL_TUNNELS_UP=false
            fi
        done

        echo
        ALL_PEERS_UP=true
        echo -e "${C_BOLD}--- BGP Peer Status ---${C_RESET}"
        for ((i = 0; i < GW_COUNT; i++)); do
            site="${SITE_NAMES[$i]}"
            remote_vti="${VTI_REMOTE_IPS[$i]}"
            peer_state="$(bgp_peer_state "$BGP_PEERS_OUTPUT" "$remote_vti")"
            if [[ "$peer_state" == "Established" ]]; then
                printf "  %-12s (peer %s): %sEstablished%s\n" "$site" "$remote_vti" "$REAL_GREEN" "$REAL_RESET"
            elif [[ -n "$peer_state" ]]; then
                printf "  %-12s (peer %s): %s%s%s\n" "$site" "$remote_vti" "$REAL_YELLOW" "$peer_state" "$REAL_RESET"
                ALL_PEERS_UP=false
            else
                printf "  %-12s (peer %s): %snot visible yet%s\n" "$site" "$remote_vti" "$REAL_YELLOW" "$REAL_RESET"
                ALL_PEERS_UP=false
            fi
        done

        echo
        echo -e "${C_BOLD}Full command output is being appended to:${C_RESET} ${LOG_FILE}"
        {
            echo "--- Health check cycle $(date '+%Y-%m-%d %H:%M:%S') ---"
            echo "$VPN_TU_OUTPUT"
            echo "$BGP_PEERS_OUTPUT"
            echo "---------------------------------------------"
        } >> "$LOG_FILE"

        if [[ "$HEALTHCHECK_STOPPED" == true ]]; then
            break
        fi

        # Everything is healthy - stop monitoring, show the full raw
        # command output once as final confirmation, and end.
        if [[ "$ALL_TUNNELS_UP" == true && "$ALL_PEERS_UP" == true ]]; then
            HEALTHCHECK_ALL_GREEN=true
            log_msg "Health check: all tunnels UP and all BGP peers Established - stopping monitoring."
            break
        fi

        # If 5 minutes have passed without everything being healthy yet,
        # pause and ask whether to keep monitoring - by this point
        # everything should normally have come up already.
        HEALTHCHECK_ELAPSED=$(( $(date +%s) - HEALTHCHECK_START_TIME ))
        if [ "$HEALTHCHECK_ELAPSED" -ge 300 ]; then
            echo
            echo -e "${C_YELLOW}This health check has been running for 5 minutes and not everything is"
            echo -e "healthy yet. Tunnels and BGP peering should normally be up well before now.${C_RESET}"
            echo
            read -rp "Continue monitoring? (y/N): " HEALTHCHECK_CONTINUE
            if [[ ! "$HEALTHCHECK_CONTINUE" =~ ^[Yy]$ ]]; then
                log_msg "User stopped health check after 5-minute checkpoint (not all healthy)."
                break
            fi
            log_msg "User chose to continue health check monitoring past the 5-minute checkpoint."
            HEALTHCHECK_START_TIME=$(date +%s)
        fi

        for ((s = 10; s > 0; s--)); do
            [[ "$HEALTHCHECK_STOPPED" == true ]] && break
            printf "\rNext refresh in %2ds (Ctrl+C to stop)..." "$s"
            sleep 1
        done
        echo
    done

    echo

    if [[ "$HEALTHCHECK_ALL_GREEN" == true ]]; then
        echo -e "${C_GREEN}${C_BOLD}All tunnels are up and all BGP peers are Established.${C_RESET}"
        echo
        echo -e "${C_BOLD}--- vpn tu tlist (full output) ---${C_RESET}"
        echo "$VPN_TU_OUTPUT"
        echo
        echo -e "${C_BOLD}--- show bgp peers (full output) ---${C_RESET}"
        echo "$BGP_PEERS_OUTPUT"
        echo
        log_msg "Health check finished: all green, full command output displayed."
    else
        echo "Health check stopped."
        log_msg "Health check dashboard stopped by user (Ctrl+C)."
    fi
}

# Returns 0 (true) if the given peer IP's block in "vpn tu tlist" output
# contains a real "Out SPI:" field. Per observed appliance behavior, a down
# tunnel either omits this field entirely or shows "No outbound SPI"
# instead - neither of which contains the literal substring "Out SPI:".
tunnel_is_up() {
    local tu_output="$1" peer_ip="$2"
    local -a lines
    mapfile -t lines <<< "$tu_output"
    local -a border_idxs=()
    local i
    for i in "${!lines[@]}"; do
        [[ "${lines[$i]}" =~ ^[+-]+[[:space:]]*$ ]] && border_idxs+=("$i")
    done
    [ "${#border_idxs[@]}" -lt 2 ] && return 1
    local k start end block_text
    for ((k = 0; k < ${#border_idxs[@]} - 1; k++)); do
        start="${border_idxs[$k]}"
        end="${border_idxs[$((k + 1))]}"
        block_text="$(printf '%s\n' "${lines[@]:$start:$((end - start + 1))}")"
        if [[ "$block_text" == *"$peer_ip"* ]]; then
            [[ "$block_text" == *"Out SPI:"* ]] && return 0 || return 1
        fi
    done
    return 1
}

# Prints the BGP State field for the given peer IP from "show bgp peers"
# output, or empty if that peer isn't listed at all yet.
bgp_peer_state() {
    local bgp_output="$1" peer_ip="$2"
    echo "$bgp_output" | awk -v ip="$peer_ip" '$1 == ip { print $5 }' | head -n1
}

log_msg "=== Run started ==="

# ---------------------------------------------------------------------------
# --help / -h
#
# Prints usage information and exits. Checked before anything else so it
# works regardless of what other flags might otherwise be expected.
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat << HELPEOF
${C_BOLD}SASE Route-Based VPN + BGP Configuration Script${C_RESET}

Configures (and can later remove, or check the health of) a route-based
site-to-site VPN with numbered VTIs and BGP peering between a Check Point
Spark appliance and one or more SASE gateways.

${C_BOLD}USAGE${C_RESET}
  $0 [FLAG] [ARGUMENT]

${C_BOLD}FLAGS${C_RESET}
  (none)
        Runs the normal interactive creation flow: prompts for every
        setting needed (gateway count, BGP AS numbers, per-gateway public
        IP/PSK/VTI addresses, Spark gateway IP, route advertisement, etc.),
        shows a summary, and applies the configuration after confirmation.
        Offers a live health check dashboard at the end.

  --auto "ANSWER;ANSWER;..."
        Runs the same normal creation flow non-interactively, by feeding a
        single semicolon-separated string of answers into stdin in the
        exact order prompts would normally appear. This does not skip any
        validation or confirmation step - it only supplies the answers, so
        every check still applies. Use a comma WITHIN one answer for
        multi-value prompts (e.g. "1,2" for selecting multiple interfaces);
        semicolons only separate one answer from the next. Leave an answer
        blank (";;") to accept a default. Example:
          $0 --auto "1;;;131.226.45.218;MySecretKey123;MySecretKey123;169.254.10.1;169.254.10.2;65.185.68.215;1;y;n"

  --revert [manifest_file]
        Undoes a previous run of this script. If no manifest path is
        given, the most recent one found under /storage/sase_vpn (or the
        fallback locations) is used automatically. Shows exactly what will
        be removed/disabled before asking for confirmation.

  --healthcheck [manifest_file]
        Runs only the live health check dashboard (VPN tunnel and BGP peer
        status, refreshed every 10 seconds) without repeating the creation
        flow. Loads the same rollback manifest used by --revert to know
        which tunnels/peers to check; auto-detects the most recent one if
        no path is given.

  --help, -h
        Shows this help message and exits.

${C_BOLD}NOTES${C_RESET}
  - A log file and rollback manifest are written to /storage/sase_vpn (the
    partition that survives a reboot on Spark appliances) every time the
    creation flow is run and confirmed.
  - This script is provided AS-IS for Proof of Value (PoV) demonstrations
    and has been tested with Check Point Spark version R82.00.10.
HELPEOF
    exit 0
fi

BANNER_WIDTH=78
echo -e "${C_RED}${C_BOLD}$(printf '=%.0s' $(seq 1 $BANNER_WIDTH))${C_RESET}"
echo -e "${C_RED}${C_BOLD}  DISCLAIMER${C_RESET}"
echo -e "${C_YELLOW}  This script is provided AS-IS, with no warranty of any kind, and is${C_RESET}"
echo -e "${C_YELLOW}  intended solely for use in Proof of Value (PoV) demonstrations.${C_RESET}"
echo -e "${C_YELLOW}  It has been tested with Check Point Spark version R82.00.10.${C_RESET}"
echo -e "${C_YELLOW}  Other versions may produce mixed or unexpected results.${C_RESET}"
echo -e "${C_YELLOW}  This script assumes all encryption settings on the SASE side have been${C_RESET}"
echo -e "${C_YELLOW}  left at their defaults. If any have been changed, manual adjustment on${C_RESET}"
echo -e "${C_YELLOW}  this gateway will be required after this script completes successfully.${C_RESET}"
echo -e "${C_RED}${C_BOLD}$(printf '=%.0s' $(seq 1 $BANNER_WIDTH))${C_RESET}"
echo
log_msg "Displayed AS-IS / PoV-only disclaimer banner (tested with Spark R82.00.10, assumes default SASE-side encryption settings)."

# ---------------------------------------------------------------------------
# --revert [manifest_file]
#
# Undoes a previous run of this script. If no manifest path is given, the
# most recent manifest found in the known log directories is used. Reads
# the manifest written by a prior creation run and issues the documented
# Check Point Spark clish equivalents to remove everything that was created:
#
#   add vpn site name "X"                          -> delete vpn site name X
#   add vpn tunnel "<id>" ...                       -> delete vpn tunnel <id>
#   add access-rule ... name "SASE_BGP_ALLOW"       -> delete access-rule type incoming-internal-and-vpn
#                                                      name "SASE_BGP_ALLOW" (only if this run created it;
#                                                      if the rule pre-existed, only the source entries
#                                                      this run added are removed, via "set access-rule
#                                                      ... remove source <name>", leaving the rule itself
#                                                      and its original sources untouched)
#   add host name "<site>_VTI_Remote" ...            -> delete host "<site>_VTI_Remote"
#                                                      (only if this run created it; a pre-existing host
#                                                      object with the same name is reused, not deleted)
#   set bgp external remote-as X peer Y ... on      -> set bgp external remote-as X peer Y ... off
#   set inbound-route-filter bgp-policy N ... on    -> set inbound-route-filter bgp-policy N off
#                                                      (per Check Point's docs, "off" directly after the
#                                                       policy ID - with no other parameters - deletes the
#                                                       entire policy; it must NOT be combined with
#                                                       "based-on-as as <AS> off", which is invalid syntax)
#   set route-redistribution ... on                 -> set route-redistribution ... off
#
# If this run was the one that FIRST introduced the SASE remote-as group or
# the local BGP AS number (i.e. neither existed beforehand), those are also
# removed on revert:
#   set bgp external remote-as X on                 -> set bgp external remote-as X off
#                                                      (only if this run created the AS group)
#   set as <LOCAL_AS>                                -> set as off
#                                                      (only if no local AS existed before this run)
#
# The tunnel health monitoring mode (and overall site-to-site mode) as they
# existed BEFORE this run are also captured and restored on revert, since
# this script always switches monitoring to "dpd" - if the system previously
# used a different mode (e.g. "tunnel-test"), that is restored.
#
# Always left untouched (a shared/global setting unrelated to any single
# run): the global "set vpn site-to-site mode" switch.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# --auto "ANSWER;ANSWER;ANSWER;..."
#
# Lets the entire normal creation flow run non-interactively by supplying
# every prompt's answer up front, in a single string, semicolon-separated.
# This does NOT bypass any validation, conditional prompts, or confirmation
# steps - it simply feeds the given answers into stdin in order, exactly as
# if they had been typed live, so every existing check still applies.
#
# Answers must be given in the SAME ORDER prompts would normally appear,
# including any conditional ones that only show up depending on system
# state or what was entered (e.g. a private-IP confirmation, an AS-mismatch
# warning, or the tunnel-test compatibility warning) - if a run hits one of
# these and no matching answer is left, that prompt will fail to read
# input and the script will exit with an unexpected-error message. When in
# doubt, run interactively once first on a similar system to see the exact
# prompt sequence, then build the --auto string to match it.
#
# A comma is used WITHIN a single answer for multi-value prompts (e.g.
# "1,2" for selecting multiple interfaces, or a comma-separated CIDR list) -
# semicolons are only the separator BETWEEN answers.
#
# Example (1 gateway, defaults for local/SASE AS, "all interfaces", confirm
# both the apply step and the health check offer):
#   ./create_sase_vpn.sh --auto "1;;;131.226.45.218;MySecretKey123;MySecretKey123;169.254.10.1;169.254.10.2;65.185.68.215;1;y;y"
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--auto" ]]; then
    AUTO_ANSWERS="${2:-}"
    if [[ -z "$AUTO_ANSWERS" ]]; then
        echo "Error: --auto requires an answer string. Example:"
        echo "  $0 --auto \"1;;;131.226.45.218;MySecretKey123;MySecretKey123;169.254.10.1;169.254.10.2;65.185.68.215;1;y;y\""
        exit 1
    fi
    log_msg "Running in --auto (non-interactive) mode."
    # Feed the semicolon-separated answers into stdin, one per line, so the
    # normal read-based prompts below consume them in order - this changes
    # nothing about what gets validated or asked, only where the answers
    # come from.
    exec < <(printf '%s\n' "${AUTO_ANSWERS//;/$'\n'}")
fi

if [[ "${1:-}" == "--revert" ]]; then
    REVERT_MANIFEST="${2:-}"

    if [[ -z "$REVERT_MANIFEST" ]]; then
        REVERT_MANIFEST="$(ls -t /storage/sase_vpn/sase_vpn_manifest_*.conf /var/log/sase_vpn/sase_vpn_manifest_*.conf /var/tmp/sase_vpn/sase_vpn_manifest_*.conf 2>/dev/null | head -n1 || true)"
    fi

    if [[ -z "$REVERT_MANIFEST" || ! -f "$REVERT_MANIFEST" ]]; then
        echo -e "${C_RED}Error: no rollback manifest found. Specify one explicitly:${C_RESET}"
        echo "  $0 --revert /path/to/sase_vpn_manifest_TIMESTAMP.conf"
        log_msg "FATAL: --revert requested but no manifest file found (given: '${REVERT_MANIFEST}')."
        exit 1
    fi

    echo -e "${C_BOLD}=== SASE VPN Configuration Rollback ===${C_RESET}"
    echo "Using manifest: ${REVERT_MANIFEST}"
    log_msg "Revert requested using manifest: ${REVERT_MANIFEST}"
    echo

    # Manifest contains only plain KEY=value assignments written by this
    # script itself (see manifest-writing section above) - safe to source.
    # shellcheck disable=SC1090
    source "$REVERT_MANIFEST"

    IFS=',' read -ra R_SITE_NAMES <<< "${SITE_NAMES:-}"
    IFS=',' read -ra R_VTI_IDS <<< "${VTI_IDS:-}"
    IFS=',' read -ra R_VTI_REMOTE_IPS <<< "${VTI_REMOTE_IPS:-}"
    IFS=',' read -ra R_HOST_OBJ_NAMES <<< "${HOST_OBJ_NAMES:-}"
    IFS=',' read -ra R_HOST_OBJ_CREATED <<< "${HOST_OBJ_CREATED:-}"
    IFS=',' read -ra R_ADVERTISE_INTERFACES <<< "${ADVERTISE_INTERFACES:-}"
    IFS=',' read -ra R_ADVERTISE_NETWORKS <<< "${ADVERTISE_NETWORKS:-}"
    # Older manifests written before route advertisement selection was added
    # always redistributed from "all" interfaces - default to that if missing.
    R_ADVERTISE_MODE="${ADVERTISE_MODE:-all}"

    if [[ -z "${SASE_AS:-}" || "${#R_SITE_NAMES[@]}" -eq 0 ]]; then
        echo -e "${C_RED}Error: manifest file is missing required data. Aborting.${C_RESET}"
        log_msg "FATAL: manifest file '${REVERT_MANIFEST}' is missing required fields."
        exit 1
    fi

    if [[ -z "${NEXT_POLICY_ID:-}" || ! "${NEXT_POLICY_ID}" =~ ^[0-9]+$ ]]; then
        echo -e "${C_RED}Error: manifest file is missing a valid inbound route filter policy ID."
        echo -e "It may be corrupted, hand-edited, or from an incompatible version. Aborting.${C_RESET}"
        log_msg "FATAL: manifest file '${REVERT_MANIFEST}' has an invalid or missing NEXT_POLICY_ID."
        exit 1
    fi

    if [[ "${#R_SITE_NAMES[@]}" -ne "${#R_VTI_IDS[@]}" || "${#R_SITE_NAMES[@]}" -ne "${#R_VTI_REMOTE_IPS[@]}" ]]; then
        echo -e "${C_RED}Error: manifest file has mismatched data (different numbers of site names,"
        echo -e "VTI IDs, and VTI remote IPs). It may be corrupted or hand-edited. Aborting.${C_RESET}"
        log_msg "FATAL: manifest file '${REVERT_MANIFEST}' has mismatched array lengths (sites=${#R_SITE_NAMES[@]}, vti_ids=${#R_VTI_IDS[@]}, vti_remote_ips=${#R_VTI_REMOTE_IPS[@]})."
        exit 1
    fi

    echo -e "${C_BOLD}This will revert the following, created by that run:${C_RESET}"
    for ((i = 0; i < ${#R_SITE_NAMES[@]}; i++)); do
        echo "  - VPN site \"${R_SITE_NAMES[$i]}\" - will be deleted"
        echo "  - VTI tunnel ${R_VTI_IDS[$i]} (vpnt${R_VTI_IDS[$i]}) - will be deleted"
        echo "  - BGP peer ${R_VTI_REMOTE_IPS[$i]} under AS ${SASE_AS} - will be removed"
        if [[ "${R_HOST_OBJ_CREATED[$i]:-false}" == true ]]; then
            echo "  - Host object \"${R_HOST_OBJ_NAMES[$i]:-unknown}\" - will be deleted (this run created it)"
        else
            echo "  - Host object \"${R_HOST_OBJ_NAMES[$i]:-unknown}\" - left alone (it already existed before that run)"
        fi
    done
    echo "  - Inbound route filter policy ${NEXT_POLICY_ID} - will be deleted"
    case "$R_ADVERTISE_MODE" in
        all)
            echo "  - Route redistribution to BGP AS ${SASE_AS} (all interfaces) - will be removed"
            ;;
        interfaces)
            echo "  - Route redistribution to BGP AS ${SASE_AS} (interface(s) $(IFS=,; echo "${R_ADVERTISE_INTERFACES[*]}")) - will be removed"
            ;;
        networks)
            echo "  - Route redistribution to BGP AS ${SASE_AS} (network(s) $(IFS=,; echo "${R_ADVERTISE_NETWORKS[*]}")) - will be removed"
            ;;
    esac
    if [[ "${REMOTE_AS_IS_NEW:-false}" == true ]]; then
        echo "  - BGP AS group ${SASE_AS} - will be removed (this run created it)"
    else
        echo "  - BGP AS group ${SASE_AS} - left alone (it already existed before that run)"
    fi
    if [[ "${LOCAL_AS_IS_NEW:-false}" == true ]]; then
        echo "  - Local BGP AS number ${LOCAL_AS:-unknown} - will be removed (this run set it for the first time)"
    else
        echo "  - Local BGP AS number - left alone (it already existed before that run)"
    fi
    if [[ "${ACCESS_RULE_CREATED:-false}" == true ]]; then
        echo "  - Access rule \"SASE_BGP_ALLOW\" - will be deleted (this run created it)"
    else
        echo "  - Access rule \"SASE_BGP_ALLOW\" - left alone (it already existed before that run)"
    fi
    if [[ -n "${ORIGINAL_TUNNEL_HEALTH_MODE:-}" ]]; then
        echo "  - Tunnel health monitoring - will be restored to \"${ORIGINAL_TUNNEL_HEALTH_MODE}\" (site-to-site mode \"${ORIGINAL_S2S_MODE:-on}\", as it was before that run)"
    else
        echo "  - Tunnel health monitoring - left as \"dpd\" (that run found no site-to-site VPN configured beforehand)"
    fi
    echo
    read -rp "Proceed with reverting this configuration? (y/N): " REVERT_CONFIRM
    if [[ ! "$REVERT_CONFIRM" =~ ^[Yy]$ ]]; then
        echo "Aborted by user."
        log_msg "Revert aborted by user at confirmation prompt."
        exit 0
    fi
    echo
    log_msg "User confirmed revert of manifest ${REVERT_MANIFEST}."

    COMMANDS=()
    DESCRIPTIONS=()
    STEP_GROUPS=()
    PSKS=()

    for ((i = 0; i < ${#R_SITE_NAMES[@]}; i++)); do
        site="${R_SITE_NAMES[$i]}"
        vti_id="${R_VTI_IDS[$i]}"
        remote_vti="${R_VTI_REMOTE_IPS[$i]}"

        COMMANDS+=("set bgp external remote-as ${SASE_AS} peer ${remote_vti} graceful-restart off")
        DESCRIPTIONS+=("[${site}] Removing BGP graceful-restart for peer ${remote_vti}")
        STEP_GROUPS+=("[${site}] Reverting BGP peer")

        COMMANDS+=("set bgp external remote-as ${SASE_AS} peer ${remote_vti} multihop off")
        DESCRIPTIONS+=("[${site}] Removing BGP multihop for peer ${remote_vti}")
        STEP_GROUPS+=("[${site}] Reverting BGP peer")

        COMMANDS+=("set bgp external remote-as ${SASE_AS} peer ${remote_vti} off")
        DESCRIPTIONS+=("[${site}] Removing BGP peer ${remote_vti}")
        STEP_GROUPS+=("[${site}] Reverting BGP peer")

        COMMANDS+=("delete vpn site name ${site}")
        DESCRIPTIONS+=("[${site}] Deleting VPN site \"${site}\"")
        STEP_GROUPS+=("[${site}] Deleting VPN site")

        COMMANDS+=("delete vpn tunnel ${vti_id}")
        DESCRIPTIONS+=("[${site}] Deleting VTI tunnel ${vti_id} (vpnt${vti_id})")
        STEP_GROUPS+=("[${site}] Deleting VTI tunnel")
    done

    # Per Check Point's Spark CLI reference: "set inbound-route-filter bgp-policy
    # <ID> off" deletes the entire policy from the configuration - it must NOT
    # be combined with "based-on-as as <AS>" (that combination is invalid syntax
    # and returns "Bad parameter starting at 'off'").
    COMMANDS+=("set inbound-route-filter bgp-policy ${NEXT_POLICY_ID} off")
    DESCRIPTIONS+=("Deleting inbound route filter policy ${NEXT_POLICY_ID}")
    STEP_GROUPS+=("Reverting BGP routing settings")

    case "$R_ADVERTISE_MODE" in
        all)
            COMMANDS+=("set route-redistribution to bgp-as ${SASE_AS} from interface all off")
            DESCRIPTIONS+=("Removing route redistribution to BGP AS ${SASE_AS}")
            STEP_GROUPS+=("Reverting BGP routing settings")
            ;;
        interfaces)
            for r_adv_iface in "${R_ADVERTISE_INTERFACES[@]}"; do
                COMMANDS+=("set route-redistribution to bgp-as ${SASE_AS} from interface \"${r_adv_iface}\" off")
                DESCRIPTIONS+=("Removing route redistribution to BGP AS ${SASE_AS} from interface ${r_adv_iface}")
                STEP_GROUPS+=("Reverting BGP routing settings")
            done
            ;;
        networks)
            for r_adv_net in "${R_ADVERTISE_NETWORKS[@]}"; do
                COMMANDS+=("set route-redistribution to bgp-as ${SASE_AS} from aggregate ${r_adv_net} off")
                DESCRIPTIONS+=("Removing route redistribution to BGP AS ${SASE_AS} from network ${r_adv_net}")
                STEP_GROUPS+=("Reverting BGP routing settings")
            done
            ;;
    esac

    # Only remove the remote-as group and local AS number if THIS run set
    # them for the first time - if they already existed beforehand, other
    # peers/tunnels not created by this run may still depend on them.
    if [[ "${REMOTE_AS_IS_NEW:-false}" == true ]]; then
        COMMANDS+=("set bgp external remote-as ${SASE_AS} off")
        DESCRIPTIONS+=("Removing BGP AS group ${SASE_AS} (created by that run)")
        STEP_GROUPS+=("Reverting BGP routing settings")
    fi

    if [[ "${LOCAL_AS_IS_NEW:-false}" == true ]]; then
        COMMANDS+=("set as off")
        DESCRIPTIONS+=("Removing local BGP AS number (set for the first time by that run)")
        STEP_GROUPS+=("Reverting BGP routing settings")
    fi

    if [[ "${ACCESS_RULE_CREATED:-false}" == true ]]; then
        COMMANDS+=("delete access-rule type incoming-internal-and-vpn name \"SASE_BGP_ALLOW\"")
        DESCRIPTIONS+=("Deleting access rule \"SASE_BGP_ALLOW\"")
        STEP_GROUPS+=("Deleting access rule")
    else
        # The rule already existed before that run - it must NOT be deleted,
        # but the source entries that run added to it should be detached.
        for ((i = 0; i < ${#R_HOST_OBJ_NAMES[@]}; i++)); do
            COMMANDS+=("set access-rule type incoming-internal-and-vpn name \"SASE_BGP_ALLOW\" remove source \"${R_HOST_OBJ_NAMES[$i]}\"")
            DESCRIPTIONS+=("Removing ${R_HOST_OBJ_NAMES[$i]} as an allowed BGP source (rule itself left alone)")
            STEP_GROUPS+=("Reverting access rule sources")
        done
    fi

    # Delete host objects that this run created (leave alone any that
    # already existed beforehand and were simply reused).
    for ((i = 0; i < ${#R_HOST_OBJ_NAMES[@]}; i++)); do
        if [[ "${R_HOST_OBJ_CREATED[$i]:-false}" == true ]]; then
            COMMANDS+=("delete host \"${R_HOST_OBJ_NAMES[$i]}\"")
            DESCRIPTIONS+=("Deleting host object \"${R_HOST_OBJ_NAMES[$i]}\"")
            STEP_GROUPS+=("Deleting host objects")
        fi
    done

    # Restore the tunnel health monitoring mode (and overall site-to-site
    # mode) to what it was before this run, if we captured one. Nothing to
    # restore on a fresh system that had no site-to-site VPN configured yet.
    if [[ -n "${ORIGINAL_TUNNEL_HEALTH_MODE:-}" ]]; then
        COMMANDS+=("set vpn site-to-site mode \"${ORIGINAL_S2S_MODE:-on}\" default-access-to-lan \"accept\" track \"log\" local-encryption-domain \"auto\" source-ip-address-selection \"automatically\" outgoing-interface-selection \"routing-table\" tunnel-health-monitor-mode \"${ORIGINAL_TUNNEL_HEALTH_MODE}\" ike-v2-global-gateway-id \"${GATEWAY_ID}\"")
        DESCRIPTIONS+=("Restoring tunnel health monitoring to \"${ORIGINAL_TUNNEL_HEALTH_MODE}\" (as it was before that run)")
        STEP_GROUPS+=("Restoring tunnel health monitoring")
    fi

    execute_command_groups
    exit 0
fi

# ---------------------------------------------------------------------------
# --healthcheck [manifest_file]
#
# Runs only the live health check dashboard, without going through the
# creation flow - useful for re-checking tunnel/BGP status later without
# needing to reconfigure anything. Loads the same rollback manifest used by
# --revert (most recent one found if no path is given) to know which
# tunnels and BGP peers to check.
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--healthcheck" ]]; then
    HEALTHCHECK_MANIFEST="${2:-}"

    if [[ -z "$HEALTHCHECK_MANIFEST" ]]; then
        HEALTHCHECK_MANIFEST="$(ls -t /storage/sase_vpn/sase_vpn_manifest_*.conf /var/log/sase_vpn/sase_vpn_manifest_*.conf /var/tmp/sase_vpn/sase_vpn_manifest_*.conf 2>/dev/null | head -n1 || true)"
    fi

    if [[ -z "$HEALTHCHECK_MANIFEST" || ! -f "$HEALTHCHECK_MANIFEST" ]]; then
        echo -e "${C_RED}Error: no rollback manifest found. Specify one explicitly:${C_RESET}"
        echo "  $0 --healthcheck /path/to/sase_vpn_manifest_TIMESTAMP.conf"
        log_msg "FATAL: --healthcheck requested but no manifest file found (given: '${HEALTHCHECK_MANIFEST}')."
        exit 1
    fi

    echo -e "${C_BOLD}=== SASE Configuration Health Check ===${C_RESET}"
    echo "Using manifest: ${HEALTHCHECK_MANIFEST}"
    log_msg "Standalone health check requested using manifest: ${HEALTHCHECK_MANIFEST}"
    echo

    # Manifest contains only plain KEY=value assignments written by this
    # script itself - safe to source.
    # shellcheck disable=SC1090
    source "$HEALTHCHECK_MANIFEST"

    IFS=',' read -ra SITE_NAMES <<< "${SITE_NAMES:-}"
    IFS=',' read -ra SASE_GW_IPS <<< "${SASE_GW_IPS:-}"
    IFS=',' read -ra VTI_REMOTE_IPS <<< "${VTI_REMOTE_IPS:-}"
    GW_COUNT="${#SITE_NAMES[@]}"

    if [ "$GW_COUNT" -eq 0 ] || [ "${#SASE_GW_IPS[@]}" -eq 0 ] || [ "${#VTI_REMOTE_IPS[@]}" -eq 0 ]; then
        echo -e "${C_RED}Error: manifest file is missing required data (site names, SASE gateway IPs,"
        echo -e "or VTI remote IPs). It may have been written by an older version of this script."
        echo -e "Aborting.${C_RESET}"
        log_msg "FATAL: manifest file '${HEALTHCHECK_MANIFEST}' is missing data required for --healthcheck."
        exit 1
    fi

    if [[ "$GW_COUNT" -ne "${#SASE_GW_IPS[@]}" || "$GW_COUNT" -ne "${#VTI_REMOTE_IPS[@]}" ]]; then
        echo -e "${C_RED}Error: manifest file has mismatched data (different numbers of site names,"
        echo -e "SASE gateway IPs, and VTI remote IPs). It may be corrupted or hand-edited.${C_RESET}"
        echo -e "${C_RED}Aborting.${C_RESET}"
        log_msg "FATAL: manifest file '${HEALTHCHECK_MANIFEST}' has mismatched array lengths (sites=${GW_COUNT}, gw_ips=${#SASE_GW_IPS[@]}, vti_remote_ips=${#VTI_REMOTE_IPS[@]})."
        exit 1
    fi

    echo "Monitoring the following tunnel(s):"
    for ((i = 0; i < GW_COUNT; i++)); do
        echo "  - ${SITE_NAMES[$i]}: gateway ${SASE_GW_IPS[$i]}, BGP peer ${VTI_REMOTE_IPS[$i]}"
    done
    echo

    run_health_check_dashboard
    exit 0
fi

echo -e "${C_BOLD}=== SASE Route-Based VPN + BGP Configuration ===${C_RESET}"
echo

# ---------------------------------------------------------------------------
# Pull the running configuration immediately, before any prompts, and check
# right away for signs this appliance is centrally managed. This script is
# not supported on a centrally-managed Spark appliance, so this must happen
# before asking for anything else - not after the gateway count or any
# other prompt.
# ---------------------------------------------------------------------------
echo "Retrieving current configuration (this may take a moment)..."
log_msg "Retrieving current configuration (show configuration)..."

# Captured to a file FIRST, and the centrally-managed check below runs
# directly against that file - not a bash variable. Command substitution
# (VAR="$(...)") silently truncates at the first NUL byte if one appears
# anywhere in the output, which would make a real line simply vanish from
# a bash variable's perspective while still being fully present on disk.
# Smart-1 Cloud (MaaS) connection data can plausibly include such bytes,
# so this check must not depend on data having survived that trip through
# a variable.
SHOW_CONFIG_FILE="$(mktemp)"
clish -c "show configuration" > "$SHOW_CONFIG_FILE" 2>&1
log_msg "show configuration captured to file: $(wc -l < "$SHOW_CONFIG_FILE") lines, $(wc -c < "$SHOW_CONFIG_FILE") bytes."

CENTRAL_MGMT_TYPE=""
if grep -qiE 'maas[[:space:]]+mode[[:space:]]+"?enable"?' "$SHOW_CONFIG_FILE"; then
    CENTRAL_MGMT_TYPE="Smart-1 Cloud"
elif grep -qiE 'security-management[[:space:]]+mode[[:space:]]+"?centrally-managed"?' "$SHOW_CONFIG_FILE"; then
    CENTRAL_MGMT_TYPE="an SMS or MDM"
fi

# Diagnostic breadcrumb in case neither pattern matches on some system but
# the word "maas" or "centrally-managed" still shows up somewhere - helps
# pinpoint a formatting difference without needing to reproduce it live.
if [[ -z "$CENTRAL_MGMT_TYPE" ]]; then
    if grep -qi 'maas' "$SHOW_CONFIG_FILE"; then
        log_msg "DIAGNOSTIC: 'maas' found in the show-configuration FILE but did not match the expected pattern: $(grep -i 'maas' "$SHOW_CONFIG_FILE")"
    fi
    if grep -qi 'centrally-managed' "$SHOW_CONFIG_FILE"; then
        log_msg "DIAGNOSTIC: 'centrally-managed' found in the show-configuration FILE but did not match the expected pattern: $(grep -i 'centrally-managed' "$SHOW_CONFIG_FILE")"
    fi
fi

if [[ -n "$CENTRAL_MGMT_TYPE" ]]; then
    echo
    echo -e "${C_RED}${C_BOLD}Error: this Spark appliance appears to be centrally managed.${C_RESET}"
    echo -e "${C_RED}It looks like it is being managed by ${CENTRAL_MGMT_TYPE}. This script does"
    echo -e "not support centrally-managed appliances and will now exit.${C_RESET}"
    log_msg "FATAL: appliance appears centrally managed (${CENTRAL_MGMT_TYPE}). Exiting - not supported."
    rm -f "$SHOW_CONFIG_FILE"
    exit 1
fi

# Now populate the variable used by the rest of the script from the same
# file. If this ever comes out a different size than the file above, that
# confirms the variable itself is being truncated somewhere along the way.
SHOW_CONFIG_OUTPUT="$(cat "$SHOW_CONFIG_FILE")"
log_msg "show configuration in variable: $(echo "${SHOW_CONFIG_OUTPUT}" | wc -l) lines, $(echo "${SHOW_CONFIG_OUTPUT}" | wc -c) bytes (compare to the file-based count above - a mismatch indicates truncation)."
rm -f "$SHOW_CONFIG_FILE"
echo
echo

# ---------------------------------------------------------------------------
# Helper: validate a dotted-decimal IPv4 address (each octet 0-255)
# ---------------------------------------------------------------------------
is_valid_ipv4() {
    local ip=$1
    local IFS='.'
    local -a octets
    read -ra octets <<< "$ip"
    [ "${#octets[@]}" -eq 4 ] || return 1
    for o in "${octets[@]}"; do
        # Reject leading zeros (e.g. "01") to avoid octal-parsing ambiguity -
        # only a bare "0" or a number not starting with 0 is accepted.
        [[ "$o" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
        [ "$o" -ge 0 ] && [ "$o" -le 255 ] || return 1
    done
    return 0
}

# ---------------------------------------------------------------------------
# Helpers: convert between dotted-decimal IPv4 and a 32-bit integer, used to
# compute the network address of an interface from its IP + subnet mask.
# ---------------------------------------------------------------------------
ip_to_int() {
    local a b c d
    IFS='.' read -r a b c d <<< "$1"
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

int_to_ip() {
    local ip_int=$1
    echo "$(( (ip_int >> 24) & 255 )).$(( (ip_int >> 16) & 255 )).$(( (ip_int >> 8) & 255 )).$(( ip_int & 255 ))"
}

# Converts a dotted-decimal subnet mask (e.g. 255.255.255.0) to a CIDR
# prefix length (e.g. 24), by counting the set bits in its integer form.
mask_to_prefix() {
    local mask_int prefix=0 bit
    mask_int=$(ip_to_int "$1")
    for ((bit = 31; bit >= 0; bit--)); do
        (( (mask_int >> bit) & 1 )) || break
        prefix=$((prefix + 1))
    done
    echo "$prefix"
}

# Converts a CIDR prefix length (e.g. 24) to a dotted-decimal subnet mask
# (e.g. 255.255.255.0). Some interface types (e.g. VLAN sub-interfaces) are
# configured with "mask-length" rather than "subnet-mask" in the running
# configuration.
prefix_to_mask() {
    local prefix=$1
    local mask_int=0
    if [ "$prefix" -gt 0 ]; then
        mask_int=$(( 0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF ))
    fi
    int_to_ip "$mask_int"
}

# Given an interface's IPv4 address and subnet mask, returns the network
# it's on in CIDR form (e.g. 192.168.1.1 + 255.255.255.0 -> 192.168.1.0/24) -
# this is what should actually be offered/advertised, not the host IP itself.
network_from_ip_and_mask() {
    local ip="$1" mask="$2"
    local ip_int mask_int network_int prefix
    ip_int=$(ip_to_int "$ip")
    mask_int=$(ip_to_int "$mask")
    network_int=$(( ip_int & mask_int ))
    prefix=$(mask_to_prefix "$mask")
    echo "$(int_to_ip "$network_int")/${prefix}"
}

# ---------------------------------------------------------------------------
# Helper: validate a BGP AS number
# ---------------------------------------------------------------------------
is_valid_asn() {
    local val=$1
    [[ "$val" =~ ^[0-9]{1,10}$ ]] || return 1
    [ "$val" -ge 1 ] && [ "$val" -le 4294967295 ] || return 1
    return 0
}

# ---------------------------------------------------------------------------
# Helper: given two IPv4 addresses on the same /30, return "lower-upper"
# to use as a DHCP pool range for the tunnel interface
# ---------------------------------------------------------------------------
vti_pool_range() {
    local ip1=$1 ip2=$2
    local last1="${ip1##*.}"
    local last2="${ip2##*.}"
    if [ "$last1" -le "$last2" ]; then
        echo "${ip1}-${ip2}"
    else
        echo "${ip2}-${ip1}"
    fi
}

# ---------------------------------------------------------------------------
# Helper: returns 0 (true) if the given IPv4 address is in a private/
# reserved range (RFC1918 or loopback) - used to gently flag likely typos
# in fields that should hold a public/internet-routable IP
# ---------------------------------------------------------------------------
is_private_ipv4() {
    local ip="$1"
    local IFS='.'
    local -a o
    read -ra o <<< "$ip"
    [ "${o[0]}" -eq 10 ] && return 0
    [ "${o[0]}" -eq 127 ] && return 0
    [ "${o[0]}" -eq 172 ] && [ "${o[1]}" -ge 16 ] && [ "${o[1]}" -le 31 ] && return 0
    [ "${o[0]}" -eq 192 ] && [ "${o[1]}" -eq 168 ] && return 0
    return 1
}

# ---------------------------------------------------------------------------
# Helper: prompts for and validates an IPv4 address, retrying on bad input.
# Result is assigned into the variable name given as $2 (via printf -v, for
# broad bash-version compatibility). If $3 is "true", also rejects IPs
# already in use elsewhere on the system (via ip_in_use, defined later).
# If $4 is non-empty, it's offered as a default the user can accept with Enter.
# ---------------------------------------------------------------------------
prompt_ipv4() {
    local prompt_text="$1" out_var="$2" check_conflict="${3:-false}" default_val="${4:-}"
    local input
    while true; do
        if [[ -n "$default_val" ]]; then
            read -rp "${prompt_text} [default: ${default_val}]: " input
            input="${input:-$default_val}"
        else
            read -rp "${prompt_text}: " input
        fi

        if ! is_valid_ipv4 "$input"; then
            echo "  Error: \"${input}\" is not a valid IPv4 address. Please try again."
            continue
        fi

        if [[ "$check_conflict" == true ]] && ip_in_use "$input"; then
            echo "  Error: \"${input}\" is already in use on this system (or was already entered for another tunnel above). Please enter a different IP."
            show_ip_conflict_source "$input"
            continue
        fi

        printf -v "$out_var" '%s' "$input"
        break
    done
}

# ---------------------------------------------------------------------------
# Helper: warns (without hard-blocking) if an IP entered for a field that
# should be public/internet-routable looks like a private/reserved address
# ---------------------------------------------------------------------------
confirm_if_private_ip() {
    local ip="$1" field_label="$2"
    if is_private_ipv4 "$ip"; then
        echo "  Warning: ${ip} is a private/reserved address; ${field_label} is normally a public IP."
        read -rp "  Continue with this address anyway? [y/N]: " priv_confirm
        [[ "$priv_confirm" =~ ^[Yy]$ ]]
        return $?
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Helper: suggests a local VTI IP as the /30 partner of the given remote VTI
# IP (e.g. remote .1 -> suggest .2, remote .2 -> suggest .1). This is only a
# convenience default - the user can always type a different address.
# ---------------------------------------------------------------------------
suggest_local_vti() {
    local remote="$1"
    local prefix="${remote%.*}"
    local last="${remote##*.}"
    local suggested
    if (( last % 2 == 1 )); then
        suggested=$((last + 1))
        # If incrementing would go out of range (remote ends in .255),
        # decrement instead - either way, this must never equal $last,
        # or the suggested default would collide with the remote IP itself.
        (( suggested > 255 )) && suggested=$((last - 1))
    else
        suggested=$((last - 1))
        # Same idea for the low boundary (remote ends in .0).
        (( suggested < 0 )) && suggested=$((last + 1))
    fi
    echo "${prefix}.${suggested}"
}

# ---------------------------------------------------------------------------
# 0. How many SASE gateways does the user want to establish tunnels to?
#    Capped at a sane maximum to guard against an accidental typo (e.g.
#    entering "100000" instead of "1") from creating a runaway number of
#    tunnels/objects.
# ---------------------------------------------------------------------------
MAX_GATEWAYS=50
while true; do
    read -rp "How many SASE gateways would you like to establish tunnels to?: " GW_COUNT_INPUT
    if [[ "$GW_COUNT_INPUT" =~ ^[0-9]{1,9}$ ]] && [ "$GW_COUNT_INPUT" -ge 1 ] && [ "$GW_COUNT_INPUT" -le "$MAX_GATEWAYS" ]; then
        GW_COUNT="$GW_COUNT_INPUT"
        break
    fi
    echo "Error: please enter a whole number between 1 and ${MAX_GATEWAYS}."
done
log_msg "Gateway count: ${GW_COUNT}"
echo

# ---------------------------------------------------------------------------
# Check whether dynamic routing (BGP) is already configured on this system
# ---------------------------------------------------------------------------
echo "Checking for existing dynamic routing configuration..."
log_msg "Checking for existing dynamic routing configuration (show router-configuration)..."
ROUTER_CONFIG_OUTPUT="$(clish -c "show router-configuration" 2>&1 || true)"

EXISTING_LOCAL_AS="$(echo "${ROUTER_CONFIG_OUTPUT}" | sed -n 's/^set as \([0-9]\+\).*/\1/p' | head -n1)"
EXISTING_REMOTE_AS_LIST="$(echo "${ROUTER_CONFIG_OUTPUT}" | sed -n 's/.*bgp external remote-as \([0-9]\+\) on.*/\1/p' | sort -un)"
EXISTING_PEERS="$(echo "${ROUTER_CONFIG_OUTPUT}" | sed -n 's/.*remote-as [0-9]\+ peer \([0-9.]\+\) on.*/\1/p' | sort -u)"
EXISTING_INBOUND_FILTER="$(echo "${ROUTER_CONFIG_OUTPUT}" | grep -c 'inbound-route-filter' || true)"
EXISTING_REDISTRIBUTION="$(echo "${ROUTER_CONFIG_OUTPUT}" | grep -c 'route-redistribution' || true)"

# Determine the next free inbound-route-filter bgp-policy ID. Policy IDs
# start at 512 on Spark systems; if one or more policies already exist
# (for this or any other BGP relationship), continue from the highest one
# found rather than reusing an ID that's already in use.
HIGHEST_POLICY_ID="$(echo "${ROUTER_CONFIG_OUTPUT}" | grep -oE 'inbound-route-filter bgp-policy [0-9]+' | grep -oE '[0-9]+' | sort -n | tail -n1 || true)"
if [[ -n "$HIGHEST_POLICY_ID" ]]; then
    NEXT_POLICY_ID=$((HIGHEST_POLICY_ID + 1))
    [ "$NEXT_POLICY_ID" -lt 512 ] && NEXT_POLICY_ID=512
else
    NEXT_POLICY_ID=512
fi

ROUTING_MODE="overwrite"

if [[ -n "$EXISTING_LOCAL_AS" || -n "$EXISTING_REMOTE_AS_LIST" ]]; then
    echo
    echo -e "${C_YELLOW}${C_BOLD}=== Existing Dynamic Routing Configuration Detected ===${C_RESET}"
    [[ -n "$EXISTING_LOCAL_AS" ]] && echo "  Local BGP AS         : ${EXISTING_LOCAL_AS}"
    if [[ -n "$EXISTING_REMOTE_AS_LIST" ]]; then
        echo "  Remote BGP AS number(s):"
        while IFS= read -r as_num; do
            echo "    - ${as_num}"
        done <<< "$EXISTING_REMOTE_AS_LIST"
    fi
    if [[ -n "$EXISTING_PEERS" ]]; then
        echo "  Existing BGP peer(s) :"
        while IFS= read -r peer_ip; do
            echo "    - ${peer_ip}"
        done <<< "$EXISTING_PEERS"
    fi
    [[ "$EXISTING_INBOUND_FILTER" -gt 0 ]] && echo "  Inbound route filter : already present"
    [[ "$EXISTING_REDISTRIBUTION" -gt 0 ]] && echo "  Route redistribution : already present"
    echo

    if [[ -n "$EXISTING_LOCAL_AS" ]]; then
        while true; do
            read -rp "Use the existing local BGP AS number shown above instead of entering a new one? [Y/n]: " ROUTING_CHOICE
            case "${ROUTING_CHOICE,,}" in
                y|yes|"")
                    ROUTING_MODE="auto"
                    break
                    ;;
                n|no)
                    ROUTING_MODE="overwrite"
                    break
                    ;;
                *)
                    echo "Please enter \"y\" or \"n\"."
                    ;;
            esac
        done
        echo
    fi
fi

# ---------------------------------------------------------------------------
# The running configuration was already pulled (and checked for signs of
# central management) right at the start, before any prompts - reused here
# to auto-discover the ike-v2-global-gateway-id, avoid creating duplicate
# objects (access rules, VPN sites, VTI tunnel IDs) on re-runs, and detect
# IP addresses already in use on this system.
# ---------------------------------------------------------------------------

# Look for a line such as:
#   set vpn site-to-site mode "off" ... ike-v2-global-gateway-id "Gateway-ID-7FB70622"
GATEWAY_ID="$(echo "${SHOW_CONFIG_OUTPUT}" | sed -n 's/.*ike-v2-global-gateway-id[[:space:]]*"\([^"]*\)".*/\1/p' | sort -u | head -n1)"

if [[ -z "${GATEWAY_ID}" ]]; then
    echo "Error: Could not locate an existing ike-v2-global-gateway-id in 'show configuration' output. Aborting."
    log_msg "FATAL: no ike-v2-global-gateway-id found in show configuration output. Aborting."
    exit 1
fi

# Determine the next free VPN site number (SASE<n>), continuing past
# any that already exist rather than restarting at 1.
HIGHEST_SITE_NUM="$(echo "${SHOW_CONFIG_OUTPUT}" | grep -oE 'add vpn site name "SASE[0-9]+"' | grep -oE '[0-9]+' | sort -n | tail -n1 || true)"
if [[ -n "$HIGHEST_SITE_NUM" ]]; then
    NEXT_SITE_NUM=$((HIGHEST_SITE_NUM + 1))
else
    NEXT_SITE_NUM=1
fi

# Determine the next free VTI tunnel ID, starting at 10, continuing past any
# that already exist rather than restarting at 10.
HIGHEST_VTI_ID="$(echo "${SHOW_CONFIG_OUTPUT}" | grep -oE 'add vpn tunnel "[0-9]+"' | grep -oE '[0-9]+' | sort -n | tail -n1 || true)"
if [[ -n "$HIGHEST_VTI_ID" ]]; then
    NEXT_VTI_ID=$((HIGHEST_VTI_ID + 1))
    [ "$NEXT_VTI_ID" -lt 10 ] && NEXT_VTI_ID=10
else
    NEXT_VTI_ID=10
fi

# Check whether the shared BGP access rule already exists
ACCESS_RULE_EXISTS=false
if echo "${SHOW_CONFIG_OUTPUT}" | grep -q 'name "SASE_BGP_ALLOW"'; then
    ACCESS_RULE_EXISTS=true
fi

# Capture the tunnel health monitoring mode and overall site-to-site mode
# state as they exist BEFORE this run makes any changes, so --revert can
# restore them later rather than leaving the system on "dpd"/"on" forever.
ORIGINAL_TUNNEL_HEALTH_MODE="$(echo "${SHOW_CONFIG_OUTPUT}" | sed -n 's/.*tunnel-health-monitor-mode[[:space:]]*"\([^"]*\)".*/\1/p' | tail -n1)"
ORIGINAL_S2S_MODE="$(echo "${SHOW_CONFIG_OUTPUT}" | sed -n 's/.*vpn site-to-site mode[[:space:]]*"\([^"]*\)".*/\1/p' | tail -n1)"

# "tunnel-test" is a Check Point-proprietary tunnel health monitoring method
# that only works between two Check Point gateways. If it's already the
# configured method AND other VPN sites already exist on this system (which
# would depend on it), warn clearly before this script switches monitoring
# to "dpd" for the new SASE tunnels - "tunnel-test" is not supported for a
# non-Check-Point SASE peer.
OTHER_SITES_EXIST=false
if echo "${SHOW_CONFIG_OUTPUT}" | grep -q 'add vpn site name'; then
    OTHER_SITES_EXIST=true
fi

if [[ "$ORIGINAL_TUNNEL_HEALTH_MODE" == "tunnel-test" && "$OTHER_SITES_EXIST" == true ]]; then
    echo
    echo -e "${C_RED}${C_BOLD}Warning: incompatible tunnel health monitoring detected${C_RESET}"
    echo -e "${C_YELLOW}This system is currently using \"tunnel-test\" (Check Point-proprietary)"
    echo -e "tunnel health monitoring, and already has other VPN site(s) configured that"
    echo -e "may depend on it. \"tunnel-test\" only works between two Check Point gateways"
    echo -e "and is not supported for the SASE tunnels this script creates.${C_RESET}"
    echo -e "${C_YELLOW}Continuing will switch tunnel health monitoring to \"dpd\" (a standard,"
    echo -e "vendor-neutral method), which may change monitoring behavior for any"
    echo -e "existing tunnels as well. This will be restored to \"tunnel-test\" if you"
    echo -e "later run this script with --revert.${C_RESET}"
    echo
    read -rp "Continue and switch tunnel health monitoring to \"dpd\"? [y/N]: " HEALTH_MODE_CONFIRM
    if [[ ! "$HEALTH_MODE_CONFIRM" =~ ^[Yy]$ ]]; then
        echo "Aborted by user."
        log_msg "Run aborted by user: existing tunnel-test monitoring incompatible with other configured sites."
        exit 0
    fi
    log_msg "User confirmed switching tunnel health monitoring from tunnel-test to dpd despite other existing sites."
fi

log_msg "Original tunnel-health-monitor-mode=${ORIGINAL_TUNNEL_HEALTH_MODE:-none}, original site-to-site mode=${ORIGINAL_S2S_MODE:-none}, other sites exist=${OTHER_SITES_EXIST}"

log_msg "Gateway ID=${GATEWAY_ID}, next site num=${NEXT_SITE_NUM}, next VTI id=${NEXT_VTI_ID}, next policy id=${NEXT_POLICY_ID}, access rule exists=${ACCESS_RULE_EXISTS}"

# Build the set of IPv4 addresses already in use on this system (interface
# addresses plus existing VTI tunnel local/remote endpoints), so newly
# entered VTI IPs can be checked for conflicts before they're applied.
EXISTING_IPS_LIST="$(echo "${SHOW_CONFIG_OUTPUT}" | grep -oE '(ipv4-address|local|remote) "[0-9]{1,3}(\.[0-9]{1,3}){3}"' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sort -u || true)"

# Returns 0 (true) if the given IP already exists on the system, or matches
# a VTI IP already entered earlier in this same run.
ip_in_use() {
    local ip="$1"
    if [[ -n "$EXISTING_IPS_LIST" ]] && grep -qx "$ip" <<< "$EXISTING_IPS_LIST"; then
        return 0
    fi
    local existing
    for existing in "${VTI_REMOTE_IPS[@]:-}" "${VTI_LOCAL_IPS[@]:-}"; do
        [[ -n "$existing" && "$existing" == "$ip" ]] && return 0
    done
    return 1
}

# Prints the actual show-configuration line(s) referencing the given IP, so
# the user can identify exactly what still holds onto it (e.g. a leftover
# "add vpn tunnel" object left behind by only partially removing a VTI by
# hand) rather than just being told it's "in use" with no further detail.
show_ip_conflict_source() {
    local ip="$1"
    local matches
    matches="$(echo "${SHOW_CONFIG_OUTPUT}" | grep -F "\"${ip}\"" || true)"
    if [[ -n "$matches" ]]; then
        echo "  This IP appears in the current configuration here:"
        echo "$matches" | sed 's/^/    /'
    fi
}
echo

# ---------------------------------------------------------------------------
# 1. Local BGP AS number (shared) - defaults to 65000, or reused if the user
#    chose to keep the existing one found on this system
# ---------------------------------------------------------------------------
if [[ "$ROUTING_MODE" == "auto" && -n "$EXISTING_LOCAL_AS" ]]; then
    LOCAL_AS="$EXISTING_LOCAL_AS"
    echo "Using existing local BGP AS number: ${LOCAL_AS}"
else
    while true; do
        read -rp "Enter BGP AS number for the local Spark gateway [default: 65000]: " LOCAL_AS_INPUT
        if [[ -z "$LOCAL_AS_INPUT" ]]; then
            LOCAL_AS=65000
            break
        fi
        if is_valid_asn "$LOCAL_AS_INPUT"; then
            LOCAL_AS="$LOCAL_AS_INPUT"
            break
        fi
        echo "Error: please enter a valid AS number (1-4294967295), or leave blank for the default."
    done
fi

# ---------------------------------------------------------------------------
# 2. SASE BGP AS number (shared, required)
# This is always entered fresh - it is never auto-populated from an existing
# remote AS, since the existing config may belong to a different SASE
# tenant/deployment than the one being configured now.
# ---------------------------------------------------------------------------
while true; do
    while true; do
        read -rp "Enter the SASE BGP AS number [default: 64512]: " SASE_AS_INPUT
        if [[ -z "$SASE_AS_INPUT" ]]; then
            SASE_AS=64512
            break
        fi
        if is_valid_asn "$SASE_AS_INPUT"; then
            SASE_AS="$SASE_AS_INPUT"
            break
        fi
        echo "Error: please enter a valid AS number (1-4294967295), or leave blank for the default."
    done

    # Same AS on both sides is unusual for external BGP peering and is often
    # a copy-paste mistake, so flag it (without hard-blocking, since some
    # valid lab/testing setups do intentionally reuse the same AS). If the
    # user doesn't confirm, re-prompt for the SASE AS rather than aborting.
    if [[ "$LOCAL_AS" == "$SASE_AS" ]]; then
        echo -e "${C_YELLOW}Warning: the local BGP AS (${LOCAL_AS}) and SASE BGP AS (${SASE_AS}) are the same number.${C_RESET}"
        read -rp "This is unusual for external BGP peering - continue anyway? [y/N]: " AS_MATCH_CONFIRM
        if [[ ! "$AS_MATCH_CONFIRM" =~ ^[Yy]$ ]]; then
            log_msg "User declined matching local/SASE AS numbers (${LOCAL_AS}); re-prompting."
            echo "Please re-enter the SASE BGP AS number."
            echo
            continue
        fi
        log_msg "User confirmed proceeding with matching local/SASE AS numbers (${LOCAL_AS})."
    fi
    break
done

# Track whether this run is the one introducing the local AS number and/or
# the SASE remote-as group for the first time, so --revert can safely remove
# them later without disturbing something that already existed beforehand.
LOCAL_AS_IS_NEW=false
[[ -z "$EXISTING_LOCAL_AS" ]] && LOCAL_AS_IS_NEW=true

REMOTE_AS_IS_NEW=true
if [[ -n "$EXISTING_REMOTE_AS_LIST" ]] && grep -qx "$SASE_AS" <<< "$EXISTING_REMOTE_AS_LIST"; then
    REMOTE_AS_IS_NEW=false
fi

log_msg "Local AS=${LOCAL_AS} (new=${LOCAL_AS_IS_NEW}), SASE AS=${SASE_AS} (new=${REMOTE_AS_IS_NEW})"
echo

# ---------------------------------------------------------------------------
# 3. Per-gateway collection: public IP, PSK, VTI remote IP, local VTI IP
# ---------------------------------------------------------------------------
SASE_GW_IPS=()
PSKS=()
VTI_REMOTE_IPS=()
VTI_LOCAL_IPS=()

for ((g = 1; g <= GW_COUNT; g++)); do
    echo -e "${C_BOLD}--- SASE Gateway ${g} of ${GW_COUNT} ---${C_RESET}"

    while true; do
        prompt_ipv4 "  Enter the public IP address of this SASE gateway" SASE_GW_IP_INPUT false
        DUPLICATE_GW_IP=false
        for existing_gw_ip in "${SASE_GW_IPS[@]:-}"; do
            if [[ -n "$existing_gw_ip" && "$existing_gw_ip" == "$SASE_GW_IP_INPUT" ]]; then
                DUPLICATE_GW_IP=true
                break
            fi
        done
        if [[ "$DUPLICATE_GW_IP" == true ]]; then
            echo "  Error: \"${SASE_GW_IP_INPUT}\" was already entered for another gateway above. Each SASE gateway must have a unique public IP - a duplicate here will cause failures later. Please enter a different IP."
            continue
        fi
        if confirm_if_private_ip "$SASE_GW_IP_INPUT" "a SASE gateway's public IP"; then
            break
        fi
    done
    SASE_GW_IPS+=("$SASE_GW_IP_INPUT")

    while true; do
        read -rsp "  Enter the Pre-Shared Secret Key for this tunnel: " PSK_INPUT
        echo
        if [[ -z "$PSK_INPUT" ]]; then
            echo "  Error: the Pre-Shared Secret Key cannot be empty. Please try again."
            continue
        fi
        if [[ "$PSK_INPUT" == *'"'* || "$PSK_INPUT" == *'\'* ]]; then
            echo "  Error: the Pre-Shared Secret Key cannot contain a double-quote (\") or backslash (\\) character. Please try again."
            continue
        fi
        read -rsp "  Confirm the Pre-Shared Secret Key: " PSK_CONFIRM_INPUT
        echo
        if [[ "$PSK_INPUT" != "$PSK_CONFIRM_INPUT" ]]; then
            echo "  Error: Pre-Shared Secret Key entries did not match. Please try again."
            echo
            continue
        fi
        if [[ "${#PSK_INPUT}" -lt 8 ]]; then
            read -rp "  Warning: this key is shorter than 8 characters. Use it anyway? [y/N]: " short_psk_confirm
            if [[ ! "$short_psk_confirm" =~ ^[Yy]$ ]]; then
                continue
            fi
        fi
        PSKS+=("$PSK_INPUT")
        break
    done

    prompt_ipv4 "  Enter the VTI remote IP (Check Point SASE Gateway Internal IP)" VTI_REMOTE_INPUT true
    VTI_REMOTE_IPS+=("$VTI_REMOTE_INPUT")

    SUGGESTED_LOCAL_VTI="$(suggest_local_vti "$VTI_REMOTE_INPUT")"
    prompt_ipv4 "  Enter the local VTI IP address for this tunnel" VTI_LOCAL_INPUT true "$SUGGESTED_LOCAL_VTI"
    VTI_LOCAL_IPS+=("$VTI_LOCAL_INPUT")

    log_msg "Gateway ${g}: public_ip=${SASE_GW_IP_INPUT}, vti_remote=${VTI_REMOTE_INPUT}, vti_local=${VTI_LOCAL_INPUT} (PSK redacted)"

    echo
done

# ---------------------------------------------------------------------------
# Data local to the Spark appliance - collected ONCE, shared across all tunnels
# ---------------------------------------------------------------------------
echo -e "${C_BOLD}--- Local Spark Gateway Settings (shared by all tunnels) ---${C_RESET}"

# Try to find the public IP already configured on the "Internet1" WAN
# connection, so it can be offered as a default rather than requiring the
# user to look it up and retype it.
SUGGESTED_SPARK_IP="$(echo "${SHOW_CONFIG_OUTPUT}" | grep -i 'Internet1' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | head -n1 || true)"
if [[ -n "$SUGGESTED_SPARK_IP" ]]; then
    log_msg "Found candidate Spark public IP from Internet1 connection: ${SUGGESTED_SPARK_IP}"
else
    log_msg "No IP found for an Internet1 connection in show configuration output."
fi

while true; do
    prompt_ipv4 "Enter the public IP address of the locally managed Spark gateway" SPARK_GW_IP false "$SUGGESTED_SPARK_IP"
    if confirm_if_private_ip "$SPARK_GW_IP" "the Spark gateway's public IP"; then
        break
    fi
done
log_msg "Spark gateway public IP=${SPARK_GW_IP}"

echo

# ---------------------------------------------------------------------------
# Which local interfaces/networks should be advertised (redistributed) to
# the SASE gateway(s) over BGP - all interfaces, one or more specific
# interfaces, or one or more manually specified CIDR networks.
#
# "All interfaces" advertises exactly the interfaces listed above (each as
# its own "from interface" redistribution entry) - never the excluded
# WAN/Internet or VTI tunnel interfaces, and never a blanket "interface all"
# that could sweep those back in. The blanket command is only used as a
# last-resort fallback if no interfaces could be discovered at all.
#
# VLAN sub-interfaces (e.g. "DMZ.10" for VLAN 10 on interface DMZ) are
# discovered the same way as physical interfaces, since Check Point Spark
# configures their IP the same way ("set interface <name> ipv4-address ...")
# - the only difference is VLANs may specify their mask via "mask-length"
# (a prefix, e.g. 24) rather than "subnet-mask" (dotted-decimal), which is
# handled below.
# ---------------------------------------------------------------------------
echo -e "${C_BOLD}--- Route Advertisement to SASE ---${C_RESET}"

# Discover configured interfaces and their IPv4 addresses from the running
# configuration, excluding:
#   - VTI tunnel interfaces (vpnt*), since those are point-to-point tunnel
#     links, not LAN networks worth advertising
#   - Any Internet/WAN connection, whether it shows up in "show configuration"
#     under its own connection name (e.g. "Internet1") or under the physical
#     interface name it's bound to (e.g. "WAN"), since advertising a WAN
#     uplink to the SASE gateway would never be correct
INTERNET_CONN_NAMES="$(echo "${SHOW_CONFIG_OUTPUT}" | sed -n 's/.*internet-connection name "\?\([^" ]*\)"\?.*/\1/p' | sort -u || true)"
INTERNET_BOUND_IFACES="$(echo "${SHOW_CONFIG_OUTPUT}" | sed -n 's/.*internet-connection name "\?[^" ]*"\? interface "\?\([^" ]*\)"\?.*/\1/p' | sort -u || true)"
INTERNET_IFACE_NAMES="$(printf '%s\n%s\n' "${INTERNET_CONN_NAMES}" "${INTERNET_BOUND_IFACES}" | sed '/^$/d' | sort -u || true)"

INTERFACE_NAMES=()
INTERFACE_IPS=()
INTERFACE_NETWORKS=()

# Capture each interface's IP and subnet mask independently (rather than
# requiring both on the same line in a fixed order), then join them by
# interface name - this is more robust to formatting differences in
# "show configuration" output across appliance versions.
declare -A IFACE_IP_BY_NAME
declare -A IFACE_MASK_BY_NAME
IFACE_ORDER=()

while IFS=' ' read -r iface_name iface_ip; do
    [[ -z "$iface_name" ]] && continue
    if [[ -z "${IFACE_IP_BY_NAME[$iface_name]:-}" ]]; then
        IFACE_ORDER+=("$iface_name")
    fi
    IFACE_IP_BY_NAME["$iface_name"]="$iface_ip"
done <<< "$(echo "${SHOW_CONFIG_OUTPUT}" | sed -n 's/.*set interface "\([^"]*\)" ipv4-address "\([0-9]\{1,3\}\(\.[0-9]\{1,3\}\)\{3\}\)".*/\1 \2/p' | awk '!seen[$1]++' || true)"

while IFS=' ' read -r iface_name iface_mask; do
    [[ -z "$iface_name" ]] && continue
    IFACE_MASK_BY_NAME["$iface_name"]="$iface_mask"
done <<< "$(echo "${SHOW_CONFIG_OUTPUT}" | sed -n 's/.*set interface "\([^"]*\)".*subnet-mask "\([0-9]\{1,3\}\(\.[0-9]\{1,3\}\)\{3\}\)".*/\1 \2/p' | awk '!seen[$1]++' || true)"

# Some interface types (notably VLAN sub-interfaces, e.g. "DMZ.10" for VLAN
# 10 on interface DMZ) are configured with "mask-length" <prefix> instead of
# "subnet-mask" <dotted-decimal>. Only fill this in for interfaces that
# don't already have a subnet-mask captured above.
while IFS=' ' read -r iface_name iface_prefix; do
    [[ -z "$iface_name" ]] && continue
    [[ -n "${IFACE_MASK_BY_NAME[$iface_name]:-}" ]] && continue
    [[ "$iface_prefix" =~ ^[0-9]{1,2}$ ]] || continue
    [ "$iface_prefix" -ge 0 ] && [ "$iface_prefix" -le 32 ] || continue
    IFACE_MASK_BY_NAME["$iface_name"]="$(prefix_to_mask "$iface_prefix")"
done <<< "$(echo "${SHOW_CONFIG_OUTPUT}" | sed -n 's/.*set interface "\([^"]*\)".*mask-length "\?\([0-9]\{1,2\}\)"\?.*/\1 \2/p' | awk '!seen[$1]++' || true)"

for iface_name in "${IFACE_ORDER[@]}"; do
    [[ "$iface_name" == vpnt* ]] && continue

    if [[ -n "$INTERNET_IFACE_NAMES" ]] && grep -qx "$iface_name" <<< "$INTERNET_IFACE_NAMES"; then
        log_msg "Excluding Internet/WAN-backed interface from advertisement list: ${iface_name}"
        continue
    fi
    # Fallback: also exclude by name pattern, in case this system's
    # "show configuration" doesn't expose the internet-connection
    # binding in a form the parsing above can match.
    if [[ "$iface_name" =~ ^[Ii]nternet[0-9]*$ || "$iface_name" =~ ^WAN[0-9]*$ ]]; then
        log_msg "Excluding likely Internet/WAN interface by name pattern: ${iface_name}"
        continue
    fi

    iface_ip="${IFACE_IP_BY_NAME[$iface_name]}"
    iface_mask="${IFACE_MASK_BY_NAME[$iface_name]:-}"

    INTERFACE_NAMES+=("$iface_name")
    INTERFACE_IPS+=("$iface_ip")
    if [[ -n "$iface_mask" ]] && is_valid_ipv4 "$iface_mask"; then
        INTERFACE_NETWORKS+=("$(network_from_ip_and_mask "$iface_ip" "$iface_mask")")
    else
        # Couldn't determine the mask for this interface - fall back to
        # showing the host IP rather than guessing at a network.
        INTERFACE_NETWORKS+=("${iface_ip} (mask unknown)")
    fi
done

echo "Select which local interface(s) should be advertised to the SASE gateway(s) over BGP:"
for i in "${!INTERFACE_NAMES[@]}"; do
    printf "  %d) %s - %s\n" "$((i + 1))" "${INTERFACE_NAMES[$i]}" "${INTERFACE_NETWORKS[$i]}"
done
ALL_IFACE_OPTION=$(( ${#INTERFACE_NAMES[@]} + 1 ))
NETWORK_OPTION=$(( ${#INTERFACE_NAMES[@]} + 2 ))
echo "  ${ALL_IFACE_OPTION}) All interfaces"
echo "  ${NETWORK_OPTION}) Specify network(s) in CIDR format instead"

ADVERTISE_MODE=""
ADVERTISE_INTERFACES=()
ADVERTISE_NETWORKS=()

while true; do
    read -rp "Enter your choice (e.g. 1,3 for specific interfaces, ${ALL_IFACE_OPTION} for all, or ${NETWORK_OPTION} for networks): " ADV_INPUT
    ADV_INPUT="$(echo "$ADV_INPUT" | tr -d '[:space:]')"

    if [[ "$ADV_INPUT" == "$ALL_IFACE_OPTION" ]]; then
        if [ "${#INTERFACE_NAMES[@]}" -gt 0 ]; then
            # "All" means all interfaces printed above - build the same
            # per-interface redistribution as if every number had been
            # selected, so excluded WAN/VTI interfaces are never included.
            ADVERTISE_MODE="interfaces"
            ADVERTISE_INTERFACES=("${INTERFACE_NAMES[@]}")
        else
            # No interfaces were discovered to enumerate individually - fall
            # back to the blanket "from interface all" command as a last resort.
            ADVERTISE_MODE="all"
        fi
        break
    fi

    if [[ "$ADV_INPUT" == "$NETWORK_OPTION" ]]; then
        ADVERTISE_MODE="networks"
        break
    fi

    IFS=',' read -ra ADV_CHOICES <<< "$ADV_INPUT"
    ADV_VALID=true
    ADVERTISE_INTERFACES=()
    if [ "${#ADV_CHOICES[@]}" -eq 0 ] || [ "${#INTERFACE_NAMES[@]}" -eq 0 ]; then
        ADV_VALID=false
    fi
    for choice in "${ADV_CHOICES[@]}"; do
        if [[ ! "$choice" =~ ^[0-9]{1,9}$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "${#INTERFACE_NAMES[@]}" ]; then
            ADV_VALID=false
            break
        fi
        ADVERTISE_INTERFACES+=("${INTERFACE_NAMES[$((choice - 1))]}")
    done

    if [[ "$ADV_VALID" == true ]]; then
        ADVERTISE_MODE="interfaces"
        break
    fi

    echo "Error: please enter a comma-separated list of interface numbers (1-${#INTERFACE_NAMES[@]}), ${ALL_IFACE_OPTION} for all interfaces, or ${NETWORK_OPTION} to specify networks."
done

if [[ "$ADVERTISE_MODE" == "networks" ]]; then
    # BGP "aggregate" redistribution requires the network to already exist
    # as a pre-configured aggregate route ("set aggregate <prefix> ...") -
    # Check Point will not create one on the fly, and will fail at
    # execution time with "Unable to redistribute an Aggregate Route that
    # is not already configured." Build the set of what's already
    # configured so each entry can be validated up front instead.
    EXISTING_AGGREGATES="$(echo "${ROUTER_CONFIG_OUTPUT}" | sed -n 's/.*set aggregate "\?\([0-9]\{1,3\}\(\.[0-9]\{1,3\}\)\{3\}\/[0-9]\{1,2\}\)"\?.*/\1/p' | sort -u || true)"

    if [[ -z "$EXISTING_AGGREGATES" ]]; then
        echo -e "${C_YELLOW}Warning: no pre-configured aggregate routes (\"set aggregate ...\") were found"
        echo -e "on this system. BGP can only redistribute a network via \"aggregate\" if it has"
        echo -e "already been configured as one - this script will not create it for you, since"
        echo -e "that requires choices (contributing protocol, contributing route, etc.) only"
        echo -e "you can make correctly for your topology.${C_RESET}"
        echo -e "${C_YELLOW}Configure the aggregate route(s) first (see Check Point's \"Configuring Route"
        echo -e "Aggregation\" guide), then re-run this script - or choose interface-based"
        echo -e "advertisement instead.${C_RESET}"
        echo
    fi

    while true; do
        read -rp "Enter network(s) to advertise in CIDR format, comma separated (e.g. 10.0.0.0/24,192.168.1.0/24): " NET_INPUT
        IFS=',' read -ra NET_CHOICES <<< "$NET_INPUT"
        NET_VALID=true
        ADVERTISE_NETWORKS=()
        if [ "${#NET_CHOICES[@]}" -eq 0 ]; then
            NET_VALID=false
        fi
        for net_raw in "${NET_CHOICES[@]}"; do
            net_entry="$(echo "$net_raw" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
            if [[ ! "$net_entry" =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/([0-9]{1,2})$ ]]; then
                echo "Error: \"$net_entry\" is not in the format A.B.C.D/prefix (e.g. 10.0.0.0/24). Please try again."
                NET_VALID=false
                break
            fi
            net_addr="${BASH_REMATCH[1]}"
            net_prefix="${BASH_REMATCH[2]}"
            if ! is_valid_ipv4 "$net_addr"; then
                echo "Error: \"$net_addr\" is not a valid IPv4 address. Please try again."
                NET_VALID=false
                break
            fi
            if [ "$net_prefix" -lt 0 ] || [ "$net_prefix" -gt 32 ]; then
                echo "Error: prefix \"/$net_prefix\" in \"$net_entry\" must be between /0 and /32. Please try again."
                NET_VALID=false
                break
            fi
            if [[ -z "$EXISTING_AGGREGATES" ]] || ! grep -qx "$net_entry" <<< "$EXISTING_AGGREGATES"; then
                echo "Error: \"$net_entry\" is not configured as an aggregate route on this system yet (checked \"show router-configuration\")."
                echo "  Configure it first with: set aggregate ${net_entry} contributing protocol <protocol> contributing-route all on"
                echo "  Then re-run this script, or choose a different, already-configured network."
                NET_VALID=false
                break
            fi
            ADVERTISE_NETWORKS+=("$net_entry")
        done
        if [[ "$NET_VALID" == true ]]; then
            break
        fi
    done
fi

case "$ADVERTISE_MODE" in
    all)
        log_msg "Route advertisement: all interfaces"
        ;;
    interfaces)
        log_msg "Route advertisement: specific interfaces ($(IFS=,; echo "${ADVERTISE_INTERFACES[*]}"))"
        ;;
    networks)
        log_msg "Route advertisement: specific networks ($(IFS=,; echo "${ADVERTISE_NETWORKS[*]}"))"
        ;;
esac
echo

# Assign site names and VTI IDs/interfaces per gateway now that we know
# where to safely start numbering from.
SITE_NAMES=()
VTI_IDS=()
VTI_IFACES=()
for ((i = 0; i < GW_COUNT; i++)); do
    SITE_NAMES+=("SASE$((NEXT_SITE_NUM + i))")
    VTI_IDS+=("$((NEXT_VTI_ID + i))")
    VTI_IFACES+=("vpnt$((NEXT_VTI_ID + i))")
done

# Host objects representing each SASE gateway's VTI remote IP, used to
# restrict the BGP access rule's source to just these peers instead of
# "any". Named after the site they belong to. If an object with the exact
# same name already exists (e.g. from a prior run), it is reused rather
# than re-created, and left alone on --revert.
HOST_OBJ_NAMES=()
HOST_OBJ_CREATED=()
for ((i = 0; i < GW_COUNT; i++)); do
    host_name="${SITE_NAMES[$i]}_VTI_Remote"
    HOST_OBJ_NAMES+=("$host_name")
    if echo "${SHOW_CONFIG_OUTPUT}" | grep -q "add host name \"${host_name}\""; then
        HOST_OBJ_CREATED+=("false")
    else
        HOST_OBJ_CREATED+=("true")
    fi
done

echo
echo -e "${C_BOLD}=== Collected values ===${C_RESET}"
echo "Local BGP AS (shared)       : ${LOCAL_AS}"
echo "SASE BGP AS (shared)        : ${SASE_AS}"
echo "Inbound route filter policy : ${NEXT_POLICY_ID}"
case "$ADVERTISE_MODE" in
    all)
        echo "Route advertisement        : all interfaces"
        ;;
    interfaces)
        echo "Route advertisement        : interface(s) $(IFS=,; echo "${ADVERTISE_INTERFACES[*]}")"
        ;;
    networks)
        echo "Route advertisement        : network(s) $(IFS=,; echo "${ADVERTISE_NETWORKS[*]}")"
        ;;
esac
if [[ "$ACCESS_RULE_EXISTS" == true ]]; then
    echo "Access rule \"SASE_BGP_ALLOW\": already exists - will not be re-created"
else
    echo "Access rule \"SASE_BGP_ALLOW\": will be created"
fi
for ((i = 0; i < GW_COUNT; i++)); do
    echo "Tunnel ${SITE_NAMES[$i]} (VTI ${VTI_IDS[$i]} / ${VTI_IFACES[$i]}):"
    echo "  SASE Gateway IP  : ${SASE_GW_IPS[$i]}"
    echo "  VTI remote IP    : ${VTI_REMOTE_IPS[$i]}"
    echo "  VTI local IP     : ${VTI_LOCAL_IPS[$i]}"
    if [[ "${HOST_OBJ_CREATED[$i]}" == true ]]; then
        echo "  Host object      : \"${HOST_OBJ_NAMES[$i]}\" (will be created)"
    else
        echo "  Host object      : \"${HOST_OBJ_NAMES[$i]}\" (already exists - will be reused)"
    fi
    echo "  Pre-Shared Secret: (hidden)"
done
echo "Spark Gateway IP (shared)   : ${SPARK_GW_IP}"
echo "Gateway ID (shared, found)  : ${GATEWAY_ID}"
if [[ -n "$ORIGINAL_TUNNEL_HEALTH_MODE" ]]; then
    echo "Tunnel health monitoring    : ${ORIGINAL_TUNNEL_HEALTH_MODE} -> dpd (will be restored to ${ORIGINAL_TUNNEL_HEALTH_MODE} on --revert)"
else
    echo "Tunnel health monitoring    : none -> dpd (fresh system, nothing to restore on --revert)"
fi
echo
read -rp "Proceed with applying this configuration? (y/N): " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Aborted by user."
    log_msg "Run aborted by user at final confirmation prompt."
    exit 0
fi
echo

log_msg "User confirmed configuration. Local AS=${LOCAL_AS}, SASE AS=${SASE_AS}, tunnels=${GW_COUNT}, policy ID=${NEXT_POLICY_ID}"
{
    echo "--- Collected configuration summary ---"
    echo "Local BGP AS (shared)       : ${LOCAL_AS}"
    echo "SASE BGP AS (shared)        : ${SASE_AS}"
    for ((i = 0; i < GW_COUNT; i++)); do
        echo "Tunnel ${SITE_NAMES[$i]} (VTI ${VTI_IDS[$i]}): gw=${SASE_GW_IPS[$i]} remote_vti=${VTI_REMOTE_IPS[$i]} local_vti=${VTI_LOCAL_IPS[$i]} (PSK redacted)"
    done
    echo "Spark Gateway IP (shared) : ${SPARK_GW_IP}"
    echo "Gateway ID (shared)       : ${GATEWAY_ID}"
    echo "----------------------------------------------------------------"
} >> "$LOG_FILE"

# ---------------------------------------------------------------------------
# Write a rollback manifest describing exactly what THIS run is about to
# create, so it can later be undone with: ./create_sase_vpn.sh --revert
# This is written before execution so even a partially-failed run leaves a
# manifest matching what was attempted. No secrets are included.
# ---------------------------------------------------------------------------
MANIFEST_FILE="${LOG_DIR}/sase_vpn_manifest_${TIMESTAMP}.conf"
{
    echo "# SASE VPN rollback manifest - created $(date)"
    echo "LOCAL_AS=${LOCAL_AS}"
    echo "SASE_AS=${SASE_AS}"
    echo "LOCAL_AS_IS_NEW=${LOCAL_AS_IS_NEW}"
    echo "REMOTE_AS_IS_NEW=${REMOTE_AS_IS_NEW}"
    echo "NEXT_POLICY_ID=${NEXT_POLICY_ID}"
    echo "ADVERTISE_MODE=${ADVERTISE_MODE}"
    ( IFS=','; echo "ADVERTISE_INTERFACES=${ADVERTISE_INTERFACES[*]}" )
    ( IFS=','; echo "ADVERTISE_NETWORKS=${ADVERTISE_NETWORKS[*]}" )
    echo "ORIGINAL_TUNNEL_HEALTH_MODE=${ORIGINAL_TUNNEL_HEALTH_MODE}"
    echo "ORIGINAL_S2S_MODE=${ORIGINAL_S2S_MODE}"
    echo "ACCESS_RULE_CREATED=$([[ "$ACCESS_RULE_EXISTS" == true ]] && echo false || echo true)"
    echo "GATEWAY_ID=${GATEWAY_ID}"
    ( IFS=','; echo "SITE_NAMES=${SITE_NAMES[*]}" )
    ( IFS=','; echo "SASE_GW_IPS=${SASE_GW_IPS[*]}" )
    ( IFS=','; echo "VTI_IDS=${VTI_IDS[*]}" )
    ( IFS=','; echo "VTI_REMOTE_IPS=${VTI_REMOTE_IPS[*]}" )
    ( IFS=','; echo "HOST_OBJ_NAMES=${HOST_OBJ_NAMES[*]}" )
    ( IFS=','; echo "HOST_OBJ_CREATED=${HOST_OBJ_CREATED[*]}" )
} > "$MANIFEST_FILE"
log_msg "Rollback manifest written to: ${MANIFEST_FILE}"
echo -e "${C_BOLD}A rollback manifest was saved to:${C_RESET} ${MANIFEST_FILE}"
echo -e "${C_BOLD}To undo this configuration later, run:${C_RESET} $0 --revert \"${MANIFEST_FILE}\""
echo

# ---------------------------------------------------------------------------
# Build the list of clish commands
# ---------------------------------------------------------------------------
COMMANDS=()
DESCRIPTIONS=()
STEP_GROUPS=()

# --- Host objects for each SASE gateway's VTI remote IP (used to restrict
# the BGP access rule's source instead of "any") ---
for ((i = 0; i < GW_COUNT; i++)); do
    host_name="${HOST_OBJ_NAMES[$i]}"
    if [[ "${HOST_OBJ_CREATED[$i]}" == true ]]; then
        COMMANDS+=("add host name \"${host_name}\" ipv4-address \"${VTI_REMOTE_IPS[$i]}\"")
        DESCRIPTIONS+=("Creating host object \"${host_name}\" (${VTI_REMOTE_IPS[$i]})")
        STEP_GROUPS+=("Creating host objects for BGP access rule")
    fi
done

# --- Shared access rule allowing BGP (once, if not already present),
# restricted to the SASE gateways' VTI remote IPs rather than "any" ---
if [[ "$ACCESS_RULE_EXISTS" != true ]]; then
    COMMANDS+=("add access-rule type incoming-internal-and-vpn action \"accept\" name \"SASE_BGP_ALLOW\" new-name \"SASE_BGP_ALLOW\" log \"none\" source \"${HOST_OBJ_NAMES[0]}\" source-negate \"false\" destination-negate \"false\" service \"BGP\" service-negate \"false\" app-and-service-negate \"false\" disabled \"false\" comment \"Generated rule: Access policy for BGP\" hours-range-enabled \"false\" position \"1\" destination-updatable-object vpn \"clear-and-encrypted\"")
    DESCRIPTIONS+=("Creating access rule \"SASE_BGP_ALLOW\" to allow BGP from ${HOST_OBJ_NAMES[0]}")
    STEP_GROUPS+=("Creating access rule for BGP")

    # Any additional gateways beyond the first must be added to the rule
    # afterward - "add access-rule" only accepts a single source object.
    for ((i = 1; i < GW_COUNT; i++)); do
        COMMANDS+=("set access-rule type incoming-internal-and-vpn name \"SASE_BGP_ALLOW\" add source \"${HOST_OBJ_NAMES[$i]}\"")
        DESCRIPTIONS+=("Adding ${HOST_OBJ_NAMES[$i]} as an allowed BGP source")
        STEP_GROUPS+=("Creating access rule for BGP")
    done
else
    # The rule already existed - add all of this run's gateways as
    # additional sources rather than creating a new rule.
    for ((i = 0; i < GW_COUNT; i++)); do
        COMMANDS+=("set access-rule type incoming-internal-and-vpn name \"SASE_BGP_ALLOW\" add source \"${HOST_OBJ_NAMES[$i]}\"")
        DESCRIPTIONS+=("Adding ${HOST_OBJ_NAMES[$i]} as an allowed BGP source (existing rule)")
        STEP_GROUPS+=("Creating access rule for BGP")
    done
fi

# --- Per-tunnel VPN site + route-based VTI configuration ---
for ((i = 0; i < GW_COUNT; i++)); do
    site="${SITE_NAMES[$i]}"
    gwip="${SASE_GW_IPS[$i]}"
    psk="${PSKS[$i]}"
    vti_id="${VTI_IDS[$i]}"
    iface="${VTI_IFACES[$i]}"
    remote_vti="${VTI_REMOTE_IPS[$i]}"
    local_vti="${VTI_LOCAL_IPS[$i]}"
    pool="$(vti_pool_range "$remote_vti" "$local_vti")"

    COMMANDS+=("add vpn site name \"${site}\" remote-site-link-selection \"ip-address\" remote-site-ip-address \"${gwip}\" is-site-behind-static-nat \"false\" auth-method \"preshared-secret\" password \"${psk}\" enabled \"true\" origin \"none\" remote-site-enc-dom-type \"route-based-vpn\" enc-profile \"custom\" phase1-reneg-interval \"1440\" phase2-reneg-interval \"3600\" enable-perfect-forward-secrecy \"true\" phase2-dh \"Group14\" is-check-point-site \"false\" disable-nat \"true\" internet-traffic-through-this-gw \"false\" aggressive-mode-enabled \"false\" ike-v2-use-identifiers \"true\" ike-v2-peer-id \"${gwip}\" gateway-id-source \"override-global-identifier\" ike-v2-gateway-id-override \"${SPARK_GW_IP}\" enc-method \"ike-v2\" use-trusted-ca \"anyCa\" match-cert-ip \"false\" match-cert-dn \"false\" match-cert-e-mail \"false\" link-selection-probing-method \"ongoing\"")
    DESCRIPTIONS+=("[${site}] Creating VPN site \"${site}\"")
    STEP_GROUPS+=("[${site}] Creating VPN site")

    COMMANDS+=("set vpn site \"${site}\" remove-all remote-site-enc-dom-network-obj")
    DESCRIPTIONS+=("[${site}] Clearing encryption domain (route-based)")
    STEP_GROUPS+=("[${site}] Creating VPN site")

    COMMANDS+=("set vpn site \"${site}\" remove-all custom-enc-phase1-auth add \"SHA256\"")
    DESCRIPTIONS+=("[${site}] Setting Phase 1 authentication (SHA256)")
    STEP_GROUPS+=("[${site}] Creating VPN site")

    COMMANDS+=("set vpn site \"${site}\" remove-all custom-enc-phase1-dh-group add \"Group14\"")
    DESCRIPTIONS+=("[${site}] Setting Phase 1 Diffie-Hellman group (Group14)")
    STEP_GROUPS+=("[${site}] Creating VPN site")

    COMMANDS+=("set vpn site \"${site}\" remove-all custom-enc-phase2-enc add \"AES-256\"")
    DESCRIPTIONS+=("[${site}] Setting Phase 2 encryption (AES-256)")
    STEP_GROUPS+=("[${site}] Creating VPN site")

    COMMANDS+=("set vpn site \"${site}\" remove-all custom-enc-phase1-enc add \"AES-256\"")
    DESCRIPTIONS+=("[${site}] Setting Phase 1 encryption (AES-256)")
    STEP_GROUPS+=("[${site}] Creating VPN site")

    COMMANDS+=("set vpn site \"${site}\" remove-all remote-site-enc-dom-route-excluded-network-obj")
    DESCRIPTIONS+=("[${site}] Clearing excluded encryption domain routes")
    STEP_GROUPS+=("[${site}] Creating VPN site")

    COMMANDS+=("set vpn site \"${site}\" remove-all link-selection-multiple-addrs addr")
    DESCRIPTIONS+=("[${site}] Clearing link selection multiple addresses")
    STEP_GROUPS+=("[${site}] Creating VPN site")

    COMMANDS+=("set vpn site \"${site}\" remove-all custom-enc-phase2-auth add \"SHA256\"")
    DESCRIPTIONS+=("[${site}] Setting Phase 2 authentication (SHA256)")
    STEP_GROUPS+=("[${site}] Creating VPN site")

    COMMANDS+=("set vpn site \"${site}\" enabled \"true\" origin \"none\" remote-site-enc-dom-type \"route-based-vpn\" enc-profile \"custom\" phase1-reneg-interval \"1440\" phase2-reneg-interval \"3600\" enable-perfect-forward-secrecy \"true\" phase2-dh \"Group14\" is-check-point-site \"false\" disable-nat \"true\" internet-traffic-through-this-gw \"false\" aggressive-mode-enabled \"false\" aggressive-mode-enable-peer-id \"false\" ike-v2-use-identifiers \"true\" ike-v2-peer-id \"${gwip}\" gateway-id-source \"override-global-identifier\" ike-v2-gateway-id-override \"${SPARK_GW_IP}\" enc-method \"ike-v2\" use-trusted-ca \"anyCa\" match-cert-ip \"false\" match-cert-dn \"false\" match-cert-e-mail \"false\" link-selection-probing-method \"ongoing\" name \"${site}\" remote-site-link-selection \"ip-address\" remote-site-ip-address \"${gwip}\" is-site-behind-static-nat \"false\" auth-method \"preshared-secret\" password \"${psk}\" link-selection-primary-addr \"none\"")
    DESCRIPTIONS+=("[${site}] Finalizing VPN site \"${site}\" configuration")
    STEP_GROUPS+=("[${site}] Creating VPN site")

    # --- Route-based VTI tunnel + interface (peer name matches ${site}) ---
    COMMANDS+=("add vpn tunnel \"${vti_id}\" type \"numbered\" local \"${local_vti}\" remote \"${remote_vti}\" peer \"${site}\"")
    DESCRIPTIONS+=("[${site}] Creating VTI tunnel ${vti_id} (${iface}), peer=\"${site}\"")
    STEP_GROUPS+=("[${site}] Creating VTI tunnel")

    COMMANDS+=("set interface \"${iface}\" ipv4-address \"${local_vti}\" subnet-mask \"255.255.255.255\"")
    DESCRIPTIONS+=("[${site}] Setting ${iface} IPv4 address")
    STEP_GROUPS+=("[${site}] Creating VTI tunnel")

    COMMANDS+=("set interface \"${iface}\" ipv4-address \"${local_vti}\" mask-length \"32\" cluster-status \"non-ha\"")
    DESCRIPTIONS+=("[${site}] Setting ${iface} mask-length / cluster status")
    STEP_GROUPS+=("[${site}] Creating VTI tunnel")

    COMMANDS+=("set interface \"${iface}\" mtu \"1500\" 802dot1x-authentication \"off\" 802dot1x-re-authentication-frequency \"0\" lan-mac-filtering \"on\"")
    DESCRIPTIONS+=("[${site}] Setting ${iface} MTU and 802.1x options")
    STEP_GROUPS+=("[${site}] Creating VTI tunnel")

    COMMANDS+=("set dhcp server interface \"${iface}\" dns \"auto\"")
    DESCRIPTIONS+=("[${site}] Setting ${iface} DHCP DNS to auto")
    STEP_GROUPS+=("[${site}] Creating VTI tunnel")

    COMMANDS+=("set interface \"${iface}\" exclude-from-dns-proxy \"off\" enable-device-recognition \"true\" enable-iot-discovery \"true\"")
    DESCRIPTIONS+=("[${site}] Setting ${iface} DNS proxy / device recognition options")
    STEP_GROUPS+=("[${site}] Creating VTI tunnel")

    COMMANDS+=("set dhcp server interface \"${iface}\" assign-addresses-for-known-hosts-only \"off\"")
    DESCRIPTIONS+=("[${site}] Setting ${iface} DHCP known-hosts option")
    STEP_GROUPS+=("[${site}] Creating VTI tunnel")

    COMMANDS+=("set dhcp server interface \"${iface}\" include-ip-pool \"${pool}\"")
    DESCRIPTIONS+=("[${site}] Setting ${iface} DHCP pool (${pool})")
    STEP_GROUPS+=("[${site}] Creating VTI tunnel")

    COMMANDS+=("set dhcp server interface \"${iface}\" lease-time \"4\"")
    DESCRIPTIONS+=("[${site}] Setting ${iface} DHCP lease time")
    STEP_GROUPS+=("[${site}] Creating VTI tunnel")

    COMMANDS+=("set interface \"${iface}\" hotspot \"off\"")
    DESCRIPTIONS+=("[${site}] Disabling hotspot on ${iface}")
    STEP_GROUPS+=("[${site}] Creating VTI tunnel")
done

# --- Shared BGP configuration (once, covering all tunnels) ---
COMMANDS+=("set as ${LOCAL_AS}")
DESCRIPTIONS+=("Setting local BGP AS number to ${LOCAL_AS}")
STEP_GROUPS+=("Configuring BGP routing")

COMMANDS+=("set bgp external remote-as ${SASE_AS} on")
DESCRIPTIONS+=("Enabling BGP external remote-as ${SASE_AS}")
STEP_GROUPS+=("Configuring BGP routing")

for ((i = 0; i < GW_COUNT; i++)); do
    site="${SITE_NAMES[$i]}"
    remote_vti="${VTI_REMOTE_IPS[$i]}"

    COMMANDS+=("set bgp external remote-as ${SASE_AS} peer ${remote_vti} on")
    DESCRIPTIONS+=("[${site}] Enabling BGP peer ${remote_vti}")
    STEP_GROUPS+=("Configuring BGP routing")

    COMMANDS+=("set bgp external remote-as ${SASE_AS} peer ${remote_vti} multihop on")
    DESCRIPTIONS+=("[${site}] Enabling BGP multihop for peer ${remote_vti}")
    STEP_GROUPS+=("Configuring BGP routing")

    COMMANDS+=("set bgp external remote-as ${SASE_AS} peer ${remote_vti} graceful-restart on")
    DESCRIPTIONS+=("[${site}] Enabling BGP graceful-restart for peer ${remote_vti}")
    STEP_GROUPS+=("Configuring BGP routing")
done

COMMANDS+=("set inbound-route-filter bgp-policy ${NEXT_POLICY_ID} based-on-as as ${SASE_AS} on")
DESCRIPTIONS+=("Enabling inbound route filter (policy ${NEXT_POLICY_ID}) based on AS ${SASE_AS}")
STEP_GROUPS+=("Configuring BGP routing")

COMMANDS+=("set inbound-route-filter bgp-policy ${NEXT_POLICY_ID} accept-all-ipv4")
DESCRIPTIONS+=("Accepting all IPv4 routes on the inbound route filter")
STEP_GROUPS+=("Configuring BGP routing")

case "$ADVERTISE_MODE" in
    all)
        COMMANDS+=("set route-redistribution to bgp-as ${SASE_AS} from interface all on")
        DESCRIPTIONS+=("Enabling route redistribution to BGP AS ${SASE_AS} from all interfaces")
        STEP_GROUPS+=("Configuring BGP routing")
        ;;
    interfaces)
        for adv_iface in "${ADVERTISE_INTERFACES[@]}"; do
            COMMANDS+=("set route-redistribution to bgp-as ${SASE_AS} from interface \"${adv_iface}\" on")
            DESCRIPTIONS+=("Enabling route redistribution to BGP AS ${SASE_AS} from interface ${adv_iface}")
            STEP_GROUPS+=("Configuring BGP routing")
        done
        ;;
    networks)
        for adv_net in "${ADVERTISE_NETWORKS[@]}"; do
            COMMANDS+=("set route-redistribution to bgp-as ${SASE_AS} from aggregate ${adv_net} on")
            DESCRIPTIONS+=("Enabling route redistribution to BGP AS ${SASE_AS} from network ${adv_net}")
            STEP_GROUPS+=("Configuring BGP routing")
        done
        ;;
esac

# --- Apply the site-to-site VPN configuration ---
COMMANDS+=("set vpn site-to-site mode \"on\" default-access-to-lan \"accept\" track \"log\" local-encryption-domain \"auto\" source-ip-address-selection \"automatically\" outgoing-interface-selection \"routing-table\" tunnel-health-monitor-mode \"dpd\" ike-v2-global-gateway-id \"${GATEWAY_ID}\"")
DESCRIPTIONS+=("Enabling site-to-site VPN with DPD monitoring")
STEP_GROUPS+=("Enabling site-to-site VPN")

# ---------------------------------------------------------------------------
# Execute everything currently in COMMANDS/DESCRIPTIONS/STEP_GROUPS, grouped
# by on-screen phase, with a spinner and full logging. Shared by both the
# normal creation flow and the --revert flow.
# ---------------------------------------------------------------------------
execute_command_groups

echo
echo -e "${C_BOLD}Reminder - to undo this configuration later, run:${C_RESET}"
echo -e "  $0 --revert \"${MANIFEST_FILE}\""

# ---------------------------------------------------------------------------
# Post-run health check. Tunnels and BGP peering take time to establish, so
# this is offered as a separate, explicit step rather than being run
# immediately - the user can check back once the estimated wait has passed.
# See run_health_check_dashboard() for what the dashboard itself does.
# ---------------------------------------------------------------------------
echo
echo -e "${C_BOLD}--- Configuration Health Check ---${C_RESET}"
echo "It can take approximately 5 minutes for all tunnels and BGP peering to"
echo "fully establish after this script completes. This check refreshes every"
echo "10 seconds and stops automatically once everything is healthy."
echo
read -rp "Would you like to run a health check of the configuration now? (y/N): " HEALTHCHECK_CONFIRM
if [[ ! "$HEALTHCHECK_CONFIRM" =~ ^[Yy]$ ]]; then
    log_msg "User declined the post-run health check."
    exit 0
fi
log_msg "User requested the post-run health check (live dashboard, 10s refresh)."

run_health_check_dashboard
