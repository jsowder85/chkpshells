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
#     2. SASE BGP AS number (defaults to 64515 if left blank; shared by all SASE peers)
#     3. Public IP of the locally managed Spark gateway (local)          -> ike-v2-gateway-id-override
#   Collected for EACH SASE gateway:
#     4. Public IP of that SASE gateway (remote peer)                    -> remote-site-ip-address / ike-v2-peer-id
#     5. Pre-Shared Secret Key (can differ per gateway)                  -> auth password
#     6. VTI remote IP (the peer's tunnel interface address)             -> vpn tunnel "remote"
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
# ---------------------------------------------------------------------------
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_CANDIDATES=("/var/log/sase_vpn" "/storage/sase_vpn" "/var/tmp/sase_vpn")
LOG_DIR=""
for candidate in "${LOG_CANDIDATES[@]}"; do
    if mkdir -p "$candidate" 2>/dev/null; then
        LOG_DIR="$candidate"
        break
    fi
done
if [[ -z "$LOG_DIR" ]]; then
    # Last resort so a run is never completely unlogged
    LOG_DIR="/tmp"
fi
LOG_FILE="${LOG_DIR}/sase_vpn_${TIMESTAMP}.log"
: > "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/sase_vpn_${TIMESTAMP}.log"

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
    local j cmd output status encoded attempt
    : > "$outfile"
    for ((j = start; j <= end; j++)); do
        cmd="${COMMANDS[$j]}"

        for attempt in 1 2 3; do
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
            # If we see this class of error, pause briefly and retry (up to
            # 3 attempts total) before giving up.
            if [[ "$attempt" -lt 3 ]] && [[ "$output" == *"There is no"*"with id"* || "$output" == *"does not exist"* || "$output" == *"not configured"* ]]; then
                sleep 2
                continue
            fi
            break
        done

        encoded="${output//$'\n'/\\n}"
        printf '%s\t%s\n' "$status" "$encoded" >> "$outfile"

        # After creating an inbound-route-filter bgp-policy, give it a flat
        # 15-second settle window before the next command (which configures
        # it further) runs.
        case "$cmd" in
            *"based-on-as as "*" on")
                sleep 15
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

            if [[ -n "$output" ]] && [[ "$output" == *"Could not"* || "$output" == *"Error"* || "$output" == *"error"* || "$r_status" -ne 0 ]]; then
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
            echo -e "        ${C_YELLOW}[WARN] completed with ${group_fail} issue(s) - see above${C_RESET}"
        fi
    done

    echo
    if [[ "$FAIL_COUNT" -eq 0 ]]; then
        echo -e "${C_GREEN}${C_BOLD}=== Operation complete (${TOTAL}/${TOTAL} steps succeeded) ===${C_RESET}"
    else
        echo -e "${C_YELLOW}${C_BOLD}=== Operation finished with ${FAIL_COUNT} issue(s) out of ${TOTAL} steps ===${C_RESET}"
    fi

    {
        echo "Run finished $(date)"
        echo "Result: ${TOTAL} total steps, $((TOTAL - FAIL_COUNT)) succeeded, ${FAIL_COUNT} reported issues"
    } >> "$LOG_FILE"

    echo -e "${C_BOLD}Full command output has been saved to:${C_RESET} ${LOG_FILE}"
}

log_msg "=== Run started ==="

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
if [[ "${1:-}" == "--revert" ]]; then
    REVERT_MANIFEST="${2:-}"

    if [[ -z "$REVERT_MANIFEST" ]]; then
        REVERT_MANIFEST="$(ls -t /var/log/sase_vpn/sase_vpn_manifest_*.conf /storage/sase_vpn/sase_vpn_manifest_*.conf /var/tmp/sase_vpn/sase_vpn_manifest_*.conf 2>/dev/null | head -n1 || true)"
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

echo -e "${C_BOLD}=== SASE Route-Based VPN + BGP Configuration ===${C_RESET}"
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
        [[ "$o" =~ ^[0-9]{1,3}$ ]] || return 1
        [ "$o" -ge 0 ] && [ "$o" -le 255 ] || return 1
    done
    return 0
}

# ---------------------------------------------------------------------------
# Helper: validate a BGP AS number
# ---------------------------------------------------------------------------
is_valid_asn() {
    local val=$1
    [[ "$val" =~ ^[0-9]+$ ]] || return 1
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
    else
        suggested=$((last - 1))
    fi
    (( suggested < 0 )) && suggested=0
    (( suggested > 255 )) && suggested=255
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
    if [[ "$GW_COUNT_INPUT" =~ ^[0-9]+$ ]] && [ "$GW_COUNT_INPUT" -ge 1 ] && [ "$GW_COUNT_INPUT" -le "$MAX_GATEWAYS" ]; then
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
            read -rp "Use the existing local BGP AS number shown above instead of entering a new one? [y/n]: " ROUTING_CHOICE
            case "${ROUTING_CHOICE,,}" in
                y|yes)
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
# Retrieve the running configuration once - used to auto-discover the
# ike-v2-global-gateway-id, to avoid creating duplicate objects (access
# rules, VPN sites, VTI tunnel IDs) on re-runs, and to detect IP addresses
# already in use on this system so newly entered VTI IPs can be checked
# for conflicts before they're applied.
# ---------------------------------------------------------------------------
echo "Retrieving current configuration (this may take a moment)..."
log_msg "Retrieving current configuration (show configuration)..."
SHOW_CONFIG_OUTPUT="$(clish -c "show configuration")"

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
        read -rp "Enter the SASE BGP AS number [default: 64515]: " SASE_AS_INPUT
        if [[ -z "$SASE_AS_INPUT" ]]; then
            SASE_AS=64515
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

    prompt_ipv4 "  Enter the VTI remote IP (the SASE gateway's tunnel interface address)" VTI_REMOTE_INPUT true
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
# the SASE gateway(s) over BGP - all interfaces (as before), one or more
# specific interfaces, or one or more manually specified CIDR networks.
# ---------------------------------------------------------------------------
echo -e "${C_BOLD}--- Route Advertisement to SASE ---${C_RESET}"

# Discover configured interfaces and their IPv4 addresses from the running
# configuration, excluding VTI tunnel interfaces (vpnt*) since those are
# point-to-point tunnel links, not LAN networks worth advertising.
INTERFACE_NAMES=()
INTERFACE_IPS=()
INTERFACE_LINES="$(echo "${SHOW_CONFIG_OUTPUT}" | sed -n 's/.*set interface "\([^"]*\)" ipv4-address "\([0-9]\{1,3\}\(\.[0-9]\{1,3\}\)\{3\}\)".*/\1 \2/p' | awk '!seen[$1]++' | grep -v '^vpnt' || true)"
if [[ -n "$INTERFACE_LINES" ]]; then
    while IFS=' ' read -r iface_name iface_ip; do
        [[ -z "$iface_name" ]] && continue
        INTERFACE_NAMES+=("$iface_name")
        INTERFACE_IPS+=("$iface_ip")
    done <<< "$INTERFACE_LINES"
fi

echo "Select which local interface(s) should be advertised to the SASE gateway(s) over BGP:"
for i in "${!INTERFACE_NAMES[@]}"; do
    printf "  %d) %s - %s\n" "$((i + 1))" "${INTERFACE_NAMES[$i]}" "${INTERFACE_IPS[$i]}"
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
        ADVERTISE_MODE="all"
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
        if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "${#INTERFACE_NAMES[@]}" ]; then
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
