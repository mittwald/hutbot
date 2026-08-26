import shutil
import subprocess
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
# The Secret is managed out of band, so the chart refuses to render without a name for it.
SECRET_NAME = "hutbot-test"

# CI runs a bare `python -m pytest`, so the chart tests only run where helm is installed.
pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")


def _helm_template_command(tag, *extra, show_only="templates/deployment.yaml"):
    command = [
        "helm", "template", "hutbot", str(ROOT / "charts/hutbot"),
        "--set", f"image.tag={tag}",
        "--set", f"existingSecret={SECRET_NAME}",
    ]
    if show_only:
        command += ["--show-only", show_only]
    return command + list(extra)


def _render(tag="v1.2.3", *extra, show_only="templates/deployment.yaml"):
    return subprocess.run(
        _helm_template_command(tag, *extra, show_only=show_only),
        cwd=ROOT, capture_output=True, text=True, check=False,
    )


@pytest.mark.parametrize("script", ["deploy-dev.sh", "deploy-prod.sh"])
@pytest.mark.parametrize("tag", ["latest", "main", "MAIN"])
def test_deploy_scripts_reject_floating_tags(script, tag):
    result = subprocess.run(
        [str(ROOT / script), tag],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "must be pinned" in result.stderr


@pytest.mark.parametrize("tag", ["latest", "main", "MAIN"])
def test_chart_rejects_floating_tags(tag):
    result = subprocess.run(
        _helm_template_command(tag),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "floating tags" in result.stderr


def test_chart_accepts_pinned_tag():
    result = subprocess.run(
        _helm_template_command("v1.2.3"),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "image: \"hutbot:v1.2.3\"" in result.stdout


def test_chart_forces_timezone_and_default_locale_when_set():
    result = subprocess.run(
        _helm_template_command("v1.2.3") + [
            "--set", "time.timezone=Europe/Berlin",
            "--set", "time.locale=de_DE",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "- name: TZ\n              value: \"Europe/Berlin\"" in result.stdout
    assert "- name: HUTBOT_DEFAULT_DATETIME_LOCALE\n              value: \"de_DE\"" in result.stdout


def test_chart_omits_timezone_and_locale_by_default():
    result = subprocess.run(
        _helm_template_command("v1.2.3"),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "name: TZ" not in result.stdout
    assert "HUTBOT_DEFAULT_DATETIME_LOCALE" not in result.stdout


def test_chart_passes_the_image_tag_as_the_bot_version():
    result = subprocess.run(
        _helm_template_command("v1.2.3"),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "- name: HUTBOT_VERSION\n              value: \"v1.2.3\"" in result.stdout


# ----- the Secret is managed out of band -----

def test_chart_requires_an_existing_secret():
    """No fallback that templates the credentials back into the release."""
    result = subprocess.run(
        ["helm", "template", "hutbot", str(ROOT / "charts/hutbot"), "--set", "image.tag=v1.2.3"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )

    assert result.returncode != 0
    assert "existingSecret is required" in result.stderr


def test_chart_has_no_secret_template():
    result = _render(show_only="templates/secret.yaml")

    assert result.returncode != 0
    assert "could not find template" in result.stderr


def test_chart_never_renders_a_secret_of_its_own():
    result = _render(show_only=None)

    assert result.returncode == 0, result.stderr
    assert "kind: Secret" not in result.stdout
    assert "stringData" not in result.stdout


def test_deployment_reads_the_out_of_band_secret():
    result = _render()

    assert result.returncode == 0, result.stderr
    assert f"- secretRef:\n                name: {SECRET_NAME}" in result.stdout
    assert "hutbot-secret" not in result.stdout


def test_deployment_recreates_rather_than_rolls():
    """A rolling restart would run two bots against one ReadWriteOnce volume."""
    result = _render()

    assert result.returncode == 0, result.stderr
    assert "type: Recreate" in result.stdout


# ----- egress policy -----

def _egress(result):
    return yaml.safe_load(result.stdout)["spec"]["egress"]


def test_chart_renders_without_any_networkpolicy_values():
    """values.yaml carries the defaults, so a plain render needs no --set placeholders."""
    result = _render(show_only="templates/networkpolicy.yaml")

    assert result.returncode == 0, result.stderr
    assert _egress(result)


def test_egress_pairs_a_rules_ports_with_its_destinations():
    """Two items — ports here, destinations there — would mean "this port to anywhere"."""
    result = _render("v1.2.3",
                     "--set", "networkPolicy.rules[0].port=443",
                     "--set-string", "networkPolicy.rules[0].cidrs[0]=192.168.0.15/32",
                     "--set-string", "networkPolicy.rules[0].cidrs[1]=192.168.0.16/32",
                     show_only="templates/networkpolicy.yaml")

    assert result.returncode == 0, result.stderr
    rule = next(item for item in _egress(result)
                if item.get("to") == [{"ipBlock": {"cidr": "192.168.0.15/32"}},
                                      {"ipBlock": {"cidr": "192.168.0.16/32"}}])
    assert rule["ports"] == [{"port": 443, "protocol": "TCP"}]
    # Nothing else may carry those ports, and no item may name that port without a destination.
    assert [item for item in _egress(result) if item.get("ports") == rule["ports"]] == [rule]


def test_egress_allows_dns_and_every_public_destination():
    """Slack Socket Mode and public feeds must keep working without a rule per host."""
    result = _render(show_only="templates/networkpolicy.yaml")

    assert result.returncode == 0, result.stderr
    egress = _egress(result)
    dns = next(item for item in egress if "to" not in item)
    assert dns["ports"] == [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]
    public = next(item for item in egress
                  if item.get("to", [{}])[0].get("ipBlock", {}).get("cidr") == "0.0.0.0/0")
    # No `ports`: all outbound ports to public destinations.
    assert "ports" not in public
    assert public["to"][0]["ipBlock"]["except"] == [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]
    # DNS is the only item allowed to name ports without a destination.
    assert [item for item in egress if "to" not in item] == [dns]


def test_egress_can_drop_dns_and_public_destinations():
    result = _render("v1.2.3",
                     "--set", "networkPolicy.allowDNS=false",
                     "--set", "networkPolicy.publicEgress.enabled=false",
                     "--set", "networkPolicy.rules[0].port=443",
                     "--set-string", "networkPolicy.rules[0].cidrs[0]=192.168.0.15/32",
                     show_only="templates/networkpolicy.yaml")

    assert result.returncode == 0, result.stderr
    assert _egress(result) == [{"to": [{"ipBlock": {"cidr": "192.168.0.15/32"}}],
                               "ports": [{"port": 443, "protocol": "TCP"}]}]


def test_a_policy_that_allows_nothing_is_refused():
    """`enabled` with no rule of any kind denies all egress — almost never the intent."""
    result = _render("v1.2.3",
                     "--set", "networkPolicy.allowDNS=false",
                     "--set", "networkPolicy.publicEgress.enabled=false",
                     show_only="templates/networkpolicy.yaml")

    assert result.returncode != 0
    assert "would deny all egress" in result.stderr


def test_a_rule_without_a_destination_is_refused():
    result = _render("v1.2.3", "--set", "networkPolicy.rules[0].port=443",
                    show_only="templates/networkpolicy.yaml")

    assert result.returncode != 0
    assert "needs at least one entry in cidrs" in result.stderr


# ----- built-in calendars are mounted as a file -----

def _deployment(result):
    return yaml.safe_load(result.stdout)


def _container(result):
    return _deployment(result)["spec"]["template"]["spec"]["containers"][0]


def test_builtin_calendars_are_projected_as_one_file():
    result = _render()
    assert result.returncode == 0, result.stderr
    container = _container(result)
    spec = _deployment(result)["spec"]["template"]["spec"]

    assert {"name": "HUTBOT_BUILTIN_CALENDARS_FILE",
            "value": "/etc/hutbot/builtin-calendars.json"} in container["env"]
    volume = next(v for v in spec["volumes"] if v["name"] == "builtin-calendars")
    assert volume["secret"]["secretName"] == SECRET_NAME
    # A instance with no built-in calendars must still start.
    assert volume["secret"]["optional"] is True
    assert volume["secret"]["defaultMode"] == 0o440
    assert volume["secret"]["items"] == [{"key": "HUTBOT_BUILTIN_CALENDARS",
                                          "path": "builtin-calendars.json"}]
    mount = next(m for m in container["volumeMounts"] if m["name"] == "builtin-calendars")
    assert mount["mountPath"] == "/etc/hutbot" and mount["readOnly"] is True


def test_the_builtin_calendar_mount_can_be_switched_off():
    result = _render("v1.2.3", "--set", "builtinCalendars.mountFile=false")

    assert result.returncode == 0, result.stderr
    assert "HUTBOT_BUILTIN_CALENDARS_FILE" not in result.stdout
    assert "builtin-calendars" not in result.stdout


def test_the_builtin_calendar_mount_survives_persistence_being_off():
    result = _render("v1.2.3", "--set", "persistence.enabled=false")

    assert result.returncode == 0, result.stderr
    spec = _deployment(result)["spec"]["template"]["spec"]
    assert [v["name"] for v in spec["volumes"]] == ["builtin-calendars"]
    assert [m["name"] for m in spec["containers"][0]["volumeMounts"]] == ["builtin-calendars"]


def test_the_builtin_calendar_mount_must_not_shadow_the_data_volume():
    result = _render("v1.2.3", "--set", "builtinCalendars.mountPath=/data")

    assert result.returncode != 0
    assert "must differ from persistence.mountPath" in result.stderr


# ----- scripts/sync-secret.sh -----

SYNC_SECRET = ROOT / "scripts/sync-secret.sh"
VAULT_JSON = {
    "SLACK_APP_TOKEN": "xapp-1-abc",
    "SLACK_BOT_TOKEN": "xoxb-2-def",
    "OPSGENIE_TOKEN": "og-token",
}


def _stub(directory, name, body):
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(0o755)
    return path


def _stub_cluster(tmp_path, vault_fields=None, live_secret=None, context="coabkube-prod"):
    """A PATH holding fake `kubectl` and `vault`, plus the file recording kubectl's argv."""
    import json as _json

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True)
    calls = tmp_path / "kubectl-calls"
    vault_payload = _json.dumps({"data": {"data": VAULT_JSON if vault_fields is None else vault_fields}})
    secret_payload = _json.dumps({"data": live_secret or {}})
    _stub(bin_dir, "vault", f'''
if [[ "$1 $2" == "kv get" ]]; then
  cat <<'JSON'
{vault_payload}
JSON
  exit 0
fi
exit 0
''')
    _stub(bin_dir, "kubectl", f'''
printf '%s\\n' "$*" >> {calls}
case "$*" in
  "config current-context") echo "{context}" ;;
  *"get secret"*"-o json"*) cat <<'JSON'
{secret_payload}
JSON
    ;;
  *"get secret"*"jsonpath"*) echo -n "" ;;
  *"get secret"*) exit 0 ;;
esac
exit 0
''')
    return bin_dir, calls


def _run_sync(tmp_path, *args, vault_fields=None, live_secret=None, context="coabkube-prod", env=None):
    bin_dir, calls = _stub_cluster(tmp_path, vault_fields, live_secret, context)
    import os

    environment = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    environment.update(env or {})
    result = subprocess.run([str(SYNC_SECRET), *args], cwd=ROOT, capture_output=True, text=True,
                            check=False, env=environment)
    result.kubectl_calls = calls.read_text() if calls.exists() else ""
    return result


def test_sync_secret_writes_every_known_key_without_putting_a_value_in_argv(tmp_path):
    result = _run_sync(tmp_path)

    assert result.returncode == 0, result.stderr
    assert "Secret mw-internal/hutbot synced." in result.stdout
    assert "--from-literal" not in result.kubectl_calls
    for value in VAULT_JSON.values():
        assert value not in result.kubectl_calls
        assert value not in result.stdout


def test_sync_secret_refuses_a_foreign_kube_context(tmp_path):
    result = _run_sync(tmp_path, context="some-other-cluster")

    assert result.returncode != 0
    assert "refusing to run" in result.stderr


def test_sync_secret_rejects_a_key_that_cannot_be_a_variable(tmp_path):
    result = _run_sync(tmp_path, vault_fields={**VAULT_JSON, "my.key": "x"})

    assert result.returncode != 0
    assert "not a usable environment variable name" in result.stderr


def test_sync_secret_requires_both_slack_tokens(tmp_path):
    result = _run_sync(tmp_path, vault_fields={"OPSGENIE_TOKEN": "og"})

    assert result.returncode != 0
    assert "SLACK_APP_TOKEN" in result.stderr


def test_sync_secret_rejects_a_null_field(tmp_path):
    """`jq -j` renders a JSON null as the four bytes "null", which must not become a token."""
    result = _run_sync(tmp_path, vault_fields={**VAULT_JSON, "SLACK_BOT_TOKEN": None})

    assert result.returncode != 0
    assert "SLACK_BOT_TOKEN is empty" in result.stderr


def test_sync_secret_skips_an_empty_optional_field(tmp_path):
    result = _run_sync(tmp_path, "--dry-run",
                       vault_fields={**VAULT_JSON, "OPSGENIE_HEARTBEAT_NAME": ""})

    assert result.returncode == 0, result.stderr
    assert "OPSGENIE_HEARTBEAT_NAME is empty; leaving it out" in result.stdout
    assert "OPSGENIE_HEARTBEAT_NAME" not in result.stdout.split("==> keys:")[1].splitlines()[0]


def test_sync_secret_ignores_a_field_hutbot_does_not_read(tmp_path):
    result = _run_sync(tmp_path, "--dry-run", vault_fields={**VAULT_JSON, "NETWORKPOLICY_RULES": "443:0.0.0.0/0"})

    assert result.returncode == 0, result.stderr
    assert "NETWORKPOLICY_RULES is not a key hutbot reads" in result.stderr


def test_sync_secret_refuses_to_drop_a_key_the_live_secret_has(tmp_path):
    """A `vault kv put` replaces the whole version; that must not silently retire a key."""
    live = {"SLACK_APP_TOKEN": "eA==", "SLACK_BOT_TOKEN": "eA==", "EMPLOYEE_LIST_PASSWORD": "eA=="}
    result = _run_sync(tmp_path, "--dry-run", live_secret=live)

    assert result.returncode != 0
    assert "would REMOVE" in result.stderr and "EMPLOYEE_LIST_PASSWORD" in result.stderr

    allowed = _run_sync(tmp_path / "allowed", "--dry-run", "--allow-drop", live_secret=live)
    assert allowed.returncode == 0, allowed.stderr


def test_sync_secret_rejects_a_malformed_builtin_calendar_list(tmp_path):
    import json as _json

    payloads = [
        '{}',
        _json.dumps([{"name": "rota", "title": "R", "url": "http://cal.example.com/x.ics"}]),
        _json.dumps([{"name": "Rota", "title": "R", "url": "https://cal.example.com/x.ics"}]),
        _json.dumps([{"name": "rota", "title": "", "url": "https://cal.example.com/x.ics"}]),
        _json.dumps([{"name": "rota", "title": "A", "url": "https://a/x.ics"},
                     {"name": "rota", "title": "B", "url": "https://b/x.ics"}]),
    ]
    for index, payload in enumerate(payloads):
        result = _run_sync(tmp_path / f"case{index}", "--dry-run",
                           vault_fields={**VAULT_JSON, "HUTBOT_BUILTIN_CALENDARS": payload})
        assert result.returncode != 0, payload
        assert "HUTBOT_BUILTIN_CALENDARS" in result.stderr or "built-in calendar" in result.stderr


def test_sync_secret_names_the_builtin_calendar_feed_hosts(tmp_path):
    import json as _json

    payload = _json.dumps([{"name": "rota", "title": "Rota",
                            "url": "https://cal.example.com/SECRETTOKEN/rota.ics"}])
    result = _run_sync(tmp_path, "--dry-run",
                       vault_fields={**VAULT_JSON, "HUTBOT_BUILTIN_CALENDARS": payload})

    assert result.returncode == 0, result.stderr
    # The host has to be checked against the egress allow-list; the token stays unprinted.
    assert "cal.example.com" in result.stdout and "SECRETTOKEN" not in result.stdout


def test_sync_secret_dry_run_writes_nothing(tmp_path):
    result = _run_sync(tmp_path, "--dry-run")

    assert result.returncode == 0, result.stderr
    assert "dry run: nothing was written." in result.stdout
    assert "apply" not in result.kubectl_calls


@pytest.mark.parametrize("script", ["deploy-dev.sh", "deploy-prod.sh"])
def test_deploy_scripts_require_the_secret(tmp_path, script):
    import os

    bin_dir, _ = _stub_cluster(tmp_path)
    _stub(bin_dir, "kubectl", '''
[[ "$*" == "config current-context" ]] && { echo coabkube-prod; exit 0; }
[[ "$*" == *"get secret"* ]] && exit 1
exit 0
''')
    _stub(bin_dir, "helmfile", "exit 0\n")
    result = subprocess.run([str(ROOT / script), "-y", "v1.2.3"], cwd=ROOT, capture_output=True,
                            text=True, check=False,
                            env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"})

    assert result.returncode != 0
    assert "not found" in result.stderr and "sync it first" in result.stderr


# ----- scripts/seed-vault.sh -----

SEED_VAULT = ROOT / "scripts/seed-vault.sh"
ENV_FILE = """export SLACK_APP_TOKEN='xapp-secretapp'
export SLACK_BOT_TOKEN='xoxb-secretbot'
export OPSGENIE_TOKEN='og-secret'
export OPSGENIE_HEARTBEAT_NAME=''
export EMPLOYEE_LIST_USERNAME='employee-user'
export EMPLOYEE_LIST_PASSWORD='employee-pass'
export NETWORKPOLICY_RULES='443:192.168.0.15/32'
"""


def _run_seed(tmp_path, *args, existing=None, env_file=ENV_FILE):
    """Run the seeder against a stub `vault` that records its argv and the payload it got."""
    import json as _json
    import os

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True)
    state = tmp_path / "vault-state.json"
    state.write_text(_json.dumps({"data": {"data": existing or {}}}))
    calls = tmp_path / "vault-calls"
    payload = tmp_path / "payload.json"
    _stub(bin_dir, "vault", f'''
printf '%s\\n' "$*" >> {calls}
if [[ "$1 $2" == "kv get" ]]; then cat {state}; fi
if [[ "$1 $2" == "kv put" ]]; then cp "${{4#@}}" {payload}; fi
exit 0
''')
    path = tmp_path / "env"
    path.write_text(env_file)
    result = subprocess.run([str(SEED_VAULT), "--env", "dev", "--env-file", str(path), *args],
                            cwd=ROOT, capture_output=True, text=True, check=False,
                            env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"})
    result.vault_calls = calls.read_text() if calls.exists() else ""
    result.payload = _json.loads(payload.read_text()) if payload.exists() else None
    return result


def test_seed_vault_writes_only_the_secret_keys(tmp_path):
    result = _run_seed(tmp_path)

    assert result.returncode == 0, result.stderr
    # Deploy settings from the same env file are no secrets and stay out of Vault.
    assert set(result.payload) == {"SLACK_APP_TOKEN", "SLACK_BOT_TOKEN", "OPSGENIE_TOKEN",
                                  "EMPLOYEE_LIST_USERNAME", "EMPLOYEE_LIST_PASSWORD"}
    assert result.payload["SLACK_BOT_TOKEN"] == "xoxb-secretbot"
    # An empty optional field is left unset rather than stored as "".
    assert "OPSGENIE_HEARTBEAT_NAME" not in result.payload


def test_seed_vault_never_puts_a_value_on_the_command_line(tmp_path):
    result = _run_seed(tmp_path)

    assert result.returncode == 0, result.stderr
    assert "kv put secrets-coabkube/production/hutbot-dev @" in result.vault_calls
    for value in ("xoxb-secretbot", "xapp-secretapp", "og-secret", "employee-pass"):
        assert value not in result.vault_calls
        assert value not in result.stdout


def test_seed_vault_refuses_a_path_that_already_has_fields(tmp_path):
    """A put replaces the whole version, so seeding over a live path would drop fields."""
    result = _run_seed(tmp_path, existing={"SLACK_APP_TOKEN": "x", "OPSGENIE_TOKEN": "y"})

    assert result.returncode != 0
    assert "already has fields" in result.stderr and "vault kv patch" in result.stderr
    assert result.payload is None

    forced = _run_seed(tmp_path / "forced", "--force",
                       existing={"SLACK_APP_TOKEN": "x", "OPSGENIE_TOKEN": "y"})
    assert forced.returncode == 0, forced.stderr


def test_seed_vault_requires_both_slack_tokens(tmp_path):
    env_file = "\n".join(line for line in ENV_FILE.splitlines() if "SLACK_BOT_TOKEN" not in line)
    result = _run_seed(tmp_path, env_file=env_file)

    assert result.returncode != 0
    assert "SLACK_BOT_TOKEN is not set" in result.stderr


def test_seed_vault_can_include_the_builtin_calendar_list(tmp_path):
    calendars = tmp_path / "calendars.json"
    calendars.write_text('[{"name":"rota","title":"Rota","url":"https://cal.example.com/T/rota.ics"}]')
    result = _run_seed(tmp_path, "--calendars", str(calendars))

    assert result.returncode == 0, result.stderr
    assert '"name":"rota"' in result.payload["HUTBOT_BUILTIN_CALENDARS"].replace(" ", "")


def test_seed_vault_rejects_a_malformed_builtin_calendar_list(tmp_path):
    calendars = tmp_path / "calendars.json"
    calendars.write_text('[{"name":"Rota","title":"Rota","url":"http://cal.example.com/x.ics"}]')
    result = _run_seed(tmp_path, "--calendars", str(calendars))

    assert result.returncode != 0
    assert "must be a JSON array" in result.stderr
    assert result.payload is None


def test_seed_vault_dry_run_writes_nothing(tmp_path):
    result = _run_seed(tmp_path, "--dry-run")

    assert result.returncode == 0, result.stderr
    assert "dry run: nothing was written." in result.stdout
    assert "kv put" not in result.vault_calls


# ----- scripts/edit-calendars.sh -----

EDIT_CALENDARS = ROOT / "scripts/edit-calendars.sh"
CALENDARS_JSON = ('[{"name":"notfallhotline","title":"Notfallhotline",'
                  '"url":"https://bridge.example.com/calendars/notfallhotline.ics?token=SECRETTOKEN"}]')


def _run_edit_calendars(tmp_path, state, edit=CALENDARS_JSON, *args):
    """Run the editor flow against a stub `vault` and a non-interactive $EDITOR."""
    import json as _json
    import os

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True)
    state_file = tmp_path / "vault-state.json"
    state_file.write_text(_json.dumps(state))
    calls = tmp_path / "vault-calls"
    payload = tmp_path / "payload.json"
    _stub(bin_dir, "vault", f'''
printf '%s\\n' "$*" >> {calls}
case "$1 $2" in
  "kv get") cat {state_file} ;;
  "kv put") cp "${{4#@}}" {payload} ;;
  "kv patch") cp "${{4#*=@}}" {payload} ;;
esac
exit 0
''')
    _stub(bin_dir, "fake-editor", f'''
cat > "$1" <<'JSON'
{edit}
JSON
''')
    result = subprocess.run([str(EDIT_CALENDARS), "--env", "dev", *args], cwd=ROOT,
                            capture_output=True, text=True, check=False,
                            env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}",
                                 "EDITOR": "fake-editor"})
    result.vault_calls = calls.read_text() if calls.exists() else ""
    result.payload = _json.loads(payload.read_text()) if payload.exists() else None
    return result


def test_edit_calendars_patches_a_v2_mount(tmp_path):
    state = {"data": {"data": {"SLACK_APP_TOKEN": "xapp-a"}, "metadata": {"version": 3}}}
    result = _run_edit_calendars(tmp_path, state)

    assert result.returncode == 0, result.stderr
    assert "kv patch" in result.vault_calls and "kv put" not in result.vault_calls
    # patch touches one field, so the payload is the list itself.
    assert result.payload[0]["name"] == "notfallhotline"


def test_edit_calendars_merges_the_other_fields_on_a_kv_v1_mount(tmp_path):
    """v1 has no `kv patch`, so a put has to carry every sibling field back."""
    state = {"data": {"SLACK_APP_TOKEN": "xapp-a", "SLACK_BOT_TOKEN": "xoxb-b",
                      "OPSGENIE_TOKEN": "og"}}
    result = _run_edit_calendars(tmp_path, state)

    assert result.returncode == 0, result.stderr
    assert "kv put" in result.vault_calls and "kv patch" not in result.vault_calls
    assert "KV v1 mount" in result.stderr
    assert set(result.payload) == {"SLACK_APP_TOKEN", "SLACK_BOT_TOKEN", "OPSGENIE_TOKEN",
                                   "HUTBOT_BUILTIN_CALENDARS"}
    assert result.payload["SLACK_BOT_TOKEN"] == "xoxb-b"
    assert "notfallhotline" in result.payload["HUTBOT_BUILTIN_CALENDARS"]


def test_edit_calendars_never_puts_a_value_on_the_command_line(tmp_path):
    result = _run_edit_calendars(tmp_path, {"data": {"SLACK_APP_TOKEN": "xapp-a"}})

    assert result.returncode == 0, result.stderr
    assert "SECRETTOKEN" not in result.vault_calls
    # The feed host is printed for the egress check; the token in its query string is not.
    assert "bridge.example.com" in result.stdout and "SECRETTOKEN" not in result.stdout


@pytest.mark.parametrize("edit", [
    '{"notfallhotline": "…"}',
    '[{"name":"Notfallhotline","title":"N","url":"https://bridge.example.com/x.ics"}]',
    '[{"name":"rota","title":"","url":"https://bridge.example.com/x.ics"}]',
    '[{"name":"rota","title":"R","url":"http://bridge.example.com/x.ics"}]',
])
def test_edit_calendars_refuses_to_write_an_invalid_list(tmp_path, edit):
    result = _run_edit_calendars(tmp_path, {"data": {"SLACK_APP_TOKEN": "xapp-a"}}, edit)

    assert result.returncode != 0
    assert result.payload is None
    # The temp file is shredded on exit, so say plainly that the edit is gone.
    assert "was NOT saved" in result.stderr


def test_edit_calendars_writes_nothing_when_the_list_is_unchanged(tmp_path):
    state = {"data": {"HUTBOT_BUILTIN_CALENDARS": CALENDARS_JSON, "SLACK_APP_TOKEN": "xapp-a"}}
    result = _run_edit_calendars(tmp_path, state)

    assert result.returncode == 0, result.stderr
    assert "unchanged; nothing was written." in result.stdout
    assert "kv put" not in result.vault_calls and "kv patch" not in result.vault_calls


def test_edit_calendars_show_prints_the_current_list(tmp_path):
    state = {"data": {"HUTBOT_BUILTIN_CALENDARS": CALENDARS_JSON}}
    result = _run_edit_calendars(tmp_path, state, CALENDARS_JSON, "--show")

    assert result.returncode == 0, result.stderr
    assert "notfallhotline" in result.stdout
    assert "kv put" not in result.vault_calls


# ----- Makefile deploy guard -----

def _make(*args):
    return subprocess.run(["make", *args], cwd=ROOT, capture_output=True, text=True, check=False)


@pytest.mark.skipif(shutil.which("make") is None, reason="make is not installed")
def test_the_deploy_targets_default_to_the_newest_tag():
    """`make deploy-dev` with no IMAGE_TAG deploys the most recently cut release tag."""
    newest = subprocess.run(["git", "tag", "-l", "v[0-9]*", "--sort=-creatordate"],
                            cwd=ROOT, capture_output=True, text=True, check=False).stdout.split("\n")[0]
    if not newest:
        pytest.skip("no release tags in this clone")

    result = _make("-n", "deploy-dev")

    assert result.returncode == 0, result.stderr
    assert f'./deploy-dev.sh "{newest}"' in result.stdout


@pytest.mark.skipif(shutil.which("make") is None, reason="make is not installed")
def test_the_deploy_guard_refuses_an_empty_image_tag():
    """A clone without tags must not fall through to a deploy with no tag at all."""
    result = _make("require-image-tag", "IMAGE_TAG=")

    assert result.returncode != 0
    assert "no v* git tag found" in result.stderr


@pytest.mark.skipif(shutil.which("make") is None, reason="make is not installed")
def test_the_deploy_guard_warns_when_head_is_ahead_of_the_tag():
    first = subprocess.run(["git", "tag", "-l", "v[0-9]*", "--sort=creatordate"],
                           cwd=ROOT, capture_output=True, text=True, check=False).stdout.split("\n")[0]
    if not first:
        pytest.skip("no release tags in this clone")

    result = _make("require-image-tag", f"IMAGE_TAG={first}")

    assert result.returncode == 0, result.stderr
    assert "commit(s) ahead of" in result.stderr
