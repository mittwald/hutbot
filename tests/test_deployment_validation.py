import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _helm_template_command(tag):
    return [
        "helm", "template", "hutbot", str(ROOT / "charts/hutbot"),
        "--show-only", "templates/deployment.yaml",
        "--set", f"image.tag={tag}",
        "--set", "networkPolicy.rules[0].port=443",
        "--set-string", "networkPolicy.rules[0].cidrs[0]=0.0.0.0/0",
    ]


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
