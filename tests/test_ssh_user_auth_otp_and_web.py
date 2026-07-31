import asyncio
import os
import subprocess
import tempfile
import uuid
from base64 import b64decode
from pathlib import Path
from textwrap import dedent
from uuid import uuid4

import aiohttp
import pyotp
import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import alloc_port, wait_port


class Test:
    @pytest.mark.asyncio
    async def test_otp_and_web_auth(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        otp_key_base32: str,
        otp_key_base64: str,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_public_key_credential(
                user.id,
                sdk.NewPublicKeyCredential(
                    label="Public Key",
                    openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip(),
                ),
            )
            api.create_otp_credential(
                user.id,
                sdk.NewOtpCredential(secret_key=list(b64decode(otp_key_base64))),
            )
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.update_user(
                user.id,
                sdk.UserDataRequest(
                    username=user.username,
                    credential_policy=sdk.UserRequireCredentialsPolicy(
                        ssh=[
                            sdk.CredentialKind.PUBLICKEY,
                            sdk.CredentialKind.TOTP,
                            sdk.CredentialKind.WEBUSERAPPROVAL,
                        ],
                    ),
                ),
            )
            api.add_user_role(user.id, role.id)
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

        totp = pyotp.TOTP(otp_key_base32)

        # Temp files for signaling between the expect script and this async task.
        # round2_ready: expect writes this after seeing the round-2 "Press Enter" prompt.
        # web_approved: Python writes this after approving browser auth.
        tmpdir = Path(tempfile.mkdtemp())
        round2_ready_flag = tmpdir / "round2_ready"
        web_approved_flag = tmpdir / "web_approved"

        script = dedent(
            f"""
            set timeout {timeout - 5}

            spawn ssh {user.username}:{ssh_target.name}@localhost \
                -p {shared_wg.ssh_port} \
                -o StrictHostKeychecking=no \
                -o UserKnownHostsFile=/dev/null \
                -o IdentitiesOnly=yes \
                -o IdentityFile=ssh-keys/id_ed25519 \
                -o PreferredAuthentications=publickey,keyboard-interactive \
                ls /bin/sh

            # Round 1 — both OTP and web approval prompts must appear.
            expect "One-time password:"
            sleep 0.5
            send "{totp.now()}\\r"

            expect "Press Enter when done:"
            send "\\r"

            # Round 2 — only the web approval prompt must appear, NOT the OTP prompt.
            # Matching "One-time password:" here is a test failure (exit 10).
            expect {{
                "One-time password:" {{ exit 10 }}
                "Press Enter when done:" {{ }}
            }}

            # Signal Python that the round-2 prompt has been seen.
            set fh [open "{round2_ready_flag}" w]
            close $fh

            # Wait for Python to approve browser auth before sending Enter.
            while {{![file exists "{web_approved_flag}"]}} {{
                sleep 0.1
            }}

            send "\\r"

            expect {{
                "/bin/sh" {{ exit 0 }}
                eof {{ exit 1 }}
            }}
            """
        )

        # Log in via HTTP to establish a session that can approve web auth requests.
        session = aiohttp.ClientSession()
        try:
            headers = {"Host": f"localhost:{shared_wg.http_port}"}
            await session.post(
                f"{url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
                headers=headers,
                ssl=False,
            )
            ws = await session.ws_connect(
                url.replace("https:", "wss:") + "/@warpgate/api/auth/web-auth-requests/stream",
                ssl=False,
            )

            expect_proc = processes.start(
                ["expect"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # Write the script now so expect starts running immediately.
            # Null out stdin afterwards so communicate() doesn't try to flush
            # the already-closed pipe.
            expect_proc.stdin.write(script.encode())
            expect_proc.stdin.close()
            expect_proc.stdin = None

            # Receive the first web-auth notification (sent when round 1 starts).
            msg = await ws.receive(timeout)
            auth_id = msg.data

            # Poll until the expect script signals that the round-2 prompt is visible.
            while not round2_ready_flag.exists():
                await asyncio.sleep(0.1)

            # Verify the pending auth state before approving.
            auth_state_resp = await session.get(
                f"{url}/@warpgate/api/auth/state/{auth_id}", ssl=False
            )
            auth_state = await auth_state_resp.json()
            assert auth_state["protocol"] == "SSH"
            assert auth_state["state"] == "WebUserApprovalNeeded"

            # Approve browser auth.
            r = await session.post(
                f"{url}/@warpgate/api/auth/state/{auth_id}/approve", ssl=False
            )
            assert r.status == 200

            # Unblock the expect script so it can send Enter and complete.
            web_approved_flag.touch()

            output, stderr_out = expect_proc.communicate(timeout=timeout)
            assert expect_proc.returncode == 0, output + stderr_out
        finally:
            await session.close()


# ---------------------------------------------------------------------------
# ssh.web_auth_auto_continue coverage: TOTP + web composite, flag on.
#
# `_start_ssh_server_no_selinux` is a local copy of
# `ProcessManager.start_ssh_server` (conftest.py) with `--security-opt
# label=disable` added to the `docker run` invocation, needed because this
# host's SELinux Enforcing denies the container read access to the plain
# bind-mounted sshd_config `start_ssh_server` writes (no `:z`/`:Z` relabel
# flag) -- verified by hand: the unmodified invocation exits 1 with
# "<path>: Permission denied" and never binds port 22, while adding
# `--security-opt label=disable` to the same command starts sshd cleanly.
# This is a pre-existing environment gap in conftest.py, unrelated to
# ssh.web_auth_auto_continue; conftest.py isn't a file this task may touch,
# so the case below routes through this local helper instead so its
# assertions aren't gated on it. Duplicated from
# test_ssh_user_auth_in_browser.py rather than shared, since these two
# files are the only ones this task may modify.
def _start_ssh_server_no_selinux(processes: "ProcessManager", trusted_keys):
    port = alloc_port()
    data_dir = processes.ctx.tmpdir / f"sshd-{uuid.uuid4()}"
    data_dir.mkdir(parents=True)
    authorized_keys_path = data_dir / "authorized_keys"
    authorized_keys_path.write_text("\n".join(trusted_keys))
    config_path = data_dir / "sshd_config"
    config_path.write_text(
        dedent(
            f"""\
            Port 22
            AuthorizedKeysFile {authorized_keys_path}
            AllowAgentForwarding yes
            AllowTcpForwarding yes
            GatewayPorts yes
            X11Forwarding yes
            UseDNS no
            PermitTunnel yes
            StrictModes no
            PermitRootLogin yes
            HostKey /ssh-keys/id_ed25519
            Subsystem\tsftp\t/usr/lib/ssh/sftp-server
            LogLevel DEBUG3
            """
        )
    )
    data_dir.chmod(0o700)
    authorized_keys_path.chmod(0o600)
    config_path.chmod(0o600)

    processes.start(
        [
            "docker",
            "run",
            "--rm",
            "--security-opt",
            "label=disable",
            "-p",
            f"{port}:22",
            "-v",
            f"{data_dir}:{data_dir}",
            "-v",
            f"{os.getcwd()}/ssh-keys:/ssh-keys",
            "warpgate-e2e-ssh-server",
            "-f",
            str(config_path),
        ]
    )
    return port


class TestAutoContinueOtpAndWeb:
    @pytest.mark.asyncio
    async def test_otp_and_web_auth_flag_on(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        otp_key_base32: str,
        otp_key_base64: str,
    ):
        """I5 (OTP still required and prompted exactly once) + SC2 (URL
        printed once) with ssh.web_auth_auto_continue on.

        Unlike the flag-off composite above, there is no round-2
        "Press Enter when done:" prompt to synchronise on -- flag-on never
        emits one. Approving must still wait until *after* the OTP prompt
        has actually been sent to the client (signalled below via
        `otp_sent_flag`, the same technique the flag-off composite above
        uses for its own round-2 prompt): `_auth_keyboard_interactive`
        re-checks `kinds` from a fresh `verify()` on every invocation, and
        an approve landing before that read removes WebUserApproval from
        the outstanding set entirely -- the banner is only emitted from
        inside the `kinds.contains(&CredentialKind::WebUserApproval)`
        block, so it would never be shown at all. Confirmed directly:
        approving as soon as the websocket notification arrives -- which
        fires when the AuthState is *created*, well before round 1 -- is
        already too early and produces a clean OTP-then-accept run with
        zero "Please verify" text, which would make the SC2 assertion
        below pass vacuously instead of on real evidence. Waiting on the
        daemon log's "Keyboard-interactive auth as" line is *also* too
        early: that line is emitted at the top of the handler, before it
        reads `kinds`, so the approve can still race ahead of the very
        round it was meant to wait for.
        """
        wg = processes.start_wg(
            config_patch={
                "ssh": {
                    "web_auth_auto_continue": True,
                    "web_auth_wait_timeout": "25s",
                }
            },
        )
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        wait_port(wg.ssh_port, for_process=wg.process)

        ssh_port = _start_ssh_server_no_selinux(processes, [wg_c_ed25519_pubkey.read_text()])
        wait_port(ssh_port)

        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_public_key_credential(
                user.id,
                sdk.NewPublicKeyCredential(
                    label="Public Key",
                    openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip(),
                ),
            )
            api.create_otp_credential(
                user.id,
                sdk.NewOtpCredential(secret_key=list(b64decode(otp_key_base64))),
            )
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.update_user(
                user.id,
                sdk.UserDataRequest(
                    username=user.username,
                    credential_policy=sdk.UserRequireCredentialsPolicy(
                        ssh=[
                            sdk.CredentialKind.PUBLICKEY,
                            sdk.CredentialKind.TOTP,
                            sdk.CredentialKind.WEBUSERAPPROVAL,
                        ],
                    ),
                ),
            )
            api.add_user_role(user.id, role.id)
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

        totp = pyotp.TOTP(otp_key_base32)

        # otp_sent_flag: expect writes this right after sending the OTP
        # code, once the round-1 "One-time password:" prompt (and its
        # accompanying web-auth banner) is known to have already been
        # delivered to the client -- see the docstring for why python must
        # not approve any earlier than that.
        tmpdir = Path(tempfile.mkdtemp())
        otp_sent_flag = tmpdir / "otp_sent"

        script = dedent(
            f"""
            set timeout 60

            spawn ssh {user.username}:{ssh_target.name}@localhost \
                -p {wg.ssh_port} \
                -o StrictHostKeychecking=no \
                -o UserKnownHostsFile=/dev/null \
                -o IdentitiesOnly=yes \
                -o IdentityFile=ssh-keys/id_ed25519 \
                -o PreferredAuthentications=publickey,keyboard-interactive \
                ls /bin/sh

            # Round 1: OTP is a real prompt (flag-on doesn't change that --
            # only the web-approval sub-flow goes zero-prompt), with the
            # web-auth banner in the same round's instructions.
            expect "One-time password:"
            sleep 0.5
            send "{totp.now()}\\r"

            set fh [open "{otp_sent_flag}" w]
            close $fh

            # From here on, flag-on's poll rounds carry zero prompts. If
            # the OTP prompt reappears, that's I5 violated (OTP asked
            # twice); if the manual "Press Enter" prompt appears at all,
            # flag-on leaked into the manual path.
            expect {{
                "One-time password:" {{ exit 10 }}
                "Press Enter when done:" {{ exit 11 }}
                "/bin/sh" {{ exit 0 }}
            }}
            """
        )

        session = aiohttp.ClientSession()
        try:
            headers = {"Host": f"localhost:{wg.http_port}"}
            await session.post(
                f"{url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
                headers=headers,
                ssl=False,
            )
            ws = await session.ws_connect(
                url.replace("https:", "wss:") + "/@warpgate/api/auth/web-auth-requests/stream",
                ssl=False,
            )

            expect_proc = processes.start(
                ["expect"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            expect_proc.stdin.write(script.encode())
            expect_proc.stdin.close()
            expect_proc.stdin = None

            msg = await ws.receive(30)
            auth_id = msg.data

            # Fired as soon as the AuthState is created, before the OTP is
            # typed -- both Otp and WebUserApproval are still outstanding at
            # this point, and the coarse `state` label prefers "OtpNeeded"
            # when both are pending (unlike the flag-off composite test
            # above, which only checks `state` after OTP is already
            # satisfied). Assert the protocol and that a state exists;
            # the exact label isn't the evidence this case needs.
            auth_state = await (
                await session.get(f"{url}/@warpgate/api/auth/state/{auth_id}", ssl=False)
            ).json()
            assert auth_state["protocol"] == "SSH"
            assert auth_state["state"] in ("OtpNeeded", "WebUserApprovalNeeded")

            while not otp_sent_flag.exists():
                await asyncio.sleep(0.05)

            r = await session.post(f"{url}/@warpgate/api/auth/state/{auth_id}/approve", ssl=False)
            assert r.status == 200

            output, stderr_out = expect_proc.communicate(timeout=60)
        finally:
            await session.close()

        combined = output + stderr_out
        assert expect_proc.returncode == 0, combined
        assert combined.count(b"One-time password:") == 1
        assert combined.count(b"Please verify the SSH authentication request") == 1
        assert b"Press Enter when done" not in combined
