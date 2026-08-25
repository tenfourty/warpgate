import asyncio
import subprocess
import time
from pathlib import Path
from uuid import uuid4

import aiohttp
import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


class Test:
    # When include_pk is False, we're testing for
    # https://github.com/warp-tech/warpgate/issues/972
    # where the SSH server fails to offer keyboard-interactive authentication
    # when no OTP credential is present.
    @pytest.mark.parametrize("include_pk", [True, False])
    @pytest.mark.asyncio
    async def test(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
        include_pk: bool,
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )

        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            if include_pk:
                api.create_public_key_credential(
                    user.id,
                    sdk.NewPublicKeyCredential(
                        label="Public Key",
                        openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip()
                    ),
                )
            api.add_user_role(user.id, role.id)
            api.update_user(
                user.id,
                sdk.UserDataRequest(
                    username=user.username,
                    credential_policy=sdk.UserRequireCredentialsPolicy(
                        ssh=[sdk.CredentialKind.WEBUSERAPPROVAL] if not include_pk else [
                            sdk.CredentialKind.PUBLICKEY,
                            sdk.CredentialKind.WEBUSERAPPROVAL,
                        ],
                    ),
                ),
            )
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
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey"
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

        session = aiohttp.ClientSession()
        headers = {"Host": f"localhost:{shared_wg.http_port}"}

        await session.post(
            f"{url}/@warpgate/api/auth/login",
            json={
                "username": user.username,
                "password": "123",
            },
            headers=headers,
            ssl=False,
        )
        ws = await session.ws_connect(url.replace('https:', 'wss:') + '/@warpgate/api/auth/web-auth-requests/stream', ssl=False)

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_ed25519",
            "ls",
            "/bin/sh",
        )

        msg = await ws.receive(5)

        auth_id = msg.data
        auth_state = await (await session.get(f'{url}/@warpgate/api/auth/state/{auth_id}', ssl=False)).json()
        assert auth_state['protocol'] == 'SSH'
        assert auth_state['state'] == 'WebUserApprovalNeeded'
        r = await session.post(f'{url}/@warpgate/api/auth/state/{auth_id}/approve', json={"scope": "Once"}, ssl=False)
        assert r.status == 200

        ssh_client.stdin.write(b"\r\n")

        assert ssh_client.communicate(timeout=timeout)[0] == b"/bin/sh\n"
        assert ssh_client.returncode == 0


# ---------------------------------------------------------------------------
# ssh.web_auth_auto_continue coverage.
#
# Every case below starts its OWN `wg` instance via `config_patch` (never
# `shared_wg`, which is session-scoped and always started with the flag
# off) and waits on both `wg.http_port` and `wg.ssh_port` before touching
# it, since `start_wg` does not wait on its own.
#
# Cases below use `ProcessManager.start_ssh_server` (conftest.py) directly --
# it now passes `--security-opt label=disable` to the `docker run`
# invocation itself (added in 60837adb), so the SELinux-Enforcing-host
# permission denial that used to gate SSH sessions here no longer applies.
def _setup_pubkey_user(api, ssh_port, pubkey_text, require_web_approval: bool):
    """Role + password/pubkey user + SSH target, mirroring the existing
    `Test.test` setup above. `require_web_approval` controls whether
    WEBUSERAPPROVAL is a *required* credential kind:

    - True: the usual "browser approval is mandatory" policy the rest of
      this file already exercises.
    - False: PUBLICKEY only. Required for the step-up-gate cases below --
      session.rs's gate (`pubkey_used && !has_stepup`) only fires when
      WebUserApproval is *not* already a required kind; if it were, the
      gate is redundant with the policy and the case is vacuous.
    """
    role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
    user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
    api.create_public_key_credential(
        user.id,
        sdk.NewPublicKeyCredential(label="Public Key", openssh_public_key=pubkey_text),
    )
    api.add_user_role(user.id, role.id)
    ssh_kinds = [sdk.CredentialKind.PUBLICKEY]
    if require_web_approval:
        ssh_kinds.append(sdk.CredentialKind.WEBUSERAPPROVAL)
    api.update_user(
        user.id,
        sdk.UserDataRequest(
            username=user.username,
            credential_policy=sdk.UserRequireCredentialsPolicy(ssh=ssh_kinds),
        ),
    )
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
    return user, ssh_target


class TestAutoContinue:
    @pytest.mark.asyncio
    async def test_flag_on_delayed_approve_completes_without_keypress(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
    ):
        """SC1 (completes without a keypress) + SC2 (URL printed once).

        A fast approve cannot distinguish this from the flag-off manual
        loop -- both complete in ~2 keyboard-interactive rounds regardless
        of the flag (measured directly: 2 rounds, 0 "Press Enter" hits, in
        both flag states). Delaying the approve past one 10s poll cadence
        is what makes the two paths distinguishable: flag-on then logs
        several zero-prompt poll rounds as it waits, flag-off has no such
        mechanism at all. That round-count evidence is asserted below
        alongside the completion itself.
        """
        log_path = processes.ctx.tmpdir / f"wg-log-{uuid4()}.log"
        log_file = open(log_path, "w")
        wg = processes.start_wg(
            config_patch={
                "ssh": {
                    "web_auth_auto_continue": True,
                    "web_auth_wait_timeout": "25s",
                }
            },
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        wait_port(wg.ssh_port, for_process=wg.process)

        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            user, ssh_target = _setup_pubkey_user(
                api, ssh_port, open("ssh-keys/id_ed25519.pub").read().strip(), True
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

            ssh_client = processes.start_ssh_client(
                f"{user.username}:{ssh_target.name}@localhost",
                "-p",
                str(wg.ssh_port),
                "-o",
                "IdentityFile=ssh-keys/id_ed25519",
                "ls",
                "/bin/sh",
                stderr=subprocess.PIPE,
            )

            msg = await ws.receive(5)
            auth_id = msg.data

            for _ in range(100):
                if "Keyboard-interactive auth as" in log_path.read_text():
                    break
                await asyncio.sleep(0.05)
            else:
                raise AssertionError("kbd-interactive round never showed up in the daemon log")

            # Past one 10s poll cadence -- see docstring.
            await asyncio.sleep(25)

            r = await session.post(f"{url}/@warpgate/api/auth/state/{auth_id}/approve", json={"scope": "Once"}, ssl=False)
            assert r.status == 200

            stdout, stderr = ssh_client.communicate(timeout=60)
        finally:
            await session.close()

        assert stdout == b"/bin/sh\n"
        assert ssh_client.returncode == 0

        log_content = log_path.read_text()
        assert log_content.count("Press Enter when done: ") == 0, (
            "flag-on must never emit the manual prompt"
        )
        round_count = log_content.count("Keyboard-interactive auth as")
        assert round_count >= 3, (
            f"expected several zero-prompt poll rounds under a 25s delayed "
            f"approve with a 10s cadence, got {round_count} -- the config "
            f"patch may not have taken effect"
        )

        assert stderr.count(b"Please verify the SSH authentication request") == 1
        assert b"Press Enter when done" not in stderr

    @pytest.mark.asyncio
    async def test_flag_on_timeout_rejects_after_budget(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
    ):
        """SC3: a wait exceeding the budget rejects, delivering the
        not-confirmed text first, and never accepts. Never approves.
        `web_auth_wait_timeout: "25s"` is >= 20s so T1's short-timeout
        warning does not fire (irrelevant here regardless -- it only
        warns, never fails). Uses an explicit `communicate(timeout=90)`,
        not the session-scoped `timeout` fixture, since that fixture reads
        an env var once at session start and cannot be raised per-case.
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

        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            user, ssh_target = _setup_pubkey_user(
                api, ssh_port, open("ssh-keys/id_ed25519.pub").read().strip(), True
            )

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_ed25519",
            "ls",
            "/bin/sh",
            stderr=subprocess.PIPE,
        )

        started = time.monotonic()
        stdout, stderr = ssh_client.communicate(timeout=90)
        elapsed = time.monotonic() - started

        assert ssh_client.returncode != 0
        assert stdout == b""
        assert b"not confirmed" in stderr
        assert elapsed >= 20, (
            f"rejected after only {elapsed:.1f}s against a 25s budget -- "
            f"looks like the timeout isn't actually being honoured"
        )

    @pytest.mark.asyncio
    async def test_flag_on_browser_reject_fails_early(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
    ):
        """A browser rejection wakes the poll loop almost immediately (the
        completion signal fires on reject too, per session.rs), well
        before the 25s budget -- unlike the timeout case above, which can
        only fail once the whole budget has elapsed. That timing gap is
        what makes this case distinguishable from the timeout one.

        Uses the reject endpoint directly via aiohttp with the
        user-session cookie from /auth/login, not the generated admin SDK
        -- `POST /auth/state/:id/reject` is user-session-authenticated
        (`transform = "endpoint_auth"` in warpgate-protocol-http), and the
        SDK client is bound to `/@warpgate/admin/api`.
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

        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            user, ssh_target = _setup_pubkey_user(
                api, ssh_port, open("ssh-keys/id_ed25519.pub").read().strip(), True
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

            ssh_client = processes.start_ssh_client(
                f"{user.username}:{ssh_target.name}@localhost",
                "-p",
                str(wg.ssh_port),
                "-o",
                "IdentityFile=ssh-keys/id_ed25519",
                "ls",
                "/bin/sh",
                stderr=subprocess.PIPE,
            )

            msg = await ws.receive(5)
            auth_id = msg.data

            r = await session.post(f"{url}/@warpgate/api/auth/state/{auth_id}/reject", ssl=False)
            assert r.status == 200

            started = time.monotonic()
            stdout, stderr = ssh_client.communicate(timeout=60)
            elapsed = time.monotonic() - started
        finally:
            await session.close()

        assert ssh_client.returncode != 0
        assert stdout == b""
        assert elapsed < 15, (
            f"reject took {elapsed:.1f}s -- should wake on the completion "
            f"signal almost immediately, not require waiting out (part of) "
            f"the 25s budget like the timeout case does"
        )

    @pytest.mark.asyncio
    async def test_flag_on_step_up_gate_stamps_last_sso_at(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
    ):
        """SC7: last_sso_at is stamped on the matched pubkey row when
        auto-continue accepts. The only observable proof of the stamp is
        behavioural: a second connection immediately after the first must
        NOT trigger a second web-approval request.

        The user's ssh credential_policy is PUBLICKEY only -- WEBUSERAPPROVAL
        is deliberately not a required kind. If it were, the step-up gate
        in session.rs (which only fires on `pubkey_used && !has_stepup`)
        would never be reached and this case would be vacuous.

        Detects the approval request by polling
        `GET /auth/web-auth-requests` rather than the
        `/web-auth-requests/stream` websocket the other cases use. Measured
        directly: for this specific gate, the AuthState races through
        three verification-state transitions synchronously before the
        auth_state_store's forwarding task (which relays
        `Need(WebUserApproval)` onto the websocket's broadcast channel) gets
        its first scheduler turn -- `None -> Need(PublicKey) -> Accepted ->
        Need(WebUserApproval)` -- and that forwarding task subscribes to a
        capacity-1 broadcast channel via a bare `while let Ok(...)`, so a
        lagged receiver silently ends the task and the notification never
        reaches the websocket. The plain WebUserApproval-required cases
        elsewhere in this file don't hit this: their AuthState's first
        notable transition already contains WebUserApproval, so there is
        only ever one send before the forwarding task's first poll. This
        looks like a pre-existing bug in warpgate-core's
        `AuthStateStore::create`, orthogonal to ssh.web_auth_auto_continue
        and outside this task's owned files -- worth a follow-up, not a fix
        here. The list endpoint reads `AuthState::verify()` directly on
        every poll, so it has no such race.
        """
        log_path = processes.ctx.tmpdir / f"wg-log-{uuid4()}.log"
        log_file = open(log_path, "w")
        wg = processes.start_wg(
            config_patch={
                "ssh": {
                    "web_auth_auto_continue": True,
                    "web_auth_wait_timeout": "25s",
                },
                "step_up_interval": {"ssh": "12h"},
            },
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        wait_port(wg.http_port, for_process=wg.process, recv=False)
        wait_port(wg.ssh_port, for_process=wg.process)

        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        pubkey_text = open("ssh-keys/id_ed25519.pub").read().strip()
        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            # Freshly created -- its last_sso_at is genuinely NULL.
            user, ssh_target = _setup_pubkey_user(api, ssh_port, pubkey_text, False)

        session = aiohttp.ClientSession()
        try:
            headers = {"Host": f"localhost:{wg.http_port}"}
            await session.post(
                f"{url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
                headers=headers,
                ssl=False,
            )
            # --- Connection 1: stale/missing last_sso_at -> gate fires. ---
            ssh_client_1 = processes.start_ssh_client(
                f"{user.username}:{ssh_target.name}@localhost",
                "-p",
                str(wg.ssh_port),
                "-o",
                "IdentityFile=ssh-keys/id_ed25519",
                "ls",
                "/bin/sh",
                stderr=subprocess.PIPE,
            )

            # Wait for round 1 of the auto-continue driver to have actually
            # started (and so already emitted the banner) before approving --
            # `_auth_keyboard_interactive` re-checks the verdict up front and
            # accepts immediately with zero rounds if it is already
            # Accepted, which an approve fired before the client even
            # attempts keyboard-interactive would otherwise cause here.
            for _ in range(100):
                if "Keyboard-interactive auth as" in log_path.read_text():
                    break
                await asyncio.sleep(0.05)
            else:
                raise AssertionError("kbd-interactive round never showed up in the daemon log")

            auth_state = None
            for _ in range(100):
                pending = await (
                    await session.get(f"{url}/@warpgate/api/auth/web-auth-requests", ssl=False)
                ).json()
                ssh_pending = [p for p in pending if p["protocol"] == "SSH"]
                if ssh_pending:
                    auth_state = ssh_pending[0]
                    break
                await asyncio.sleep(0.1)
            assert auth_state is not None, "step-up gate never produced a pending web-auth request"
            auth_id = auth_state["id"]
            assert auth_state["state"] == "WebUserApprovalNeeded"

            r = await session.post(f"{url}/@warpgate/api/auth/state/{auth_id}/approve", json={"scope": "Once"}, ssl=False)
            assert r.status == 200

            stdout_1, stderr_1 = ssh_client_1.communicate(timeout=30)
            assert stdout_1 == b"/bin/sh\n"
            assert ssh_client_1.returncode == 0
            assert b"Please verify the SSH authentication request" in stderr_1

            # --- Connection 2: same pubkey, immediately after. last_sso_at
            # was just stamped, so this must NOT need a second approval. ---
            ssh_client_2 = processes.start_ssh_client(
                f"{user.username}:{ssh_target.name}@localhost",
                "-p",
                str(wg.ssh_port),
                "-o",
                "IdentityFile=ssh-keys/id_ed25519",
                "ls",
                "/bin/sh",
                stderr=subprocess.PIPE,
            )
            stdout_2, stderr_2 = ssh_client_2.communicate(timeout=30)
        finally:
            await session.close()

        assert stdout_2 == b"/bin/sh\n"
        assert ssh_client_2.returncode == 0
        assert b"Please verify the SSH authentication request" not in stderr_2, (
            "second connection right after the first triggered a second "
            "web-approval request -- last_sso_at was not stamped/read back"
        )

    @pytest.mark.asyncio
    async def test_flag_on_no_step_up_interval_never_gates(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
    ):
        """Control for the step-up-gate case above: with `step_up_interval`
        left unset entirely (the default), a PUBLICKEY-only login never
        sees a web-approval notification at all.
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

        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        pubkey_text = open("ssh-keys/id_ed25519.pub").read().strip()
        url = f"https://localhost:{wg.http_port}"
        with admin_client(url) as api:
            user, ssh_target = _setup_pubkey_user(api, ssh_port, pubkey_text, False)

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_ed25519",
            "ls",
            "/bin/sh",
            stderr=subprocess.PIPE,
        )
        stdout, stderr = ssh_client.communicate(timeout=30)

        assert stdout == b"/bin/sh\n"
        assert ssh_client.returncode == 0
        assert b"Please verify the SSH authentication request" not in stderr
