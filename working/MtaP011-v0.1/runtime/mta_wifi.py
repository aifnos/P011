# -*- coding: utf-8 -*-
"""Finite ConnMan STA leases for P011; Python 3.5, no shell or json stdlib.

Read-only capabilities do not enable Wi-Fi, register an agent or scan. Receiving
requires explicit consent and validated MTA credentials. Sender AP/P2P support
is unavailable until its ownership, concurrency and restoration are verified.
"""
import base64
import os
import queue
import re
import socket
import stat
import subprocess
import threading
import time

import p011_json as json
from mta_protocol import P2pInfo, ProtocolError


class WifiError(RuntimeError):
    pass


class WifiUnavailable(WifiError):
    pass


class WifiCancelled(WifiError):
    pass


class WifiRestoreError(WifiError):
    pass


_REASONS = {
    'CONNMAN_READONLY_PROBE_UNAVAILABLE': 'ConnMan 只读探测不可用',
    'WIFI_POWERED_OFF_NO_AUTOMATIC_ENABLE': 'Wi-Fi 已关闭，请先在系统中开启',
    'MULTIPLE_WIFI_CONNECTIONS_UNSUPPORTED': '现有多 Wi-Fi 连接无法安全恢复',
    'CONNMAN_AGENT_REGISTER_FAILED': 'ConnMan 凭据代理注册失败',
    'TARGET_PROFILE_OWNERSHIP_NOT_PROVEN': '目标网络已存在于基线，无法证明临时配置归属，未覆盖原配置',
    'AMBIGUOUS_TARGET_NETWORK': '同名目标网络不唯一，已停止连接',
    'TEMPORARY_CONNECTION_FAILED': '临时 Wi-Fi 连接失败',
    'TARGET_CONNECTION_TIMEOUT': '等待目标 Wi-Fi 连接超时',
    'TARGET_IPV4_GATEWAY_UNAVAILABLE': '目标网络未提供有效 IPv4 网关',
    'TEMPORARY_AUTOCONNECT_DISABLE_FAILED': '临时网络自动连接限制失败',
    'CONNMAN_STATE_UNAVAILABLE': 'ConnMan 状态不可读取，网络恢复待核实',
    'NETWORK_RESTORE_NOT_CONFIRMED': '原网络与临时配置清理尚未确认',
    'TEMPORARY_PROFILE_IDENTITY_CHANGED': '临时网络身份变化，未删除不明配置',
    'SEND_P2P_AP_NOT_VERIFIED': 'P2P/AP 租约与网络并发尚未实机验证',
    'CONNMAN_AGENT_CANCELED': 'ConnMan 已取消临时凭据请求',
    'PARENT_PIPE_CLOSED': '父进程通信已关闭',
    'LEASE_INTERRUPTED': '临时网络租约已中止',
    'TEMPORARY_LEASE_ENDED': '临时连接已结束',
    'INVALID_LEASE_CONTROL': '网络租约控制命令无效',
    'PREPARED_LEASE_EXPIRED': '接收准备已到时，尚未切换网络',
    'JOURNAL_PREPARE_FAILED_NETWORK_UNTOUCHED': '网络恢复记录无法安全保存，未切换网络',
    'JOURNAL_WRITE_FAILED_RECOVERY_LOCKED': '恢复记录写入失败，已锁定互传网络操作',
    'JOURNAL_CLEANUP_FAILED_RECOVERY_LOCKED': '恢复记录清理未确认，请重试恢复检查',
    'JOURNAL_IDENTITY_UNPROVEN_RECOVERY_LOCKED': '旧会话归属无法确认，请保留日志并检查系统重启或 ConnMan 重启',
    'TEMPORARY_PROFILE_HASH_NOT_PROVEN': '临时配置归属校验失败，已保留记录，未删除不明配置',
    'PRIOR_WIFI_OWNERSHIP_NOT_VERIFIED': '原厂联网与临时配置归属尚未核实，未开放临时 Wi-Fi 接收',
}


def _reason(event):
    code = event.get('reason', '') if isinstance(event, dict) else ''
    return _REASONS.get(code, '网络助手返回异常，状态待核实')


def _integer(value, low, high, label):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise WifiError('invalid ' + label)
    return value


def _validate_credentials(ssid, psk):
    if not isinstance(ssid, str) or not isinstance(psk, str):
        raise WifiError('invalid network credentials')
    if not 1 <= len(ssid.encode('utf-8')) <= 32 or '\x00' in ssid:
        raise WifiError('invalid SSID')
    if not 8 <= len(psk) <= 64 or any(ord(c) < 32 or ord(c) > 126 for c in psk):
        raise WifiError('invalid WPA2 PSK')
    if len(psk) == 64 and re.match(r'^[0-9a-fA-F]{64}\Z', psk) is None:
        raise WifiError('invalid WPA2 PSK')


def _ipv4(text):
    if not isinstance(text, str) or re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\Z', text) is None:
        raise WifiError('helper did not report a real IPv4 address')
    parts = text.split('.')
    if any(int(p) > 255 or (len(p) > 1 and p.startswith('0')) for p in parts) or text in ('0.0.0.0', '255.255.255.255'):
        raise WifiError('invalid IPv4 address')
    socket.inet_aton(text)
    return text


class NetworkInfo(object):
    """Private credentials; repr never exposes SSID or PSK."""
    def __init__(self, ssid, psk):
        _validate_credentials(ssid, psk)
        self.ssid = ssid
        self.psk = psk

    def __repr__(self):
        return '<NetworkInfo redacted>'

    @classmethod
    def from_p2p_info(cls, info):
        if isinstance(info, dict):
            info = P2pInfo.from_dict(info)
        if not isinstance(info, P2pInfo) or info.key is not None:
            raise WifiError('decrypted validated P2pInfo required')
        # Revalidate mutable attributes; do not trust the object's former state.
        P2pInfo(info.ssid, info.psk, info.mac, info.port, sender_id=info.id, cat_share=info.cat_share)
        return cls(info.ssid, info.psk)


def _decode_event(raw):
    if not isinstance(raw, bytes) or len(raw) > 8192:
        raise WifiError('network helper response limit')
    try:
        value = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeError, RuntimeError, TypeError):
        raise WifiError('invalid network helper response')
    if not isinstance(value, dict) or value.get('event') not in ('capabilities', 'prepared', 'connecting', 'connected', 'restoring', 'restored', 'error'):
        raise WifiError('unknown network helper event')
    return value


def _restored(event):
    return event.get('event') == 'restored' and event.get('ok') is True and event.get('temporaryProfileRemoved') is True and (event.get('networkUntouched') is True or event.get('originalNetworkRestored') is True)


def _process_start(pid):
    try:
        with open('/proc/' + str(pid) + '/stat', 'r') as stream:
            text = stream.read(4096)
        return int(text[text.rindex(')') + 2:].split()[19])
    except (OSError, ValueError, IndexError):
        return None


class WifiBackend(object):
    def __init__(self, helper_path, journal_dir=None):
        self.helper_path = os.path.abspath(helper_path) if helper_path else ''
        self._lease_lock = threading.Lock()
        self._active_lease = None
        self._restore_failed = False
        self.journal_dir = os.path.abspath(journal_dir or '/mnt/data/p011-toolbox/sessions/mta-network')
        self._reason = ''
        self._recovery_locked = False
        self._pending = []
        self._recovery_actor = None
        self._recovery_spawn_pending = False
        self._recovery_spawn_unknown = False
        self._recovery_guard = threading.Lock()
        self._refresh_pending()

    def _refresh_pending(self):
        self._pending = []
        try:
            if not os.path.lexists(self.journal_dir):
                return
            st = os.lstat(self.journal_dir)
            if not stat.S_ISDIR(st.st_mode) or os.path.realpath(self.journal_dir) != self.journal_dir or (st.st_mode & 0o777) != 0o700 or (hasattr(os, 'geteuid') and st.st_uid != os.geteuid()):
                raise WifiRestoreError('恢复记录目录的权限或归属不安全')
            names = os.listdir(self.journal_dir)
            if len(names) > 16:
                raise WifiRestoreError('恢复记录过多，需要人工检查')
            for name in names:
                if re.match(r'^lease-[0-9]+-[0-9]+\.ini\Z', name):
                    path = os.path.join(self.journal_dir, name)
                    st = os.lstat(path)
                    if not stat.S_ISREG(st.st_mode) or (st.st_mode & 0o777) != 0o600 or st.st_nlink != 1 or (hasattr(os, 'geteuid') and st.st_uid != os.geteuid()):
                        raise WifiRestoreError('恢复记录的权限或归属不安全')
                    self._pending.append(path)
                else:
                    raise WifiRestoreError('存在未确认的恢复记录，请保留目录并检查')
        except OSError:
            self._recovery_locked = True
            self._reason = '网络恢复记录无法读取'
        except WifiRestoreError as error:
            self._recovery_locked = True
            self._reason = str(error)

    def _ensure_journal_dir(self):
        if os.path.realpath(self.journal_dir) != self.journal_dir:
            raise WifiRestoreError('恢复记录目录不能使用符号链接')
        if not os.path.exists(self.journal_dir):
            os.makedirs(self.journal_dir, mode=0o700)
        self._refresh_pending()
        if self._recovery_locked or self._pending:
            raise WifiRestoreError(self._reason or '上次网络恢复待核实，请先执行恢复检查')

    def status(self):
        self._refresh_pending()
        return {'restorePending': (bool(self._pending) and self._active_lease is None) or self._restore_failed or self._recovery_actor is not None or self._recovery_spawn_pending or self._recovery_spawn_unknown,
                'recoveryLocked': self._recovery_locked or self._restore_failed or self._recovery_actor is not None or self._recovery_spawn_pending or self._recovery_spawn_unknown,
                'prepared': bool(self._active_lease and self._active_lease.prepared and not self._active_lease.closed and self._active_lease.process.poll() is None),
                'reason': self._reason or (_REASONS['NETWORK_RESTORE_NOT_CONFIRMED'] if self._restore_failed else '')}

    def recover_pending(self):
        if not self._recovery_guard.acquire(False):
            return False
        try:
            return self._recover_pending()
        finally:
            self._recovery_guard.release()

    def _recover_pending(self):
        """Fixed native recovery; hash/boot/daemon/live actor gates run natively.

        Never kills another actor or parses credentials from a profile/journal.
        A failed check preserves the journal and locks new network leases.
        """
        if self._active_lease and not self._active_lease.closed:
            return self.restore_active()
        if self._active_lease and self._active_lease.actors_closed() is not True:
            return False
        if self._recovery_spawn_unknown or self._recovery_spawn_pending:return False
        native_confirmed=False
        if self._recovery_actor is not None:
            actor = self._recovery_actor
            process = actor['process']
            if process.poll() is None:
                return False  # One mutation actor only; retain handle/identity.
            try:
                output, _ = process.communicate(timeout=1)
                if not self._recovery_confirmed(output, actor['path']) or not self._recovery_closed(actor):
                    return False
            except (OSError, ValueError, WifiError, subprocess.TimeoutExpired):
                return False
            self._recovery_actor = None
            self._recovery_locked = False
            self._restore_failed = False
            native_confirmed=True
        self._refresh_pending()
        if self._recovery_locked:
            return False
        if (self._active_lease and self._active_lease.restored is not True and not self._pending and not native_confirmed):
            self._restore_failed=True
            self._reason=_REASONS['NETWORK_RESTORE_NOT_CONFIRMED']
            return False # Absence of a journal cannot prove a failed old lease recovered.
        for path in list(self._pending):
            process = None
            try:
                self._recovery_spawn_pending = True
                try:process = self._spawn('--recover')
                except BaseException:self._recovery_spawn_unknown=True;raise
                finally:self._recovery_spawn_pending=False
                self._recovery_actor = {'process':process,'path':path,'stdin':getattr(process,'stdin',None),
                                        'stdout':getattr(process,'stdout',None),'pid':getattr(process,'pid',None),'start':None}
                if hasattr(process,'pid'):self._recovery_actor['start']=_process_start(process.pid)
                wire = (json.dumps({'cmd': 'recover', 'journal_file_b64': base64.b64encode(path.encode('utf-8')).decode('ascii')}) + '\n').encode('ascii')
                output, _ = process.communicate(wire, timeout=40)
                if not self._recovery_confirmed(output, path) or not self._recovery_closed(self._recovery_actor):
                    raise WifiRestoreError(_REASONS['JOURNAL_IDENTITY_UNPROVEN_RECOVERY_LOCKED'])
                self._recovery_actor = None
            except BaseException as error:
                # No SIGKILL of recovery helpers. Closing stdin asks for bounded
                # cleanup; the native restore deadline is independent.
                if process and process.poll() is None:
                    try: process.stdin.close()
                    except (OSError, ValueError): pass
                    process.stdin = None
                self._recovery_locked = True
                self._restore_failed = True
                self._reason = str(error) if isinstance(error, WifiError) else _REASONS['JOURNAL_IDENTITY_UNPROVEN_RECOVERY_LOCKED']
                return False
        self._active_lease = None
        self._restore_failed = False
        self._reason = ''
        self._refresh_pending()
        return not self._pending and not self._recovery_locked

    @staticmethod
    def _recovery_confirmed(output, path):
        events = [_decode_event(line) for line in output.splitlines()] if len(output) <= 32768 else []
        return any(_restored(event) for event in events) and not os.path.lexists(path)

    @staticmethod
    def _recovery_closed(actor):
        try:return (actor['process'].poll() is not None and actor['stdin'].closed is True and
                    actor['stdout'].closed is True)
        except Exception:return False

    def _spawn(self, mode):
        if not self.helper_path or not os.path.isfile(self.helper_path) or not os.access(self.helper_path, os.X_OK):
            raise WifiUnavailable('网络助手未安装或不可执行')
        # No command string, shell, SSID, passphrase or arbitrary D-Bus method.
        return subprocess.Popen([self.helper_path, mode], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                close_fds=(os.name != 'nt'))

    def capabilities(self):
        unavailable = {'connman': False, 'wifiPowered': False, 'receive': False,
                       'receiveVerified': False, 'send': False, 'p2pVerified': False,
                       'concurrencyVerified': False, 'reason': '网络助手未就绪'}
        self._refresh_pending()
        if self._restore_failed or self._recovery_locked or (self._pending and self._active_lease is None):
            unavailable['reason'] = self._reason or '上次网络恢复待核实，请先执行恢复检查'
            return unavailable
        process = None
        try:
            process = self._spawn('--capabilities')
            output, _ = process.communicate(timeout=8)
            if len(output) > 8192 or len(output.splitlines()) != 1:
                raise WifiError('network helper response limit')
            value = _decode_event(output.strip())
            if process.returncode != 0 or value.get('event') != 'capabilities' or value.get('ok') is not True:
                unavailable['reason'] = _reason(value)
                return unavailable
            return {'connman': value.get('connman') is True,
                    'wifiPowered': value.get('wifiPowered') is True,
                    'receive': value.get('receive') is True,
                    'receiveVerified': False, 'send': False, 'p2pVerified': False,
                    'concurrencyVerified': False,
                    'reason': _reason(value) if value.get('reason') else ''}
        except subprocess.TimeoutExpired:
            # This mode is strictly read-only, so terminating it cannot strand
            # a lease or temporary credentials. Receive is never killed here.
            if process is not None:
                process.kill(); process.communicate()
            unavailable['reason'] = 'ConnMan 只读探测超时'
            return unavailable
        except (OSError, WifiError):
            return unavailable

    def begin_prepare(self, cancelled=None, timeout=180):
        """Private owner reservation: no spawn, RF, credentials or restore.

        Session callers must retain this exact lease before lease.prepare().
        The legacy prepare wrapper remains for existing direct users.
        """
        _integer(timeout, 10, 600, 'lease timeout')
        if cancelled and cancelled():
            raise WifiCancelled('接收准备已取消')
        if self._restore_failed or self._recovery_locked or self._recovery_guard.locked() or self._recovery_actor is not None or self._recovery_spawn_pending or self._recovery_spawn_unknown:
            raise WifiRestoreError(self._reason or _REASONS['NETWORK_RESTORE_NOT_CONFIRMED'])
        if self._active_lease:
            if self._active_lease.prepared and not self._active_lease.closed and self._active_lease.process.poll() is None:
                return self._active_lease
            raise WifiUnavailable('已有互传网络租约，请等待恢复完成')
        self._ensure_journal_dir()
        if not self._lease_lock.acquire(False):
            raise WifiUnavailable('已有互传网络租约，请等待恢复完成')
        lease = WifiLease(self, cancelled, timeout)
        self._active_lease = lease
        return lease

    def prepare(self, cancelled=None, timeout=180):
        lease = self.begin_prepare(cancelled, timeout)
        if lease.prepared:
            return lease
        try:
            lease.prepare()
            return lease
        except Exception:
            if not lease.restore():
                raise WifiRestoreError(_REASONS['NETWORK_RESTORE_NOT_CONFIRMED'])
            raise

    def receive(self, info, cancelled=None, timeout=180, consented=False):
        if consented is not True:
            raise WifiUnavailable('临时 Wi-Fi 切换需要明确同意')
        _integer(timeout, 10, 600, 'lease timeout')
        if not isinstance(info, NetworkInfo):
            try:
                info = NetworkInfo.from_p2p_info(info)
            except (ProtocolError, TypeError, ValueError):
                raise WifiError('validated P2pInfo required')
        _validate_credentials(info.ssid, info.psk)
        if cancelled and cancelled():
            raise WifiCancelled('网络连接已取消')
        if self._restore_failed:
            raise WifiRestoreError(_REASONS['NETWORK_RESTORE_NOT_CONFIRMED'])
        lease = self._active_lease or self.prepare(cancelled, timeout)
        if not lease.prepared or lease.closed:
            raise WifiUnavailable('接收准备未就绪，请重新开启可发现')
        lease.cancelled = cancelled
        lease.timeout = timeout
        try:
            lease.connect(info)
            return lease
        except Exception:
            if not lease.restore():
                raise WifiRestoreError(_REASONS['NETWORK_RESTORE_NOT_CONFIRMED'])
            raise

    def restore_active(self):
        if self._active_lease is None:
            return not self._restore_failed
        return self._active_lease.restore()

    def send_lease(self, *args, **kwargs):
        raise WifiUnavailable(_REASONS['SEND_P2P_AP_NOT_VERIFIED'])

    create_p2p_lease = send_lease
    create_ap_lease = send_lease


class WifiLease(object):
    def __init__(self, backend, cancelled, timeout):
        self.backend = backend
        self.cancelled = cancelled
        self.timeout = timeout
        self.gateway = None
        self.local_ip = None
        self.process = None
        self.events = queue.Queue(maxsize=32)
        self.reader = None
        self.restored = False
        self.closed = False
        self._lock_owned = True
        self._control_sent = False
        self._reader_error = False
        self.prepared = False
        self._spawn_claimed = False
        self._spawn_resolved = False
        self._spawn_unknown = False
        self._reader_claimed = False
        self._reader_resolved = False
        self._reader_unknown = False
        self._actor_lock = threading.RLock()

    def _release_lock(self):
        if self._lock_owned:
            self.backend._lease_lock.release()
            self._lock_owned = False
        if self.restored:
            self.backend._active_lease = None
            self.backend._restore_failed = False

    def _reader_main(self):
        try:
            while not self._reader_resolved:
                if self._reader_unknown:return
                time.sleep(.005)
            if self._reader_unknown:return
            while True:
                raw = self.process.stdout.readline(8193)
                if not raw:
                    break
                value = _decode_event(raw)
                self.events.put_nowait(value)
        except (WifiError, OSError, ValueError, queue.Full):
            self._reader_error = True
        finally:
            try:
                self.events.put_nowait({'event': '_eof'})
            except queue.Full:
                self._reader_error = True

    def _event(self, wait=0.2):
        try:
            return self.events.get(timeout=wait)
        except queue.Empty:
            return None

    def _write(self, value):
        wire = (json.dumps(value) + '\n').encode('ascii')
        if len(wire) > 8192:
            raise WifiError('network command limit')
        self.process.stdin.write(wire)
        self.process.stdin.flush()

    def prepare(self):
        with self._actor_lock:
            if self._spawn_claimed:raise WifiUnavailable('网络准备不能重复启动')
            self._spawn_claimed = True
        try:self.process = self.backend._spawn('--prepare')
        except BaseException:
            self._spawn_unknown = True;self.backend._restore_failed = True
            raise
        finally:self._spawn_resolved = True
        self.reader = threading.Thread(target=self._reader_main)
        self.reader.daemon = True
        self._reader_claimed = True
        try:self.reader.start()
        except BaseException:
            self._reader_unknown = True;self.backend._restore_failed = True
            raise
        finally:self._reader_resolved = True
        self._write({'cmd': 'prepare', 'ttl': self.timeout,
                     'journal_dir_b64': base64.b64encode(self.backend.journal_dir.encode('utf-8')).decode('ascii')})
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.cancelled and self.cancelled():
                raise WifiCancelled('接收准备已取消')
            if self._reader_error:
                raise WifiError('网络准备响应异常')
            event = self._event()
            if not event:
                continue
            if event.get('event') == 'prepared' and event.get('ok') is True and event.get('networkUntouched') is True and event.get('snapshotCaptured') is True:
                self.prepared = True
                return
            if event.get('event') == 'error':
                raise WifiUnavailable(_reason(event))
            if event.get('event') == '_eof':
                raise WifiError('网络准备助手提前退出')
        raise WifiError('网络准备超时，未开启可发现')

    def connect(self, info):
        if not self.prepared or self.process.poll() is not None:
            raise WifiError('未持有接收前的只读网络基线')
        self.prepared = False
        connect_seconds = min(90, max(10, self.timeout))
        # Base64 is framing, not encryption. These fields exist only in this
        # private pipe; they are not returned to the UI, argv or any logs.
        self._write({'cmd': 'receive', 'consented': True,
                     'ssid_b64': base64.b64encode(info.ssid.encode('utf-8')).decode('ascii'),
                     'psk_b64': base64.b64encode(info.psk.encode('ascii')).decode('ascii'),
                     'timeout': connect_seconds, 'ttl': self.timeout})
        deadline = time.monotonic() + connect_seconds + 8
        while time.monotonic() < deadline:
            if self.cancelled and self.cancelled():
                raise WifiCancelled('网络连接已取消')
            if self._reader_error:
                raise WifiError('网络助手响应异常，需核实恢复')
            event = self._event()
            if event is None:
                continue
            kind = event.get('event')
            if kind == 'connected' and event.get('ok') is True:
                self.local_ip = _ipv4(event.get('address'))
                self.gateway = _ipv4(event.get('gateway'))
                return
            if kind == 'restored':
                self.restored = _restored(event)
            if kind == 'error':
                raise WifiUnavailable(_reason(event))
            if kind == '_eof':
                raise WifiError('网络助手提前退出，恢复状态待核实')
        raise WifiError('临时网络连接超时')

    def restore(self):
        if self.closed:
            return self.restored
        if self.process is None:
            if self._spawn_unknown or (self._spawn_claimed and not self._spawn_resolved):
                self.backend._restore_failed = True
                return False
            self.closed = True
            self.restored = True  # No helper was started, so no network changed.
            self._release_lock()
            return True
        if not self._control_sent and self.process.poll() is None:
            try:
                self._write({'cmd': 'restore'})
                self._control_sent = True
            except (OSError, ValueError, WifiError):
                # EOF is a second finite restoration trigger, not proof.
                try:
                    self.process.stdin.close()
                except (OSError, ValueError):
                    pass
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            event = self._event()
            if event and event.get('event') == 'restored':
                self.restored = _restored(event)
            if self.process.poll() is not None and self.events.empty():
                break
        # Do not SIGKILL a mutation helper and strand its lease. Closing its
        # input requests cleanup; the native helper also has an independent TTL.
        try:
            self.process.stdin.close()
        except (OSError, ValueError):
            pass
        if self.process.poll() is not None:
            # A dead process is not an exited Python reader. Never join while
            # holding the actor lock, and never join the current reader.
            if self.reader is not None and self.reader is not threading.current_thread():
                try:self.reader.join(2)
                except (RuntimeError,ValueError):pass
            try:
                if self.reader is None or not self.reader.is_alive():self.process.stdout.close()
            except (OSError, ValueError):
                pass
            self.closed = self.actors_closed()
            if self.closed:self._release_lock()
        verified = self.restored and self.closed
        self.backend._restore_failed = not verified
        return verified

    def actors_closed(self):
        """Passive exact process/reader/pipe proof, not an RF recovery claim."""
        if self._spawn_unknown or self._reader_unknown:return False
        if self._spawn_claimed and not self._spawn_resolved:return False
        if self._reader_claimed and not self._reader_resolved:return False
        if self.reader is not None and self.reader.is_alive():return False
        if self.process is None:return not self._spawn_claimed
        try:return (self.process.poll() is not None and self.process.stdin.closed is True and
                    self.process.stdout.closed is True)
        except Exception:return False

    close = restore

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        if not self.restore():
            raise WifiRestoreError(_REASONS['NETWORK_RESTORE_NOT_CONFIRMED'])
        return False
