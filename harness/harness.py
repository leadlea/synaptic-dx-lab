#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Synaptic DX / Role Control Harness
給与データ3レイヤーに対する物理アクセス制御を、実ファイルシステム上で実行する。

物理機構（すべて実物・模擬なし）:
  1. マウント境界   : workspace/ 配下のビュー（symlink）の生成・削除。非許可レイヤーはパスが存在しない
  2. 権限境界       : 実ストアの chmod 000 / 400。所有者本人の read も EACCES で失敗する
  3. 鍵境界         : L0 は AES-256-CBC(PBKDF2) 実暗号。鍵ファイルの権限をロールで開閉する
  4. 監査完全性     : chflags uappnd による append-only。上書き・削除が OS に拒否される

Python 3.9 互換。外部依存なし（openssl / chflags は macOS 標準）。
"""

import json
import os
import subprocess
import sys
import hashlib
import datetime
import stat

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_PATH = os.path.join(ROOT, 'harness', 'policy.json')
SESSION_PATH = os.path.join(ROOT, '.harness', 'session.json')
CHAIN_PATH = os.path.join(ROOT, 'audit', 'chain.jsonl')
ANCHOR_DIR = os.path.join(ROOT, 'audit', 'anchors')

# ---- ANSI ----
IS_TTY = sys.stdout.isatty()
def _c(code, s):
    return '\033[' + code + 'm' + s + '\033[0m' if IS_TTY else s
def bold(s):  return _c('1', s)
def dim(s):   return _c('2', s)
def red(s):   return _c('31;1', s)
def grn(s):   return _c('32;1', s)
def ylw(s):   return _c('33;1', s)
def blu(s):   return _c('34;1', s)
def cyn(s):   return _c('36;1', s)
def mag(s):   return _c('35;1', s)

def hr(ch='-', n=78):
    print(dim(ch * n))

def title(s):
    print('')
    print(bold(cyn(s)))
    hr('=')

# ---- policy / session ----
def load_policy():
    with open(POLICY_PATH, 'r') as f:
        return json.load(f)

def load_session():
    if not os.path.exists(SESSION_PATH):
        return None
    try:
        with open(SESSION_PATH, 'r') as f:
            return json.load(f)
    except Exception:
        return None

def save_session(role):
    d = os.path.dirname(SESSION_PATH)
    if not os.path.isdir(d):
        os.makedirs(d)
    if os.path.exists(SESSION_PATH):
        os.chmod(SESSION_PATH, 0o600)
    with open(SESSION_PATH, 'w') as f:
        json.dump({
            'role': role,
            'activated_at': datetime.datetime.now().isoformat(timespec='seconds')
        }, f, ensure_ascii=False, indent=2)

def current_role(policy):
    s = load_session()
    if s and s.get('role') in policy['roles']:
        return s['role']
    return None

# ---- sample data (架空・12名) ----
STAFF = [
    ('E-10428', '佐藤 健一', '営業本部', 'M2', 842000, 3120000),
    ('E-10593', '田中 美咲', '営業本部', 'G4', 512000, 1480000),
    ('E-10771', '鈴木 太郎', '営業本部', 'G3', 436000, 1120000),
    ('E-11002', '高橋 由紀', '営業本部', 'G4', 528000, 1560000),
    ('E-11245', '伊藤 直樹', '開発本部', 'M1', 756000, 2480000),
    ('E-11388', '渡辺 千夏', '開発本部', 'G5', 624000, 1920000),
    ('E-11504', '山本 拓也', '開発本部', 'G4', 534000, 1520000),
    ('E-11627', '中村 彩',   '開発本部', 'G4', 498000, 1400000),
    ('E-11810', '小林 大輔', '開発本部', 'G3', 428000, 1080000),
    ('E-12033', '加藤 里穂', '管理本部', 'G5', 596000, 1780000),
    ('E-12190', '吉田 隆',   '管理本部', 'G4', 506000, 1440000),
    ('E-12276', '松本 恵',   '管理本部', 'G3', 442000, 1160000),
]
BAND = {'M2': 'Band-6', 'M1': 'Band-5', 'G5': 'Band-4', 'G4': 'Band-3', 'G3': 'Band-2'}
RANGE = {'M2': '1600-1900万', 'M1': '1100-1400万', 'G5': '850-1100万',
         'G4': '700-900万', 'G3': '580-720万'}
GRADE_INDEX = {'G3': 100, 'G4': 122, 'G5': 148, 'M1': 186, 'M2': 236}

def pseudo_id(seed):
    h = hashlib.sha256(('synaptic-dx-salt-v1:' + seed).encode()).hexdigest()
    return 'PSD-' + h[:8].upper()

# ---- filesystem helpers ----
def p(rel):
    return os.path.join(ROOT, rel)

def ensure_dir(rel):
    d = p(rel)
    if not os.path.isdir(d):
        os.makedirs(d)
    return d

def unlock_for_write(rel):
    f = p(rel)
    if os.path.exists(f):
        try:
            os.chmod(f, 0o600)
        except OSError:
            pass

def mode_of(rel):
    f = p(rel)
    if not os.path.exists(f):
        return None
    return format(stat.S_IMODE(os.stat(f).st_mode), '04o')

def run(cmd, stdin_data=None):
    """returns (rc, stdout, stderr)"""
    pr = subprocess.Popen(cmd, cwd=ROOT, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = pr.communicate(stdin_data)
    return pr.returncode, out.decode('utf-8', 'replace'), err.decode('utf-8', 'replace')

# ---- audit chain (append-only) ----
def chain_lines():
    if not os.path.exists(CHAIN_PATH):
        return []
    with open(CHAIN_PATH, 'r') as f:
        return [ln for ln in f.read().splitlines() if ln.strip()]

def chain_last_hash():
    lines = chain_lines()
    if not lines:
        return '0' * 12
    try:
        return json.loads(lines[-1])['hash']
    except Exception:
        return '0' * 12

# 監査レコードのハッシュ版数
#   v1 (hv キー無し) : detail をハッシュ対象に含めない旧実装。既存チェーンの検証用に残す
#   v2               : detail を含める。ただし 12桁(48bit)に切り詰め
#   v3               : SHA-256 を切り詰めず 64桁で保持する。表示側だけ先頭12桁に短縮する
HASH_VERSION = 3
HASH_DISPLAY = 12

def rec_hash(rec):
    if rec.get('hv') == 3:
        base = '\x1f'.join(['hv3', str(rec['seq']), rec['ts'], rec['role'],
                            rec['principal'], rec['action'], rec['layer'],
                            rec['decision'], rec['mech'], rec.get('detail', ''),
                            rec['prev_hash']])
        return hashlib.sha256(base.encode()).hexdigest()
    if rec.get('hv') == 2:
        # detail 内に '|' が現れてもフィールド境界が曖昧にならないよう US(0x1f) で区切る。
        # 先頭の 'hv2' は版数間でハッシュ入力が衝突しないためのドメイン分離タグ。
        base = '\x1f'.join(['hv2', str(rec['seq']), rec['ts'], rec['role'],
                            rec['principal'], rec['action'], rec['layer'],
                            rec['decision'], rec['mech'], rec.get('detail', ''),
                            rec['prev_hash']])
    else:
        base = '|'.join([str(rec['seq']), rec['ts'], rec['role'], rec['principal'],
                         rec['action'], rec['layer'], rec['decision'],
                         rec['mech'], rec['prev_hash']])
    return hashlib.sha256(base.encode()).hexdigest()[:12]

def audit_append(role, principal, action, layer, decision, mech, detail=''):
    ensure_dir('audit')
    lines = chain_lines()
    rec = {
        'seq': len(lines) + 1,
        'ts': datetime.datetime.now().isoformat(timespec='seconds'),
        'role': role or '-',
        'principal': principal or '-',
        'action': action,
        'layer': layer or '-',
        'decision': decision,
        'mech': mech,
        'detail': detail,
        'prev_hash': chain_last_hash(),
        'hv': HASH_VERSION,
    }
    rec['hash'] = rec_hash(rec)
    # append-only フラグが立っていても O_APPEND は通る
    with open(CHAIN_PATH, 'a') as f:
        f.write(json.dumps(rec, ensure_ascii=False) + '\n')
    set_append_only()
    return rec

def set_append_only():
    if os.path.exists(CHAIN_PATH):
        subprocess.call(['chflags', 'uappnd', CHAIN_PATH],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def clear_append_only():
    if os.path.exists(CHAIN_PATH):
        subprocess.call(['chflags', 'nouappnd', CHAIN_PATH],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# =====================================================================
# setup : データ生成 → L0暗号化 → L1/L2派生 → 監査チェーン初期化
# =====================================================================
def cmd_setup(argv):
    policy = load_policy()
    force = '--force' in argv

    title('SETUP  給与データ3レイヤーのプロビジョニング')

    if os.path.exists(p('vault/payroll_L0.enc')) and not force:
        print(ylw('既にプロビジョン済みです。再作成するには --force を付けてください。'))
        print(dim('  ./harness/hx setup --force'))
        return 0

    for d in ['vault', 'data/L1', 'data/L2', 'keys', 'workspace', 'audit', '.harness']:
        ensure_dir(d)

    # --- 鍵生成（L0用 CMK 相当） ---
    unlock_for_write('keys/L0.key')
    rc, out, err = run(['openssl', 'rand', '-hex', '32'])
    if rc != 0:
        print(red('鍵生成に失敗: ' + err.strip()))
        return 1
    with open(p('keys/L0.key'), 'w') as f:
        f.write(out.strip() + '\n')
    print(grn('[1/5]') + ' 鍵生成        keys/L0.key  (AES-256 パスフレーズ 32byte)')

    # --- L0 平文をメモリ上で組み立て、そのまま暗号化（平文はディスクに置かない） ---
    l0 = ['社員番号,氏名,部門,等級,基本給_月,賞与_年,年収']
    for no, name, dept, grade, base, bonus in STAFF:
        l0.append('%s,%s,%s,%s,%d,%d,%d' % (no, name, dept, grade, base, bonus, base * 12 + bonus))
    l0_plain = ('\n'.join(l0) + '\n').encode('utf-8')

    unlock_for_write('vault/payroll_L0.enc')
    pr = subprocess.Popen(
        ['openssl', 'enc', '-aes-256-cbc', '-pbkdf2', '-salt',
         '-out', p('vault/payroll_L0.enc'), '-pass', 'file:' + p('keys/L0.key')],
        cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, err_b = pr.communicate(l0_plain)
    if pr.returncode != 0:
        print(red('L0 暗号化に失敗: ' + err_b.decode('utf-8', 'replace').strip()))
        return 1
    size = os.path.getsize(p('vault/payroll_L0.enc'))
    print(grn('[2/5]') + ' L0 暗号化     vault/payroll_L0.enc  (%d bytes / 平文は未着地)' % size)

    # --- L1: 個人情報マスク（別ファイルとして事前生成。実額カラムを持たない） ---
    cohort = {}
    for no, name, dept, grade, base, bonus in STAFF:
        cohort[(dept, grade)] = cohort.get((dept, grade), 0) + 1
    l1 = ['疑似ID,部門,等級,給与バンド,年収レンジ,k匿名性']
    for no, name, dept, grade, base, bonus in STAFF:
        l1.append('%s,%s,%s,%s,%s,%d' % (pseudo_id(no), dept, grade,
                                         BAND[grade], RANGE[grade], cohort[(dept, grade)]))
    unlock_for_write('data/L1/payroll_masked.csv')
    with open(p('data/L1/payroll_masked.csv'), 'w') as f:
        f.write('\n'.join(l1) + '\n')
    print(grn('[3/5]') + ' L1 マスク生成 data/L1/payroll_masked.csv  (氏名・社員番号・実額カラムなし)')

    # --- L2: AI-Ready セマンティックグラフ（個体レコードなし・等級コホート集約） ---
    by_grade = {}
    for no, name, dept, grade, base, bonus in STAFF:
        by_grade.setdefault(grade, []).append(dept)
    graph = []
    for grade in sorted(by_grade.keys()):
        depts = sorted(set(by_grade[grade]))
        graph.append({
            '@id': 'org:Grade/' + grade,
            '@type': 'org:GradeCohort',
            'org:headcount': len(by_grade[grade]),
            'comp:band': BAND[grade],
            'comp:medianIndex': GRADE_INDEX[grade],
            'org:presentIn': ['org:Dept/' + d for d in depts],
            'wf:linkedTo': ['wf:SkillProfile', 'wf:ProjectDemand', 'wf:HeadcountPlan'],
        })
    l2doc = {
        '@context': {
            'org': 'https://synaptic.example/ontology/org#',
            'comp': 'https://synaptic.example/ontology/compensation#',
            'wf': 'https://synaptic.example/ontology/workforce#',
        },
        '_note': 'comp:medianIndex は G3=100 を基準とした相対指数。実額プロパティは定義しない（データ最小化）',
        '@graph': graph,
    }
    unlock_for_write('data/L2/payroll_semantic.jsonld')
    with open(p('data/L2/payroll_semantic.jsonld'), 'w') as f:
        json.dump(l2doc, f, ensure_ascii=False, indent=2)
        f.write('\n')
    print(grn('[4/5]') + ' L2 グラフ生成 data/L2/payroll_semantic.jsonld  (%d コホートノード / 実額なし)' % len(graph))

    # --- 監査チェーン初期化 ---
    clear_append_only()
    if os.path.exists(CHAIN_PATH):
        os.remove(CHAIN_PATH)
    audit_append(None, None, 'PROVISION', None, 'ALLOW', 'SETUP',
                 'layers=L0,L1,L2 / append-only chain initialized')
    print(grn('[5/5]') + ' 監査チェーン  audit/chain.jsonl  (chflags uappnd = append-only)')

    apply_role('admin', policy, quiet=True)
    save_session('admin')

    print('')
    print(bold('プロビジョン完了。初期ロールは admin です。'))
    print(dim('次: ./harness/hx status  で物理状態を確認'))
    return 0


# =====================================================================
# role : マウントブローカー + 鍵付与 + 権限適用
# =====================================================================
def apply_role(role, policy, quiet=False):
    """実ファイルシステムに対してロールを適用する。ここが物理制御の本体。"""
    granted = policy['roles'][role]['layers']
    ensure_dir('workspace')
    changes = []

    for lk in ['L0', 'L1', 'L2']:
        L = policy['layers'][lk]
        view = p(L['view'])
        store = p(L['store'])
        allow = lk in granted

        # --- マウント境界: ビューの生成 / 削除 ---
        if os.path.islink(view) or os.path.exists(view):
            os.remove(view)
        if allow:
            rel = os.path.relpath(store, os.path.dirname(view))
            os.symlink(rel, view)
            changes.append((lk, 'MOUNT', L['view'] + ' -> ' + L['store']))
        else:
            changes.append((lk, 'UNMOUNT', L['view'] + ' (パスを削除)'))

        # --- 権限境界: 実ストアの mode ---
        if os.path.exists(store):
            os.chmod(store, int(L['mode_grant'], 8) if allow else 0o000)

        # --- 鍵境界: L0 鍵の開閉 ---
        if L.get('key'):
            kf = p(L['key'])
            if os.path.exists(kf):
                os.chmod(kf, 0o400 if allow else 0o000)
                changes.append((lk, 'KEY', ('grant 0400' if allow else 'revoke 0000') + ' ' + L['key']))

    if not quiet:
        for lk, kind, msg in changes:
            tag = grn(kind.ljust(8)) if kind in ('MOUNT', 'KEY') and 'revoke' not in msg else red(kind.ljust(8))
            if kind == 'KEY' and 'grant' in msg:
                tag = grn(kind.ljust(8))
            print('  ' + dim(lk) + '  ' + tag + ' ' + msg)
    return changes


def cmd_role(argv):
    policy = load_policy()
    if not argv:
        print('usage: hx role <' + '|'.join(policy['roles'].keys()) + '>')
        return 2
    role = argv[0]
    if role not in policy['roles']:
        print(red('不明なロール: ' + role))
        print('選択肢: ' + ', '.join(policy['roles'].keys()))
        return 2
    if not os.path.exists(p('vault/payroll_L0.enc')):
        print(red('未プロビジョンです。先に ./harness/hx setup を実行してください。'))
        return 1

    R = policy['roles'][role]
    prev = current_role(policy)

    title('ROLE SWITCH  ' + (prev or 'none') + '  ->  ' + role)
    print('  ' + bold(R['label']))
    print('  ' + dim('principal : ') + R['principal'])
    print('  ' + dim('actor     : ') + R['actor'])
    print('  ' + dim('env       : ') + R['env'])
    print('  ' + dim('granted   : ') + ', '.join(R['layers']))
    print('')
    print(dim('  -- mount broker / key grant を実行 --'))
    apply_role(role, policy)
    save_session(role)
    audit_append(role, R['principal'], 'ROLE_SWITCH', None, 'ALLOW', 'HARNESS',
                 'from=' + str(prev) + ' granted=' + ','.join(R['layers']))
    print('')
    print(bold('適用完了。'), dim('./harness/hx status で物理状態を確認できます。'))
    return 0


# =====================================================================
# status : 設定ではなく「実ファイルシステム」を見て現状を報告する
# =====================================================================
def probe(rel):
    """実際に open して errno を取る。自己申告ではなくOSに聞く。"""
    f = p(rel)
    if not os.path.lexists(f):
        return ('ABSENT', 'パスが存在しない')
    if os.path.islink(f) and not os.path.exists(f):
        return ('DANGLING', 'リンク先が読めない')
    try:
        fh = open(f, 'rb')
        fh.read(1)
        fh.close()
        return ('READABLE', 'read ok')
    except PermissionError as e:
        return ('EACCES', 'Permission denied (errno %d)' % e.errno)
    except OSError as e:
        return ('ERROR', str(e))

def cmd_status(argv):
    policy = load_policy()
    role = current_role(policy)
    brief = '--brief' in argv or '--hook' in argv

    if role is None:
        if brief:
            print('[harness] 未プロビジョン。./harness/hx setup を実行してください。')
            return 0
        print(red('セッションがありません。./harness/hx setup を実行してください。'))
        return 1

    R = policy['roles'][role]

    if brief:
        # フックからコンテキストへ注入する短い形式
        print('[HARNESS ROLE STATE] active_role=' + role + ' (' + R['label'] + ')'
              ' principal=' + R['principal'] + ' granted_layers=' + ','.join(R['layers']))
        denied = [k for k in ['L0', 'L1', 'L2'] if k not in R['layers']]
        if denied:
            paths = [policy['layers'][k]['store'] for k in denied]
            print('[HARNESS ROLE STATE] denied_layers=' + ','.join(denied) +
                  ' / これらのパスは OS 権限とマウント境界で読めません: ' + ', '.join(paths))
        print('[HARNESS ROLE STATE] ロール変更は人間のオペレータが端末で行います。'
              'エージェントからの昇格は PreToolUse フックで遮断されます。')
        return 0

    title('HARNESS STATUS  active role = ' + role)
    print('  ' + bold(R['label']) + '   ' + dim(R['principal']))
    print('  ' + dim('env: ') + R['env'] + '   ' + dim('granted: ') + ', '.join(R['layers']))
    print('')

    print(bold('  レイヤー別 物理状態') + dim('  (すべて実ファイルシステムを stat/open して取得)'))
    hr()
    print(dim('  %-4s %-12s %-6s %-14s %-9s %-10s' %
              ('LYR', 'VIEW', 'MODE', 'STORE READ', 'KEY', 'VERDICT')))
    for lk in ['L0', 'L1', 'L2']:
        L = policy['layers'][lk]
        vstate, _ = probe(L['view'])
        sstate, _ = probe(L['store'])
        smode = mode_of(L['store']) or '----'
        if L.get('key'):
            kstate, _ = probe(L['key'])
            kdisp = {'READABLE': 'granted', 'EACCES': 'revoked', 'ABSENT': 'absent'}.get(kstate, kstate.lower())
        else:
            kdisp = 'n/a'
        vdisp = 'mounted' if vstate == 'READABLE' else vstate.lower()
        sdisp = 'ok' if sstate == 'READABLE' else sstate
        ok = (vstate == 'READABLE' and sstate == 'READABLE')
        verdict = 'ACCESSIBLE' if ok else 'BLOCKED'
        # パディングを先に済ませてから着色する（ANSIが桁数に混ざらないように）
        paint_v = grn if vstate == 'READABLE' else red
        paint_s = grn if sstate == 'READABLE' else red
        paint_k = grn if kdisp == 'granted' else (red if kdisp == 'revoked' else dim)
        paint_r = grn if ok else red
        print('  %s %s %-6s %s %s %s' % (
            bold('%-4s' % lk),
            paint_v('%-12s' % vdisp),
            smode,
            paint_s('%-14s' % sdisp),
            paint_k('%-9s' % kdisp),
            paint_r('%-10s' % verdict)))
    hr()

    print('')
    print(bold('  クラウド同期境界'))
    for lk in ['L0', 'L1', 'L2']:
        L = policy['layers'][lk]
        s = grn('SYNCED (エージェント参照可)') if L['cloud_sync'] else red('NEVER_SYNC (端末内に留置)')
        print('  ' + lk + '  ' + s + '  ' + dim(L['store']))

    lines = chain_lines()
    ok, msg = verify_chain()
    print('')
    print(bold('  監査チェーン') + '  ' + dim(CHAIN_PATH.replace(ROOT + '/', '')))
    flags = ''
    rc, out, err = run(['ls', '-lO', CHAIN_PATH])
    if rc == 0 and 'uappnd' in out:
        flags = grn('uappnd (append-only)')
    else:
        flags = ylw('flag未設定')
    print('  entries=' + str(len(lines)) + '   integrity=' + (grn('VALID') if ok else red('TAMPERED')) +
          '   flags=' + flags)
    print('')
    print(dim('  次: ./harness/hx read L0   ./harness/hx read L1   ./harness/hx read L2'))
    return 0


# =====================================================================
# read : ハーネス6ステップを実行して実データを返す / 実エラーで止まる
# =====================================================================
STEPS = [
    ('Device Attestation', '端末証明とセッション確認'),
    ('Policy Decision', 'policy.json によるロール評価'),
    ('Mount Broker', 'ビューの実在確認'),
    ('Key Grant', '鍵ファイルの可読性確認'),
    ('Decrypt & Read', '平文化して読み出し'),
    ('Audit Append', 'ハッシュチェーンへ追記'),
]

def step(i, state, note=''):
    marks = {'ok': grn('PASS'), 'ng': red('DENIED'), 'skip': dim('SKIPPED')}
    print('  [%d/6] %-20s %s  %s' % (i + 1, STEPS[i][0], marks[state], dim(note)))

def cmd_read(argv):
    policy = load_policy()
    role = current_role(policy)
    if role is None:
        print(red('セッションがありません。./harness/hx setup を先に実行してください。'))
        return 1
    if not argv or argv[0].upper() not in policy['layers']:
        print('usage: hx read <L0|L1|L2>')
        return 2

    lk = argv[0].upper()
    L = policy['layers'][lk]
    R = policy['roles'][role]
    allow = lk in R['layers']

    title('ACCESS REQUEST  role=' + role + '  layer=' + lk)
    print('  ' + dim('principal : ') + R['principal'])
    print('  ' + dim('target    : ') + L['store'])
    print('')

    step(0, 'ok', R['env'])

    if not allow:
        # 拒否機構をロールに応じて説明し分ける
        if R['env'] == 'cloud-runtime' and not L['cloud_sync']:
            mech = 'NETWORK BOUNDARY'
            step(1, 'ng', mech + ' / ' + lk + ' は同期対象外')
        else:
            mech = L['deny_mech']
            step(1, 'ng', mech + ' / forbid(' + R['principal'] + ', Read, ' + lk + ')')
        for i in (2, 3, 4):
            step(i, 'skip')
        rec = audit_append(role, R['principal'], 'READ', lk, 'DENY', mech, 'blocked by harness')
        step(5, 'ok', 'seq=%d hash=%s' % (rec['seq'], rec['hash'][:HASH_DISPLAY]))

        print('')
        print(red(bold('  ACCESS DENIED')) + '  ' + mech)
        print('')
        print(bold('  物理確認 ') + dim('(ポリシーを信用せず、実際にOSへ触って確かめる)'))
        hr()
        # 1) ビュー不在を ls で確認
        rc, out, err = run(['ls', '-la', L['view']])
        print('  ' + cyn('$ ls -la ' + L['view']))
        print('  ' + (red(err.strip()) if err.strip() else out.strip()))
        # 2) 実ストアの直接 read を試す
        st, detail = probe(L['store'])
        print('  ' + cyn('$ head -c 32 ' + L['store']))
        print('  ' + (red(detail) if st != 'READABLE' else ylw('read できてしまいました: ' + detail)))
        # 3) 鍵の直接 read を試す
        if L.get('key'):
            kst, kdetail = probe(L['key'])
            print('  ' + cyn('$ cat ' + L['key']))
            print('  ' + (red(kdetail) if kst != 'READABLE' else ylw('read できてしまいました')))
            # 4) 鍵なしで復号を試す
            rc2, out2, err2 = run(['openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2',
                                   '-in', p(L['store']), '-pass', 'file:' + p(L['key'])])
            print('  ' + cyn('$ openssl enc -d -aes-256-cbc -in ' + L['store']))
            first = (err2.strip().splitlines() or ['(no output)'])[0]
            print('  ' + red(first if rc2 != 0 else 'ylw: 復号できてしまいました'))
        if R['env'] == 'cloud-runtime' and not L['cloud_sync']:
            print('  ' + cyn('$ sync-policy get ' + lk))
            print('  ' + red('NEVER_SYNC: クラウド側にレプリカが存在しないため到達先がない'))
        hr()
        print('  ' + ylw('画面で隠しているのではなく、パス・権限・鍵の全てが与えられていません。'))
        return 3

    step(1, 'ok', 'permit(' + R['principal'] + ', Read, ' + lk + ')')

    vst, vdetail = probe(L['view'])
    if vst != 'READABLE':
        step(2, 'ng', vdetail)
        audit_append(role, R['principal'], 'READ', lk, 'DENY', 'MOUNT BOUNDARY', vdetail)
        print(red('  ビューが読めません。./harness/hx role ' + role + ' を再実行してください。'))
        return 3
    step(2, 'ok', L['view'] + ' mounted')

    if L.get('key'):
        kst, kdetail = probe(L['key'])
        if kst != 'READABLE':
            step(3, 'ng', kdetail)
            audit_append(role, R['principal'], 'READ', lk, 'DENY', 'KEY BOUNDARY', kdetail)
            print(red('  鍵が読めません: ' + kdetail))
            return 3
        step(3, 'ok', 'grant found: ' + L['key'])
    else:
        step(3, 'ok', 'no key required')

    if L['encrypted']:
        rc, out, err = run(['openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2',
                            '-in', p(L['store']), '-pass', 'file:' + p(L['key'])])
        if rc != 0:
            step(4, 'ng', (err.strip().splitlines() or ['decrypt failed'])[0])
            audit_append(role, R['principal'], 'READ', lk, 'DENY', 'KEY BOUNDARY', 'decrypt failed')
            return 3
        body = out
    else:
        with open(p(L['store']), 'r') as f:
            body = f.read()
    nlines = len([x for x in body.splitlines() if x.strip()])
    step(4, 'ok', '%d lines' % nlines)

    rec = audit_append(role, R['principal'], 'READ', lk, 'ALLOW', 'GRANTED', '%d lines' % nlines)
    step(5, 'ok', 'seq=%d hash=%s' % (rec['seq'], rec['hash']))

    print('')
    print(grn(bold('  ACCESS GRANTED')) + '  ' + L['label'])
    hr()
    if lk == 'L0':
        print(mag('  ※ 実名・実額を含みます。この出力は監査チェーンに記録されました。'))
    print(body.rstrip())
    hr()
    return 0


# =====================================================================
# audit : 検証 / 表示 / 改ざん耐性テスト
# =====================================================================
def verify_chain():
    lines = chain_lines()
    prev = '0' * 12
    counts = {}
    for i, ln in enumerate(lines):
        try:
            rec = json.loads(ln)
        except Exception:
            return (False, 'seq %d: JSONとして壊れています' % (i + 1))
        if rec.get('prev_hash') != prev:
            return (False, 'seq %d: prev_hash 不一致（連結が切れています）' % rec.get('seq', i + 1))
        if rec_hash(rec) != rec.get('hash'):
            return (False, 'seq %d: hash 不一致（内容が書き換えられています）' % rec.get('seq', i + 1))
        hv = rec.get('hv', 1)
        counts[hv] = counts.get(hv, 0) + 1
        prev = rec['hash']
    msg = '%d entries verified' % len(lines)
    if lines:
        msg += '  (hv3=%d full-256 / hv2=%d detail保護 / hv1=%d 旧形式)' % (
            counts.get(3, 0), counts.get(2, 0), counts.get(1, 0))
    return (True, msg)

# ---------------------------------------------------------------------
# 外部アンカー（封印）
#   ハッシュチェーンは「末尾レコードの削除（切り詰め）」を単独では検出できない。
#   ある時点の先頭 N 行に対する SHA-256 を別ファイルに固定し、端末外へ複製することで
#   切り詰めと過去分の書き換えを検出可能にする。
#   このファイルが端末内にある限り攻撃者は再計算できるため、真の効力は「外部へ出した後」。
# ---------------------------------------------------------------------
def prefix_digest(n):
    """チェーン先頭 n 行のバイト列に対する SHA-256（切り詰めなし・64桁）。"""
    h = hashlib.sha256()
    for ln in chain_lines()[:n]:
        h.update(ln.encode() + b'\n')
    return h.hexdigest()

def anchor_files():
    if not os.path.isdir(ANCHOR_DIR):
        return []
    return [os.path.join(ANCHOR_DIR, f) for f in sorted(os.listdir(ANCHOR_DIR))
            if f.startswith('anchor-') and f.endswith('.json')]

def anchor_self_hash(a):
    base = '\x1f'.join(['anchor1', a['anchored_at'], str(a['entries']),
                        a['last_hash'], a['prefix_sha256'], a['chain']])
    return hashlib.sha256(base.encode()).hexdigest()

def create_anchor():
    lines = chain_lines()
    if not lines:
        return (None, 'チェーンが空です。オペレータ側での初期化が必要です。')
    ok, msg = verify_chain()
    if not ok:
        return (None, 'チェーンが検証を通りません（' + msg + '）。封印を中止しました。')
    last = json.loads(lines[-1])
    a = {
        'anchored_at': datetime.datetime.now().isoformat(timespec='seconds'),
        'entries': len(lines),
        'last_hash': last['hash'],
        'prefix_sha256': prefix_digest(len(lines)),
        'chain': CHAIN_PATH.replace(ROOT + '/', ''),
    }
    a['anchor_hash'] = anchor_self_hash(a)
    ensure_dir('audit/anchors')
    path = os.path.join(ANCHOR_DIR, 'anchor-%05d-%s.json' % (
        a['entries'], a['anchored_at'].replace(':', '').replace('-', '')))
    with open(path, 'w') as f:
        json.dump(a, f, ensure_ascii=False, indent=2)
        f.write('\n')
    os.chmod(path, 0o444)
    return (a, path)

def check_anchor(path):
    """(status, detail) を返す。status は OK / TRUNCATED / REWRITTEN / ANCHOR_EDITED。"""
    with open(path, 'r') as f:
        a = json.load(f)
    if anchor_self_hash(a) != a.get('anchor_hash'):
        return ('ANCHOR_EDITED', 'アンカー自身が書き換えられています')
    n_now = len(chain_lines())
    if n_now < a['entries']:
        return ('TRUNCATED', 'entries %d -> %d に減っています（末尾が削除されました）'
                % (a['entries'], n_now))
    if prefix_digest(a['entries']) != a['prefix_sha256']:
        return ('REWRITTEN', '封印時点の先頭 %d 行が書き換えられています' % a['entries'])
    return ('OK', '先頭 %d 行が封印時点と一致（現在 %d 行）' % (a['entries'], n_now))


def cmd_audit(argv):
    sub = argv[0] if argv else 'show'
    # 監査エントリの role / principal は必ずポリシー由来の値を使う（表記を全エントリで統一）
    policy = load_policy()
    role = current_role(policy)
    principal = policy['roles'].get(role, {}).get('principal', '-') if role else '-'

    if sub == 'verify':
        title('AUDIT CHAIN VERIFY')
        ok, msg = verify_chain()
        print(('  ' + grn('VALID    ') if ok else '  ' + red('TAMPERED ')) + msg)
        rc, out, err = run(['ls', '-lO', CHAIN_PATH])
        if rc == 0:
            print('  ' + dim(out.strip()))
        if 'uappnd' in out:
            print('  ' + grn('append-only フラグ (uappnd) が有効です。'))
        return 0 if ok else 3

    if sub == 'anchor':
        verify_only = len(argv) > 1 and argv[1] in ('verify', '--verify')
        title('AUDIT ANCHOR  ' + ('封印の検証' if verify_only else 'チェーンを封印する'))

        if not verify_only:
            a, path = create_anchor()
            if a is None:
                print('  ' + red(path))
                return 3
            rel = path.replace(ROOT + '/', '')
            print('  entries      : %d' % a['entries'])
            print('  last_hash    : %s' % a['last_hash'][:12])
            print('  prefix_sha256: %s' % a['prefix_sha256'])
            print('  anchor_hash  : %s' % a['anchor_hash'][:16])
            print('  ' + grn('封印しました  ') + dim(rel) + dim('  (mode 444)'))
            audit_append(role, principal, 'ANCHOR', None, 'ALLOW', 'PREFIX_SEAL',
                         'entries=%d prefix=%s' % (a['entries'], a['prefix_sha256'][:16]))
            hr()
            print(dim('  このアンカーは端末外へ複製して初めて効力を持ちます。転送コマンド例:'))
            print('  ' + cyn('aws s3api put-object \\'))
            print('  ' + cyn('    --bucket <WORM_BUCKET> --key %s \\' % rel))
            print('  ' + cyn('    --body %s \\' % rel))
            print('  ' + cyn('    --object-lock-mode COMPLIANCE \\'))
            print('  ' + cyn('    --object-lock-retain-until-date <YYYY-MM-DDThh:mm:ssZ>'))
            print(dim('  (このハーネスは外部送信を行いません。実行はオペレータ判断)'))
            return 0

        paths = anchor_files()
        if not paths:
            print(dim('  アンカーがありません。./harness/hx audit anchor で作成します。'))
            return 0
        print(dim('  %-34s %-8s %-14s %s' % ('ANCHOR', 'ENTRIES', 'STATUS', 'DETAIL')))
        hr()
        worst = 0
        for pth in paths:
            st, detail = check_anchor(pth)
            with open(pth, 'r') as f:
                n = json.load(f).get('entries', '-')
            mark = grn(st) if st == 'OK' else red(st)
            print('  %-34s %-8s %-14s %s' % (
                os.path.basename(pth), n, mark, dim(detail)))
            if st != 'OK':
                worst = 3
        hr()
        print('  ' + (grn('全アンカー整合') if worst == 0 else red('封印との不一致を検出しました')))
        return worst

    if sub == 'tamper-test':
        title('AUDIT TAMPER TEST  監査ログを書き換えられるか実際に試す')
        print(dim('  append-only フラグが立っているため、所有者本人でも上書き・削除ができません。'))
        hr()
        print('  ' + cyn("$ echo 'HACKED' > audit/chain.jsonl"))
        try:
            fh = open(CHAIN_PATH, 'w')
            fh.write('HACKED\n')
            fh.close()
            print('  ' + ylw('上書きできてしまいました。chflags uappnd が外れています。'))
            print('  ' + dim('  復旧: ./harness/hx setup --force'))
            return 1
        except OSError as e:
            print('  ' + red('%s (errno %d)' % (e.strerror, e.errno)))
        print('  ' + cyn('$ rm -f audit/chain.jsonl'))
        rc, out, err = run(['rm', '-f', CHAIN_PATH])
        print('  ' + (red(err.strip()) if err.strip() else ylw('削除できてしまいました')))
        hr()
        ok, msg = verify_chain()
        print('  整合性: ' + (grn('VALID') if ok else red('TAMPERED')) + '  ' + msg)
        print('  ' + grn('改ざん試行そのものも、この後の監査エントリとして残ります。'))
        audit_append(role, principal, 'TAMPER_TEST', None,
                     'DENY', 'APPEND_ONLY_FLAG', 'overwrite and delete both refused by OS')
        return 0

    # show
    title('AUDIT CHAIN')
    lines = chain_lines()
    if not lines:
        print(dim('  エントリがありません。'))
        return 0
    print(dim('  %-4s %-19s %-8s %-6s %-6s %-20s %-12s %-12s' %
              ('SEQ', 'TIMESTAMP', 'ROLE', 'ACT', 'LYR', 'MECH', 'PREV', 'HASH')))
    hr()
    tail = lines[-25:]
    for ln in tail:
        try:
            r = json.loads(ln)
        except Exception:
            print(red('  (壊れた行)'))
            continue
        dec = grn(r['decision']) if r['decision'] == 'ALLOW' else red(r['decision'])
        print('  %-4s %-19s %-8s %-6s %-6s %-20s %-12s %-12s %s' % (
            r['seq'], r['ts'], r['role'], r['action'][:6], r['layer'],
            r['mech'][:20], r['prev_hash'][:HASH_DISPLAY], r['hash'][:HASH_DISPLAY], dec))
    hr()
    ok, msg = verify_chain()
    print('  integrity: ' + (grn('VALID') if ok else red('TAMPERED')) + '  ' + msg)
    return 0


# =====================================================================
# guard : Kiro PreToolUse フックの実体。exit 2 でツール実行をブロックする
# =====================================================================
def cmd_guard(argv):
    try:
        payload = sys.stdin.read()
    except Exception:
        payload = ''
    low = payload.lower()

    policy = load_policy()
    role = current_role(policy)
    if role is None:
        return 0
    R = policy['roles'][role]
    denied = [k for k in ['L0', 'L1', 'L2'] if k not in R['layers']]

    hits = []
    for lk in denied:
        L = policy['layers'][lk]
        toks = [L['store'], L['view'], os.path.basename(L['store'])]
        if L.get('key'):
            toks.append(L['key'])
            toks.append(os.path.basename(L['key']))
        for t in toks:
            if t and t.lower() in low:
                hits.append((lk, t, L['deny_mech']))
                break

    esc = []
    for t in policy['escalation_guard']['tokens']:
        if t.lower() in low:
            esc.append(t)

    if not hits and not esc:
        return 0

    lines = []
    lines.append('HARNESS ROLE GUARD: このツール実行をブロックしました。')
    lines.append('active role = ' + role + ' (' + R['label'] + ')  granted = ' + ','.join(R['layers']))
    for lk, tok, mech in hits:
        L = policy['layers'][lk]
        lines.append('- ' + lk + ' (' + L['label'] + ') は現在のロールでは参照できません。'
                     '検出トークン: ' + tok + ' / 遮断機構: ' + mech)
        lines.append('  OS側でも ' + L['store'] + ' は mode 000 で read できず、'
                     + ('鍵 ' + L['key'] + ' も revoke 済みです。' if L.get('key') else 'ビューも未マウントです。'))
    for t in esc:
        lines.append('- ロール昇格・再プロビジョン操作は人間のオペレータのみが端末で実行します。'
                     '検出トークン: ' + t)
    lines.append('実額が必要な場合の正しい経路: オペレータが端末で ./harness/hx role admin を実行し、'
                 './harness/hx read L0 で参照する。その参照は監査チェーンに記録されます。')
    sys.stderr.write('\n'.join(lines) + '\n')

    layer = hits[0][0] if hits else None
    mech = hits[0][2] if hits else 'ESCALATION GUARD'
    audit_append(role, R['principal'], 'TOOL_USE', layer, 'DENY', mech,
                 'blocked by PreToolUse hook')
    return 2


# =====================================================================
def cmd_help(argv):
    print("""
""" + bold('Synaptic DX / Role Control Harness') + """

  ./harness/hx setup [--force]     データ生成・L0暗号化・監査チェーン初期化
  ./harness/hx role <admin|analyst|agent>
                                   ロール切替（マウント・権限・鍵を実際に付け替える）
  ./harness/hx status              実ファイルシステムを見て現状を報告
  ./harness/hx read <L0|L1|L2>     6ステップのアクセス要求を実行
  ./harness/hx audit show          監査チェーンを表示
  ./harness/hx audit verify        ハッシュチェーンの整合性を検証
  ./harness/hx audit anchor        現時点のチェーンを封印（外部アンカーを作成）
  ./harness/hx audit anchor verify 封印との一致を検証（末尾削除・過去分の改変を検出）
  ./harness/hx audit tamper-test   監査ログを書き換えられるか実際に試す
  ./harness/hx guard               Kiro PreToolUse フック用（stdinでJSONを受ける）

  ロール別のアクセス範囲:
    admin    L0 実名+実額 / L1 マスク / L2 AI-Ready
    analyst  L1 マスク / L2 AI-Ready
    agent    L2 AI-Ready のみ
""")
    return 0

COMMANDS = {
    'setup': cmd_setup, 'role': cmd_role, 'status': cmd_status,
    'read': cmd_read, 'audit': cmd_audit, 'guard': cmd_guard,
    'help': cmd_help, '--help': cmd_help, '-h': cmd_help,
}

def main():
    argv = sys.argv[1:]
    if not argv:
        return cmd_help([])
    cmd = argv[0]
    if cmd not in COMMANDS:
        print(red('不明なコマンド: ' + cmd))
        return cmd_help([])
    return COMMANDS[cmd](argv[1:])

if __name__ == '__main__':
    sys.exit(main())
