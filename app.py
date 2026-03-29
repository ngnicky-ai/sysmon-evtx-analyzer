import os
import json
from datetime import datetime
from collections import Counter, defaultdict
from Evtx import PyEvtxParser
from flask import Flask, render_template, request, send_file, redirect, url_for, session, make_response
import tempfile

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
app.secret_key = os.urandom(24)

MAX_UPLOAD_MB = 500

_analysis_cache = {}

SYSMON_EVENT_NAMES = {
    1: "Process Create",
    2: "File Creation Time Changed",
    3: "Network Connection",
    4: "Sysmon Service State Changed",
    5: "Process Terminated",
    6: "Driver Loaded",
    7: "Image Loaded",
    8: "CreateRemoteThread",
    9: "RawAccessRead",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "Registry Event (Create/Delete)",
    13: "Registry Event (Value Set)",
    14: "Registry Event (Rename)",
    15: "FileCreateStreamHash",
    17: "PipeEvent (Created)",
    18: "PipeEvent (Connected)",
    22: "DNSEvent",
    23: "FileDelete",
    25: "ProcessTampering",
    26: "FileDeleteDetected",
}

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#6b7280",
}


def parse_evtx(filepath):
    parser = PyEvtxParser(filepath)
    events = []
    for record in parser.records_json():
        try:
            data = json.loads(record['data'])
            event = data.get('Event', {})
            system = event.get('System', {})
            event_data = event.get('EventData', {})

            event_id = system.get('EventID', 0)
            if isinstance(event_id, dict):
                event_id = event_id.get('#text', 0)
            event_id = int(event_id)

            time_created = system.get('TimeCreated', {}).get('#attributes', {}).get('SystemTime', '')

            events.append({
                'event_id': event_id,
                'event_name': SYSMON_EVENT_NAMES.get(event_id, f"Unknown ({event_id})"),
                'timestamp': time_created,
                'record_id': system.get('EventRecordID', ''),
                'computer': system.get('Computer', ''),
                'event_data': event_data,
                'raw': data,
            })
        except Exception:
            continue

    events.sort(key=lambda e: e['timestamp'])
    return events


def detect_threats(events):
    threats = []

    suspicious_processes = [
        'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
        'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe',
        'bitsadmin.exe', 'msiexec.exe', 'wmic.exe',
    ]

    suspicious_parents = [
        'hfs.exe', 'httpd.exe', 'nginx.exe', 'w3wp.exe',
        'tomcat', 'java.exe', 'node.exe',
    ]

    suspicious_paths = [
        '\\temp\\', '\\tmp\\', '\\appdata\\', '\\programdata\\',
        '\\downloads\\', '\\public\\',
    ]

    suspicious_extensions = ['.vbs', '.js', '.bat', '.ps1', '.hta', '.wsf', '.scr']

    suspicious_ports = [4444, 4445, 5555, 8888, 1234, 31337, 6666, 7777, 9999]

    for evt in events:
        ed = evt['event_data']

        if evt['event_id'] == 1:
            image = (ed.get('Image', '') or '').lower()
            cmd = (ed.get('CommandLine', '') or '').lower()
            parent = (ed.get('ParentImage', '') or '').lower()
            parent_cmd = (ed.get('ParentCommandLine', '') or '').lower()
            user = ed.get('User', '')
            integrity = ed.get('IntegrityLevel', '')

            proc_name = os.path.basename(image)
            parent_name = os.path.basename(parent)

            for sp in suspicious_parents:
                if sp in parent:
                    threats.append({
                        'severity': 'critical',
                        'title': f'Web Server Spawned Process',
                        'description': f'웹 서버 프로세스({parent_name})가 자식 프로세스({proc_name})를 생성했습니다. '
                                       f'웹 쉘이나 원격 코드 실행(RCE) 취약점이 악용되었을 수 있습니다.',
                        'detail': f'부모: {ed.get("ParentImage", "")}\n'
                                  f'자식: {ed.get("Image", "")}\n'
                                  f'명령어: {ed.get("CommandLine", "")}\n'
                                  f'사용자: {user} | 무결성: {integrity}',
                        'timestamp': evt['timestamp'],
                        'event': evt,
                        'mitre': 'T1190 (Exploit Public-Facing Application)',
                    })
                    break

            for sp in suspicious_processes:
                if sp in image:
                    severity = 'high'
                    if any(p in parent for p in suspicious_parents):
                        severity = 'critical'

                    threats.append({
                        'severity': severity,
                        'title': f'Suspicious Process Execution: {proc_name}',
                        'description': f'의심스러운 프로세스({proc_name})가 실행되었습니다. '
                                       f'공격자가 스크립트 실행 또는 LOLBins를 사용하고 있을 수 있습니다.',
                        'detail': f'프로세스: {ed.get("Image", "")}\n'
                                  f'명령어: {ed.get("CommandLine", "")}\n'
                                  f'부모 프로세스: {ed.get("ParentImage", "")}\n'
                                  f'부모 명령어: {ed.get("ParentCommandLine", "")}',
                        'timestamp': evt['timestamp'],
                        'event': evt,
                        'mitre': 'T1059 (Command and Scripting Interpreter)',
                    })
                    break

            for ext in suspicious_extensions:
                if ext in cmd:
                    threats.append({
                        'severity': 'high',
                        'title': f'Suspicious Script Execution ({ext})',
                        'description': f'의심스러운 스크립트 파일({ext})이 실행되었습니다. '
                                       f'악성 스크립트를 통한 공격일 수 있습니다.',
                        'detail': f'명령어: {ed.get("CommandLine", "")}\n'
                                  f'프로세스: {ed.get("Image", "")}',
                        'timestamp': evt['timestamp'],
                        'event': evt,
                        'mitre': 'T1059.005 (Visual Basic)',
                    })
                    break

            for sp in suspicious_paths:
                if sp in cmd:
                    threats.append({
                        'severity': 'medium',
                        'title': 'Execution from Suspicious Path',
                        'description': f'의심스러운 경로에서 파일이 실행되었습니다. '
                                       f'공격자가 임시 디렉토리를 사용하여 악성 파일을 실행하고 있을 수 있습니다.',
                        'detail': f'명령어: {ed.get("CommandLine", "")}\n'
                                  f'경로: {sp.strip(chr(92))}',
                        'timestamp': evt['timestamp'],
                        'event': evt,
                        'mitre': 'T1204 (User Execution)',
                    })
                    break

            if integrity == 'High' or integrity == 'System':
                threats.append({
                    'severity': 'medium',
                    'title': f'Elevated Process Execution ({integrity})',
                    'description': f'높은 권한({integrity})으로 프로세스가 실행되었습니다.',
                    'detail': f'프로세스: {ed.get("Image", "")}\n'
                              f'사용자: {user}',
                    'timestamp': evt['timestamp'],
                    'event': evt,
                    'mitre': 'T1548 (Abuse Elevation Control)',
                })

        elif evt['event_id'] == 3:
            image = (ed.get('Image', '') or '').lower()
            src_ip = ed.get('SourceIp', '')
            dst_ip = ed.get('DestinationIp', '')
            dst_port = ed.get('DestinationPort', 0)
            src_port = ed.get('SourcePort', 0)
            initiated = ed.get('Initiated', '')
            proc_name = os.path.basename(image)

            try:
                dst_port = int(dst_port)
            except (ValueError, TypeError):
                dst_port = 0
            try:
                src_port = int(src_port)
            except (ValueError, TypeError):
                src_port = 0

            if dst_port in suspicious_ports or src_port in suspicious_ports:
                threats.append({
                    'severity': 'critical',
                    'title': f'Connection on Suspicious Port ({dst_port or src_port})',
                    'description': f'알려진 의심스러운 포트에서 네트워크 연결이 감지되었습니다. '
                                   f'리버스 쉘이나 C2 통신일 수 있습니다.',
                    'detail': f'프로세스: {ed.get("Image", "")}\n'
                              f'{src_ip}:{src_port} → {dst_ip}:{dst_port}',
                    'timestamp': evt['timestamp'],
                    'event': evt,
                    'mitre': 'T1571 (Non-Standard Port)',
                })

            for sp in suspicious_processes:
                if sp in image and initiated:
                    threats.append({
                        'severity': 'high',
                        'title': f'Outbound Connection by {proc_name}',
                        'description': f'의심스러운 프로세스({proc_name})가 외부 네트워크 연결을 시도했습니다.',
                        'detail': f'{src_ip}:{src_port} → {dst_ip}:{dst_port}\n'
                                  f'프로세스: {ed.get("Image", "")}',
                        'timestamp': evt['timestamp'],
                        'event': evt,
                        'mitre': 'T1071 (Application Layer Protocol)',
                    })
                    break

            if any(sp in image for sp in suspicious_parents):
                unique_ips = set()
                conn_key = f"{dst_ip}:{dst_port}"
                if conn_key not in unique_ips:
                    unique_ips.add(conn_key)
                    threats.append({
                        'severity': 'medium',
                        'title': f'Web Server Network Activity: {proc_name}',
                        'description': f'웹 서버 프로세스의 네트워크 연결이 감지되었습니다.',
                        'detail': f'{src_ip}:{src_port} → {dst_ip}:{dst_port}\n'
                                  f'프로세스: {ed.get("Image", "")}',
                        'timestamp': evt['timestamp'],
                        'event': evt,
                        'mitre': 'T1071 (Application Layer Protocol)',
                    })

        elif evt['event_id'] == 6:
            signed = (ed.get('Signed', '') or '').lower()
            sig_status = (ed.get('SignatureStatus', '') or '').lower()
            image_loaded = ed.get('ImageLoaded', '')

            if signed == 'false' or sig_status != 'valid':
                threats.append({
                    'severity': 'high',
                    'title': 'Unsigned/Invalid Driver Loaded',
                    'description': f'서명되지 않았거나 유효하지 않은 드라이버가 로드되었습니다. '
                                   f'루트킷이나 악성 드라이버일 수 있습니다.',
                    'detail': f'드라이버: {image_loaded}\n'
                              f'서명: {ed.get("Signed", "")} | 상태: {ed.get("SignatureStatus", "")}',
                    'timestamp': evt['timestamp'],
                    'event': evt,
                    'mitre': 'T1014 (Rootkit)',
                })

    seen = set()
    unique_threats = []
    for t in threats:
        key = (t['title'], t['timestamp'])
        if key not in seen:
            seen.add(key)
            unique_threats.append(t)

    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    unique_threats.sort(key=lambda t: (severity_order.get(t['severity'], 5), t['timestamp']))

    return unique_threats


def _build_process_graph(process_creates, network_conns, process_terms):
    nodes = {}
    for e in process_creates:
        ed = e['event_data']
        guid = ed.get('ProcessGuid', '')
        parent_guid = ed.get('ParentProcessGuid', '')
        image = ed.get('Image', '')
        name = os.path.basename(image)
        nodes[guid] = {
            'guid': guid,
            'parent_guid': parent_guid,
            'name': name,
            'image': image,
            'pid': ed.get('ProcessId', ''),
            'cmd': ed.get('CommandLine', ''),
            'parent_image': ed.get('ParentImage', ''),
            'parent_name': os.path.basename(ed.get('ParentImage', '')),
            'user': ed.get('User', ''),
            'integrity': ed.get('IntegrityLevel', ''),
            'timestamp': e['timestamp'],
            'children': [],
            'network': [],
            'terminated': False,
        }

    net_by_guid = defaultdict(list)
    net_by_image = defaultdict(list)
    for e in network_conns:
        ed = e['event_data']
        conn = {
            'src_ip': ed.get('SourceIp', ''),
            'src_port': ed.get('SourcePort', ''),
            'dst_ip': ed.get('DestinationIp', ''),
            'dst_port': ed.get('DestinationPort', ''),
            'protocol': ed.get('Protocol', ''),
            'initiated': ed.get('Initiated', ''),
            'timestamp': e['timestamp'],
        }
        guid = ed.get('ProcessGuid', '')
        image = ed.get('Image', '')
        net_by_guid[guid].append(conn)
        net_by_image[image.lower()].append(conn)

    term_guids = set()
    for e in process_terms:
        ed = e['event_data']
        term_guids.add(ed.get('ProcessGuid', ''))

    for guid, node in nodes.items():
        if guid in net_by_guid:
            node['network'] = net_by_guid[guid]
        elif node['image'].lower() in net_by_image:
            node['network'] = net_by_image[node['image'].lower()]
        if guid in term_guids:
            node['terminated'] = True

    for guid, node in nodes.items():
        pg = node['parent_guid']
        if pg in nodes:
            nodes[pg]['children'].append(guid)

    child_guids = set()
    for node in nodes.values():
        child_guids.update(node['children'])
    root_guids = [g for g in nodes if g not in child_guids]

    def build_tree(guid, depth=0):
        node = nodes[guid]
        result = dict(node)
        result['depth'] = depth
        result['children_nodes'] = [build_tree(cg, depth + 1) for cg in node['children']]
        return result

    trees = [build_tree(g) for g in root_guids]
    trees.sort(key=lambda t: t['timestamp'])

    virtual_parents = {}
    for guid, node in nodes.items():
        pg = node['parent_guid']
        if pg not in nodes and pg:
            if pg not in virtual_parents:
                virtual_parents[pg] = {
                    'guid': pg,
                    'parent_guid': '',
                    'name': node['parent_name'],
                    'image': node['parent_image'],
                    'pid': '',
                    'cmd': '',
                    'parent_image': '',
                    'parent_name': '',
                    'user': '',
                    'integrity': '',
                    'timestamp': '',
                    'children': [],
                    'network': [],
                    'terminated': False,
                    'virtual': True,
                    'depth': 0,
                    'children_nodes': [],
                }
                img_lower = node['parent_image'].lower()
                if img_lower in net_by_image:
                    virtual_parents[pg]['network'] = net_by_image[img_lower]

    for guid, node in nodes.items():
        pg = node['parent_guid']
        if pg in virtual_parents:
            vp = virtual_parents[pg]
            already = any(c['guid'] == guid for c in vp['children_nodes'])
            if not already:
                vp['children_nodes'].append(build_tree(guid, 1))

    final_trees = []
    used_roots = set()
    for pg, vp in virtual_parents.items():
        if vp['children_nodes']:
            final_trees.append(vp)
            for c in vp['children_nodes']:
                used_roots.add(c['guid'])

    for t in trees:
        if t['guid'] not in used_roots:
            final_trees.append(t)

    final_trees.sort(key=lambda t: t.get('timestamp', '') or 'z')
    return final_trees


def build_analysis(events):
    total = len(events)
    eid_counter = Counter(e['event_id'] for e in events)

    timestamps = [e['timestamp'] for e in events if e['timestamp']]
    time_range = {
        'start': min(timestamps) if timestamps else '',
        'end': max(timestamps) if timestamps else '',
    }

    computers = set(e['computer'] for e in events)
    users = set(e['event_data'].get('User', '') for e in events if e['event_data'].get('User'))

    process_creates = [e for e in events if e['event_id'] == 1]
    network_conns = [e for e in events if e['event_id'] == 3]
    process_terms = [e for e in events if e['event_id'] == 5]
    drivers = [e for e in events if e['event_id'] == 6]

    unique_processes = set()
    process_tree = []
    for e in process_creates:
        ed = e['event_data']
        proc_info = {
            'image': ed.get('Image', ''),
            'pid': ed.get('ProcessId', ''),
            'cmd': ed.get('CommandLine', ''),
            'parent_image': ed.get('ParentImage', ''),
            'parent_pid': ed.get('ParentProcessId', ''),
            'user': ed.get('User', ''),
            'integrity': ed.get('IntegrityLevel', ''),
            'timestamp': e['timestamp'],
        }
        unique_processes.add(ed.get('Image', ''))
        process_tree.append(proc_info)

    network_summary = []
    for e in network_conns:
        ed = e['event_data']
        network_summary.append({
            'process': ed.get('Image', ''),
            'src_ip': ed.get('SourceIp', ''),
            'src_port': ed.get('SourcePort', ''),
            'dst_ip': ed.get('DestinationIp', ''),
            'dst_port': ed.get('DestinationPort', ''),
            'protocol': ed.get('Protocol', ''),
            'initiated': ed.get('Initiated', ''),
            'timestamp': e['timestamp'],
        })

    ip_counter = Counter()
    for n in network_summary:
        ip_counter[n['dst_ip']] += 1
        ip_counter[n['src_ip']] += 1

    timeline_data = []
    for e in events:
        ed = e['event_data']
        label = ''
        if e['event_id'] == 1:
            label = f"Process: {os.path.basename(ed.get('Image', ''))}"
        elif e['event_id'] == 3:
            label = f"Net: {ed.get('SourceIp', '')}:{ed.get('SourcePort', '')} → {ed.get('DestinationIp', '')}:{ed.get('DestinationPort', '')}"
        elif e['event_id'] == 5:
            label = f"Terminated: {os.path.basename(ed.get('Image', ''))}"
        elif e['event_id'] == 6:
            label = f"Driver: {os.path.basename(ed.get('ImageLoaded', ''))}"
        else:
            label = f"Event {e['event_id']}"

        timeline_data.append({
            'timestamp': e['timestamp'],
            'event_id': e['event_id'],
            'event_name': e['event_name'],
            'label': label,
            'record_id': e['record_id'],
        })

    threats = detect_threats(events)

    proc_graph = _build_process_graph(process_creates, network_conns, process_terms)

    return {
        'total_events': total,
        'eid_distribution': dict(eid_counter),
        'time_range': time_range,
        'computers': list(computers),
        'users': list(users),
        'process_tree': process_tree,
        'network_summary': network_summary,
        'ip_counter': dict(ip_counter.most_common(20)),
        'unique_processes': list(unique_processes),
        'timeline': timeline_data,
        'threats': threats,
        'threat_summary': {
            'critical': sum(1 for t in threats if t['severity'] == 'critical'),
            'high': sum(1 for t in threats if t['severity'] == 'high'),
            'medium': sum(1 for t in threats if t['severity'] == 'medium'),
            'low': sum(1 for t in threats if t['severity'] == 'low'),
            'info': sum(1 for t in threats if t['severity'] == 'info'),
        },
        'drivers_loaded': len(drivers),
        'proc_graph': proc_graph,
    }


@app.errorhandler(413)
def request_entity_too_large(error):
    return render_template('index.html',
                           error=f'파일 크기가 {MAX_UPLOAD_MB}MB 제한을 초과했습니다. 더 작은 파일을 업로드해 주세요.'), 413


@app.route('/')
def index():
    return render_template('index.html', max_upload_mb=MAX_UPLOAD_MB)


@app.route('/analyze', methods=['POST'])
def analyze():
    if 'evtx_file' not in request.files:
        return redirect(url_for('index'))

    file = request.files['evtx_file']
    if file.filename == '':
        return redirect(url_for('index'))

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)
    file_size_mb = os.path.getsize(filepath) / (1024 * 1024)

    try:
        events = parse_evtx(filepath)
        analysis = build_analysis(events)
        analysis['filename'] = file.filename
        analysis['file_size_mb'] = round(file_size_mb, 1)
        cache_key = os.urandom(8).hex()
        _analysis_cache[cache_key] = analysis
        return render_template('result.html', analysis=analysis, cache_key=cache_key)
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


@app.route('/analyze_default')
def analyze_default():
    default_file = os.path.join(os.path.dirname(__file__), '01_sysmon_quiz.evtx')
    if not os.path.exists(default_file):
        return redirect(url_for('index'))

    file_size_mb = os.path.getsize(default_file) / (1024 * 1024)
    events = parse_evtx(default_file)
    analysis = build_analysis(events)
    analysis['filename'] = '01_sysmon_quiz.evtx'
    analysis['file_size_mb'] = round(file_size_mb, 1)
    cache_key = os.urandom(8).hex()
    _analysis_cache[cache_key] = analysis
    return render_template('result.html', analysis=analysis, cache_key=cache_key)


@app.route('/download_report/<cache_key>')
def download_report(cache_key):
    analysis = _analysis_cache.get(cache_key)
    if not analysis:
        return redirect(url_for('index'))

    html = render_template('report_download.html', analysis=analysis)
    response = make_response(html)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['Content-Disposition'] = 'attachment; filename=sysmon_analysis_report.html'
    return response


if __name__ == '__main__':
    app.run(debug=True, port=5000)
