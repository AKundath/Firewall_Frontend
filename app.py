# app.py
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
from system_update import SystemUpdater
from snapshot_manager import SnapshotManager
from FirewallScript import NetworkConfigManager
from ip_manager import IPManager
import subprocess
import os
import sys
from functools import wraps
import queue
import threading
import time

app = Flask(__name__)

# Queue for storing console output
output_queue = queue.Queue()

def check_sudo():
    """Check if the application is running with sudo privileges."""
    return os.geteuid() == 0

def requires_sudo(f):
    """Decorator to check for sudo privileges."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not check_sudo():
            return jsonify({
                'status': 'error',
                'message': 'This operation requires sudo privileges.'
            }), 403
        return f(*args, **kwargs)
    return decorated_function

def enqueue_output(pipe, queue):
    """Helper function to enqueue output from a pipe."""
    for line in iter(pipe.readline, b''):
        queue.put(line.decode())
    pipe.close()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/stream')
def stream():
    """Stream console output."""
    def generate():
        while True:
            try:
                output = output_queue.get_nowait()
                yield f"data: {output}\n\n"
            except queue.Empty:
                time.sleep(0.1)
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/system/update', methods=['POST'])
@requires_sudo
def system_update():
    updater = SystemUpdater()
    success = updater.update_system()
    return jsonify({'status': 'success' if success else 'error'})

@app.route('/snapshot/create', methods=['POST'])
@requires_sudo
def create_snapshot():
    description = request.json.get('description')
    snapshot = SnapshotManager()
    success = snapshot.create_snapshot(description)
    return jsonify({'status': 'success' if success else 'error'})

@app.route('/snapshot/list', methods=['GET'])
@requires_sudo
def list_snapshots():
    snapshot = SnapshotManager()
    success = snapshot.list_snapshots()
    return jsonify({'status': 'success' if success else 'error'})

@app.route('/firewall/status', methods=['GET'])
@requires_sudo
def firewall_status():
    firewall = NetworkConfigManager()
    status = firewall.check_ufw_status()
    return jsonify(status)

@app.route('/firewall/toggle', methods=['POST'])
@requires_sudo
def toggle_firewall():
    firewall = NetworkConfigManager()
    action = request.json.get('action')
    success = firewall.enable_ufw() if action == 'enable' else firewall.disable_ufw()
    return jsonify({'status': 'success' if success else 'error'})

@app.route('/firewall/port', methods=['POST'])
@requires_sudo
def manage_port():
    firewall = NetworkConfigManager()
    action = request.json.get('action')
    port = request.json.get('port')
    protocol = request.json.get('protocol', 'tcp')
    
    if action == 'open':
        success = firewall.add_rule(port, protocol)
    else:
        success = firewall.delete_rule(port, protocol)
    return jsonify({'status': 'success' if success else 'error'})

@app.route('/ip/manage', methods=['POST'])
@requires_sudo
def manage_ip():
    ip_manager = IPManager()
    action = request.json.get('action')
    ip_address = request.json.get('ip_address')
    
    if action == 'allow':
        success = ip_manager.allow_ip(ip_address)
    elif action == 'deny':
        success = ip_manager.deny_ip(ip_address)
    elif action == 'delete':
        success = ip_manager.delete_rules(ip_address)
    else:
        return jsonify({'status': 'error', 'message': 'Invalid action'})
        
    return jsonify({'status': 'success' if success else 'error'})

if __name__ == '__main__':
    if not check_sudo():
        print("This application must be run with sudo privileges.")
        sys.exit(1)
    app.run(debug=True)