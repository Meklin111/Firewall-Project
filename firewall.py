import sys
from scapy.all import *
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget, 
                            QPushButton, QTextEdit, QLabel, QLineEdit, 
                            QHBoxLayout, QCheckBox, QTableWidget, 
                            QTableWidgetItem, QHeaderView)
from PyQt5.QtCore import Qt, QTimer
import threading
import time

class FirewallRule:
    def __init__(self, name, protocol, src_ip, dst_ip, src_port, dst_port, action):
        self.name = name
        self.protocol = protocol
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.action = action  # 'allow' or 'block'

class PersonalFirewall(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Personal Firewall")
        self.setGeometry(100, 100, 800, 600)
        
        # Firewall state
        self.is_running = False
        self.rules = []
        self.packet_count = 0
        self.blocked_count = 0
        
        # Default rules
        self.add_default_rules()
        
        # UI Setup
        self.init_ui()
        
        # Packet capture thread
        self.capture_thread = None
        self.stop_capture = threading.Event()
        
    def add_default_rules(self):
        # Allow localhost traffic
        self.rules.append(FirewallRule("Allow localhost", "ALL", "127.0.0.1", None, None, None, "allow"))
        
        # Block some known malicious IPs (example)
        self.rules.append(FirewallRule("Block malicious IP", "ALL", "192.168.1.100", None, None, None, "block"))
        
        # Block incoming ICMP (ping)
        self.rules.append(FirewallRule("Block ICMP", "ICMP", None, None, None, None, "block"))
        
        # Allow HTTP/HTTPS outbound
        self.rules.append(FirewallRule("Allow HTTP out", "TCP", None, None, None, 80, "allow"))
        self.rules.append(FirewallRule("Allow HTTPS out", "TCP", None, None, None, 443, "allow"))
    
    def init_ui(self):
        main_widget = QWidget()
        layout = QVBoxLayout()
        
        # Control buttons
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Firewall")
        self.start_btn.clicked.connect(self.start_firewall)
        self.stop_btn = QPushButton("Stop Firewall")
        self.stop_btn.clicked.connect(self.stop_firewall)
        self.stop_btn.setEnabled(False)
        
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        layout.addLayout(btn_layout)
        
        # Stats
        stats_layout = QHBoxLayout()
        self.packet_label = QLabel("Packets processed: 0")
        self.blocked_label = QLabel("Packets blocked: 0")
        stats_layout.addWidget(self.packet_label)
        stats_layout.addWidget(self.blocked_label)
        layout.addLayout(stats_layout)
        
        # Rule management
        rule_layout = QVBoxLayout()
        rule_layout.addWidget(QLabel("Firewall Rules:"))
        
        # Rule table
        self.rule_table = QTableWidget()
        self.rule_table.setColumnCount(7)
        self.rule_table.setHorizontalHeaderLabels(["Name", "Protocol", "Source IP", "Dest IP", "Source Port", "Dest Port", "Action"])
        self.rule_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.update_rule_table()
        rule_layout.addWidget(self.rule_table)
        
        # Add rule form
        add_rule_layout = QHBoxLayout()
        
        form_layout = QVBoxLayout()
        self.rule_name = QLineEdit()
        self.rule_name.setPlaceholderText("Rule name")
        form_layout.addWidget(self.rule_name)
        
        self.protocol = QLineEdit()
        self.protocol.setPlaceholderText("Protocol (TCP/UDP/ICMP/ALL)")
        form_layout.addWidget(self.protocol)
        
        self.src_ip = QLineEdit()
        self.src_ip.setPlaceholderText("Source IP (leave blank for any)")
        form_layout.addWidget(self.src_ip)
        
        self.dst_ip = QLineEdit()
        self.dst_ip.setPlaceholderText("Destination IP (leave blank for any)")
        form_layout.addWidget(self.dst_ip)
        
        self.src_port = QLineEdit()
        self.src_port.setPlaceholderText("Source port (leave blank for any)")
        form_layout.addWidget(self.src_port)
        
        self.dst_port = QLineEdit()
        self.dst_port.setPlaceholderText("Destination port (leave blank for any)")
        form_layout.addWidget(self.dst_port)
        
        self.action_allow = QCheckBox("Allow")
        self.action_allow.setChecked(True)
        form_layout.addWidget(self.action_allow)
        
        add_btn = QPushButton("Add Rule")
        add_btn.clicked.connect(self.add_rule)
        form_layout.addWidget(add_btn)
        
        add_rule_layout.addLayout(form_layout)
        rule_layout.addLayout(add_rule_layout)
        layout.addLayout(rule_layout)
        
        # Log
        layout.addWidget(QLabel("Firewall Log:"))
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        layout.addWidget(self.log)
        
        main_widget.setLayout(layout)
        self.setCentralWidget(main_widget)
        
        # Update timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(1000)
    
    def update_rule_table(self):
        self.rule_table.setRowCount(len(self.rules))
        for i, rule in enumerate(self.rules):
            self.rule_table.setItem(i, 0, QTableWidgetItem(rule.name))
            self.rule_table.setItem(i, 1, QTableWidgetItem(rule.protocol))
            self.rule_table.setItem(i, 2, QTableWidgetItem(rule.src_ip if rule.src_ip else "Any"))
            self.rule_table.setItem(i, 3, QTableWidgetItem(rule.dst_ip if rule.dst_ip else "Any"))
            self.rule_table.setItem(i, 4, QTableWidgetItem(str(rule.src_port) if rule.src_port else "Any"))
            self.rule_table.setItem(i, 5, QTableWidgetItem(str(rule.dst_port) if rule.dst_port else "Any"))
            self.rule_table.setItem(i, 6, QTableWidgetItem(rule.action.capitalize()))
    
    def add_rule(self):
        name = self.rule_name.text()
        protocol = self.protocol.text().upper()
        src_ip = self.src_ip.text() if self.src_ip.text() else None
        dst_ip = self.dst_ip.text() if self.dst_ip.text() else None
        
        try:
            src_port = int(self.src_port.text()) if self.src_port.text() else None
        except ValueError:
            self.log_message("Error: Source port must be a number")
            return
            
        try:
            dst_port = int(self.dst_port.text()) if self.dst_port.text() else None
        except ValueError:
            self.log_message("Error: Destination port must be a number")
            return
            
        action = "allow" if self.action_allow.isChecked() else "block"
        
        if not name:
            self.log_message("Error: Rule name is required")
            return
            
        if protocol not in ["TCP", "UDP", "ICMP", "ALL"]:
            self.log_message("Error: Protocol must be TCP, UDP, ICMP, or ALL")
            return
            
        self.rules.append(FirewallRule(name, protocol, src_ip, dst_ip, src_port, dst_port, action))
        self.update_rule_table()
        self.log_message(f"Added rule: {name}")
        
        # Clear form
        self.rule_name.clear()
        self.protocol.clear()
        self.src_ip.clear()
        self.dst_ip.clear()
        self.src_port.clear()
        self.dst_port.clear()
    
    def log_message(self, message):
        self.log.append(f"[{time.strftime('%H:%M:%S')}] {message}")
    
    def update_stats(self):
        self.packet_label.setText(f"Packets processed: {self.packet_count}")
        self.blocked_label.setText(f"Packets blocked: {self.blocked_count}")
    
    def start_firewall(self):
        if not self.is_running:
            self.is_running = True
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.stop_capture.clear()
            
            self.capture_thread = threading.Thread(target=self.packet_capture)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
            self.log_message("Firewall started")
    
    def stop_firewall(self):
        if self.is_running:
            self.is_running = False
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.stop_capture.set()
            
            if self.capture_thread and self.capture_thread.is_alive():
                self.capture_thread.join(timeout=1)
                
            self.log_message("Firewall stopped")
    
    def packet_capture(self):
        def packet_handler(packet):
            self.packet_count += 1
            action = self.check_packet(packet)
            
            if action == "block":
                self.blocked_count += 1
                self.log_message(f"Blocked packet: {packet.summary()}")
                return "Drop"
            else:
                return "Accept"
        
        sniff(prn=packet_handler, stop_filter=lambda x: self.stop_capture.is_set(), store=0)
    
    def check_packet(self, packet):
        # Default action if no rules match (default deny)
        default_action = "block"
        
        for rule in self.rules:
            # Check protocol
            if rule.protocol != "ALL":
                if rule.protocol == "ICMP" and not (ICMP in packet or (IP in packet and packet[IP].proto == 1)):
                    continue
                elif rule.protocol == "TCP" and not (TCP in packet or (IP in packet and packet[IP].proto == 6)):
                    continue
                elif rule.protocol == "UDP" and not (UDP in packet or (IP in packet and packet[IP].proto == 17)):
                    continue
            
            # Check IP addresses
            if IP in packet:
                if rule.src_ip and packet[IP].src != rule.src_ip:
                    continue
                if rule.dst_ip and packet[IP].dst != rule.dst_ip:
                    continue
            else:
                # Skip non-IP packets if IP rules are specified
                if rule.src_ip or rule.dst_ip:
                    continue
            
            # Check ports
            if TCP in packet or UDP in packet:
                if rule.src_port:
                    if TCP in packet and packet[TCP].sport != rule.src_port:
                        continue
                    if UDP in packet and packet[UDP].sport != rule.src_port:
                        continue
                
                if rule.dst_port:
                    if TCP in packet and packet[TCP].dport != rule.dst_port:
                        continue
                    if UDP in packet and packet[UDP].dport != rule.dst_port:
                        continue
            else:
                # Skip if port rules are specified but packet doesn't have ports
                if rule.src_port or rule.dst_port:
                    continue
            
            # If we get here, all conditions matched
            return rule.action
        
        return default_action
    
    def closeEvent(self, event):
        self.stop_firewall()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    firewall = PersonalFirewall()
    firewall.show()
    sys.exit(app.exec_())