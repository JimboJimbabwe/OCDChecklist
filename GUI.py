import sys
import json
import os
from typing import Any, Dict, Union, List
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTreeWidget, QTreeWidgetItem,
                             QVBoxLayout, QWidget, QLabel, QComboBox, QPushButton,
                             QHBoxLayout, QCheckBox, QScrollArea, QSplitter,
                             QTextEdit, QFileDialog)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QIcon


class CommandItem(QTreeWidgetItem):
    def __init__(self, command: str, parent=None):
        super().__init__(parent)
        self.checkbox = QCheckBox()
        self.command = command
        self.setText(1, command)


class ChecklistTree(QTreeWidget):
    command_selected = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setHeaderLabels(['✓', 'Attack Path Components'])
        self.setColumnWidth(0, 50)
        self.header().setStretchLastSection(True)

    def handle_item_clicked(self, item: QTreeWidgetItem, column: int):
        if isinstance(item, CommandItem) and column == 1:
            self.command_selected.emit(item.command)


class ADChecklistGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Active Directory Attack Path Checklist")
        self.setGeometry(100, 100, 1200, 800)

        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # Top controls
        top_controls = QHBoxLayout()

        # Checklist selector
        self.checklist_selector = QComboBox()
        self.checklist_selector.currentTextChanged.connect(self.load_selected_checklist)
        top_controls.addWidget(QLabel("Select Attack Path:"))
        top_controls.addWidget(self.checklist_selector)

        # Load and Save buttons
        load_button = QPushButton("Load JSON")
        load_button.clicked.connect(self.load_json_file)
        save_button = QPushButton("Save Progress")
        save_button.clicked.connect(self.save_progress)
        top_controls.addWidget(load_button)
        top_controls.addWidget(save_button)

        layout.addLayout(top_controls)

        # Splitter for tree and details
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Tree widget
        self.tree = ChecklistTree()
        self.tree.itemClicked.connect(self.tree.handle_item_clicked)
        self.tree.command_selected.connect(self.show_command_details)

        # Create scroll area for tree
        tree_scroll = QScrollArea()
        tree_scroll.setWidget(self.tree)
        tree_scroll.setWidgetResizable(True)
        splitter.addWidget(tree_scroll)

        # Details panel
        self.details_panel = QTextEdit()
        self.details_panel.setReadOnly(True)
        splitter.addWidget(self.details_panel)

        layout.addWidget(splitter)

        # Set splitter sizes
        splitter.setSizes([600, 600])

        self.checklists = {}
        self.load_checklists()

    def load_checklists(self):
        directory = 'ad_checklists'
        if not os.path.exists(directory):
            os.makedirs(directory)
            return

        for filename in os.listdir(directory):
            if filename.endswith('.json'):
                with open(os.path.join(directory, filename), 'r') as f:
                    try:
                        name = filename.replace('.json', '').replace('-', ' ').title()
                        self.checklists[name] = json.load(f)
                        self.checklist_selector.addItem(name)
                    except json.JSONDecodeError:
                        print(f"Error loading {filename}")

    def format_command(self, cmd: Union[str, dict, list]) -> str:
        if isinstance(cmd, str):
            return cmd
        elif isinstance(cmd, dict):
            if 'step1' in cmd and 'step2' in cmd:
                return f"1. {cmd['step1']}\n2. {cmd['step2']}"
            elif 'chain' in cmd:
                steps = cmd['chain']
                return '\n'.join([f"{k}: {v}" for k, v in steps.items()])
            else:
                return '\n'.join([f"{k}: {v}" for k, v in cmd.items()])
        elif isinstance(cmd, list):
            return '\n'.join([self.format_command(c) for c in cmd])
        return str(cmd)

    def extract_commands(self, data: Any, prefix: str = "") -> List[tuple]:
        """Recursively extract commands with their context from nested structures."""
        commands = []

        if isinstance(data, dict):
            for key, value in data.items():
                new_prefix = f"{prefix}/{key}" if prefix else key

                # If the value is a string and looks like a command
                if isinstance(value, str) and any(cmd in value.lower() for cmd in
                                                  ['py', 'exe', 'use', 'cmd', 'run', 'get-', 'set-', 'invoke-',
                                                   'ntlm']):
                    commands.append((new_prefix, value))

                # If it's a nested structure, recurse
                elif isinstance(value, (dict, list)):
                    commands.extend(self.extract_commands(value, new_prefix))

        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_prefix = f"{prefix}[{i}]"
                if isinstance(item, str) and any(cmd in item.lower() for cmd in
                                                 ['py', 'exe', 'use', 'cmd', 'run', 'get-', 'set-', 'invoke-', 'ntlm']):
                    commands.append((prefix, item))
                elif isinstance(item, (dict, list)):
                    commands.extend(self.extract_commands(item, new_prefix))

        return commands

    def create_tree_items(self, data: Any, parent: QTreeWidgetItem = None) -> None:
        """Create tree items with improved command handling."""
        if isinstance(data, dict):
            for key, value in data.items():
                if key in ['result', 'description', 'notes', 'type']:
                    continue

                if parent is None:
                    item = QTreeWidgetItem(self.tree)
                else:
                    item = QTreeWidgetItem(parent)

                item.setText(1, key)

                # Handle commands and nested structures
                if isinstance(value, (dict, list)):
                    # Extract commands from this branch
                    commands = self.extract_commands(value, key)
                    if commands:
                        for cmd_context, cmd in commands:
                            cmd_item = CommandItem(f"{cmd_context}: {cmd}", item)
                            checkbox = QCheckBox()
                            self.tree.setItemWidget(cmd_item, 0, checkbox)

                    # Continue processing nested structures
                    self.create_tree_items(value, item)
                elif isinstance(value, str):
                    # Direct command string
                    if any(cmd in value.lower() for cmd in
                           ['py', 'exe', 'use', 'cmd', 'run', 'get-', 'set-', 'invoke-', 'ntlm']):
                        cmd_item = CommandItem(value, item)
                        checkbox = QCheckBox()
                        self.tree.setItemWidget(cmd_item, 0, checkbox)
                    else:
                        child = QTreeWidgetItem(item)
                        child.setText(1, value)

                # Add metadata
                if isinstance(value, dict):
                    if 'description' in value:
                        item.setToolTip(1, value['description'])
                    if 'access_gained' in value:
                        access = ', '.join(value['access_gained'])
                        child = QTreeWidgetItem(item)
                        child.setText(1, f"Access Gained: {access}")

        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    if any(cmd in item.lower() for cmd in
                           ['py', 'exe', 'use', 'cmd', 'run', 'get-', 'set-', 'invoke-', 'ntlm']):
                        cmd_item = CommandItem(item, parent)
                        checkbox = QCheckBox()
                        self.tree.setItemWidget(cmd_item, 0, checkbox)
                    else:
                        child = QTreeWidgetItem(parent)
                        child.setText(1, item)
                else:
                    self.create_tree_items(item, parent)

    def show_command_details(self, command: str) -> None:
        """Enhanced command details display."""
        # Split context from command if present
        if ': ' in command:
            context, cmd = command.split(': ', 1)
            details = f"Context: {context}\n\nCommand:\n{cmd}"
        else:
            details = f"Command:\n{command}"

        # Add any additional helpful information
        if 'ntlmrelay' in command.lower():
            details += "\n\nNote: This is an NTLM relay attack command. Ensure proper targeting and network positioning."
        elif 'ldap' in command.lower():
            details += "\n\nNote: This command interacts with LDAP. Verify LDAP connection settings."

        self.details_panel.setText(details)

    def add_command_items(self, commands: Union[List, Dict, str], parent: QTreeWidgetItem) -> None:
        if isinstance(commands, str):
            item = CommandItem(commands, parent)
            checkbox = QCheckBox()
            self.tree.setItemWidget(item, 0, checkbox)
        elif isinstance(commands, list):
            for cmd in commands:
                item = CommandItem(self.format_command(cmd), parent)
                checkbox = QCheckBox()
                self.tree.setItemWidget(item, 0, checkbox)
        elif isinstance(commands, dict):
            for key, cmd in commands.items():
                if key not in ['description', 'notes', 'type', 'access_gained']:
                    formatted_cmd = f"{key}: {self.format_command(cmd)}"
                    item = CommandItem(formatted_cmd, parent)
                    checkbox = QCheckBox()
                    self.tree.setItemWidget(item, 0, checkbox)

    def load_selected_checklist(self, name: str) -> None:
        if not name:
            return

        self.tree.clear()
        data = self.checklists.get(name)
        if data:
            self.create_tree_items(data)
            self.tree.expandAll()

    def show_command_details(self, command: str) -> None:
        self.details_panel.setText(command)

    def load_json_file(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Load JSON Checklist",
            "",
            "JSON Files (*.json)"
        )
        if filename:
            try:
                with open(filename, 'r') as f:
                    data = json.load(f)
                name = os.path.basename(filename).replace('.json', '').replace('-', ' ').title()
                self.checklists[name] = data
                self.checklist_selector.addItem(name)
                self.checklist_selector.setCurrentText(name)
            except Exception as e:
                print(f"Error loading file: {e}")

    def save_progress(self) -> None:
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Progress",
            "",
            "JSON Files (*.json)"
        )
        if filename:
            progress = self.get_progress()
            try:
                with open(filename, 'w') as f:
                    json.dump(progress, f, indent=4)
            except Exception as e:
                print(f"Error saving progress: {e}")

    def get_progress(self) -> Dict:
        progress = {}
        iterator = QTreeWidgetItemIterator(self.tree)
        while iterator.value():
            item = iterator.value()
            if isinstance(item, CommandItem):
                checkbox = self.tree.itemWidget(item, 0)
                if checkbox and checkbox.isChecked():
                    progress[item.text(1)] = True
            iterator += 1
        return progress


def main():
    app = QApplication(sys.argv)

    # Set application style
    app.setStyle("Fusion")

    window = ADChecklistGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()