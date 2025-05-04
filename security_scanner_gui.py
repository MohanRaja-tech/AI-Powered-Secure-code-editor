import os
import sys
import datetime
import re
import random
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTextEdit, QLineEdit, 
                             QPushButton, QVBoxLayout, QHBoxLayout, QWidget, 
                             QLabel, QSplitter, QFrame, QFileDialog, QMessageBox,
                             QScrollArea, QTabWidget, QToolTip, QAction, QMenu,
                             QToolBar, QStatusBar, QComboBox, QPlainTextEdit)
from PyQt5.QtCore import Qt, QSize, pyqtSlot, QTimer, QRect, QPoint
from PyQt5.QtGui import (QFont, QIcon, QTextCursor, QColor, QPalette, QSyntaxHighlighter, 
                        QTextCharFormat, QLinearGradient, QBrush, QTextFormat,
                        QPainter, QPen, QFontMetrics)
from typing import Optional, List, Dict, Tuple, Set
import time

# Import the vulnerability scanner from check_model.py
from check_model import VulnerabilityScanner
from groq import Groq

# Import Claude API
try:
    from anthropic import Anthropic
    CLAUDE_AVAILABLE = True
except ImportError:
    CLAUDE_AVAILABLE = False

from config import GROQ_API_KEY, CLAUDE_API_KEY


class LineNumberArea(QWidget):
    """Widget that displays line numbers for a CodeEditor"""
    def __init__(self, editor):
        super().__init__(editor)
        self.editor = editor

    def sizeHint(self):
        return QSize(self.editor.line_number_area_width(), 0)

    def paintEvent(self, event):
        self.editor.line_number_area_paint_event(event)


class PythonHighlighter(QSyntaxHighlighter):
    """Advanced syntax highlighter for Python code"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        # Define formats for different syntax elements
        
        # Keywords format
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#FF79C6"))
        keyword_format.setFontWeight(QFont.Bold)
        keywords = [
            "import", "from", "def", "class", "return", "if", "else", "elif",
            "for", "while", "try", "except", "finally", "with", "as", "and",
            "or", "not", "in", "is", "None", "True", "False", "self", "async", 
            "await", "break", "continue", "global", "lambda", "nonlocal", "pass",
            "raise", "yield"
        ]
        for word in keywords:
            pattern = r'\b' + word + r'\b'
            self.highlighting_rules.append((pattern, keyword_format))
        
        # Function call format
        function_format = QTextCharFormat()
        function_format.setForeground(QColor("#50FA7B"))
        function_pattern = r'\b[A-Za-z0-9_]+(?=\s*\()'
        self.highlighting_rules.append((function_pattern, function_format))
        
        # String format - single quotes
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#F1FA8C"))
        string_pattern = r"'[^'\\]*(\\.[^'\\]*)*'"
        self.highlighting_rules.append((string_pattern, string_format))
        
        # String format - double quotes
        string_double_format = QTextCharFormat()
        string_double_format.setForeground(QColor("#F1FA8C"))
        string_double_pattern = r'"[^"\\]*(\\.[^"\\]*)*"'
        self.highlighting_rules.append((string_double_pattern, string_double_format))
        
        # Numbers format
        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#BD93F9"))
        number_pattern = r'\b[0-9]+\b'
        self.highlighting_rules.append((number_pattern, number_format))
        
        # Class name format
        class_format = QTextCharFormat()
        class_format.setForeground(QColor("#8BE9FD"))
        class_format.setFontWeight(QFont.Bold)
        class_pattern = r'\bclass\s+(\w+)'
        self.highlighting_rules.append((class_pattern, class_format))
        
        # Comment format
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#6272A4"))
        comment_format.setFontItalic(True)
        comment_pattern = r'#[^\n]*'
        self.highlighting_rules.append((comment_pattern, comment_format))
        
        # Decorator format
        decorator_format = QTextCharFormat()
        decorator_format.setForeground(QColor("#FFB86C"))
        decorator_pattern = r'@\w+\b'
        self.highlighting_rules.append((decorator_pattern, decorator_format))
        
        # Self parameter format
        self_format = QTextCharFormat()
        self_format.setForeground(QColor("#FF79C6"))
        self_format.setFontItalic(True)
        self_pattern = r'\bself\b'
        self.highlighting_rules.append((self_pattern, self_format))
    
    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            for match in re.finditer(pattern, text):
                start = match.start()
                length = match.end() - start
                self.setFormat(start, length, format)


class NeonButton(QPushButton):
    """Custom button with neon glow effect"""
    def __init__(self, text, color="#4CAF50", parent=None):
        super().__init__(text, parent)
        self.base_color = QColor(color)
        self.glow_color = QColor(color)
        self.glow_color.setAlpha(80)
        
        # Set style
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: #282A36;
                color: {color};
                border: 2px solid {color};
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
                font-family: 'Segoe UI', sans-serif;
            }}
            QPushButton:hover {{
                background-color: rgba({self.base_color.red()}, {self.base_color.green()}, {self.base_color.blue()}, 30);
                color: #FFFFFF;
            }}
            QPushButton:pressed {{
                background-color: rgba({self.base_color.red()}, {self.base_color.green()}, {self.base_color.blue()}, 50);
            }}
        """)


class FuturisticTabButton(QPushButton):
    """Custom button styled as a futuristic tab"""
    def __init__(self, text, color="#4CAF50", parent=None):
        super().__init__(text, parent)
        self.setCheckable(True)
        self.base_color = QColor(color)
        
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba(40, 42, 54, 0.8);
                color: #CCCCCC;
                border: none;
                border-bottom: 2px solid transparent;
                border-radius: 0px;
                padding: 8px 16px;
                font-weight: bold;
                font-family: 'Segoe UI', sans-serif;
                min-width: 120px;
                text-align: center;
            }}
            QPushButton:checked {{
                color: {color};
                border-bottom: 2px solid {color};
            }}
            QPushButton:hover {{
                background-color: rgba(68, 71, 90, 0.8);
            }}
        """)


class SecurityScannerGUI(QMainWindow):
    def __init__(self, groq_api_key: Optional[str] = None, claude_api_key: Optional[str] = None):
        super().__init__()
        self.scanner = VulnerabilityScanner()
        self.groq_models = [
            "gemma-7b-it",             # Latest models - try these first
            "llama3-8b-8192",
            "mixtral-8x7b-32768",
            "gemma-2b-it"              # Smaller backup model
        ]
        
        # Initialize GROQ
        try:
            # Initialize GROQ client
            self.groq_client = Groq(api_key=groq_api_key or GROQ_API_KEY)
            # Test if the client can be created
            if not groq_api_key and not GROQ_API_KEY:
                raise ValueError("GROQ API key not provided")
            self.groq_available = True
        except Exception as e:
            print(f"GROQ API initialization error: {str(e)}")
            self.groq_available = False
            self.groq_client = None
        
        # Initialize Claude
        try:
            # Only initialize if we have a key and the library is available
            if CLAUDE_AVAILABLE and (claude_api_key or CLAUDE_API_KEY):
                self.claude_client = Anthropic(api_key=claude_api_key or CLAUDE_API_KEY)
                self.claude_available = True
            else:
                if not CLAUDE_AVAILABLE:
                    print("Claude not available: Anthropic library not installed")
                else:
                    print("Claude not available: No API key provided")
                self.claude_available = False
                self.claude_client = None
        except Exception as e:
            print(f"Claude API initialization error: {str(e)}")
            self.claude_available = False
            self.claude_client = None
            
        # Show a warning if neither API is available
        if not self.groq_available and not self.claude_available:
            QMessageBox.warning(self, "API Configuration", 
                              "Neither GROQ nor Claude APIs are configured correctly. Chat will use offline responses.")
        
        self.setup_ui()

    def setup_ui(self):
        """Set up the main user interface components"""
        self.setWindowTitle("AI Security Vulnerability Scanner")
        self.setMinimumSize(1200, 800)
        
        # Set up the dark theme application-wide
        self.apply_dark_theme()
        
        # Set up the main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create splitter for resizable panels
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(1)
        splitter.setStyleSheet("""
            QSplitter::handle {
                background-color: #44475A;
            }
        """)
        
        # Create chat area
        chat_widget = QWidget()
        chat_widget.setStyleSheet("background-color: #282A36;")
        chat_layout = QVBoxLayout(chat_widget)
        chat_layout.setContentsMargins(20, 20, 20, 20)
        chat_layout.setSpacing(16)
        
        # Chat header with logo
        header_layout = QHBoxLayout()
        
        logo_label = QLabel("🔒")
        logo_label.setStyleSheet("font-size: 24px;")
        
        header_text = QLabel("AI Security Scanner")
        header_text.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: #F8F8F2;
            font-family: 'Segoe UI', sans-serif;
        """)
        
        header_layout.addWidget(logo_label)
        header_layout.addWidget(header_text)
        header_layout.addStretch()
        
        # Chat history
        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        self.chat_history.setStyleSheet("""
            QTextEdit {
                background-color: #282A36;
                color: #F8F8F2;
                border: none;
                border-radius: 8px;
                padding: 12px;
                font-family: 'Segoe UI', sans-serif;
                font-size: 14px;
            }
        """)
        
        # Input area
        input_frame = QFrame()
        input_frame.setStyleSheet("""
            QFrame {
                background-color: #44475A;
                border-radius: 8px;
                padding: 4px;
            }
        """)
        input_layout = QVBoxLayout(input_frame)
        input_layout.setContentsMargins(2, 2, 2, 2)
        
        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText("Paste your code here or type a message...")
        self.message_input.setStyleSheet("""
            QTextEdit {
                background-color: #44475A;
                color: #F8F8F2;
                border: none;
                border-radius: 6px;
                padding: 10px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 14px;
                line-height: 1.4;
            }
        """)
        self.message_input.setMinimumHeight(120)
        self.message_input.setMaximumHeight(200)
        
        # Apply syntax highlighting to input
        self.input_highlighter = PythonHighlighter(self.message_input.document())
        
        input_bottom_layout = QHBoxLayout()
        
        input_info = QLabel("Paste your code above and click the button to scan for vulnerabilities")
        input_info.setStyleSheet("""
            color: #6272A4;
            font-size: 12px;
            font-style: italic;
        """)
        
        self.send_button = NeonButton("Scan Code", "#50FA7B")
        self.send_button.setMinimumWidth(140)
        self.send_button.clicked.connect(self.send_message)
        
        input_bottom_layout.addWidget(input_info)
        input_bottom_layout.addStretch()
        input_bottom_layout.addWidget(self.send_button)
        
        input_layout.addWidget(self.message_input)
        input_layout.addLayout(input_bottom_layout)
        
        # Add components to chat layout
        chat_layout.addLayout(header_layout)
        chat_layout.addWidget(self.chat_history, 1)
        chat_layout.addWidget(input_frame)
        
        # Add chat mode toggle
        chat_mode_layout = QHBoxLayout()
        chat_mode_layout.setContentsMargins(0, 0, 0, 0)
        
        self.chat_mode_label = QLabel("Mode:")
        self.chat_mode_label.setStyleSheet("""
            color: #6272A4;
            font-size: 12px;
            font-weight: bold;
        """)
        
        self.scan_mode_button = FuturisticTabButton("Scan Code", "#50FA7B")
        self.scan_mode_button.setChecked(True)
        self.scan_mode_button.clicked.connect(lambda: self.switch_mode(0))
        
        self.chat_mode_button = FuturisticTabButton("Chat", "#8BE9FD")
        self.chat_mode_button.clicked.connect(lambda: self.switch_mode(1))
        
        chat_mode_layout.addWidget(self.chat_mode_label)
        chat_mode_layout.addWidget(self.scan_mode_button)
        chat_mode_layout.addWidget(self.chat_mode_button)
        chat_mode_layout.addStretch()
        
        # Add mode buttons to chat layout
        chat_layout.addLayout(chat_mode_layout)
        
        # Create results area with tabs
        results_container = QWidget()
        results_container.setStyleSheet("background-color: #1E1F29;")
        results_layout = QVBoxLayout(results_container)
        results_layout.setContentsMargins(20, 20, 20, 20)
        results_layout.setSpacing(16)
        
        # Results header
        results_header = QLabel("Analysis Results")
        results_header.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: #F8F8F2;
            padding-bottom: 8px;
            border-bottom: 1px solid #44475A;
            font-family: 'Segoe UI', sans-serif;
        """)
        
        # Create tab widget for results
        self.results_tabs = QTabWidget()
        self.results_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background-color: #282A36;
                border-radius: 8px;
            }
            QTabBar::tab {
                background-color: rgba(40, 42, 54, 0.8);
                color: #CCCCCC;
                border: none;
                border-bottom: 2px solid transparent;
                border-radius: 0px;
                padding: 8px 16px;
                font-weight: bold;
                font-family: 'Segoe UI', sans-serif;
                min-width: 120px;
                text-align: center;
            }
            QTabBar::tab:selected {
                color: #8BE9FD;
                border-bottom: 2px solid #8BE9FD;
            }
            QTabBar::tab:hover {
                background-color: rgba(68, 71, 90, 0.8);
            }
        """)
        
        # Vulnerabilities tab
        vuln_tab = QWidget()
        vuln_layout = QVBoxLayout(vuln_tab)
        vuln_layout.setContentsMargins(10, 10, 10, 10)
        
        self.vulnerabilities_text = QTextEdit()
        self.vulnerabilities_text.setReadOnly(True)
        self.vulnerabilities_text.setStyleSheet("""
            QTextEdit {
                background-color: #282A36;
                color: #F8F8F2;
                border: none;
                border-radius: 8px;
                padding: 16px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 14px;
                line-height: 1.5;
            }
        """)
        
        vuln_layout.addWidget(self.vulnerabilities_text)
        
        # Secure code tab
        code_tab = QWidget()
        code_layout = QVBoxLayout(code_tab)
        code_layout.setContentsMargins(10, 10, 10, 10)
        
        self.secure_code_text = QTextEdit()
        self.secure_code_text.setReadOnly(True)
        self.secure_code_text.setStyleSheet("""
            QTextEdit {
                background-color: #282A36;
                color: #F8F8F2;
                border: none;
                border-radius: 8px;
                padding: 16px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 14px;
                line-height: 1.5;
            }
        """)
        
        # Apply syntax highlighting to secure code
        self.code_highlighter = PythonHighlighter(self.secure_code_text.document())
        
        code_layout.addWidget(self.secure_code_text)
        
        # AI Chat Results tab
        chat_results_tab = QWidget()
        chat_results_layout = QVBoxLayout(chat_results_tab)
        chat_results_layout.setContentsMargins(10, 10, 10, 10)
        
        self.chat_result_text = QTextEdit()
        self.chat_result_text.setReadOnly(True)
        self.chat_result_text.setStyleSheet("""
            QTextEdit {
                background-color: #282A36;
                color: #F8F8F2;
                border: none;
                border-radius: 8px;
                padding: 16px;
                font-family: 'Segoe UI', sans-serif;
                font-size: 14px;
                line-height: 1.5;
            }
        """)
        
        chat_results_layout.addWidget(self.chat_result_text)
        
        # Add tabs to tab widget
        self.results_tabs.addTab(vuln_tab, "Vulnerability Report")
        self.results_tabs.addTab(code_tab, "Secure Code")
        self.results_tabs.addTab(chat_results_tab, "AI Chat Results")
        
        # Action buttons
        actions_layout = QHBoxLayout()
        
        self.save_report_button = NeonButton("Save Vulnerability Report", "#FF79C6")
        self.save_report_button.clicked.connect(self.save_vulnerability_report)
        
        self.save_code_button = NeonButton("Save Secure Code", "#8BE9FD")
        self.save_code_button.clicked.connect(self.save_secure_code)
        
        self.save_chat_button = NeonButton("Save Chat Response", "#50FA7B")
        self.save_chat_button.clicked.connect(self.save_chat_result)
        
        actions_layout.addWidget(self.save_report_button)
        actions_layout.addWidget(self.save_code_button)
        actions_layout.addWidget(self.save_chat_button)
        
        # Add components to results layout
        results_layout.addWidget(results_header)
        results_layout.addWidget(self.results_tabs, 1)
        results_layout.addLayout(actions_layout)
        
        # Add panels to splitter
        splitter.addWidget(chat_widget)
        splitter.addWidget(results_container)
        splitter.setSizes([450, 750])
        
        main_layout.addWidget(splitter)
        
        # Add welcome message
        self.add_bot_message("Welcome to the AI Security Vulnerability Scanner 🔒\n\nPaste your code in the input box below and click 'Scan Code' to check for vulnerabilities. The scanner will analyze your code and provide:\n\n• Detailed vulnerability report\n• Secure code recommendations\n• Fix suggestions with explanations")
    
    def apply_dark_theme(self):
        """Apply dark theme styling to the application"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1E1F29;
            }
            QScrollBar:vertical {
                border: none;
                background: #282A36;
                width: 10px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #44475A;
                min-height: 20px;
                border-radius: 5px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
                height: 0px;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }
            QToolTip {
                background-color: #282A36;
                color: #F8F8F2;
                border: 1px solid #44475A;
                padding: 4px;
            }
        """)
    
    def switch_tab(self, tab_index):
        """Switch between vulnerability report and secure code tabs"""
        for i, tab in enumerate(self.results_tabs.tabs()):
            tab.setChecked(i == tab_index)
        
        if tab_index == 0:
            self.vulnerabilities_text.show()
            self.secure_code_text.hide()
        else:
            self.vulnerabilities_text.hide()
            self.secure_code_text.show()
    
    def add_user_message(self, message):
        """Add a user message to the chat history"""
        # Truncate long messages for display
        display_message = message
        if len(display_message) > 100:
            display_message = display_message[:100] + "..."
        
        self.chat_history.append(f'<div style="text-align: right; margin: 10px 0;"><div style="display: inline-block; background: linear-gradient(135deg, #5D4CBE 0%, #9159BE 100%); padding: 12px 16px; border-radius: 18px 18px 4px 18px; max-width: 85%;"><span style="color: #FFFFFF; font-family: \'Segoe UI\', sans-serif; font-size: 14px;"><b>You:</b><br>{display_message}</span></div></div>')
        self.chat_history.ensureCursorVisible()
    
    def add_bot_message(self, message):
        """Add a bot message to the chat history"""
        self.chat_history.append(f'<div style="text-align: left; margin: 10px 0;"><div style="display: inline-block; background: linear-gradient(135deg, #272935 0%, #393E5B 100%); padding: 12px 16px; border-radius: 18px 18px 18px 4px; max-width: 85%; border-left: 3px solid #50FA7B;"><span style="color: #F8F8F2; font-family: \'Segoe UI\', sans-serif; font-size: 14px;"><b>AI Scanner:</b><br>{message}</span></div></div>')
        self.chat_history.ensureCursorVisible()
    
    def add_code_block(self, code):
        """Add a code block to the chat history with syntax highlighting"""
        # Escape HTML characters
        import html
        escaped_code = html.escape(code)
        
        # Add code block with formatting
        self.chat_history.append(f'<div style="margin: 10px 0; background-color: #282A36; padding: 12px; border-radius: 8px; border-left: 3px solid #8BE9FD;"><pre style="font-family: Consolas, \'Courier New\", monospace; color: #F8F8F2; white-space: pre-wrap; margin: 0; font-size: 13px;">{escaped_code}</pre></div>')
        self.chat_history.ensureCursorVisible()
    
    def switch_mode(self, mode_index):
        """Switch between scan mode, chat mode, and editor mode"""
        self.scan_mode_button.setChecked(mode_index == 0)
        self.chat_mode_button.setChecked(mode_index == 1)
        
        if mode_index == 0:  # Scan mode
            self.message_input.setPlaceholderText("Paste your code here to scan for vulnerabilities...")
            self.send_button.setText("Scan Code")
            self.send_button.setStyleSheet(self.send_button.styleSheet().replace("#8BE9FD", "#50FA7B").replace("#BD93F9", "#50FA7B"))
            # Show vulnerability-related tabs
            self.results_tabs.setCurrentIndex(0)  # Switch to Vulnerability Report tab
        else:  # Chat mode
            self.message_input.setPlaceholderText("Type your message here...")
            self.send_button.setText("Send")
            self.send_button.setStyleSheet(self.send_button.styleSheet().replace("#50FA7B", "#8BE9FD").replace("#BD93F9", "#8BE9FD"))
            # Show chat results tab
            self.results_tabs.setCurrentIndex(2)  # Switch to AI Chat Results tab
    
    def get_mock_response(self, message: str) -> str:
        """Generate a mock response for when the API is unavailable."""
        if "python" in message.lower() and "code" in message.lower():
            if "game" in message.lower():
                return """Here's a simple, secure Python code for a snake game:

```python
import pygame
import time
import random

# Initialize pygame
pygame.init()

# Define colors
white = (255, 255, 255)
black = (0, 0, 0)
red = (213, 50, 80)
green = (0, 255, 0)
blue = (50, 153, 213)

# Set display
display_width = 600
display_height = 400
display = pygame.display.set_mode((display_width, display_height))
pygame.display.set_caption('Snake Game')

clock = pygame.time.Clock()
snake_block = 10
snake_speed = 15

font_style = pygame.font.SysFont("bahnschrift", 25)
score_font = pygame.font.SysFont("comicsansms", 35)

def score(score):
    value = score_font.render("Score: " + str(score), True, white)
    display.blit(value, [0, 0])

def snake(snake_block, snake_list):
    for x in snake_list:
        pygame.draw.rect(display, green, [x[0], x[1], snake_block, snake_block])

def message(msg, color):
    mesg = font_style.render(msg, True, color)
    display.blit(mesg, [display_width / 6, display_height / 3])

def gameLoop():
    game_over = False
    game_close = False

    x1 = display_width / 2
    y1 = display_height / 2

    x1_change = 0
    y1_change = 0

    snake_list = []
    length_of_snake = 1

    # Food position (with safe random generation)
    foodx = round(random.randrange(0, display_width - snake_block) / 10.0) * 10.0
    foody = round(random.randrange(0, display_height - snake_block) / 10.0) * 10.0

    while not game_over:

        while game_close == True:
            display.fill(blue)
            message("You Lost! Press Q-Quit or C-Play Again", red)
            score(length_of_snake - 1)
            pygame.display.update()

            for event in pygame.event.get():
                if event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_q:
                        game_over = True
                        game_close = False
                    if event.key == pygame.K_c:
                        gameLoop()

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                game_over = True
            if event.type == pygame.KEYDOWN:
                if event.key == pygame.K_LEFT and x1_change == 0:
                    x1_change = -snake_block
                    y1_change = 0
                elif event.key == pygame.K_RIGHT and x1_change == 0:
                    x1_change = snake_block
                    y1_change = 0
                elif event.key == pygame.K_UP and y1_change == 0:
                    y1_change = -snake_block
                    x1_change = 0
                elif event.key == pygame.K_DOWN and y1_change == 0:
                    y1_change = snake_block
                    x1_change = 0

        # Check for boundary collisions
        if x1 >= display_width or x1 < 0 or y1 >= display_height or y1 < 0:
            game_close = True
            
        x1 += x1_change
        y1 += y1_change
        display.fill(black)
        pygame.draw.rect(display, red, [foodx, foody, snake_block, snake_block])
        snake_head = []
        snake_head.append(x1)
        snake_head.append(y1)
        snake_list.append(snake_head)
        if len(snake_list) > length_of_snake:
            del snake_list[0]

        # Check if snake hits itself
        for x in snake_list[:-1]:
            if x == snake_head:
                game_close = True

        snake(snake_block, snake_list)
        score(length_of_snake - 1)

        pygame.display.update()

        # Check if snake eats food
        if x1 == foodx and y1 == foody:
            # Generate new food (safely)
            foodx = round(random.randrange(0, display_width - snake_block) / 10.0) * 10.0
            foody = round(random.randrange(0, display_height - snake_block) / 10.0) * 10.0
            length_of_snake += 1

        clock.tick(snake_speed)

    pygame.quit()
    quit()

gameLoop()

This code is secure because:
1. It doesn't use any vulnerable libraries or methods
2. It properly handles user input
3. It uses safe random number generation
4. It doesn't interact with external systems or files
5. It doesn't store any sensitive data"""
            elif "security" in message.lower() or "vulnerab" in message.lower():
                return """When writing secure Python code, follow these key principles:

1. **Input Validation**: Never trust user input. Validate and sanitize all inputs.
2. **Use Parameterized Queries**: For databases, use parameterized queries to prevent SQL injection.
3. **Avoid Shell Injection**: Never pass unsanitized user input to shell commands.
4. **Secure Dependencies**: Keep dependencies updated and scan for vulnerabilities.
5. **Least Privilege**: Run code with minimal necessary permissions.
6. **Secure Authentication**: Use strong password hashing (like Argon2 or bcrypt).
7. **Protect Sensitive Data**: Never hardcode secrets or credentials.
8. **HTTPS/TLS**: Use secure connections for network communication.
9. **CSRF Protection**: Implement CSRF tokens for web applications.
10. **Proper Error Handling**: Don't expose sensitive information in error messages.

Example of insecure vs. secure code:

Insecure:
```python
# SQL Injection vulnerability
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)

# Command injection vulnerability
os.system("cat /var/log/app.log | grep " + date)

# Hard-coded credentials
API_KEY = "1234secret"
```

Secure:
```python
# Safe SQL query
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))

# Safe command execution
import subprocess
result = subprocess.run(['grep', date, '/var/log/app.log'], 
                      capture_output=True, text=True, shell=False)

# Environment variables for credentials
import os
API_KEY = os.getenv("API_KEY")
```"""
        elif "hello" in message.lower() or "hi" in message.lower() or "hey" in message.lower():
            return "Hello! I'm your AI Security Assistant. I can help you analyze code for vulnerabilities, suggest security improvements, or answer questions about secure coding practices. What would you like help with today?"
        else:
            return "I'm your AI Security Assistant running in offline mode. I can help with security-related questions and code analysis. For more advanced responses, please ensure the GROQ API is properly configured."

    def send_message(self):
        """Process the user's message or code"""
        message = self.message_input.toPlainText().strip()
        if not message:
            return
        
        # Add the message to the chat history
        self.add_user_message(message[:100] + "..." if len(message) > 100 else message)
        if len(message) > 200:
            self.add_code_block(message[:200] + "...\n[Code truncated for display]")
        
        # Clear the input field
        self.message_input.clear()
        
        if self.scan_mode_button.isChecked():
            # Indicate scanning is in progress
            self.add_bot_message("<span style='color: #FFB86C;'>⚡ Scanning your code for vulnerabilities...</span>")
            QApplication.processEvents()  # Update the UI
            
            # Perform the security scan
            vulnerabilities = self.scanner.analyze_code(message, "user_code.py")
            
            # Generate reports
            vulnerability_report = self.scanner.generate_detailed_report({"user_code.py": vulnerabilities})
            secure_code = self.scanner.generate_secure_code(message, vulnerabilities)
            
            # Update the results panes
            self.vulnerabilities_text.setText(vulnerability_report)
            self.secure_code_text.setText(secure_code)
            
            # Switch to vulnerability report tab
            self.results_tabs.setCurrentIndex(0)
            
            # Report summary in chat
            if vulnerabilities:
                vulnerability_types = set(vuln['type'] for vuln in vulnerabilities)
                type_count = len(vulnerability_types)
                type_list = ", ".join(f"<span style='color: #FF5555;'>{v_type.replace('_', ' ')}</span>" for v_type in vulnerability_types)
                
                self.add_bot_message(f"<span style='color: #FF5555;'>⚠️ Found {len(vulnerabilities)} potential security vulnerabilities</span> in your code across {type_count} vulnerability types: {type_list}\n\nCheck the <span style='color: #FF79C6;'>Vulnerability Report</span> tab for details and the <span style='color: #8BE9FD;'>Secure Code</span> tab for recommendations.")
            else:
                self.add_bot_message("✅ <span style='color: #50FA7B;'>No security vulnerabilities were detected</span> in your code. Great job!")
        
        elif self.chat_mode_button.isChecked():  # Chat mode
            # Show typing indicator
            self.add_bot_message("<span style='color: #FFB86C;'>⚡ Thinking...</span>")
            QApplication.processEvents()
            
            # Switch to chat results tab
            self.results_tabs.setCurrentIndex(2)
            
            # Display "Generating response..." in the chat results box
            self.chat_result_text.setHtml("<span style='color: #FFB86C; font-style: italic;'>Generating AI response...</span>")
            QApplication.processEvents()
            
            # Try GROQ API first if available
            response_source = "AI"  # Default - will be overridden with specific model
            if self.groq_available:
                # Try each model in the list until one works
                for model in self.groq_models:
                    try:
                        # Get response from GROQ with current model
                        response = self.groq_client.chat.completions.create(
                            model=model,
                            messages=[
                                {"role": "user", "content": message}
                            ],
                            temperature=0.7,
                            max_tokens=2048,
                            top_p=0.9
                        )
                        
                        # Get the response text
                        response_text = response.choices[0].message.content
                        response_source = f"GROQ ({model})"
                        
                        # Update the response in chat history and results box
                        self.chat_history.undo()  # Remove the "Thinking..." message
                        self.add_bot_message(f"<span style='color: #50FA7B;'>[{response_source}]</span> Response ready in Results tab")
                        
                        # Add the full response to the chat results box with formatting
                        self.format_chat_result(response_text, response_source)
                        return  # Exit after successful response
                    except Exception as e:
                        print(f"GROQ Model {model} failed: {str(e)}")
                        continue  # Try next model
            
            # If GROQ failed or is not available, try Claude
            if self.claude_available:
                try:
                    # Get response from Claude 3.5 Sonnet
                    response = self.claude_client.messages.create(
                        model="claude-3-5-sonnet-20240307",
                        max_tokens=2048,
                        temperature=0.7,
                        messages=[
                            {"role": "user", "content": message}
                        ]
                    )
                    
                    # Get the response text
                    response_text = response.content[0].text
                    response_source = "Claude 3.5 Sonnet"
                    
                    # Update the response in chat history and results box
                    self.chat_history.undo()  # Remove the "Thinking..." message
                    self.add_bot_message(f"<span style='color: #8BE9FD;'>[{response_source}]</span> Response ready in Results tab")
                    
                    # Add the full response to the chat results box with formatting
                    self.format_chat_result(response_text, response_source)
                    return  # Exit after successful response
                except Exception as e:
                    print(f"Claude API failed: {str(e)}")
            
            # If all APIs failed, use mock response
            self.chat_history.undo()  # Remove the "Thinking..." message
            response_text = self.get_mock_response(message)
            response_source = "Offline Mode"
            
            self.add_bot_message(f"<span style='color: #FF5555;'>[{response_source}]</span> Response ready in Results tab")
            self.format_chat_result(response_text, response_source)
    
    def format_chat_result(self, text, source):
        """Format and display the chat result in the results pane."""
        # Convert markdown code blocks to HTML
        # This is a simple version that handles basic markdown formatting
        formatted_text = text
        
        # Replace markdown code blocks with styled HTML
        import re
        code_block_pattern = r"```(\w*)\n(.*?)\n```"
        
        def replace_code_block(match):
            language = match.group(1) or "python"
            code = match.group(2)
            return f"<div style='background-color: #44475A; padding: 10px; border-radius: 5px; margin: 10px 0;'><pre style='font-family: Consolas, \"Courier New\", monospace; color: #F8F8F2; white-space: pre-wrap; margin: 0; font-size: 13px;'>{code}</pre></div>"
        
        formatted_text = re.sub(code_block_pattern, replace_code_block, formatted_text, flags=re.DOTALL)
        
        # Replace inline code with styled HTML
        inline_code_pattern = r"`(.*?)`"
        formatted_text = re.sub(inline_code_pattern, r"<code style='background-color: #44475A; padding: 2px 4px; border-radius: 3px; font-family: Consolas, \"Courier New\", monospace;'>\1</code>", formatted_text)
        
        # Handle basic markdown formatting (bold, italic, lists)
        formatted_text = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", formatted_text)
        formatted_text = re.sub(r"\*(.*?)\*", r"<i>\1</i>", formatted_text)
        formatted_text = re.sub(r"^- (.*?)$", r"• \1", formatted_text, flags=re.MULTILINE)
        
        # Add header with source information
        header = f"<div style='color: #8BE9FD; font-weight: bold; margin-bottom: 15px; font-size: 16px;'>Response from {source}</div>"
        
        # Process line breaks
        formatted_text = formatted_text.replace("\n", "<br>")
        
        # Set the final HTML content
        self.chat_result_text.setHtml(f"{header}{formatted_text}")
    
    def save_vulnerability_report(self):
        """Save the vulnerability report to a file"""
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Vulnerability Report", 
                                                   os.path.join(os.getcwd(), "vulnerability_report.txt"),
                                                   "Text Files (*.txt)")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.vulnerabilities_text.toPlainText())
                QMessageBox.information(self, "Save Successful", f"Vulnerability report saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Save Failed", f"Failed to save the report: {str(e)}")
    
    def save_secure_code(self):
        """Save the secure code to a file"""
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Secure Code", 
                                                  os.path.join(os.getcwd(), "secure_code.py"),
                                                  "Python Files (*.py)")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.secure_code_text.toPlainText())
                QMessageBox.information(self, "Save Successful", f"Secure code saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Save Failed", f"Failed to save the code: {str(e)}")
    
    def save_chat_result(self):
        """Save the chat result to a file"""
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Chat Response", 
                                                  os.path.join(os.getcwd(), "ai_response.txt"),
                                                  "Text Files (*.txt)")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.chat_result_text.toPlainText())
                QMessageBox.information(self, "Save Successful", f"Chat response saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Save Failed", f"Failed to save the response: {str(e)}")


def generate_test_vulnerabilities():
    """Generate sample code with test vulnerabilities for demo purposes"""
    return """import os
import sqlite3
import subprocess
import pickle

def login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()

def get_logs(date):
    # Command injection vulnerability
    os.system("cat /var/log/app.log | grep " + date)

def render_profile(user_data):
    # XSS vulnerability
    template = "<div>Name: " + user_data['name'] + "</div>"
    return template

def read_file(filename):
    # Path traversal vulnerability
    with open(user_input + ".txt", "r") as f:
        return f.read()
        
def store_secret():
    # Hard-coded credentials vulnerability
    api_key = "12345secret_key_here"
    password = "admin123"
    return encrypt(api_key)
    
def insecure_deserialize(data):
    # Insecure deserialization vulnerability
    return pickle.loads(data)
    
def hash_password(password):
    # Weak cryptography vulnerability
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()
"""


def main():
    # Train the model in terminal first
    print("\n=== Initializing Security Scanner ===")
    print("Training security model... This may take a few moments.")
    
    from model_trainer import train_model_in_background
    success = train_model_in_background()
    
    if not success:
        print("\nError: Failed to train the security model. The application may not work correctly.")
        response = input("Do you want to continue anyway? (y/n): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    print("\nModel training completed. Starting GUI...")
    
    # Start the GUI application
    app = QApplication(sys.argv)
    
    # Set application-wide font
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    # Set dark palette for entire application
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.Window, QColor(30, 31, 41))
    dark_palette.setColor(QPalette.WindowText, QColor(248, 248, 242))
    dark_palette.setColor(QPalette.Base, QColor(40, 42, 54))
    dark_palette.setColor(QPalette.AlternateBase, QColor(68, 71, 90))
    dark_palette.setColor(QPalette.ToolTipBase, QColor(40, 42, 54))
    dark_palette.setColor(QPalette.ToolTipText, QColor(248, 248, 242))
    dark_palette.setColor(QPalette.Text, QColor(248, 248, 242))
    dark_palette.setColor(QPalette.Button, QColor(40, 42, 54))
    dark_palette.setColor(QPalette.ButtonText, QColor(248, 248, 242))
    dark_palette.setColor(QPalette.Link, QColor(80, 250, 123))
    dark_palette.setColor(QPalette.Highlight, QColor(68, 71, 90))
    dark_palette.setColor(QPalette.HighlightedText, QColor(248, 248, 242))
    dark_palette.setColor(QPalette.Active, QPalette.Button, QColor(40, 42, 54))
    dark_palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(98, 114, 164))
    dark_palette.setColor(QPalette.Disabled, QPalette.WindowText, QColor(98, 114, 164))
    dark_palette.setColor(QPalette.Disabled, QPalette.Text, QColor(98, 114, 164))
    app.setPalette(dark_palette)
    
    # Initialize with API keys from config
    window = SecurityScannerGUI(groq_api_key=GROQ_API_KEY, claude_api_key=CLAUDE_API_KEY)
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main() 