// Secure Code AI - Web Interface JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // DOM elements
    const scanModeBtn = document.getElementById('scan-mode-btn');
    const chatModeBtn = document.getElementById('chat-mode-btn');
    const sendButton = document.getElementById('send-button');
    const messageInput = document.getElementById('message-input');
    const chatHistory = document.getElementById('chat-history');
    
    // Tab elements
    const vulnerabilitiesTab = document.getElementById('vulnerabilities-tab');
    const secureCodeTab = document.getElementById('secure-code-tab');
    const chatResultsTab = document.getElementById('chat-results-tab');
    
    // Panels
    const vulnerabilitiesPanel = document.getElementById('vulnerabilities-panel');
    const secureCodePanel = document.getElementById('secure-code-panel');
    const chatResultsPanel = document.getElementById('chat-results-panel');
    
    // Content elements
    const vulnerabilityReport = document.getElementById('vulnerability-report');
    const secureCodeContent = document.getElementById('secure-code-content');
    const chatResultContent = document.getElementById('chat-result-content');
    
    // Save buttons
    const saveReportBtn = document.getElementById('save-report-btn');
    const saveCodeBtn = document.getElementById('save-code-btn');
    const saveChatBtn = document.getElementById('save-chat-btn');
    
    // API base URL - change this to your server address
    const API_BASE_URL = 'http://localhost:5000/api';
    
    // Initialize particles.js
    if (document.getElementById('particles-js')) {
        initParticles();
    }
    
    // Add typing animation effect to message input
    messageInput.addEventListener('focus', function() {
        messageInput.classList.add('glow-on-hover');
    });
    
    messageInput.addEventListener('blur', function() {
        messageInput.classList.remove('glow-on-hover');
    });
    
    // Add smooth scrolling to chat history
    chatHistory.classList.add('smooth-scroll');
    
    // Add glow effect to buttons
    const allButtons = document.querySelectorAll('button');
    allButtons.forEach(button => {
        button.classList.add('glow-on-hover');
    });
    
    // Mode switching
    scanModeBtn.addEventListener('click', function() {
        switchMode('scan');
    });
    
    chatModeBtn.addEventListener('click', function() {
        switchMode('chat');
    });
    
    // Tab switching
    vulnerabilitiesTab.addEventListener('click', function() {
        switchTab('vulnerabilities');
    });
    
    secureCodeTab.addEventListener('click', function() {
        switchTab('secure-code');
    });
    
    chatResultsTab.addEventListener('click', function() {
        switchTab('chat-results');
    });
    
    // Send button click event
    sendButton.addEventListener('click', function() {
        sendMessage();
    });
    
    // Input keypress event for Enter key
    messageInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });
    
    // Save buttons
    saveReportBtn && saveReportBtn.addEventListener('click', function() {
        saveContent(vulnerabilityReport.innerHTML, 'vulnerability-report.html');
        showNotification('Report saved successfully!', 'success');
    });
    
    saveCodeBtn && saveCodeBtn.addEventListener('click', function() {
        saveContent(secureCodeContent.textContent, 'secure-code.py');
        showNotification('Secure code saved successfully!', 'success');
    });
    
    saveChatBtn && saveChatBtn.addEventListener('click', function() {
        saveContent(chatResultContent.innerHTML, 'ai-chat-response.html');
        showNotification('Chat response saved successfully!', 'success');
    });
    
    // Initialize particles.js
    function initParticles() {
        particlesJS('particles-js', {
            "particles": {
                "number": {
                    "value": 40,
                    "density": {
                        "enable": true,
                        "value_area": 800
                    }
                },
                "color": {
                    "value": ["#8be9fd", "#50fa7b", "#ff79c6"]
                },
                "shape": {
                    "type": "circle",
                    "stroke": {
                        "width": 0,
                        "color": "#000000"
                    },
                    "polygon": {
                        "nb_sides": 5
                    }
                },
                "opacity": {
                    "value": 0.3,
                    "random": true,
                    "anim": {
                        "enable": true,
                        "speed": 0.5,
                        "opacity_min": 0.1,
                        "sync": false
                    }
                },
                "size": {
                    "value": 4,
                    "random": true,
                    "anim": {
                        "enable": true,
                        "speed": 2,
                        "size_min": 0.1,
                        "sync": false
                    }
                },
                "line_linked": {
                    "enable": true,
                    "distance": 150,
                    "color": "#44475a",
                    "opacity": 0.2,
                    "width": 1
                },
                "move": {
                    "enable": true,
                    "speed": 1,
                    "direction": "none",
                    "random": true,
                    "straight": false,
                    "out_mode": "out",
                    "bounce": false,
                    "attract": {
                        "enable": false,
                        "rotateX": 600,
                        "rotateY": 1200
                    }
                }
            },
            "interactivity": {
                "detect_on": "canvas",
                "events": {
                    "onhover": {
                        "enable": true,
                        "mode": "grab"
                    },
                    "onclick": {
                        "enable": true,
                        "mode": "push"
                    },
                    "resize": true
                },
                "modes": {
                    "grab": {
                        "distance": 140,
                        "line_linked": {
                            "opacity": 0.8
                        }
                    },
                    "bubble": {
                        "distance": 400,
                        "size": 40,
                        "duration": 2,
                        "opacity": 8,
                        "speed": 3
                    },
                    "repulse": {
                        "distance": 200,
                        "duration": 0.4
                    },
                    "push": {
                        "particles_nb": 4
                    },
                    "remove": {
                        "particles_nb": 2
                    }
                }
            },
            "retina_detect": true
        });
    }
    
    // Show notification function
    function showNotification(message, type = 'success') {
        const notificationContainer = document.getElementById('notification-container');
        
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        
        // Add icon based on notification type
        let icon = 'fa-check-circle';
        if (type === 'warning') icon = 'fa-exclamation-circle';
        if (type === 'error') icon = 'fa-times-circle';
        
        notification.innerHTML = `<i class="fas ${icon}"></i>${message}`;
        
        // Add to container
        notificationContainer.appendChild(notification);
        
        // Automatically remove after 5 seconds
        setTimeout(() => {
            notification.classList.add('hide');
            // Remove from DOM after animation completes
            setTimeout(() => {
                notification.remove();
            }, 500);
        }, 5000);
    }
    
    // Functions
    function switchMode(mode) {
        // Update UI for selected mode
        if (mode === 'scan') {
            scanModeBtn.classList.add('active');
            chatModeBtn.classList.remove('active');
            messageInput.placeholder = 'Paste your code here to scan for vulnerabilities...';
            sendButton.innerHTML = '<i class="fa-solid fa-magnifying-glass"></i> Scan Code';
            switchTab('vulnerabilities');
            
            // Add animation
            scanModeBtn.querySelector('i').classList.add('animate__animated', 'animate__bounceIn');
            setTimeout(() => {
                scanModeBtn.querySelector('i').classList.remove('animate__animated', 'animate__bounceIn');
            }, 1000);
        } else {
            // Chat mode
            chatModeBtn.classList.add('active');
            scanModeBtn.classList.remove('active');
            messageInput.placeholder = 'Type your message here...';
            sendButton.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Send';
            switchTab('chat-results');
            
            // Add animation
            chatModeBtn.querySelector('i').classList.add('animate__animated', 'animate__bounceIn');
            setTimeout(() => {
                chatModeBtn.querySelector('i').classList.remove('animate__animated', 'animate__bounceIn');
            }, 1000);
        }
    }
    
    function switchTab(tabName) {
        // Hide all panels
        vulnerabilitiesPanel.classList.remove('active');
        secureCodePanel.classList.remove('active');
        chatResultsPanel.classList.remove('active');
        
        // Deactivate all tab buttons
        vulnerabilitiesTab.classList.remove('active');
        secureCodeTab.classList.remove('active');
        chatResultsTab.classList.remove('active');
        
        // Show selected panel and activate tab
        if (tabName === 'vulnerabilities') {
            vulnerabilitiesPanel.classList.add('active');
            vulnerabilitiesTab.classList.add('active');
            
            // Add animation
            vulnerabilitiesTab.classList.add('animate__animated', 'animate__fadeIn');
            setTimeout(() => {
                vulnerabilitiesTab.classList.remove('animate__animated', 'animate__fadeIn');
            }, 500);
        } else if (tabName === 'secure-code') {
            secureCodePanel.classList.add('active');
            secureCodeTab.classList.add('active');
            
            // Add animation
            secureCodeTab.classList.add('animate__animated', 'animate__fadeIn');
            setTimeout(() => {
                secureCodeTab.classList.remove('animate__animated', 'animate__fadeIn');
            }, 500);
        } else {
            chatResultsPanel.classList.add('active');
            chatResultsTab.classList.add('active');
            
            // Add animation
            chatResultsTab.classList.add('animate__animated', 'animate__fadeIn');
            setTimeout(() => {
                chatResultsTab.classList.remove('animate__animated', 'animate__fadeIn');
            }, 500);
        }
    }
    
    function sendMessage() {
        const message = messageInput.value.trim();
        if (!message) return;
        
        // Add user message to chat
        addUserMessage(message);
        
        // Clear input
        messageInput.value = '';
        
        // Add loading indicator
        addLoadingMessage();
        
        // Check current mode
        if (scanModeBtn.classList.contains('active')) {
            // Scan mode - process code
            processCodeScan(message);
        } else {
            // Chat mode - process chat
            processChatMessage(message);
        }
    }
    
    function addLoadingMessage() {
        const loadingMessageDiv = document.createElement('div');
        loadingMessageDiv.classList.add('bot-message', 'loading-message', 'animate__animated', 'animate__fadeIn');
        loadingMessageDiv.innerHTML = `
            <div class="message-content">
                <div class="loading-indicator">
                    <i class="fas fa-circle-notch fa-spin"></i> Processing your request...
                </div>
            </div>
        `;
        loadingMessageDiv.id = 'loading-message';
        
        chatHistory.appendChild(loadingMessageDiv);
        chatHistory.scrollTop = chatHistory.scrollHeight;
    }
    
    function removeLoadingMessage() {
        const loadingMessage = document.getElementById('loading-message');
        if (loadingMessage) {
            loadingMessage.remove();
        }
    }
    
    function addUserMessage(message) {
        // Truncate if very long
        let displayMessage = message;
        if (message.length > 100) {
            const shortMessage = message.substring(0, 100) + '...';
            // For code, add it in a code block
            if (message.includes('\n') || message.includes('function') || message.includes('import') || message.includes('def ')) {
                displayMessage = shortMessage + '<div class="code-block">Code block not shown in chat view</div>';
            } else {
                displayMessage = shortMessage;
            }
        }
        
        const userMessageDiv = document.createElement('div');
        userMessageDiv.classList.add('user-message', 'animate__animated', 'animate__fadeIn');
        userMessageDiv.innerHTML = `
            <div class="message-content">
                <strong>You:</strong><br>
                ${displayMessage}
            </div>
        `;
        
        chatHistory.appendChild(userMessageDiv);
        chatHistory.scrollTop = chatHistory.scrollHeight;
    }
    
    function addBotMessage(message) {
        // Remove any loading message first
        removeLoadingMessage();
        
        const botMessageDiv = document.createElement('div');
        botMessageDiv.classList.add('bot-message', 'animate__animated', 'animate__fadeIn');
        botMessageDiv.innerHTML = `
            <div class="message-content">
                <strong>AI Scanner:</strong><br>
                ${message}
            </div>
        `;
        
        chatHistory.appendChild(botMessageDiv);
        chatHistory.scrollTop = chatHistory.scrollHeight;
    }
    
    function processCodeScan(code) {
        // Show scanning status
        addBotMessage('<span style="color: var(--accent-orange);">⚡ Scanning your code for vulnerabilities...</span>');
        
        // Call the backend API to scan the code
        fetch(`${API_BASE_URL}/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ code: code }),
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            const vulnerabilities = data.vulnerabilities;
            const secureCode = data.secure_code;
            const report = data.report;
            
            // Display vulnerability report
            generateVulnerabilityReport(vulnerabilities, report);
            
            // Display secure code
            secureCodeContent.textContent = secureCode;
            highlightSecureCode();
            
            // Switch to vulnerability report tab
            switchTab('vulnerabilities');
            
            // Add summary message to chat
            if (vulnerabilities && vulnerabilities.length > 0) {
                const vulnerabilityTypes = new Set(vulnerabilities.map(v => v.type));
                const typeCount = vulnerabilityTypes.size;
                const typeList = Array.from(vulnerabilityTypes)
                    .map(type => `<span style="color: var(--accent-red);">${type.replace('_', ' ')}</span>`)
                    .join(', ');
                
                addBotMessage(`<span style="color: var(--accent-red);">⚠️ Found ${vulnerabilities.length} potential security vulnerabilities</span> in your code across ${typeCount} vulnerability types: ${typeList}
                <br><br>
                Check the <span style="color: var(--accent-purple);">Vulnerability Report</span> tab for details and the <span style="color: var(--accent-blue);">Secure Code</span> tab for recommendations.`);
            } else {
                addBotMessage(`<span style="color: var(--accent-green);">✓ No vulnerabilities detected!</span> Your code appears to be secure.`);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            addBotMessage(`<span style="color: var(--accent-red);">Error scanning code: ${error.message}</span>`);
            
            // Fallback to demo mode
            addBotMessage('Using demo data instead...');
            
            fetch(`${API_BASE_URL}/demo`)
                .then(response => response.json())
                .then(data => {
                    const vulnerabilities = data.vulnerabilities;
                    const secureCode = data.secure_code;
                    const report = data.report;
                    
                    generateVulnerabilityReport(vulnerabilities, report);
                    secureCodeContent.textContent = secureCode;
                    highlightSecureCode();
                    switchTab('vulnerabilities');
                })
                .catch(error => {
                    console.error('Demo data error:', error);
                    vulnerabilityReport.innerHTML = `
                        <div class="empty-state">
                            <i class="fa-solid fa-triangle-exclamation"></i>
                            <h3>Error</h3>
                            <p>Could not scan code. Please try again later.</p>
                        </div>
                    `;
                });
        });
    }
    
    function processChatMessage(message) {
        // Show thinking status
        addBotMessage('<span style="color: var(--accent-orange);">⚡ Thinking...</span>');
        
        // Update chat results area
        chatResultContent.innerHTML = '<span style="color: var(--accent-orange); font-style: italic;">Generating AI response...</span>';
        
        // Switch to chat results tab
        switchTab('chat-results');
        
        // Determine if this is likely a code-related question
        const isCodeRelated = message.toLowerCase().includes('code') || 
                              message.toLowerCase().includes('vulnerab') || 
                              message.toLowerCase().includes('secure') || 
                              message.toLowerCase().includes('xss') || 
                              message.toLowerCase().includes('injection');
                              
        // Set system prompt based on message content
        let systemPrompt = "You are an AI security assistant specialized in helping developers write secure code. ";
        systemPrompt += "Focus on providing best practices, identifying security vulnerabilities, and suggesting secure coding techniques. ";
        systemPrompt += "Be concise but thorough, and include code examples where appropriate.";
        
        // Call the chat API
        fetch(`${API_BASE_URL}/chat`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                message: message,
                system_prompt: systemPrompt
            }),
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            // Remove the thinking message
            chatHistory.removeChild(chatHistory.lastChild);
            
            // Get the AI response
            const aiResponse = data.response;
            
            // Format the response with code highlighting
            const formattedResponse = formatAIResponse(aiResponse);
            
            // Add response to chat
            addBotMessage('<span style="color: var(--accent-blue);">[GROQ AI]</span> Response ready in Results tab');
            
            // Update chat results area with formatting
            chatResultContent.innerHTML = `
                <div style="color: var(--accent-blue); font-weight: bold; margin-bottom: 15px; font-size: 16px;">Response from GROQ AI Security Assistant</div>
                ${formattedResponse}
            `;
            
            // Apply syntax highlighting to any code blocks
            document.querySelectorAll('pre code').forEach((block) => {
                hljs.highlightElement(block);
            });
        })
        .catch(error => {
            console.error('Chat API error:', error);
            
            // Remove the thinking message
            chatHistory.removeChild(chatHistory.lastChild);
            
            // Add error message
            addBotMessage(`<span style="color: var(--accent-red);">Error getting AI response: ${error.message}</span>`);
            
            // Provide a fallback response
            let fallbackResponse = '';
            if (message.toLowerCase().includes('hello') || message.toLowerCase().includes('hi')) {
                fallbackResponse = `Hello! I'm your AI Security Assistant. I can help you analyze code for vulnerabilities, suggest security improvements, or answer questions about secure coding practices. What would you like help with today?`;
            } else if (message.toLowerCase().includes('sql injection')) {
                fallbackResponse = `
                <h3>SQL Injection Prevention</h3>
                <p>SQL injection is a critical security vulnerability where attackers can manipulate SQL queries through user input. Here's how to prevent it:</p>
                <ul>
                    <li><strong>Use Parameterized Queries</strong> instead of string concatenation</li>
                    <li><strong>Implement Prepared Statements</strong> with placeholders</li>
                    <li><strong>Apply Input Validation</strong> to reject suspicious inputs</li>
                    <li><strong>Implement Least Privilege</strong> for database connections</li>
                </ul>
                <p>Example of vulnerable code:</p>
                <pre><code class="language-python">
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
cursor.execute(query)
                </code></pre>
                <p>Secure implementation:</p>
                <pre><code class="language-python">
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
                </code></pre>`;
            } else {
                fallbackResponse = `
                <h3>Security Best Practices</h3>
                <p>Here are some general security best practices for code development:</p>
                <ol>
                    <li><strong>Input Validation:</strong> Never trust user input. Validate all inputs against strict schemas.</li>
                    <li><strong>Output Encoding:</strong> Always encode data before displaying it to users.</li>
                    <li><strong>Authentication & Authorization:</strong> Implement proper user verification and access controls.</li>
                    <li><strong>Use Secure Dependencies:</strong> Keep libraries and frameworks updated to avoid known vulnerabilities.</li>
                    <li><strong>Implement Logging & Monitoring:</strong> Track security events and set up alerts for suspicious activities.</li>
                </ol>
                <p>Would you like more specific information about any of these topics?</p>`;
            }
            
            // Update chat results area with fallback response
            chatResultContent.innerHTML = `
                <div style="color: var(--accent-blue); font-weight: bold; margin-bottom: 15px; font-size: 16px;">Fallback Response (AI Service Unavailable)</div>
                ${fallbackResponse}
            `;
            
            // Apply syntax highlighting to any code blocks
            document.querySelectorAll('pre code').forEach((block) => {
                hljs.highlightElement(block);
            });
        });
    }
    
    function formatAIResponse(response) {
        // Check if the response is already HTML formatted
        if (response.includes('<h3>') || response.includes('<p>') || response.includes('<ul>')) {
            return response;
        }
        
        // Otherwise, apply simple formatting
        let formatted = response;
        
        // Format code blocks
        formatted = formatted.replace(/```(\w*)([\s\S]*?)```/g, function(match, language, code) {
            language = language.trim() || 'python';
            code = code.trim();
            return `<pre><code class="language-${language}">${code}</code></pre>`;
        });
        
        // Format inline code
        formatted = formatted.replace(/`([^`]+)`/g, '<code>$1</code>');
        
        // Format headings (assume lines ending with : followed by newline are headings)
        formatted = formatted.replace(/^(.*?):\s*$/gm, '<h3>$1</h3>');
        
        // Format lists
        formatted = formatted.replace(/^(\d+)\.\s+(.*?)$/gm, '<li><strong>$1.</strong> $2</li>');
        formatted = formatted.replace(/^-\s+(.*?)$/gm, '<li>$1</li>');
        
        // Wrap paragraphs
        formatted = formatted.replace(/^(?!<h3>|<li>|<pre>|<code>|<\/)(.*?)$/gm, '<p>$1</p>');
        
        // Wrap lists
        formatted = formatted.replace(/(<li>.*?)(<li>.*?)(<\/p>|<h3>|$)/gs, '<ul>$1$2</ul>$3');
        
        return formatted;
    }
    
    function generateVulnerabilityReport(vulnerabilities, report) {
        // If a pre-formatted report was provided by the backend, use it
        if (report && typeof report === 'string' && report.trim().length > 0) {
            // Create a container for the report
            const reportContainer = document.createElement('div');
            reportContainer.className = 'backend-report animate__animated animate__fadeIn';
            
            // Format the report with colorful elements
            let formattedReport = report.replace(/\n/g, '<br>');
            
            // Color code INSTANCE sections
            formattedReport = formattedReport.replace(/INSTANCE \d+:/g, match => 
                `<h3 class="report-instance">${match}</h3>`);
            
            // Color code line numbers
            formattedReport = formattedReport.replace(/Line Number: (\d+)/g, 
                '<div class="report-line">Line Number: <span class="report-line-number">$1</span></div>');
                
            // Fix different Risk Level formats
            formattedReport = formattedReport.replace(/Risk Level: (HIGH|MEDIUM|LOW|CRITICAL)/gi, match => {
                const level = match.split(':')[1].trim().toUpperCase();
                const levelClass = level.toLowerCase();
                return `Risk Level: <span class="report-risk-${levelClass}">${level}</span>`;
            });
            
            // Alternative risk level formats that might appear
            formattedReport = formattedReport.replace(/(Severity|Risk): (HIGH|MEDIUM|LOW|CRITICAL)/gi, (match, prefix, level) => {
                const levelClass = level.toLowerCase();
                return `${prefix}: <span class="report-risk-${levelClass}">${level.toUpperCase()}</span>`;
            });
            
            // Color code confidence values
            formattedReport = formattedReport.replace(/(Confidence: )([0-9.]+)/g, 
                '$1<span class="report-confidence">$2</span>');
            
            // Color code detection methods
            formattedReport = formattedReport.replace(/(Detection Method: )([a-zA-Z0-9_]+)/g, 
                '$1<span class="report-method">$2</span>');
            
            // Format line-specific code
            formattedReport = formattedReport.replace(/def ([a-zA-Z0-9_]+)\(/g, 
                'def <span class="report-keyword-info">$1</span>(');
            
            formattedReport = formattedReport.replace(/(user_input|input|query)(?=[^\w])/g, 
                '<span class="report-keyword-warning">$1</span>');
            
            formattedReport = formattedReport.replace(/"([^"]*?)"\s*\+\s*([a-zA-Z0-9_]+)/g, 
                '"<span class="report-keyword-danger">$1</span>" + <span class="report-keyword-danger">$2</span>');
                
            // Format SQL keywords
            formattedReport = formattedReport.replace(/(SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)(?=[^\w])/gi, 
                '<span class="report-keyword-info">$1</span>');
            
            // Format vulnerable code sections
            formattedReport = formattedReport.replace(/(Vulnerable Code:)(\s*\n?\s*```[\s\S]*?```)/g, (match, prefix, code) => {
                code = code.replace(/```/g, '').trim();
                return `${prefix}<pre class="report-code"><code>${escapeHtml(code)}</code></pre>`;
            });
            
            // Format code contexts
            formattedReport = formattedReport.replace(/(Code Context:)(\s*\n?\s*```[\s\S]*?```)/g, (match, prefix, code) => {
                code = code.replace(/```/g, '').trim();
                return `${prefix}<pre class="report-context"><code>${escapeHtml(code)}</code></pre>`;
            });
            
            // Highlight keywords
            const keywords = [
                { pattern: /SQL injection/gi, className: 'report-keyword-danger' },
                { pattern: /Cross-site scripting|XSS/gi, className: 'report-keyword-danger' },
                { pattern: /Command injection/gi, className: 'report-keyword-danger' },
                { pattern: /Insecure/gi, className: 'report-keyword-warning' },
                { pattern: /Vulnerability|Vulnerable/gi, className: 'report-keyword-danger' },
                { pattern: /Injection/gi, className: 'report-keyword-danger' },
                { pattern: /Sanitize|Escape/gi, className: 'report-keyword-success' },
                { pattern: /Security/gi, className: 'report-keyword-info' },
                { pattern: /Parameterized/gi, className: 'report-keyword-success' },
                { pattern: /Prepared statement/gi, className: 'report-keyword-success' }
            ];
            
            keywords.forEach(({ pattern, className }) => {
                formattedReport = formattedReport.replace(pattern, match => 
                    `<span class="${className}">${match}</span>`);
            });
            
            // Format section dividers
            formattedReport = formattedReport.replace(/(-{10,})/g, 
                '<hr class="report-divider">');
            
            reportContainer.innerHTML = `<div class="report-content">${formattedReport}</div>`;
            
            // Clear previous report and add the new one
            vulnerabilityReport.innerHTML = '';
            vulnerabilityReport.appendChild(reportContainer);
            return;
        }
        
        // If no vulnerabilities found, show empty state
        if (!vulnerabilities || vulnerabilities.length === 0) {
            vulnerabilityReport.innerHTML = `
                <div class="empty-state animate__animated animate__fadeIn">
                    <i class="fa-solid fa-check-circle"></i>
                    <h3>No vulnerabilities detected</h3>
                    <p>Your code appears to be secure. However, always review it carefully for any security issues.</p>
                </div>
            `;
            return;
        }
        
        // Clear previous report
        vulnerabilityReport.innerHTML = '';
        
        // Add summary
        const summarySection = document.createElement('div');
        summarySection.className = 'vulnerability-summary animate__animated animate__fadeInDown';
        
        // Count vulnerabilities by severity
        const severityCounts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };
        
        vulnerabilities.forEach(vuln => {
            const severity = vuln.severity ? vuln.severity.toLowerCase() : 'medium';
            if (severityCounts[severity] !== undefined) {
                severityCounts[severity]++;
            } else {
                severityCounts.medium++;
            }
        });
        
        summarySection.innerHTML = `
            <div class="summary-header">
                <i class="fa-solid fa-shield-alt"></i>
                <h2>Vulnerability Summary</h2>
            </div>
            <div class="severity-bars">
                <div class="severity-bar">
                    <div class="severity-label">Critical</div>
                    <div class="severity-progress">
                        <div class="severity-progress-bar critical" style="width: ${severityCounts.critical ? '100%' : '0%'}">
                            ${severityCounts.critical || 0}
                        </div>
                    </div>
                </div>
                <div class="severity-bar">
                    <div class="severity-label">High</div>
                    <div class="severity-progress">
                        <div class="severity-progress-bar high" style="width: ${severityCounts.high ? '100%' : '0%'}">
                            ${severityCounts.high || 0}
                        </div>
                    </div>
                </div>
                <div class="severity-bar">
                    <div class="severity-label">Medium</div>
                    <div class="severity-progress">
                        <div class="severity-progress-bar medium" style="width: ${severityCounts.medium ? '100%' : '0%'}">
                            ${severityCounts.medium || 0}
                        </div>
                    </div>
                </div>
                <div class="severity-bar">
                    <div class="severity-label">Low</div>
                    <div class="severity-progress">
                        <div class="severity-progress-bar low" style="width: ${severityCounts.low ? '100%' : '0%'}">
                            ${severityCounts.low || 0}
                        </div>
                    </div>
                </div>
            </div>
            <div class="total-count">
                Total Vulnerabilities: <span>${vulnerabilities.length}</span>
            </div>
        `;
        
        vulnerabilityReport.appendChild(summarySection);
        
        // Group vulnerabilities by type to make the report easier to read
        const vulnerabilityTypes = {};
        vulnerabilities.forEach(vuln => {
            const type = vuln.type || 'unknown';
            if (!vulnerabilityTypes[type]) {
                vulnerabilityTypes[type] = [];
            }
            vulnerabilityTypes[type].push(vuln);
        });
        
        // Create a container for all vulnerabilities
        const vulnContainer = document.createElement('div');
        vulnContainer.className = 'vulnerabilities-container';
        vulnerabilityReport.appendChild(vulnContainer);
        
        // Add each vulnerability type section
        let animationDelay = 0;
        Object.entries(vulnerabilityTypes).forEach(([type, vulnsOfType], typeIndex) => {
            // Create type section
            const typeSection = document.createElement('div');
            typeSection.className = `vulnerability-type-section animate__animated animate__fadeInUp`;
            typeSection.style.animationDelay = `${typeIndex * 0.2}s`;
            
            // Format type name for display
            const displayType = type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            
            // Get icon for vulnerability type
            let typeIcon = 'fa-bug';
            if (type === 'sql_injection') typeIcon = 'fa-database';
            if (type === 'xss') typeIcon = 'fa-code';
            if (type === 'command_injection') typeIcon = 'fa-terminal';
            if (type === 'path_traversal') typeIcon = 'fa-folder-open';
            if (type === 'csrf') typeIcon = 'fa-globe';
            if (type === 'insecure_authentication') typeIcon = 'fa-key';
            if (type === 'insecure_deserialization') typeIcon = 'fa-box-open';
            
            typeSection.innerHTML = `
                <div class="type-header">
                    <h3><i class="fa-solid ${typeIcon}"></i> ${displayType} (${vulnsOfType.length})</h3>
                    <div class="type-description">${getVulnDescription(type)}</div>
                </div>
            `;
            
            // Add each vulnerability of this type
            vulnsOfType.forEach((vuln, vulnIndex) => {
                // Create vulnerability item
                const vulnItem = document.createElement('div');
                vulnItem.className = 'vulnerability-section animate__animated animate__fadeInUp';
                vulnItem.style.animationDelay = `${animationDelay}s`;
                animationDelay += 0.1; // Stagger the animations
                
                // Get severity class
                let severityClass = 'medium';
                if (vuln.severity === 'critical') severityClass = 'critical';
                if (vuln.severity === 'high') severityClass = 'high';
                if (vuln.severity === 'medium') severityClass = 'medium';
                if (vuln.severity === 'low') severityClass = 'low';
                
                // Handle different property name variations
                const lineNumber = vuln.line || vuln.line_number || 'N/A';
                const fileName = vuln.file || vuln.fileName || 'code-snippet';
                const vulnCode = vuln.code || vuln.line_content || vuln.vulnerable_code || 'Code snippet not available';
                const vulnMessage = vuln.message || vuln.description || getVulnDescription(type);
                
                // Get fix suggestions - handle different formats
                let fixSuggestions = '';
                if (vuln.fix) {
                    fixSuggestions = vuln.fix;
                } else if (vuln.fixes && Array.isArray(vuln.fixes)) {
                    fixSuggestions = vuln.fixes.map(fix => `<li>${fix}</li>`).join('');
                    if (fixSuggestions) {
                        fixSuggestions = `<ul>${fixSuggestions}</ul>`;
                    }
                } else if (vuln.remediation) {
                    fixSuggestions = vuln.remediation;
                }
                
                if (!fixSuggestions) {
                    fixSuggestions = 'No specific fix recommendation available';
                }
                
                vulnItem.innerHTML = `
                    <div class="vulnerability-header">
                        <div class="vuln-location">
                            <span class="file-badge">
                                <i class="fa-regular fa-file-code"></i> ${fileName}
                            </span>
                            <span class="line-badge">
                                <i class="fa-solid fa-code"></i> Line ${lineNumber}
                            </span>
                        </div>
                        <div class="vulnerability-badges">
                            <span class="severity-badge ${severityClass}">
                                ${vuln.severity ? vuln.severity.toUpperCase() : 'MEDIUM'}
                            </span>
                            <span class="expand-collapse"><i class="fa-solid fa-chevron-down"></i></span>
                        </div>
                    </div>
                    
                    <div class="vulnerability-details">
                        <div class="detail-item">
                            <div class="detail-label"><i class="fa-solid fa-circle-info"></i> Description</div>
                            <div class="detail-value">${vulnMessage}</div>
                        </div>
                        
                        <div class="detail-item">
                            <div class="detail-label"><i class="fa-solid fa-code"></i> Vulnerable Code</div>
                            <div class="detail-value code-container">
                                <pre class="vulnerability-line">${escapeHtml(vulnCode)}</pre>
                            </div>
                        </div>
                        
                        <div class="fix-suggestion">
                            <div class="detail-label"><i class="fa-solid fa-wrench"></i> Fix Suggestion</div>
                            <div class="detail-value">${fixSuggestions}</div>
                        </div>
                    </div>
                `;
                
                // Add to the type section
                typeSection.appendChild(vulnItem);
                
                // Add click event to expand/collapse details
                vulnItem.querySelector('.vulnerability-header').addEventListener('click', function() {
                    const details = this.nextElementSibling;
                    const expandIcon = this.querySelector('.expand-collapse i');
                    const isVisible = details.style.display !== 'none';
                    
                    // Toggle visibility with animation
                    if (isVisible) {
                        details.classList.add('animate__animated', 'animate__fadeOutUp');
                        details.style.animationDuration = '0.3s';
                        expandIcon.classList.remove('fa-chevron-up');
                        expandIcon.classList.add('fa-chevron-down');
                        setTimeout(() => {
                            details.style.display = 'none';
                            details.classList.remove('animate__animated', 'animate__fadeOutUp');
                        }, 300);
                    } else {
                        details.style.display = 'block';
                        details.classList.add('animate__animated', 'animate__fadeInDown');
                        details.style.animationDuration = '0.3s';
                        expandIcon.classList.remove('fa-chevron-down');
                        expandIcon.classList.add('fa-chevron-up');
                        setTimeout(() => {
                            details.classList.remove('animate__animated', 'animate__fadeInDown');
                        }, 300);
                    }
                });
            });
            
            // Add the type section to the container
            vulnContainer.appendChild(typeSection);
        });
        
        // Highlight code in vulnerability sections
        if (hljs) {
            vulnerabilityReport.querySelectorAll('pre').forEach((block) => {
                hljs.highlightElement(block);
            });
        }
    }
    
    function highlightSecureCode() {
        // Apply syntax highlighting to secure code
        hljs.highlightElement(secureCodeContent);
    }
    
    function getVulnDescription(vulnType) {
        if (!vulnType) return 'Undefined security vulnerability';
        
        const descriptions = {
            sql_injection: 'SQL Injection vulnerabilities allow attackers to inject malicious SQL commands that can manipulate your database, potentially leading to data leaks, modification or destruction.',
            
            xss: 'Cross-site Scripting (XSS) allows attackers to inject client-side scripts into web pages, which can steal sensitive information, hijack user sessions, or deface websites.',
            
            command_injection: 'Command Injection vulnerabilities allow attackers to execute arbitrary system commands on the host operating system, potentially taking complete control of the server.',
            
            path_traversal: 'Path Traversal vulnerabilities allow attackers to access files and directories outside of the intended directory, potentially exposing sensitive system files.',
            
            csrf: 'Cross-Site Request Forgery (CSRF) tricks users into performing unwanted actions on a website where they\'re authenticated, potentially changing settings or making transactions.',
            
            insecure_authentication: 'Insecure Authentication vulnerabilities involve weaknesses in the login mechanism that could allow attackers to bypass authentication or brute force passwords.',
            
            insecure_deserialization: 'Insecure Deserialization vulnerabilities occur when untrusted data is used to abuse the logic of an application, potentially resulting in remote code execution.',
            
            injection: 'Injection vulnerabilities occur when untrusted data is sent to an interpreter as part of a command or query, allowing attackers to execute unintended commands or access unauthorized data.',
            
            broken_authentication: 'Broken Authentication vulnerabilities allow attackers to compromise passwords, keys, or session tokens, or exploit implementation flaws to assume other users\' identities.',
            
            sensitive_data_exposure: 'Sensitive Data Exposure happens when an application does not adequately protect sensitive information such as financial data, healthcare information, or credentials.',
            
            xxe: 'XML External Entity (XXE) attacks target applications that parse XML input, potentially leading to disclosure of confidential data or server-side request forgery.',
            
            broken_access_control: 'Broken Access Control vulnerabilities allow users to access resources or perform actions beyond their intended permissions, potentially exposing sensitive data or functionality.',
            
            security_misconfiguration: 'Security Misconfiguration is the most commonly seen vulnerability, often resulting from insecure default configurations, incomplete configurations, or verbose error messages.',
            
            unknown: 'Unclassified security vulnerability that may pose a risk to your application.'
        };
        
        const normalizedType = vulnType.toLowerCase().replace(/ /g, '_');
        return descriptions[normalizedType] || `${vulnType.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())} vulnerability that may pose a risk to your application.`;
    }
    
    function escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
    
    function saveContent(content, filename) {
        // Create a blob from the content
        const blob = new Blob([content], { type: filename.endsWith('.html') ? 'text/html' : 'text/plain' });
        const url = URL.createObjectURL(blob);
        
        // Create a temporary link element to trigger the download
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        
        // Clean up
        setTimeout(() => {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }, 100);
    }
    
    // Initialize the UI
    switchMode('scan');
    switchTab('vulnerabilities');
}); 