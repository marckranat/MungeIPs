<?php
// IP Munger Web Interface
// Converts IP lists with configurable consolidation thresholds

class IPMunger {
    private $ip_to_24_threshold;
    private $c24_to_16_threshold;
    private $errors = [];
    private $warnings = [];
    private $input_count = 0;
    private $output_count = 0;
    
    public function __construct($ip_to_24_threshold = 4, $c24_to_16_threshold = 4) {
        $this->ip_to_24_threshold = $ip_to_24_threshold;
        $this->c24_to_16_threshold = $c24_to_16_threshold;
    }
    
    public function getErrors() {
        return $this->errors;
    }
    
    public function getWarnings() {
        return $this->warnings;
    }
    
    public function getInputCount() {
        return $this->input_count;
    }
    
    public function getOutputCount() {
        return $this->output_count;
    }
    
    public function getSavingsPercentage() {
        if ($this->input_count == 0) return 0;
        return round((($this->input_count - $this->output_count) / $this->input_count) * 100, 1);
    }
    
    private function isValidIP($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }
        $parts = explode('.', $ip);
        foreach ($parts as $part) {
            if ($part < 0 || $part > 255) {
                return false;
            }
        }
        return true;
    }
    
    private function isValidSubnet($subnet) {
        return is_numeric($subnet) && $subnet >= 0 && $subnet <= 32;
    }
    
    private function ipToInt($ip) {
        return ip2long($ip);
    }
    
    private function intToIP($int) {
        return long2ip($int);
    }
    
    private function getNetwork24($ip) {
        $parts = explode('.', $ip);
        return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
    }
    
    private function getNetwork16($ip) {
        $parts = explode('.', $ip);
        return $parts[0] . '.' . $parts[1] . '.0.0/16';
    }
    
    private function expandSubnet($ip, $cidr) {
        $start = $this->ipToInt($ip);
        $num_ips = pow(2, 32 - $cidr);
        $results = [];
        
        if ($cidr < 16) {
            // Break into /16 networks
            $num_networks = $num_ips / 65536; // 2^16 = 65536
            $base_ip = $start & 0xFFFF0000; // Align to /16 boundary
            
            for ($i = 0; $i < $num_networks; $i++) {
                $network_ip = $this->intToIP($base_ip);
                $results[] = $this->getNetwork16($network_ip);
                $base_ip += 65536;
            }
        } elseif ($cidr > 24) {
            // Expand to individual IPs
            for ($i = 0; $i < $num_ips; $i++) {
                $results[] = $this->intToIP($start + $i);
            }
        } else {
            // Pass through /16 or /24
            $results[] = $ip . '/' . $cidr;
        }
        
        return $results;
    }
    
    public function processIPs($input_text) {
        $lines = preg_split('/\r?\n/', trim($input_text));
        $single_ips = [];
        $networks_16 = [];
        $line_num = 0;
        $this->input_count = 0; // Reset input count
        
        foreach ($lines as $line) {
            $line_num++;
            $line = trim($line);
            
            // Skip empty lines and comments
            if (empty($line) || preg_match('/^\s*#/', $line)) {
                continue;
            }
            
            // Remove /32 suffix
            $line = preg_replace('/\/32$/', '', $line);
            
            // Parse IP and subnet
            $parts = explode('/', $line);
            $ip = trim($parts[0]);
            $subnet = isset($parts[1]) ? trim($parts[1]) : null;
            
            // Validate IP
            if (!$this->isValidIP($ip)) {
                $this->warnings[] = "Invalid IP address '$ip' on line $line_num, skipping";
                continue;
            }
            
            // Count valid input entries
            $this->input_count++;
            
            if ($subnet === null) {
                // Single IP
                $single_ips[] = $ip;
            } else {
                // Validate subnet
                if (!$this->isValidSubnet($subnet)) {
                    $this->warnings[] = "Invalid subnet '/$subnet' for IP '$ip' on line $line_num, skipping";
                    $this->input_count--; // Don't count invalid entries
                    continue;
                }
                
                // Block dangerous large subnets
                if ($subnet <= 8) {
                    $this->warnings[] = "Subnet '$ip/$subnet' too large (would generate millions of IPs), skipping";
                    $this->input_count--; // Don't count blocked entries
                    continue;
                }
                
                if ($subnet == 16) {
                    // Pass through /16
                    $networks_16[] = $ip . '/' . $subnet;
                } elseif ($subnet == 24) {
                    // Pass through /24
                    $single_ips[] = $ip . '/' . $subnet;
                } elseif ($subnet >= 18 && $subnet <= 23) {
                    // Convert /18 to /23 to /16
                    $networks_16[] = $this->getNetwork16($ip);
                } else {
                    // Expand other subnets
                    $expanded = $this->expandSubnet($ip, $subnet);
                    foreach ($expanded as $expanded_ip) {
                        if (strpos($expanded_ip, '/16') !== false) {
                            $networks_16[] = $expanded_ip;
                        } else {
                            $single_ips[] = $expanded_ip;
                        }
                    }
                }
            }
        }
        
        // Group single IPs by /24 networks
        $network_24_counts = [];
        $processed_ips = [];
        
        foreach ($single_ips as $ip) {
            if (strpos($ip, '/24') !== false) {
                $processed_ips[] = $ip;
            } else {
                $network_24 = $this->getNetwork24($ip);
                if (!isset($network_24_counts[$network_24])) {
                    $network_24_counts[$network_24] = [];
                }
                $network_24_counts[$network_24][] = $ip;
            }
        }
        
        // Apply /24 consolidation threshold
        foreach ($network_24_counts as $network => $ips) {
            if (count($ips) >= $this->ip_to_24_threshold) {
                $processed_ips[] = $network;
            } else {
                $processed_ips = array_merge($processed_ips, $ips);
            }
        }
        
        // Group /24 networks by /16 networks
        $network_16_counts = [];
        $final_ips = [];
        
        foreach ($processed_ips as $ip) {
            if (strpos($ip, '/24') !== false) {
                $network_16 = $this->getNetwork16(str_replace('/24', '', $ip));
                if (!isset($network_16_counts[$network_16])) {
                    $network_16_counts[$network_16] = [];
                }
                $network_16_counts[$network_16][] = $ip;
            } else {
                $final_ips[] = $ip;
            }
        }
        
        // Apply /16 consolidation threshold
        foreach ($network_16_counts as $network => $subnets) {
            if (count($subnets) >= $this->c24_to_16_threshold) {
                $final_ips[] = $network;
            } else {
                $final_ips = array_merge($final_ips, $subnets);
            }
        }
        
        // Add the /16 networks from initial processing
        $final_ips = array_merge($final_ips, $networks_16);
        
        // Remove duplicates and sort
        $final_ips = array_unique($final_ips);
        sort($final_ips);
        
        // Set output count
        $this->output_count = count($final_ips);
        
        return $final_ips;
    }
}

// Process form submission
$results = null;
$errors = [];
$warnings = [];
$input_text = '';
$ip_threshold = 4;
$c24_threshold = 4;
$input_count = 0;
$output_count = 0;
$savings_percentage = 0;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input_text = $_POST['ip_list'] ?? '';
    $ip_threshold = max(1, intval($_POST['ip_threshold'] ?? 4));
    $c24_threshold = max(1, intval($_POST['c24_threshold'] ?? 4));
    
    if (empty($input_text)) {
        $errors[] = "Please enter some IP addresses to process.";
    } else {
        $munger = new IPMunger($ip_threshold, $c24_threshold);
        $results = $munger->processIPs($input_text);
        $errors = $munger->getErrors();
        $warnings = $munger->getWarnings();
        $input_count = $munger->getInputCount();
        $output_count = $munger->getOutputCount();
        $savings_percentage = $munger->getSavingsPercentage();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Address Consolidation Tool</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 10px;
        }
        
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
            color: #333;
        }
        
        textarea {
            width: 100%;
            height: 200px;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            resize: vertical;
            box-sizing: border-box;
        }
        
        textarea:focus {
            outline: none;
            border-color: #4CAF50;
        }
        
        .settings {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .setting-group {
            flex: 1;
        }
        
        select {
            width: 100%;
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            box-sizing: border-box;
        }
        
        select:focus {
            outline: none;
            border-color: #4CAF50;
        }
        
        .submit-btn {
            background-color: #4CAF50;
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            width: 100%;
            margin-bottom: 20px;
        }
        
        .submit-btn:hover {
            background-color: #45a049;
        }
        
        .results {
            margin-top: 30px;
        }
        
        .results h2 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .results-box {
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 5px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .stats {
            background-color: #e7f3ff;
            border: 1px solid #bee5eb;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }
        
        .stats h3 {
            margin-top: 0;
            color: #0c5460;
        }
        
        .error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
        }
        
        .warning {
            background-color: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
        }
        
        .help-text {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }
        
        .copy-btn {
            background-color: #17a2b8;
            color: white;
            padding: 8px 16px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 14px;
            margin-bottom: 10px;
        }
        
        .copy-btn:hover {
            background-color: #138496;
        }
        
        .github-link {
            color: #666;
            text-decoration: none;
            font-size: 14px;
            padding: 8px 16px;
            border: 1px solid #ddd;
            border-radius: 5px;
            display: inline-block;
            transition: all 0.3s ease;
        }
        
        .github-link:hover {
            color: #333;
            border-color: #999;
            background-color: #f8f9fa;
        }
        
        @media (max-width: 768px) {
            .settings {
                flex-direction: column;
            }
            
            body {
                padding: 10px;
            }
            
            .container {
                padding: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔗 IP Address Consolidation Tool</h1>
        <p class="subtitle">Optimize your IP lists for WAF configurations with configurable thresholds</p>
        
        <div style="text-align: center; margin-bottom: 20px;">
            <a href="https://github.com/marckranat/MungeIPs" target="_blank" class="github-link">
                📂 View source code on GitHub
            </a>
        </div>
        
        <form method="POST">
            <div class="form-group">
                <label for="ip_list">IP Address List:</label>
                <textarea name="ip_list" id="ip_list" placeholder="Enter IP addresses and subnets, one per line:
192.168.1.1
10.0.0.0/8
172.16.0.0/16
192.168.2.1
192.168.2.2
192.168.2.3
192.168.2.4
203.0.113.0/25"><?php echo htmlspecialchars($input_text); ?></textarea>
                <div class="help-text">
                    Supports single IPs, CIDR notation, and mixed formats. Comments (lines starting with #) are ignored.<br>
                    <strong>Note:</strong> Large subnets (/15 and smaller) are automatically split into /16 networks for WAF compatibility.<br>
                    <strong>Security:</strong> Extremely large subnets (/8 and smaller) are blocked to prevent resource exhaustion.
                </div>
            </div>
            
            <div class="settings">
                <div class="setting-group">
                    <label for="ip_threshold">Consolidate to /24 when:</label>
                    <select name="ip_threshold" id="ip_threshold">
                        <?php for ($i = 2; $i <= 10; $i++): ?>
                            <option value="<?php echo $i; ?>" <?php echo $i == $ip_threshold ? 'selected' : ''; ?>>
                                <?php echo $i; ?>+ IPs in same /24 network
                            </option>
                        <?php endfor; ?>
                    </select>
                    <div class="help-text">When this many individual IPs exist in the same /24 network, consolidate them into a single /24 subnet.</div>
                </div>
                
                <div class="setting-group">
                    <label for="c24_threshold">Consolidate to /16 when:</label>
                    <select name="c24_threshold" id="c24_threshold">
                        <?php for ($i = 2; $i <= 10; $i++): ?>
                            <option value="<?php echo $i; ?>" <?php echo $i == $c24_threshold ? 'selected' : ''; ?>>
                                <?php echo $i; ?>+ /24 subnets in same /16 network
                            </option>
                        <?php endfor; ?>
                    </select>
                    <div class="help-text">When this many /24 subnets exist in the same /16 network, consolidate them into a single /16 subnet.</div>
                </div>
            </div>
            
            <button type="submit" class="submit-btn">🚀 Process IP List</button>
        </form>
        
        <?php if (!empty($errors)): ?>
            <?php foreach ($errors as $error): ?>
                <div class="error">❌ <?php echo htmlspecialchars($error); ?></div>
            <?php endforeach; ?>
        <?php endif; ?>
        
        <?php if (!empty($warnings)): ?>
            <?php foreach ($warnings as $warning): ?>
                <div class="warning">⚠️ <?php echo htmlspecialchars($warning); ?></div>
            <?php endforeach; ?>
        <?php endif; ?>
        
        <?php if ($results !== null): ?>
            <div class="results">
                <div class="stats">
                    <h3>📊 Processing Results</h3>
                    <p><strong>📥 Input entries:</strong> <?php echo $input_count; ?> IP addresses/ranges</p>
                    <p><strong>📤 Output entries:</strong> <?php echo $output_count; ?> optimized entries</p>
                    <p><strong>💾 Space savings:</strong> 
                        <?php if ($savings_percentage > 0): ?>
                            <span style="color: #28a745; font-weight: bold;"><?php echo $savings_percentage; ?>%</span> 
                            (<?php echo ($input_count - $output_count); ?> fewer entries)
                        <?php elseif ($savings_percentage < 0): ?>
                            <span style="color: #dc3545;">+<?php echo abs($savings_percentage); ?>%</span> 
                            (<?php echo ($output_count - $input_count); ?> more entries due to subnet expansion)
                        <?php else: ?>
                            <span style="color: #6c757d;">No change</span>
                        <?php endif; ?>
                    </p>
                    <p><strong>⚙️ Consolidation thresholds:</strong> <?php echo $ip_threshold; ?>+ IPs → /24, <?php echo $c24_threshold; ?>+ /24s → /16</p>
                    <?php if (!empty($warnings)): ?>
                        <p><strong>⚠️ Warnings:</strong> <?php echo count($warnings); ?> entries skipped (see above)</p>
                    <?php endif; ?>
                </div>
                
                <h2>🎯 Optimized IP List</h2>
                <button type="button" class="copy-btn" onclick="copyResults()">📋 Copy Results</button>
                <div class="results-box" id="results-box">
                    <?php if (empty($results)): ?>
                        <em>No valid IP addresses found to process.</em>
                    <?php else: ?>
                        <?php foreach ($results as $ip): ?>
                            <?php echo htmlspecialchars($ip); ?><br>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>
        <?php endif; ?>
    </div>
    
    <script>
        function copyResults() {
            const resultsBox = document.getElementById('results-box');
            const text = resultsBox.innerText;
            
            if (navigator.clipboard) {
                navigator.clipboard.writeText(text).then(() => {
                    const btn = document.querySelector('.copy-btn');
                    const originalText = btn.textContent;
                    btn.textContent = '✅ Copied!';
                    setTimeout(() => {
                        btn.textContent = originalText;
                    }, 2000);
                });
            } else {
                // Fallback for older browsers
                const textarea = document.createElement('textarea');
                textarea.value = text;
                document.body.appendChild(textarea);
                textarea.select();
                document.execCommand('copy');
                document.body.removeChild(textarea);
                alert('Results copied to clipboard!');
            }
        }
    </script>
</body>
</html> 