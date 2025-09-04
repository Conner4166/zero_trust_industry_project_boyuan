const API = 'http://localhost:5000';
const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwcmVmZXJyZWRfdXNlcm5hbWUiOiJqb2huIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

function log(msg, color = '#667eea') {
    const results = document.getElementById('results');
    const time = new Date().toLocaleTimeString();
    results.innerHTML = `<div class="log" style="border-left-color:${color}">[${time}] ${msg}</div>` + results.innerHTML;
}

async function testAccess(resource) {
    try {
        const res = await fetch(`${API}/api/access-request`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({token, resource})
        });
        const data = await res.json();
        
        document.getElementById('trustScore').textContent = data.trust_score;
        
        const color = data.access_decision === 'deny' ? '#e53e3e' : 
                    data.access_decision === 'allow' ? '#4caf50' : '#ff9800';
        
        log(`${data.access_decision === 'allow' ? '✅' : '⚠️'} 访问${resource}: ${data.access_decision} (信任分:${data.trust_score})`, color);
        
    } catch(e) {
        log('❌ 错误: ' + e.message, '#e53e3e');
    }
}

async function simulateAttack(type) {
    try {
        await fetch(`${API}/api/simulate-attack`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({type})
        });
        log('🚨 已模拟攻击: ' + type, '#ff9800');
        setTimeout(() => testAccess('/api/data'), 500);
    } catch(e) {
        log('❌ 错误: ' + e.message, '#e53e3e');
    }
}

async function rapidAccess() {
    log('⚡ 开始频繁访问测试...', '#ff9800');
    for(let i = 0; i < 10; i++) {
        await testAccess('/api/test' + i);
        await new Promise(r => setTimeout(r, 100));
    }
}

async function getUserInfo() {
    try {
        const res = await fetch(`${API}/api/user-behavior/john`, {
            headers: {'Authorization': `Bearer ${token}`}
        });
        const data = await res.json();
        log(`👤 用户john - 信任分:${data.current_trust_score} 风险:${data.risk_level} IP:${data.last_known_ip}`, '#4caf50');
    } catch(e) {
        log('❌ 错误: ' + e.message, '#e53e3e');
    }
}

function clearLogs() {
    document.getElementById('results').innerHTML = '<div class="log">📋 日志已清空</div>';
}

// 页面加载完成提示
document.addEventListener('DOMContentLoaded', function() {
    log('✅ 系统已就绪！点击按钮测试功能', '#4caf50');
});