export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        if (request.method === 'GET' && url.pathname === '/') {
            return new Response(getHtmlContent(), {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' },
            });
        }

        if (request.method === 'POST' && url.pathname === '/api/deploy') {
            try {
                const { token } = await request.json();
                if (!token) throw new Error("توکن نمی‌تواند خالی باشد.");

                const headers = {
                    "Authorization": `Bearer ${token}`,
                    "Content-Type": "application/json"
                };

                const accRes = await fetch("https://api.cloudflare.com/client/v4/accounts", { headers });
                const accData = await accRes.json();
                if (!accData.success || accData.result.length === 0) {
                    throw new Error("خطا در یافتن اکانت. توکن نامعتبر است.");
                }
                const accountId = accData.result[0].id;

                let devSub = null;
                const subRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/subdomain`, { headers });
                const subData = await subRes.json();
                if (subData.success && subData.result.subdomain) {
                    devSub = subData.result.subdomain;
                } else {
                    const newSub = `zeus-${Math.random().toString(36).substring(2, 8)}`;
                    const createSub = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/subdomain`, {
                        method: 'PUT',
                        headers,
                        body: JSON.stringify({ subdomain: newSub })
                    });
                    const createSubData = await createSub.json();
                    if (!createSubData.success) throw new Error("ساخت ساب‌دامین شکست خورد. قوانین کلودفلر را در اکانت خود تایید کنید.");
                    devSub = newSub;
                }

                const uniqueSuffix = Math.random().toString(36).substring(2, 8);
                const workerName = `zeus-panel-${uniqueSuffix}`;
                const dbName = `zeus-db-${uniqueSuffix}`;
                
                const dbRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/d1/database`, {
                    method: 'POST',
                    headers,
                    body: JSON.stringify({ name: dbName })
                });
                const dbData = await dbRes.json();
                
                if (!dbData.success) {
                    const cfError = dbData.errors && dbData.errors.length > 0 ? dbData.errors[0].message : "نامشخص";
                    throw new Error(`ساخت دیتابیس شکست خورد: ${cfError}`);
                }
                const dbUuid = dbData.result.uuid;

                await new Promise(resolve => setTimeout(resolve, 1000));

                const githubRes = await fetch("https://raw.githubusercontent.com/IR-NETLIFY/zeus/refs/heads/main/zeus.js");
                if (!githubRes.ok) throw new Error("خطا در دریافت سورس از گیت‌هاب.");
                const zeusCode = await githubRes.text();

                const metadata = {
                    main_module: "zeus.js",
                    compatibility_date: "2024-02-08",
                    bindings: [{ type: "d1", name: "DB", id: dbUuid }]
                };

                const formData = new FormData();
                formData.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }));
                formData.append("zeus.js", new Blob([zeusCode], { type: "application/javascript+module" }), "zeus.js");

                const deployRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${workerName}`, {
                    method: 'PUT',
                    headers: { "Authorization": `Bearer ${token}` },
                    body: formData
                });
                const deployData = await deployRes.json();
                
                if (!deployData.success) {
                    const cfError = deployData.errors && deployData.errors.length > 0 ? deployData.errors[0].message : "نامشخص";
                    throw new Error(`کلودفلر اجازه آپلود نداد. دلیل: ${cfError}`);
                }

                const routeRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${workerName}/subdomain`, {
                    method: 'POST',
                    headers,
                    body: JSON.stringify({ enabled: true })
                });
                
                if (!routeRes.ok) throw new Error("خطا در فعال‌سازی لینک نهایی.");

                const finalUrl = `https://${workerName}.${devSub}.workers.dev/panel`;

                return new Response(JSON.stringify({ success: true, url: finalUrl }), {
                    headers: { 'Content-Type': 'application/json' }
                });

            } catch (error) {
                return new Response(JSON.stringify({ success: false, error: error.message }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        }

        return new Response("Not Found", { status: 404 });
    }
};

function getHtmlContent() {
    return `
    <!DOCTYPE html>
    <html lang="fa" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Zeus Panel Deployer</title>
        <style>
            @import url('https://v1.fontapi.ir/css/Vazir');
            body {
                margin: 0;
                padding: 0;
                background: linear-gradient(135deg, #040814 0%, #010205 100%);
                font-family: 'Vazir', sans-serif;
                height: 100vh;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                color: #ffffff;
                overflow: hidden;
                position: relative;
            }
            .glass-modal {
                background: rgba(255, 255, 255, 0.03);
                backdrop-filter: blur(20px);
                -webkit-backdrop-filter: blur(20px);
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 20px;
                padding: 35px 30px;
                width: 90%;
                max-width: 400px;
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);
                z-index: 10;
            }
            .mac-controls {
                display: flex;
                gap: 8px;
                margin-bottom: 20px;
            }
            .mac-btn { width: 12px; height: 12px; border-radius: 50%; }
            .close { background: #ff5f56; }
            .min { background: #ffbd2e; }
            .max { background: #27c93f; }
            
            h2 { 
                text-align: center; 
                margin-top: 0; 
                font-weight: 700; 
                color: #ffffff;
            }
            p { 
                text-align: center; 
                font-size: 14px; 
                color: #a0aabf; 
                margin-bottom: 25px; 
            }
            
            .btn-secondary {
                display: block;
                text-align: center;
                margin-bottom: 20px;
                padding: 14px;
                background: #110090ff;
                border: 1px solid #1a4073;
                color: #ffffff;
                border-radius: 10px;
                text-decoration: none;
                font-size: 14px;
                font-weight: bold;
                transition: all 0.3s ease;
                box-sizing: border-box;
                width: 100%;
            }
            .btn-secondary:hover {
                background: #143666;
                box-shadow: 0 4px 12px rgba(13, 39, 77, 0.5);
            }

            input {
                width: 100%;
                padding: 15px;
                margin-bottom: 20px;
                border-radius: 10px;
                border: 1px solid rgba(255, 255, 255, 0.1);
                background: rgba(0, 0, 0, 0.4);
                color: white;
                box-sizing: border-box;
                font-family: monospace;
                font-size: 14px;
                transition: all 0.3s ease;
                direction: ltr;
                text-align: left;
            }
            input::placeholder { color: #5c677d; text-align: right; }
            input:focus { 
                outline: none; 
                border-color: #00792dff; 
                background: rgba(0, 0, 0, 0.6);
            }
            
            .btn-primary {
                width: 100%;
                padding: 15px;
                background: #00792dff;
                border: none;
                border-radius: 10px;
                color: white;
                font-weight: bold;
                font-size: 15px;
                cursor: pointer;
                transition: all 0.3s ease;
                font-family: 'Vazir', sans-serif;
            }
            .btn-primary:hover { 
                background: #00792dff;
                box-shadow: 0 4px 15px rgba(16, 185, 129, 0.4); 
            }
            .btn-primary:disabled { 
                opacity: 0.6; 
                cursor: not-allowed; 
            }
            
            #status-container {
                margin-top: 20px;
                display: none;
            }
            #status-text {
                font-size: 13px;
                color: #a0aabf;
                margin-bottom: 8px;
                text-align: right;
            }
            .progress-bar-bg {
                width: 100%;
                height: 6px;
                background: rgba(255, 255, 255, 0.05);
                border-radius: 10px;
                overflow: hidden;
                margin-bottom: 15px;
            }
            .progress-bar-fill {
                width: 0%;
                height: 100%;
                background: #00792dff;
                border-radius: 10px;
                transition: width 0.4s ease;
            }
            #error-box {
                padding: 12px;
                background: rgba(255, 95, 86, 0.1);
                border-right: 4px solid #ff5f56;
                color: #ffe6e6;
                border-radius: 8px;
                font-size: 13px;
                display: none;
                text-align: center;
                line-height: 1.6;
                margin-top: 15px;
            }
            
            .btn-success-panel {
                display: block;
                width: 100%;
                padding: 16px;
                background: #00792dff;
                color: white;
                text-align: center;
                text-decoration: none;
                font-weight: bold;
                border-radius: 10px;
                box-shadow: 0 4px 15px rgba(16, 185, 129, 0.4);
                font-size: 16px;
                transition: all 0.3s ease;
                box-sizing: border-box;
            }
            .btn-success-panel:hover {
                background: #00792dff;
                transform: translateY(-2px);
            }

            .telegram-footer {
                position: absolute;
                bottom: 25px;
                display: flex;
                align-items: center;
                gap: 8px;
                text-decoration: none;
                color: #a0aabf;
                font-size: 14px;
                font-weight: bold;
                background: rgba(255, 255, 255, 0.03);
                backdrop-filter: blur(10px);
                padding: 10px 20px;
                border-radius: 20px;
                border: 1px solid rgba(255, 255, 255, 0.08);
                transition: all 0.3s ease;
                direction: ltr;
                z-index: 5;
            }
            .telegram-footer:hover {
                color: #ffffff;
                background: rgba(16, 185, 129, 0.1); 
                border-color: rgba(16, 185, 129, 0.4);
                transform: translateY(-3px);
                box-shadow: 0 8px 20px rgba(0, 0, 0, 0.4);
            }
            .telegram-footer svg {
                width: 22px;
                height: 22px;
                fill: #229ED9;
                transition: all 0.3s ease;
            }
            .telegram-footer:hover svg {
                fill: #308658ff;
            }
        </style>
    </head>
    <body>
        <div class="glass-modal" id="mainCard">
            <div class="mac-controls">
                <div class="mac-btn close"></div>
                <div class="mac-btn min"></div>
                <div class="mac-btn max"></div>
            </div>
            <h2> Zeus Panel Auto-Deployer ⚡️</h2>
            <p>  🔋 روزانه 10 الی 100 گیگ کانفیگ رایگان </p>
            
            <a href="https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22workers_kv_storage%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22d1%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22workers_subdomain%22%2C%22type%22%3A%22edit%22%7D%5D&accountId=*&zoneId=all&name=Zeus-Deployer-Token" target="_blank" class="btn-secondary" id="tokenBtn">
                دریافت توکن
            </a>
            
            <input type="text" id="apiToken" placeholder="توکن خود را وارد کنید" autocomplete="off" spellcheck="false">
            <button id="deployBtn" class="btn-primary" onclick="startDeploy()">ساخت پنل</button>
            
            <div id="status-container">
                <div id="status-text">شروع فرآیند... ۰٪</div>
                <div class="progress-bar-bg">
                    <div class="progress-bar-fill" id="progressBar"></div>
                </div>
            </div>
            <div id="error-box"></div>
        </div>

        <!-- لینک تلگرام -->
        <a href="https://t.me/IR_NETLIFY" target="_blank" class="telegram-footer">
            <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/>
            </svg>
            @IR_NETLIFY
        </a>

        <script>
            function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

            async function startDeploy() {
                const token = document.getElementById('apiToken').value.trim();
                const btn = document.getElementById('deployBtn');
                const statusContainer = document.getElementById('status-container');
                const statusText = document.getElementById('status-text');
                const progressBar = document.getElementById('progressBar');
                const errorBox = document.getElementById('error-box');
                
                const oldText = document.getElementById('successTxt');
                if (oldText) oldText.remove();

                const oldSuccessLink = document.getElementById('successBtn');
                if (oldSuccessLink) oldSuccessLink.remove();
                
                if(!token) {
                    errorBox.style.display = 'block';
                    errorBox.innerText = 'لطفاً ابتدا توکن را وارد کنید.';
                    return;
                }
                
                errorBox.style.display = 'none';
                btn.disabled = true;
                btn.innerText = 'در حال پردازش...';
                statusContainer.style.display = 'block';

                statusText.innerText = 'در حال بررسی توکن... ۱۵٪';
                progressBar.style.width = '15%';
                await sleep(500);

                statusText.innerText = 'در حال ایجاد ارتباط با کلودفلر... ۳۰٪';
                progressBar.style.width = '30%';
                await sleep(500);

                statusText.innerText = 'در حال ایجاد ساب‌دامین و دیتابیس D1... ۵۰٪';
                progressBar.style.width = '50%';

                try {
                    const response = await fetch('/api/deploy', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token })
                    });
                    
                    statusText.innerText = 'در حال دریافت و آپلود پنل زئوس... ۷۵٪';
                    progressBar.style.width = '75%';
                    await sleep(600);

                    statusText.innerText = 'در حال فعال‌سازی لینک نهایی... ۹۰٪';
                    progressBar.style.width = '90%';
                    await sleep(500);
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        progressBar.style.width = '100%';
                        statusText.innerText = 'تکمیل شد! ۱۰۰٪';
                        await sleep(400);

                        statusContainer.style.display = 'none';

                        const successText = document.createElement('div');
                        successText.id = 'successTxt';
                        successText.innerText = 'پنل با موفقیت ساخته شد';
                        successText.style.color = '#059669'; 
                        successText.style.textAlign = 'center';
                        successText.style.marginTop = '20px'; 
                        successText.style.fontWeight = 'bold';
                        successText.style.fontSize = '14px';
                        document.getElementById('mainCard').appendChild(successText);

                        const successLink = document.createElement('a');
                        successLink.href = result.url;
                        successLink.target = '_blank';
                        successLink.className = 'btn-success-panel';
                        successLink.id = 'successBtn'; 
                        successLink.innerText = 'ورود به پنل';
                        successLink.style.marginTop = '12px';
                        
                        document.getElementById('mainCard').appendChild(successLink);
                    } else {
                        throw new Error(result.error);
                    }
                } catch(e) {
                    statusContainer.style.display = 'none';
                    errorBox.style.display = 'block';
                    errorBox.innerText = e.message;
                } finally {
                    btn.disabled = false;
                    btn.innerText = 'ساخت پنل';
                }
            }
        </script>
    </body>
    </html>
    `;
}