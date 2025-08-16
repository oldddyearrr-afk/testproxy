import https from "node:https";
import http from "node:http";
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import cluster from 'cluster';
import os from 'os';

// تحسين إعدادات Node.js للأداء العالي
process.env.UV_THREADPOOL_SIZE = 128;
process.env.NODE_OPTIONS = '--max-old-space-size=2048';

// إعدادات عالمية للأداء
const MAX_SOCKETS = 500;
const KEEP_ALIVE_TIMEOUT = 65000;
const HEADERS_TIMEOUT = 66000;

// تحسين إعدادات HTTP للاتصالات المتزامنة
http.globalAgent.maxSockets = MAX_SOCKETS;
http.globalAgent.keepAlive = true;
http.globalAgent.keepAliveMsecs = 30000;
https.globalAgent.maxSockets = MAX_SOCKETS;
https.globalAgent.keepAlive = true;
https.globalAgent.keepAliveMsecs = 30000;

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = process.env.PORT || 3030;

// نظام إدارة التوكنز المؤقتة
const tokenStorage = new Map();

// دالة إنشاء توكن جديد
function createToken(url, headers, durationHours = 2) {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + (durationHours * 60 * 60 * 1000); // تحويل الساعات إلى milliseconds
    
    tokenStorage.set(token, {
        url: url,
        headers: headers,
        expiresAt: expiresAt,
        createdAt: Date.now()
    });
    
    return token;
}

// دالة التحقق من صحة التوكن
function validateToken(token) {
    const tokenData = tokenStorage.get(token);
    if (!tokenData) {
        return null;
    }
    
    if (Date.now() > tokenData.expiresAt) {
        tokenStorage.delete(token);
        return null;
    }
    
    return tokenData;
}

// تنظيف التوكنز المنتهية الصلاحية كل ساعة
setInterval(() => {
    const now = Date.now();
    for (const [token, data] of tokenStorage.entries()) {
        if (now > data.expiresAt) {
            tokenStorage.delete(token);
        }
    }
}, 60 * 60 * 1000); // كل ساعة

// إعدادات Express للأداء العالي
app.disable('x-powered-by');
app.set('trust proxy', true);

// معالجة طلبات OPTIONS للتوافق مع CORS
app.options('*', (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, HEAD');
    res.setHeader('Access-Control-Allow-Headers', 'Accept, Accept-Language, Content-Language, Content-Type, Authorization, Range, User-Agent, X-Requested-With, Cache-Control');
    res.setHeader('Access-Control-Max-Age', '86400');
    res.status(200).end();
});

// إنشاء الخادم مع إعدادات محسنة للأداء
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on http://0.0.0.0:${PORT}`);
    console.log(`📊 Server Listening on PORT: ${PORT} - PID: ${process.pid}`);
    console.log(`⚡ Max connections configured for: ${MAX_SOCKETS} per agent`);
    console.log(`🌐 App should be accessible via the webview`);
});

// تحسين إعدادات الخادم للتعامل مع عدد كبير من الاتصالات
server.keepAliveTimeout = KEEP_ALIVE_TIMEOUT;
server.headersTimeout = HEADERS_TIMEOUT;
server.maxConnections = 0; // بلا حدود
server.timeout = 300000; // 5 دقائق timeout

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'playground.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'login.html'));
});

// إنشاء توكن مؤقت للروابط
app.post("/generate-token", express.json(), (req, res) => {
    try {
        const { url, headers, duration } = req.body;
        
        if (!url) {
            return res.status(400).json({ message: "URL is required" });
        }
        
        const durationHours = duration || 2; // افتراضي ساعتان
        const token = createToken(url, headers || {}, durationHours);
        
        const currentDomain = req.get('host');
        const protocol = req.get('x-forwarded-proto') || req.protocol;
        const proxyUrl = `${protocol}://${currentDomain}/token-proxy/${token}`;
        
        res.json({
            token: token,
            proxyUrl: proxyUrl,
            expiresIn: durationHours,
            expiresAt: new Date(Date.now() + (durationHours * 60 * 60 * 1000)).toISOString()
        });
        
    } catch (error) {
        console.error('Token generation error:', error.message);
        res.status(500).json({ message: "Failed to generate token", error: error.message });
    }
});

// الوصول عبر التوكن
app.get("/token-proxy/:token", async (req, res) => {
    return handleTokenProxy(req, res);
});

app.get("/token-proxy/:token.m3u8", async (req, res) => {
    return handleTokenProxy(req, res);
});

// دالة معالجة التوكن المؤقت
async function handleTokenProxy(req, res) {
    try {
        const token = req.params.token;
        const tokenData = validateToken(token);
        
        if (!tokenData) {
            return res.status(401).json({ 
                message: "Token expired or invalid",
                error: "TOKEN_EXPIRED"
            });
        }
        
        // تحديد نوع الملف وإعادة التوجيه للمعالج المناسب
        const url = new URL(tokenData.url);
        
        if (url.pathname.endsWith(".ts") || url.search.includes(".ts") || url.search.includes("stream=")) {
            // إعادة توجيه لمعالج TS
            req.query.url = tokenData.url;
            req.query.headers = JSON.stringify(tokenData.headers);
            return handleTSProxy(req, res);
        } else {
            // إعادة توجيه لمعالج M3U8
            req.query.url = tokenData.url;
            req.query.headers = JSON.stringify(tokenData.headers);
            return handleM3U8Proxy(req, res);
        }
        
    } catch (error) {
        console.error('Token proxy error:', error.message);
        res.status(500).json({ message: "Token proxy failed", error: error.message });
    }
}

// دالة معالجة TS القابلة للإعادة استخدام - محسنة للأداء العالي
async function handleTSProxy(req, res) {
    try {
        const targetUrl = req.query.url;
        if (!targetUrl) {
            return res.status(400).json({ message: "URL parameter is required" });
        }

        const url = new URL(targetUrl);
        const headersParam = decodeURIComponent(req.query.headers || "{}");
        
        const headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36",
            "Connection": "keep-alive",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate"
        };

        if (headersParam) {
            try {
                const additionalHeaders = JSON.parse(headersParam);
                Object.assign(headers, additionalHeaders);
            } catch (e) {
                console.log("Error parsing headers:", e.message);
            }
        }

        // Determine if HTTPS or HTTP
        const isHTTPS = url.protocol === 'https:';
        const proxyModule = isHTTPS ? https : http;
        
        const options = {
            hostname: url.hostname,
            port: url.port || (isHTTPS ? 443 : 80),
            path: url.pathname + url.search,
            method: req.method,
            headers: headers,
            timeout: 60000, // زيادة المهلة الزمنية
            keepAlive: true,
            maxSockets: MAX_SOCKETS,
            agent: isHTTPS ? https.globalAgent : http.globalAgent
        };

        const proxy = proxyModule.request(options, (proxyRes) => {
            // إعداد timeout للاستجابة
            const responseTimeout = setTimeout(() => {
                if (!res.headersSent) {
                    res.status(504).json({ message: "Response timeout" });
                }
                proxy.destroy();
            }, 120000); // 2 دقيقة

            // رؤوس CORS محسنة للتوافق مع جميع المشغلات
            const responseHeaders = {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, HEAD',
                'Access-Control-Allow-Headers': 'Accept, Accept-Language, Content-Language, Content-Type, Authorization, Range, User-Agent, X-Requested-With, Cache-Control',
                'Access-Control-Expose-Headers': 'Accept-Ranges, Content-Length, Content-Range, Content-Type, Date, Server, Transfer-Encoding',
                'Access-Control-Max-Age': '86400',
                'Content-Type': 'video/mp2t',
                'Accept-Ranges': 'bytes',
                'Cache-Control': 'public, max-age=600', // تخزين مؤقت 10 دقائق
                'Connection': 'keep-alive',
                'X-Content-Type-Options': 'nosniff',
                'Vary': 'Accept-Encoding, Range',
                'Server': 'Stream-Proxy/1.0'
            };
            
            // نسخ رؤوس مهمة من الاستجابة الأصلية
            ['content-length', 'content-range', 'last-modified', 'etag'].forEach(header => {
                if (proxyRes.headers[header]) {
                    responseHeaders[header.split('-').map(word => 
                        word.charAt(0).toUpperCase() + word.slice(1)
                    ).join('-')] = proxyRes.headers[header];
                }
            });

            // معالجة طلبات Range للتشغيل المتقطع
            if (req.headers.range && proxyRes.statusCode === 206) {
                res.writeHead(206, responseHeaders);
            } else {
                res.writeHead(proxyRes.statusCode || 200, responseHeaders);
            }
            
            proxyRes.on('end', () => {
                clearTimeout(responseTimeout);
            });
            
            proxyRes.on('error', (err) => {
                clearTimeout(responseTimeout);
                console.error('Proxy response error:', err.message);
                if (!res.headersSent) {
                    res.status(500).json({ message: "Proxy response failed" });
                }
            });
            
            proxyRes.pipe(res, { end: true });
        });

        proxy.on('timeout', () => {
            console.log(`Request timeout for: ${url.hostname}`);
            if (!res.headersSent) {
                res.status(504).json({ message: "Request timed out" });
            }
            proxy.destroy();
        });

        proxy.on('error', (err) => {
            console.error(`Proxy error for ${url.hostname}:`, err.message);
            if (!res.headersSent) {
                if (err.code === 'ECONNRESET' || err.code === 'ENOTFOUND') {
                    res.status(502).json({ message: "Bad Gateway", error: err.code });
                } else {
                    res.status(500).json({ message: "Proxy failed", error: err.message });
                }
            }
        });

        proxy.on('socket', (socket) => {
            socket.setKeepAlive(true, 30000);
            socket.setTimeout(60000);
        });

        // تمرير الطلب الأصلي مع دعم Range requests
        if (req.headers.range) {
            options.headers['Range'] = req.headers.range;
        }
        
        // إضافة معالج لإنهاء الاتصال عند قطع العميل
        req.on('close', () => {
            proxy.destroy();
        });
        
        req.on('aborted', () => {
            proxy.destroy();
        });
        
        proxy.end();
        
    } catch (error) {
        console.error('TS Proxy error:', error.message);
        if (!res.headersSent) {
            res.status(500).json({ message: "Internal server error", error: error.message });
        }
    }
}

// Route خاص لبث روابط .ts المباشرة
app.get("/ts-proxy", handleTSProxy);
app.get("/ts-proxy.m3u8", handleTSProxy);

// دالة معالجة M3U8 القابلة للإعادة استخدام
async function handleM3U8Proxy(req, res) {
    let responseSent = false;

    const safeSendResponse = (statusCode, data) => {
        try {
            if (!responseSent) {
                responseSent = true;
                res.status(statusCode).send(data);
            }
        }
        catch (err) {

        }
    };
    try {
        // هنا الرابط الثابت للم3u8 الذي تريد بثه - غير الرابط هنا
        const fixedUrl = "http://188.241.219.157/ulke.bordo1453.befhjjjj/Orhantelegrammmm30conextionefbn/274122?token=ShJdY2ZmQQNHCmMZCDZXUh9GSHAWGFMD.ZDsGQVN.WGBFNX013GR9YV1QbGBp0QE9SWmpcXlQXXlUHWlcbRxFACmcDY1tXEVkbVAoAAQJUFxUbRFldAxdeUAdaVAFcUwcHAhwWQlpXQQMLTFhUG0FQQU1VQl4HWTsFVBQLVABGCVxEXFgeEVwNZgFcWVlZBxcDGwESHERcFxETWAxCCQgfEFNZQEBSRwYbX1dBVFtPF1pWRV5EFExGWxMmJxVJRlZKRVVaQVpcDRtfG0BLFU8XUEpvQlUVQRYEUA8HRUdeEQITHBZfUks8WgpXWl1UF1xWV0MSCkQERk0TDw1ZDBBcQG5AXVYRCQ1MCVVJ";

        const url = req.query.url ? new URL(req.query.url) : new URL(fixedUrl);
        const headersParam = decodeURIComponent(req.query.headers || "");

        if (!url) {
            safeSendResponse(400, { message: "Invalid URL" });
        }

        const headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36"
        };

        if (headersParam) {
            try {
                const additionalHeaders = JSON.parse(headersParam);
                Object.entries(additionalHeaders).forEach(([key, value]) => {
                    if (!["Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers"].includes(key)) {
                        headers[key] = value;
                    }
                });
            } catch (e) {
                console.log("Error parsing headers:", e.message);
            }
        }

        if (url.pathname.endsWith(".mp4")) {
            process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
        }
        else {
            process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";
        }

        const fetchOptions = {
            headers,
            timeout: 30000,
            compress: true,
            follow: 5,
            size: 50 * 1024 * 1024, // 50MB max
            agent: url.protocol === 'https:' ? https.globalAgent : http.globalAgent
        };

        const targetResponse = await fetch(url, fetchOptions);

        // تحسين الذاكرة - التحقق من حجم الاستجابة
        const contentLength = targetResponse.headers.get('content-length');
        if (contentLength && parseInt(contentLength) > 100 * 1024 * 1024) { // 100MB
            throw new Error('Response too large');
        }

        let modifiedM3u8;
        let forceHTTPS = false;

        if (url.pathname.endsWith(".m3u8") || targetResponse.headers.get('content-type')?.includes("mpegURL")) {
            modifiedM3u8 = await targetResponse.text();
            const targetUrlTrimmed = `${url.origin}${url.pathname.replace(/[^/]+\.m3u8$/, "").trim()}`;
            modifiedM3u8 = modifiedM3u8.split("\n").map((line) => {
                if (line.startsWith("#EXT-X-KEY")) {
                    const uriRegex = /(URI=")([^"]+)(")/;
                    const match = line.match(uriRegex);
                    if(match){
                        return line.replace(match[2], `/m3u8-proxy?url=${encodeURIComponent(match[2])}${headersParam ? `&headers=${encodeURIComponent(headersParam)}` : ""}`);
                    }
                }
                if (line.startsWith("#") || line.trim() == '') {
                    return line;
                }
                let finalUrl = undefined;
                if (line.startsWith("http://") || line.startsWith("https://")) {
                    finalUrl = line;
                }
                else if (line.startsWith('/')) {
                    if (targetUrlTrimmed.endsWith('/')) {
                        finalUrl = `${targetUrlTrimmed}${line.replace('/', '')}`;
                    }
                    else {
                        finalUrl = `${targetUrlTrimmed}/${line.replace('/', '')}`;
                    }
                }
                else {
                    if (targetUrlTrimmed.endsWith('/')) {
                        finalUrl = `${targetUrlTrimmed}${line}`;
                    }
                    else {
                        finalUrl = `${targetUrlTrimmed}/${line}`;
                    }
                }
                return `/m3u8-proxy?url=${encodeURIComponent(finalUrl)}${headersParam ? `&headers=${encodeURIComponent(headersParam)}` : ""}`;
            }).join("\n");
            // رؤوس محسنة لملفات M3U8 مع تحسين التخزين المؤقت
            res.status(200)
                .set('Access-Control-Allow-Origin', '*')
                .set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, HEAD')
                .set('Access-Control-Allow-Headers', 'Accept, Accept-Language, Content-Language, Content-Type, Authorization, Range, User-Agent, X-Requested-With, Cache-Control')
                .set('Access-Control-Expose-Headers', 'Accept-Ranges, Content-Length, Content-Range, Content-Type, Date, Server, Transfer-Encoding')
                .set('Content-Type', 'application/vnd.apple.mpegurl')
                .set('Cache-Control', 'public, max-age=10') // تخزين مؤقت 10 ثواني للM3U8
                .set('X-Content-Type-Options', 'nosniff')
                .set('Server', 'Stream-Proxy/1.0')
                .set('Connection', 'keep-alive')
                .send(modifiedM3u8 || await targetResponse.text());
        }
        else if(url.pathname.endsWith(".key")) {
            const keyData = await targetResponse.arrayBuffer();
            res.setHeader("Content-Type", targetResponse.headers.get("Content-Type") || "application/octet-stream");
            res.setHeader("Content-Length", targetResponse.headers.get("Content-Length") || 0);
            safeSendResponse(200, Buffer.from(keyData));
        }
        else if (url.pathname.includes('videos') || url.pathname.endsWith(".ts") || url.pathname.endsWith(".mp4") || url.search.includes(".ts") || url.search.includes("stream=") || targetResponse.headers.get('content-type')?.includes("video")) {
            if (req.query.url.startsWith("https://")) {
                forceHTTPS = true;
            }

            const uri = new URL(url);
            const options = {
                hostname: uri.hostname,
                port: uri.port || (uri.protocol === 'https:' ? 443 : 80),
                path: uri.pathname + uri.search,
                method: req.method,
                headers: headers,
                timeout: 15000
            };

            try {
                const proxyFn = forceHTTPS ? https.request : http.request;

                const proxy = proxyFn(options, (r) => {
                    // رؤوس محسنة للتوافق مع جميع المشغلات
                    r.headers["Access-Control-Allow-Origin"] = "*";
                    r.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, HEAD";
                    r.headers["Access-Control-Allow-Headers"] = "Accept, Accept-Language, Content-Language, Content-Type, Authorization, Range, User-Agent, X-Requested-With, Cache-Control";
                    r.headers["Access-Control-Expose-Headers"] = "Accept-Ranges, Content-Length, Content-Range, Content-Type, Date, Server, Transfer-Encoding";
                    r.headers["Cache-Control"] = "public, max-age=300";
                    r.headers["Connection"] = "keep-alive";
                    r.headers["X-Content-Type-Options"] = "nosniff";
                    
                    if (url.pathname.endsWith(".mp4")) {
                        r.headers["content-type"] = "video/mp4";
                        r.headers["accept-ranges"] = "bytes";
                        const fileName = req.query.filename || undefined;
                        if (fileName) {
                            r.headers['content-disposition'] = `attachment; filename="${fileName}.mp4"`;
                        }
                    }
                    else if (url.pathname.endsWith(".ts") || url.search.includes(".ts") || url.search.includes("stream=")) {
                        r.headers["content-type"] = "video/mp2t";
                        r.headers["accept-ranges"] = "bytes";
                    }
                    else {
                        r.headers["content-type"] = r.headers["content-type"] || "video/mp2t";
                        r.headers["accept-ranges"] = "bytes";
                    }
                    res.writeHead(r.statusCode ?? 200, r.headers);

                    r.pipe(res, { end: true });
                });

                req.pipe(proxy, { end: true });

                proxy.on('timeout', () => {
                    safeSendResponse(504, { message: "Request timed out." });
                    proxy.destroy();
                });

                proxy.on('error', (err) => {
                    console.error('Proxy request error:', err.message);
                    safeSendResponse(500, { message: "Proxy failed.", error: err.message });
                });
            } catch (e) {
                res.writeHead(500);
                res.end(e.message);
            }
        }
        else {
            res.setHeader("Content-Type", targetResponse.headers.get("Content-Type"));
            res.setHeader("Content-Length", targetResponse.headers.get("Content-Length") || 0);
            safeSendResponse(200, await targetResponse.text());
        }
    } catch (e) {
        console.log(e);
        safeSendResponse(500, { message: e.message });
    }
}

// نظام مراقبة الإحصائيات البسيط
let stats = {
    totalRequests: 0,
    activeConnections: 0,
    totalBytes: 0,
    errors: 0,
    startTime: Date.now()
};

// Middleware لمراقبة الطلبات
app.use((req, res, next) => {
    stats.totalRequests++;
    stats.activeConnections++;
    
    const originalEnd = res.end;
    res.end = function(chunk, encoding) {
        stats.activeConnections--;
        if (chunk) {
            stats.totalBytes += Buffer.byteLength(chunk, encoding || 'utf8');
        }
        originalEnd.call(this, chunk, encoding);
    };
    
    next();
});

// Route للإحصائيات
app.get("/stats", (req, res) => {
    const uptime = Date.now() - stats.startTime;
    const uptimeHours = Math.floor(uptime / (1000 * 60 * 60));
    const uptimeMinutes = Math.floor((uptime % (1000 * 60 * 60)) / (1000 * 60));
    
    res.json({
        ...stats,
        uptime: `${uptimeHours}h ${uptimeMinutes}m`,
        averageRequestsPerMinute: Math.round(stats.totalRequests / (uptime / 60000)),
        totalBytesFormatted: `${(stats.totalBytes / 1024 / 1024).toFixed(2)} MB`,
        memoryUsage: process.memoryUsage(),
        nodeVersion: process.version,
        pid: process.pid
    });
});

// Route خاص لمعالجة M3U8
app.get("/m3u8-proxy", handleM3U8Proxy);
app.get("/m3u8-proxy.m3u8", handleM3U8Proxy);
