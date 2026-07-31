# WARP WireGuard Config Generator for Cloudflare Workers

一个可自行部署的 Cloudflare Workers 小工具：打开网页，点击按钮，浏览器本地生成 X25519 密钥，然后通过 Worker 调用 WARP 注册接口并下载 `warp.conf`。

## 安全模型

- WireGuard 私钥只在浏览器内存中生成和使用，不会发送给 Worker。
- Worker 只收到 WireGuard 公钥、设备信息以及可选的 Teams enrollment JWT。
- Worker 不保存注册结果，也不会把 Cloudflare 返回的 API token 发送回浏览器。
- API 响应设置为 `Cache-Control: no-store`。

注意：Worker 的代码所有者仍然可以修改代码收集输入。请只使用自己部署并审计过的版本。

## 部署

需要 Node.js 20+ 和一个 Cloudflare 账户。

```bash
npm install
npx wrangler login
npm run deploy
```

部署完成后，打开 Wrangler 输出的 `workers.dev` 地址。

## 推荐：设置访问密钥

公开的生成接口可能被滥用。建议设置一个 Worker Secret：

```bash
npx wrangler secret put ACCESS_KEY
```

在网页的“高级设置”中输入同一个值。该值只用于访问你的 Worker，不会发送给 WARP API。

还建议在 Cloudflare 控制台为 `/api/register` 配置速率限制。

## 本地开发

```bash
npm install
npm run dev
```

然后访问 Wrangler 显示的本地地址。Web Crypto 需要安全上下文；浏览器通常将 `localhost` 视为安全上下文。

## 测试

```bash
npm test
```

测试不会请求真实的 WARP 注册接口，也不会创建任何设备。

## 功能

- 普通 Cloudflare WARP 注册
- 可选 Teams / Zero Trust enrollment JWT
- IPv4、IPv6 或主机名 Endpoint
- Cloudflare 标准、恶意软件拦截、家庭 DNS
- MTU 和 PersistentKeepalive 设置
- 自动下载、复制配置
- 可选 Worker 访问密钥

## 已知限制

1. 使用的是 Cloudflare 移动客户端的非公开注册接口，接口版本或风控规则变化后可能失效。
2. Workers 的 `fetch()` 无法复制原 shell 脚本的 TLS cipher 和 TLS 指纹设置，因此 Cloudflare 可能拒绝某些请求。
3. Teams enrollment 不会自动获取账户专属 Gateway DNS、虚拟网络或完整设备策略。
4. 生成的配置包含 WireGuard 私钥，必须像密码一样保存。
5. 这是配置生成器，不会在设备上启动 WireGuard、修改路由或设置防火墙。

## 项目结构

```text
src/index.js       Worker API 和 WARP 注册代理
public/index.html  页面
public/app.js      浏览器密钥生成和配置构建
public/app.css     页面样式
wrangler.jsonc     Workers 配置
test/              离线测试
```

## 服务条款

使用前请阅读并遵守 Cloudflare Application Services Terms：
https://www.cloudflare.com/application/terms/
