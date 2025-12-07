# Cloudflare + GitHub Pages Setup Guide

This guide provides detailed instructions for setting up your YARA Scanner subdomain using GitHub Pages with Cloudflare as your DNS and CDN provider.

## Prerequisites

- A GitHub account
- A Cloudflare account with your domain added
- Your domain's nameservers pointing to Cloudflare

## Architecture Overview

```
User Browser
     │
     ▼
┌─────────────────┐
│   Cloudflare    │  ◄── DNS, SSL, CDN, DDoS Protection
│  (Edge Network) │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌───────┐ ┌────────────┐
│GitHub │ │ Your K8s   │
│ Pages │ │  Cluster   │
│(docs) │ │  (API)     │
└───────┘ └────────────┘
```

## Step 1: Prepare Your Repository

### 1.1 Repository Structure

Ensure your repository has the `docs/` folder with:
```
docs/
├── index.html
├── styles.css
├── app.js
└── CNAME
```

### 1.2 Update CNAME File

Edit `docs/CNAME` to contain your subdomain:
```
yara.yourdomain.com
```

**Important**: Only include the domain, no `https://` or trailing slashes.

### 1.3 Push Changes

```bash
git add .
git commit -m "Configure GitHub Pages"
git push origin main
```

## Step 2: Enable GitHub Pages

1. Go to your repository on GitHub
2. Click **Settings** (gear icon)
3. Scroll down to **Pages** in the left sidebar
4. Under **Build and deployment**:
   - **Source**: Deploy from a branch
   - **Branch**: `main`
   - **Folder**: `/docs`
5. Click **Save**

GitHub will build and deploy your site. This takes 1-2 minutes.

## Step 3: Configure Cloudflare DNS

### 3.1 Add CNAME Record for Frontend

1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Select your domain
3. Go to **DNS** → **Records**
4. Click **Add record**
5. Fill in:

| Field   | Value                        |
|---------|------------------------------|
| Type    | CNAME                        |
| Name    | yara                         |
| Target  | yourusername.github.io       |
| Proxy   | Proxied (orange cloud)       |
| TTL     | Auto                         |

6. Click **Save**

### 3.2 Add Record for API (if deploying to K8s)

For the API endpoint, add an A record pointing to your Kubernetes cluster's external IP:

| Field   | Value                        |
|---------|------------------------------|
| Type    | A                            |
| Name    | yara-api                     |
| IPv4    | <Your-K8s-Load-Balancer-IP>  |
| Proxy   | Proxied (orange cloud)       |
| TTL     | Auto                         |

Or use CNAME if you have a hostname:

| Field   | Value                        |
|---------|------------------------------|
| Type    | CNAME                        |
| Name    | yara-api                     |
| Target  | k8s.yourdomain.com           |
| Proxy   | Proxied (orange cloud)       |

## Step 4: Configure Cloudflare SSL/TLS

### 4.1 SSL Mode

1. Go to **SSL/TLS** → **Overview**
2. Select **Full (strict)**

This ensures end-to-end encryption:
- Browser ↔ Cloudflare: HTTPS
- Cloudflare ↔ GitHub Pages: HTTPS

### 4.2 Edge Certificates

1. Go to **SSL/TLS** → **Edge Certificates**
2. Enable these options:
   - ✅ Always Use HTTPS
   - ✅ Automatic HTTPS Rewrites
   - ✅ TLS 1.3 (recommended)

### 4.3 Origin Certificates (for API)

If your API is on Kubernetes with an Ingress:

1. Go to **SSL/TLS** → **Origin Server**
2. Click **Create Certificate**
3. Select:
   - RSA (2048)
   - Hostnames: `yara-api.yourdomain.com`
   - Validity: 15 years
4. Download the certificate and key
5. Create a Kubernetes secret:

```bash
kubectl create secret tls yara-api-tls \
  --cert=origin-cert.pem \
  --key=origin-key.pem \
  -n yara-system
```

## Step 5: Cloudflare Page Rules (Performance)

### 5.1 Cache Static Assets

1. Go to **Rules** → **Page Rules**
2. Click **Create Page Rule**
3. URL: `yara.yourdomain.com/*`
4. Settings:
   - Cache Level: Cache Everything
   - Edge Cache TTL: 1 month
   - Browser Cache TTL: 1 day
5. Click **Save and Deploy**

### 5.2 API Bypass Cache

1. Create another Page Rule
2. URL: `yara-api.yourdomain.com/*`
3. Settings:
   - Cache Level: Bypass
   - Disable Performance (optional)
4. **Order**: Make sure this rule is above the static cache rule

## Step 6: Security Configuration

### 6.1 Firewall Rules

1. Go to **Security** → **WAF** → **Custom rules**
2. Create a rule to protect your API:

```
Expression: (http.host eq "yara-api.yourdomain.com") and (http.request.method ne "GET") and (http.request.method ne "POST") and (http.request.method ne "OPTIONS")
Action: Block
```

### 6.2 Rate Limiting

1. Go to **Security** → **WAF** → **Rate limiting rules**
2. Create a rule:
   - URL: `yara-api.yourdomain.com/api/v1/*`
   - Rate: 100 requests per 10 seconds
   - Action: Challenge

### 6.3 Bot Protection (Optional)

1. Go to **Security** → **Bots**
2. Configure based on your plan:
   - Free: Super Bot Fight Mode
   - Pro+: Bot Management

## Step 7: Verify Setup

### 7.1 Check DNS Propagation

```bash
# Check CNAME record
dig yara.yourdomain.com CNAME

# Should return something like:
# yara.yourdomain.com. 300 IN CNAME yourusername.github.io.
```

### 7.2 Check SSL Certificate

```bash
# Verify SSL
curl -vI https://yara.yourdomain.com 2>&1 | grep -i "SSL\|issuer"

# Should show Cloudflare certificate
```

### 7.3 Test the Site

1. Open `https://yara.yourdomain.com` in your browser
2. You should see the YARA Scanner interface
3. Open browser DevTools (F12) → Network tab
4. Verify all resources load over HTTPS

### 7.4 Test API Connection

```bash
# If your API is deployed
curl https://yara-api.yourdomain.com/health

# Should return: {"status":"healthy"}
```

## Troubleshooting

### Issue: "DNS_PROBE_FINISHED_NXDOMAIN"

**Cause**: DNS not propagated yet or misconfigured

**Solution**:
1. Wait 5-10 minutes for DNS propagation
2. Verify CNAME record in Cloudflare dashboard
3. Clear local DNS cache: `sudo systemd-resolve --flush-caches`

### Issue: "ERR_SSL_PROTOCOL_ERROR"

**Cause**: SSL mode mismatch

**Solution**:
1. Ensure SSL mode is set to "Full (strict)"
2. Wait for GitHub Pages SSL certificate (up to 24 hours for new domains)
3. Check that CNAME file contains only the domain

### Issue: "404 Not Found" on GitHub Pages

**Cause**: Pages not deployed or wrong branch/folder

**Solution**:
1. Check GitHub Actions workflow status
2. Verify Pages settings point to correct branch and folder
3. Ensure `index.html` exists in `docs/` folder

### Issue: CORS Errors in Browser Console

**Cause**: API not configured for cross-origin requests

**Solution**:
1. Ensure API has CORS headers enabled (done by default in our code)
2. Add Cloudflare header transformation rules if needed
3. Verify `Access-Control-Allow-Origin` header in API responses

### Issue: Mixed Content Warnings

**Cause**: HTTP resources loaded on HTTPS page

**Solution**:
1. Enable "Automatic HTTPS Rewrites" in Cloudflare
2. Update any hardcoded HTTP URLs to HTTPS
3. Use protocol-relative URLs (`//example.com`) where possible

## Updating the Frontend

When you update the frontend:

1. Edit files in `docs/` directory
2. Commit and push:
   ```bash
   git add docs/
   git commit -m "Update frontend"
   git push origin main
   ```
3. GitHub Actions will automatically deploy
4. Clear Cloudflare cache if needed:
   - Dashboard → **Caching** → **Configuration** → **Purge Everything**

## Custom Headers with Cloudflare Transform Rules

For additional security headers:

1. Go to **Rules** → **Transform Rules**
2. Create a new **Modify Response Header** rule
3. Add headers:

| Operation | Header Name              | Value                                    |
|-----------|--------------------------|------------------------------------------|
| Set       | X-Content-Type-Options   | nosniff                                  |
| Set       | X-Frame-Options          | DENY                                     |
| Set       | Referrer-Policy          | strict-origin-when-cross-origin          |
| Set       | Permissions-Policy       | geolocation=(), microphone=(), camera=() |

## Cost Considerations

| Service        | Free Tier Includes                              |
|----------------|------------------------------------------------|
| GitHub Pages   | Unlimited for public repos                      |
| Cloudflare     | Unlimited DNS, SSL, basic WAF, 100k workers/day|

For most use cases, this setup is completely free!

## Next Steps

1. ✅ Set up GitHub Pages
2. ✅ Configure Cloudflare DNS
3. ✅ Enable SSL/TLS
4. ⬜ Deploy YARA Operator to Kubernetes
5. ⬜ Configure API Ingress
6. ⬜ Update frontend with API URL
7. ⬜ Add monitoring and alerts


