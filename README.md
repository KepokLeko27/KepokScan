# KEPOKSCAN

> **Web Security Assessment Toolkit**

KepokScan is a professional, high-density, web security assessment toolkit designed for modern compliance auditing, cookie inspection, server footprinting, and automated mitigation planning. Inspired by industry-grade pentesting and analysis applications like Burp Suite, OWASP ZAP, and Nessus, KepokScan delivers instant insights into a target web server's public-facing security headers, security cookies, technology stack, and exposed configuration endpoints.

---

## Features

- **HTTP Response Header Matrix**: Instant analysis of key security headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`) with a real-time compliance score and letter grade.
- **Exposure & Crawler Scanner**: Verifies active public folders, directory listing vulnerabilities, configuration directory leaks (e.g., exposed `.git`), sitemap compliance, and administrative login portals.
- **Stateful Deployment Mitigation Recipes**: Generates copy-pasteable server deployment configurations (Nginx server blocks, Express middlewares, etc.) for missing or misconfigured security headers.
- **Deep Security AI Audit**: Utilizes the Google Gemini Pro API to run advanced client threat-modeling, identify critical gaps, and provide an objective pentest briefing.
- **ASCII Compliance Visualization**: Beautiful terminal-grade high-density dashboard visualizations for high security posture readability.
- **Professional Report Generation**: Export beautiful, clean multi-page PDF compliance reports directly from the UI or fetch the raw audit JSON stream to feed custom CI/CD pipelines.
- **Persistent Scan History**: Seamlessly caches audited target hostnames using sandboxed local storage to enable quick re-scanning and historical comparisons.

---

## Technologies Used

- **Frontend**: React 19, TypeScript, Tailwind CSS 4, Lucide React (Icons), Motion (Animations)
- **Backend**: Node.js, Express, TSX, ESBuild, DNS Resolver
- **PDF Compilation**: PDFKit (Native PDF streaming, avoiding high-overhead Python reportlab/PDF binaries)
- **Artificial Intelligence**: Google Gemini Pro SDK (`@google/genai`)

---

## Folder Structure

```text
├── metadata.json           # Application platform configuration metadata
├── package.json            # Node.js project configuration and scripts
├── tsconfig.json           # TypeScript compilation presets
├── vite.config.ts          # Vite asset bundling and compiler options
├── server.ts               # Custom Express server, endpoints & Vite middlewares
├── .env.example            # Environment variables placeholder
├── src/
│   ├── App.tsx             # Main React Single-View dashboard and user interface
│   ├── main.tsx            # React application startup entry point
│   ├── index.css           # Global Tailwind CSS directives & theme configurations
│   └── types.ts            # Core TypeScript model types and interfaces
```

---

## Installation

To set up and run KepokScan locally, ensure you have Node.js (v18+) installed.

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/kepokscan.git
   cd kepokscan
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Start the Development Server**:
   ```bash
   npm run dev
   ```

---

## Optional AI Security Audit Integration

KepokScan is fully functional **offline** and does not require an API key for any of its core features (including header scanning, compliance analysis, exposure detection, and PDF generation).

To optionally enable the **AI Security Audit** (powered by Gemini Pro):

1. **Create a local environment configuration file**:
   ```bash
   cp .env.example .env
   ```

2. **Configure your Gemini API key**:
   Open `.env` and assign your key:
   ```env
   GEMINI_API_KEY=your_gemini_api_key_here
   ```

3. Restart your dev server to load the new environment variables.

---

## Usage

1. Open your browser and navigate to `http://localhost:3000`.
2. Input a target hostname or full URL (e.g., `https://github.com`) into the main scan input field.
3. Click **INSPECT TARGET** to start the evaluation.
4. Explore the scanning modules via the top navigation tabs:
   - **Dashboard**: High-level letter grades, ASCII compliance progress, and active alert streams.
   - **Header Matrix**: Deep dive into individual headers and select any item to load its corresponding risk description and Nginx/Express deployment snippets.
   - **Exposures**: Check directory configuration leaks, directory listing, administrative interfaces, and robots.txt alignment.
   - **AI Audit**: Initiate the Gemini model to build customized threat landscapes and remediation plans.
   - **Raw Dump**: View the pristine HTTP response header key-value stream.
   - **JSON Stream**: Export the compliance dataset.
5. Click **Download PDF Report** to compile a complete multi-page, executive-ready PDF report.

---

## Future Improvements

- **SSL/TLS Cipher Suite Evaluation**: Query host cipher negotiation protocols to detect expired certificates and weak key handshakes.
- **Custom Header Profiles**: Define tailored compliance scoring rules for specific institutional baselines (PCI-DSS, HIPAA, etc.).
- **Automated Cron Scanner**: Schedule background audits and trigger slack/webhook notifications upon compliance degradation.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
