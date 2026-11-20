import Link from "next/link";
import {
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Check,
  ChevronRight,
  CircleDot,
  Code2,
  FileCode2,
  GitBranch,
  LockKeyhole,
  ScanEye,
  ShieldCheck,
  ShieldEllipsis,
  Sparkles,
  TerminalSquare,
} from "lucide-react";

export default function Home() {
  return (
    <main className="landing-page">
      <header className="landing-header">
        <Link className="brand-lockup" href="/" aria-label="ARGUS home">
          <span className="brand-symbol"><ScanEye size={21} strokeWidth={1.8} /></span>
          <span>ARGUS<span className="brand-period">.</span></span>
        </Link>
        <nav className="landing-nav" aria-label="Main navigation">
          <a href="#workflow">Workflow</a>
          <a href="#features">Platform</a>
          <a href="#why-argus">Why ARGUS</a>
          <a href="#scanners">Scanners</a>
        </nav>
        <Link className="header-login" href="/dashboard">Open workspace <ArrowUpRight size={15} /></Link>
      </header>

      <section className="hero-section">
        <div className="hero-copy">
          <div className="eyebrow"><span className="live-dot" /> SECURITY REVIEW, WITH A SECOND LOOK</div>
          <h1>See what<br />AI code <span>hides.</span></h1>
          <p className="hero-description">Find the quiet risks in code before they make it to production. Then verify the fix, not just the promise.</p>
          <div className="hero-actions">
            <Link className="button button-primary" href="/upload">Start scanning <ArrowRight size={17} /></Link>
            <a className="button button-quiet" href="#workflow">Explore the workflow <ArrowDownRight size={16} /></a>
          </div>
          <div className="hero-note"><LockKeyhole size={14} /> Your code is inspected, never executed.</div>
        </div>

        <div className="hero-visual" aria-label="Illustrative ARGUS finding preview">
          <div className="preview-glow" />
          <div className="preview-window">
            <div className="preview-topbar">
              <div className="window-controls"><i /><i /><i /></div>
              <span className="preview-path"><GitBranch size={13} /> api / auth.py</span>
              <span className="preview-state"><CircleDot size={11} /> SAMPLE</span>
            </div>
            <div className="preview-content">
              <div className="code-pane" aria-hidden="true">
                <div className="code-line"><span className="line-no">18</span><span><b>def</b> <em>authenticate</em>(token):</span></div>
                <div className="code-line"><span className="line-no">19</span><span className="code-indent">user = decode_token(token)</span></div>
                <div className="code-line code-highlight"><span className="line-no">20</span><span className="code-indent"><strong>except</strong> Exception <strong>as</strong> err:</span></div>
                <div className="code-line"><span className="line-no">21</span><span className="code-indent code-muted"># broad exception hides failure</span></div>
                <div className="code-line"><span className="line-no">22</span><span className="code-indent"><b>return</b> None</span></div>
                <div className="code-line code-gap"><span className="line-no">23</span><span /></div>
                <div className="code-line"><span className="line-no">24</span><span><b>def</b> <em>require_role</em>(role):</span></div>
                <div className="code-line"><span className="line-no">25</span><span className="code-indent">...</span></div>
              </div>
              <aside className="finding-preview">
                <div className="finding-icon"><ShieldEllipsis size={18} /></div>
                <div className="finding-kicker">SAMPLE FINDING <span>HIGH</span></div>
                <h3>Overly broad exception</h3>
                <p>Errors may be hidden, making unexpected failures harder to detect.</p>
                <div className="finding-file"><FileCode2 size={13} /> auth.py <span>20</span></div>
                <div className="finding-divider" />
                <div className="finding-next"><span className="tiny-check"><Check size={11} /></span> Fix recommendation available</div>
              </aside>
            </div>
            <div className="preview-footer"><span><span className="footer-pulse" /> Illustrative preview · not a live scan</span><span>Python <ChevronRight size={12} /> Static analysis</span></div>
          </div>
          <div className="floating-note"><div className="floating-icon"><ShieldCheck size={17} /></div><div><b>Then scan again.</b><span>Verify every change.</span></div></div>
        </div>
        <div className="hero-index">01 <span /> 04</div>
      </section>

      <section className="trust-strip" aria-label="Security tools">
        <span>BUILT AROUND OPEN-SOURCE SCANNERS</span>
        <div><i className="tool-mark semgrep-mark">S</i> Semgrep</div>
        <div><i className="tool-mark bandit-mark">B</i> Bandit</div>
        <div><i className="tool-mark git-mark"><GitBranch size={13} /></i> Gitleaks</div>
        <div><i className="tool-mark audit-mark"><ShieldCheck size={13} /></i> pip-audit</div>
      </section>

      <section className="section workflow-section" id="workflow">
        <div className="section-heading">
          <div><div className="eyebrow">A BETTER SECURITY LOOP</div><h2>One finding.<br /><span>A verified outcome.</span></h2></div>
          <p>ARGUS connects discovery to proof. Every step is designed to help developers understand what matters and confirm what changed.</p>
        </div>
        <div className="workflow-rail">
          {[
            { number: "01", title: "Upload", text: "Submit a Python project archive for inspection.", icon: <Code2 size={19} /> },
            { number: "02", title: "Detect", text: "Run established scanners against source and dependencies.", icon: <ScanEye size={19} /> },
            { number: "03", title: "Understand", text: "See the impact, location, and a practical next step.", icon: <Sparkles size={19} /> },
            { number: "04", title: "Verify", text: "Rescan and compare before calling a fix resolved.", icon: <ShieldCheck size={19} /> },
          ].map((step) => (
            <article className="workflow-step" key={step.number}>
              <div className="step-marker"><span>{step.icon}</span><small>{step.number}</small></div>
              <h3>{step.title}</h3><p>{step.text}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="section platform-section" id="features">
        <div className="platform-heading"><div className="eyebrow">BUILT FOR THE MOMENT AFTER THE ALERT</div><h2>Security feedback<br />developers can <span>act on.</span></h2></div>
        <div className="feature-grid">
          <article className="feature feature-wide">
            <div className="feature-art scan-art"><span className="scan-grid" /><span className="scan-ring"><ScanEye size={35} /></span><span className="scan-beam" /><b className="scan-label">INSPECTING SOURCE</b></div>
            <div className="feature-body"><span className="feature-number">01 / FIND</span><h3>One view across your scanners.</h3><p>Bring code patterns, exposed secrets, and vulnerable dependencies into a reviewable project context.</p></div>
          </article>
          <article className="feature">
            <div className="feature-art explain-art"><div className="explain-line"><span>Risk</span><b>What can happen</b></div><div className="explain-line"><span>Context</span><b>Where it occurs</b></div><div className="explain-line"><span>Next</span><b>How to improve it</b></div></div>
            <div className="feature-body"><span className="feature-number">02 / UNDERSTAND</span><h3>Context before code changes.</h3><p>Make findings clearer with affected lines, security impact, and remediation guidance.</p></div>
          </article>
          <article className="feature">
            <div className="feature-art verify-art"><div className="verify-flow"><span className="verify-node"><Check size={14} /></span><i /><span className="verify-node verify-node-active"><ScanEye size={15} /></span><i /><span className="verify-node verify-node-pending"><CircleDot size={14} /></span></div><div className="verify-captions"><span>Review</span><span>Rescan</span><span>Confirm</span></div><div className="verify-caption-status">Verification awaits a real follow-up scan</div></div>
            <div className="feature-body"><span className="feature-number">03 / VERIFY</span><h3>Evidence over assumptions.</h3><p>A recommendation is not a resolution. Confirm the original issue is gone and check for regressions.</p></div>
          </article>
        </div>
      </section>

      <section className="section scanner-section" id="scanners">
        <div className="scanner-copy"><div className="eyebrow">A TOOLCHAIN, NOT A BLACK BOX</div><h2>Known tools.<br /><span>Clear ownership.</span></h2><p>ARGUS is being prepared to orchestrate focused, open-source scanners. Their findings remain attributable to the scanner and rule that produced them.</p><Link className="text-link" href="/dashboard">Explore the workspace <ArrowRight size={15} /></Link></div>
        <div className="scanner-list">
          <div><span className="scanner-icon scanner-semgrep">S</span><b>Semgrep</b><span>Static analysis</span><ArrowUpRight size={15} /></div>
          <div><span className="scanner-icon scanner-bandit">B</span><b>Bandit</b><span>Python security linting</span><ArrowUpRight size={15} /></div>
          <div><span className="scanner-icon scanner-gitleaks"><GitBranch size={15} /></span><b>Gitleaks</b><span>Secret detection</span><ArrowUpRight size={15} /></div>
          <div><span className="scanner-icon scanner-audit"><ShieldCheck size={15} /></span><b>pip-audit</b><span>Dependency auditing</span><ArrowUpRight size={15} /></div>
          <div className="scanner-footnote"><TerminalSquare size={14} /> Scanner integrations are not connected in this preview.</div>
        </div>
      </section>

      <section className="section why-section" id="why-argus">
        <div className="eyebrow">WHY ARGUS</div>
        <div className="why-grid">
          <h2>Clear findings.<br /><span>Honest outcomes.</span></h2>
          <article><span>01</span><h3>Explain the context</h3><p>Give developers the location, scanner rule, and impact needed to assess a finding in their own codebase.</p></article>
          <article><span>02</span><h3>Keep the human in charge</h3><p>Recommendations are reviewed by the developer. Suggested code is never applied silently.</p></article>
          <article><span>03</span><h3>Verify before closing</h3><p>Only a follow-up scan can confirm whether an issue was resolved and whether new findings appeared.</p></article>
        </div>
      </section>

      <section className="closing-section">
        <div className="closing-orbit"><span /><span /><ShieldCheck size={25} /></div>
        <div><div className="eyebrow">MAKE THE SECOND LOOK COUNT</div><h2>Ship with a little<br />more <span>certainty.</span></h2><p>Start in the workspace. Scanning becomes available when the backend is connected.</p></div>
        <Link className="button button-primary" href="/upload">Open ARGUS <ArrowRight size={17} /></Link>
      </section>

      <footer className="landing-footer">
        <Link className="brand-lockup" href="/" aria-label="ARGUS home"><span className="brand-symbol"><ScanEye size={19} strokeWidth={1.8} /></span><span>ARGUS<span className="brand-period">.</span></span></Link>
        <p>See What AI Code Hides.</p>
        <span>Open-source scanners. Human-reviewed fixes. Verified outcomes.</span>
        <small>© 2026 ARGUS · Development preview</small>
      </footer>
    </main>
  );
}
