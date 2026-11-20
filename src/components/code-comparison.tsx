export function CodeComparison({ before, after }: { before: string; after: string }) {
  return <div className="code-comparison">
    <div className="comparison-pane comparison-before"><div className="comparison-heading"><span className="comparison-indicator" />Before <small>Illustrative</small></div><pre><code>{before}</code></pre></div>
    <div className="comparison-pane comparison-after"><div className="comparison-heading"><span className="comparison-indicator" />Safer pattern <small>Illustrative</small></div><pre><code>{after}</code></pre></div>
  </div>;
}