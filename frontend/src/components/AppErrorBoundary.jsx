import React from "react";
import { ShieldWarning, ArrowClockwise } from "@phosphor-icons/react";
import { Panel, Btn } from "./ui";

export default class AppErrorBoundary extends React.Component {
  constructor(p) {
    super(p);
    this.state = { err: null };
  }
  static getDerivedStateFromError(err) {
    return { err };
  }
  componentDidCatch(err, info) {
    console.error("[8pi] AppErrorBoundary caught:", err, info?.componentStack);
  }
  render() {
    if (!this.state.err) return this.props.children;
    return (
      <div className="min-h-screen bg-panel flex items-center justify-center p-6" data-testid="app-error">
        <Panel className="max-w-xl w-full p-10 text-center">
          <ShieldWarning size={56} weight="thin" className="mx-auto text-kill mb-5" />
          <div className="h-font text-2xl uppercase tracking-tight text-white mb-2">
            Something went wrong
          </div>
          <p className="text-sm text-muted mb-4">
            The console hit an unexpected error. Reload to resume the engagement.
          </p>
          <pre className="mono text-[11px] text-muted bg-black border border-line p-3 mb-5 text-left overflow-auto max-h-40">
            {String(this.state.err?.message || this.state.err)}
          </pre>
          <Btn
            icon={ArrowClockwise}
            onClick={() => window.location.reload()}
            data-testid="app-error-reload-btn"
          >
            Reload Console
          </Btn>
        </Panel>
      </div>
    );
  }
}
