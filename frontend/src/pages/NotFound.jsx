import React from "react";
import { Link } from "react-router-dom";
import { Compass, House } from "@phosphor-icons/react";
import { Panel, Btn } from "../components/ui";

export default function NotFound() {
  return (
    <div className="max-w-2xl mx-auto py-24 px-6" data-testid="not-found-page">
      <Panel className="p-10 text-center">
        <Compass size={56} weight="thin" className="mx-auto text-neutral mb-5" />
        <div className="h-font text-5xl font-black text-white mb-2">404</div>
        <div className="h-font text-lg uppercase tracking-tight text-sub mb-3">Route Off-Scope</div>
        <p className="text-sm text-muted max-w-md mx-auto mb-6">
          The page you requested is not part of the current 8pi engagement. Return to Operations to
          continue.
        </p>
        <Link to="/">
          <Btn icon={House} data-testid="not-found-home-btn">Back to Dashboard</Btn>
        </Link>
      </Panel>
    </div>
  );
}
