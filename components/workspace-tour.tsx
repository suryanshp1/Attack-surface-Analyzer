"use client";

import { useEffect, useRef, useState } from "react";
import { ArrowRight, ChevronLeft, Compass, X } from "lucide-react";
import { updateWorkspaceRoute, type Page } from "@/lib/workspace-route";

const preferenceKey = "surfacer:workspace-tour:v1";
const steps: { page: Page; title: string; description: string; tip: string }[] = [
  {
    page: "Overview",
    title: "Your surface starts here",
    description: "Overview brings your discovered assets, open findings, and recent changes together. Use Target scope above the page to focus views and exports on one domain.",
    tip: "An empty workspace is ready for a target. It does not mean an assessment has been completed.",
  },
  {
    page: "Targets",
    title: "Define your authorized scope",
    description: "Targets are the root domains you are authorized to assess. Owners can add domains and manage their scan schedules. DNS ownership verification follows your deployment policy.",
    tip: "Only scan domains you are authorized to test. Viewer access is read-only; ask an owner to manage targets.",
  },
  {
    page: "Scan activity",
    title: "Follow the assessment",
    description: "Owners and analysts can start scans for ready targets. Scan activity shows stages, collected observations, and why a run was partial, blocked, failed, or canceled.",
    tip: "Completed stages are not a percentage of asset coverage. Review unfinished checks before drawing conclusions.",
  },
  {
    page: "Inventory",
    title: "Meet your public assets",
    description: "Inventory lists discovered hosts, services, ports, and technologies. Select an asset to inspect its observations and related findings. Search and filters help narrow the list.",
    tip: "No HTTP response does not establish that a host is safe or absent. Check the probe status and scan coverage.",
  },
  {
    page: "Endpoints",
    title: "Explore the application surface",
    description: "Endpoints brings discovered pages, APIs, forms, and JavaScript into one view. Review methods, parameters, and sources to understand what a crawl observed.",
    tip: "Historical URLs are unverified references. They are not proof that a service is currently live.",
  },
  {
    page: "Findings",
    title: "Turn evidence into action",
    description: "Open a finding to review its evidence and remediation. Owners and analysts can triage findings and add notes. Takeovers, Governance, and Hazards provide focused assessment views.",
    tip: "Partial scans retain unchecked history. A missing detection alone does not resolve a finding.",
  },
  {
    page: "Changes",
    title: "Keep track of what changed",
    description: "Changes records observations across your surface so you can review newly discovered assets and exposures alongside earlier activity. The notification bell also shows recent changes.",
    tip: "Use the same target scope when comparing views. Your filters and selected details are kept in the page URL.",
  },
  {
    page: "Settings",
    title: "Make the workspace yours",
    description: "Settings contains workspace controls available to your role. Use the appearance control in the top bar to choose light, dark, or system appearance.",
    tip: "You’re ready to explore. Replay this tour anytime using the compass in the top bar or Take a guided tour in Help & documentation.",
  },
];

function rememberInvitation() {
  try {
    localStorage.setItem(preferenceKey, "seen");
  } catch {
    // The tour remains usable when browser storage is unavailable.
  }
}

export function WorkspaceTour({ open, onStart, onClose }: {
  open: boolean;
  onStart: () => void;
  onClose: () => void;
}) {
  const [invitation, setInvitation] = useState(false);
  useEffect(() => {
    try {
      setInvitation(localStorage.getItem(preferenceKey) !== "seen");
    } catch {
      setInvitation(true);
    }
  }, []);
  const dismiss = () => {
    rememberInvitation();
    setInvitation(false);
  };
  return (
    <>
      {invitation && !open && (
        <section className="tour-invitation" aria-label="Welcome to Surfacer">
          <Compass size={24} aria-hidden="true" />
          <div>
            <strong>A little guidance. A clearer view.</strong>
            <p>Get to know your workspace with a short guided tour.</p>
          </div>
          <button className="button button-primary" onClick={() => { dismiss(); onStart(); }}>
            Start tour <ArrowRight size={16} aria-hidden="true" />
          </button>
          <button className="text-action" onClick={dismiss}>Not now</button>
        </section>
      )}
      {open && <TourDialog onClose={onClose} onSeen={dismiss} />}
    </>
  );
}

function TourDialog({ onClose, onSeen }: { onClose: () => void; onSeen: () => void }) {
  const [index, setIndex] = useState(0);
  const dialog = useRef<HTMLDialogElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const step = steps[index];
  // Keep callbacks current without reopening the dialog on workspace refreshes.
  const callbacks = useRef({ onClose, onSeen });
  callbacks.current = { onClose, onSeen };

  useEffect(() => {
    const originalURL = window.location.href;
    const originalState = window.history.state;
    const originalScroll = window.scrollY;
    const originalFocus = document.activeElement as HTMLElement | null;
    const originalOverflow = document.body.style.overflow;
    let navigatedAway = false;
    const leave = () => {
      navigatedAway = true;
      callbacks.current.onClose();
    };
    callbacks.current.onSeen();
    dialog.current?.showModal();
    document.body.style.overflow = "hidden";
    window.addEventListener("popstate", leave);
    window.addEventListener("hashchange", leave);
    return () => {
      window.removeEventListener("popstate", leave);
      window.removeEventListener("hashchange", leave);
      document.body.style.overflow = originalOverflow;
      if (!navigatedAway) {
        // Tour steps replace one history entry; restore its exact filters and scroll.
        window.history.replaceState(originalState, "", originalURL);
        window.dispatchEvent(new Event("surfacer:navigation"));
        window.scrollTo(0, originalScroll);
      }
      const returnFocus = originalFocus?.isConnected && originalFocus !== document.body
        ? originalFocus
        : document.getElementById("workspace-tour-launcher");
      returnFocus?.focus({ preventScroll: true });
    };
  }, []);

  useEffect(() => {
    updateWorkspaceRoute({ page: step.page, query: "", detail: null, filters: {} }, true);
    heading.current?.focus({ preventScroll: true });
  }, [step]);

  return (
    <dialog ref={dialog} className="workspace-tour" aria-labelledby="tour-title" aria-describedby="tour-description"
      onCancel={(event) => { event.preventDefault(); onClose(); }}
      onKeyDown={(event) => {
        if (event.key !== "Tab") return;
        const buttons = Array.from(event.currentTarget.querySelectorAll<HTMLButtonElement>("button:not(:disabled)"));
        const first = buttons[0], last = buttons[buttons.length - 1];
        if (event.shiftKey && (document.activeElement === first || document.activeElement === heading.current)) {
          event.preventDefault();
          last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first?.focus();
        }
      }}>
      <div className="tour-heading">
        <span><Compass size={17} aria-hidden="true" /> Workspace tour</span>
        <button className="icon-button" aria-label="Close tour" onClick={onClose}><X size={20} /></button>
      </div>
      <div className="tour-progress" aria-hidden="true">
        {steps.map((item, position) => <span key={item.page} className={position <= index ? "tour-progress-active" : ""} />)}
      </div>
      <p className="tour-location">Step {index + 1} of {steps.length} · {step.page}</p>
      <h2 id="tour-title" ref={heading} tabIndex={-1}>{step.title}</h2>
      <p id="tour-description">{step.description}</p>
      <p className="tour-tip">{step.tip}</p>
      <div className="tour-actions">
        <button className="text-action" onClick={onClose}>Skip tour</button>
        <div>
          <button className="button button-secondary" disabled={index === 0} onClick={() => setIndex(index - 1)}>
            <ChevronLeft size={16} aria-hidden="true" /> Back
          </button>
          <button className="button button-primary" onClick={() => index === steps.length - 1 ? onClose() : setIndex(index + 1)}>
            {index === steps.length - 1 ? "Finish tour" : "Next"} <ArrowRight size={16} aria-hidden="true" />
          </button>
        </div>
      </div>
    </dialog>
  );
}
