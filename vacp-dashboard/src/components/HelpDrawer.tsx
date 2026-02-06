'use client';

import { useEffect, useRef } from 'react';
import { HelpContent } from '@/lib/helpContent';

interface HelpDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  content: HelpContent;
}

export default function HelpDrawer({ isOpen, onClose, content }: HelpDrawerProps) {
  const drawerRef = useRef<HTMLDivElement>(null);
  const closeBtnRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (isOpen) {
      closeBtnRef.current?.focus();
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isOpen, onClose]);

  useEffect(() => {
    if (!isOpen || !drawerRef.current) return;
    const drawer = drawerRef.current;
    const focusableEls = drawer.querySelectorAll<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    const firstEl = focusableEls[0];
    const lastEl = focusableEls[focusableEls.length - 1];

    const handleTab = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return;
      if (e.shiftKey) {
        if (document.activeElement === firstEl) {
          lastEl?.focus();
          e.preventDefault();
        }
      } else {
        if (document.activeElement === lastEl) {
          firstEl?.focus();
          e.preventDefault();
        }
      }
    };

    drawer.addEventListener('keydown', handleTab);
    return () => drawer.removeEventListener('keydown', handleTab);
  }, [isOpen]);

  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => { document.body.style.overflow = ''; };
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50" aria-modal="true" role="dialog" aria-labelledby="help-title">
      {/* Overlay */}
      <div
        className="fixed inset-0 bg-black/40 backdrop-blur-sm transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer panel */}
      <div
        ref={drawerRef}
        className="fixed inset-y-0 right-0 w-full max-w-md bg-koba-bg-secondary border-l border-koba-border shadow-xl animate-slide-in-right overflow-y-auto"
      >
        {/* Header */}
        <div className="sticky top-0 bg-koba-bg-secondary/95 backdrop-blur-sm border-b border-koba-border p-6 flex items-start justify-between gap-4 z-10">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-koba-accent/20 flex items-center justify-center flex-shrink-0">
              <svg className="w-5 h-5 text-koba-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01" />
              </svg>
            </div>
            <div>
              <h2 id="help-title" className="text-lg font-semibold text-koba-text">
                {content.title}
              </h2>
              <p className="text-koba-text-muted text-sm">Page Help</p>
            </div>
          </div>
          <button
            ref={closeBtnRef}
            onClick={onClose}
            className="p-2 -mr-2 text-koba-text-secondary hover:text-koba-text hover:bg-koba-bg-elevated rounded-lg transition-colors"
            aria-label="Close help"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* What is this page? */}
          <div>
            <h3 className="text-sm font-semibold text-koba-text-muted uppercase tracking-wider mb-3">
              What is this page?
            </h3>
            <p className="text-koba-text leading-relaxed">
              {content.description}
            </p>
          </div>

          {/* Real-world analogy */}
          {content.analogy && (
            <div className="p-4 bg-koba-accent/10 border border-koba-accent/20 rounded-xl">
              <div className="flex items-start gap-3">
                <span className="text-lg flex-shrink-0 mt-0.5">{content.analogyIcon}</span>
                <div>
                  <p className="text-koba-text text-sm font-medium mb-1">Think of it like...</p>
                  <p className="text-koba-text-secondary text-sm leading-relaxed">{content.analogy}</p>
                </div>
              </div>
            </div>
          )}

          {/* How to use */}
          <div>
            <h3 className="text-sm font-semibold text-koba-text-muted uppercase tracking-wider mb-3">
              How to use this page
            </h3>
            <ol className="space-y-3">
              {content.steps.map((step, i) => (
                <li key={i} className="flex gap-3">
                  <div className="w-7 h-7 rounded-full bg-koba-accent/15 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <span className="text-koba-accent text-sm font-bold">{i + 1}</span>
                  </div>
                  <p className="text-koba-text-secondary text-sm leading-relaxed pt-1">{step}</p>
                </li>
              ))}
            </ol>
          </div>

          {/* Tips */}
          {content.tips && content.tips.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-koba-text-muted uppercase tracking-wider mb-3">
                Good to know
              </h3>
              <ul className="space-y-2">
                {content.tips.map((tip, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-koba-text-secondary">
                    <svg className="w-4 h-4 text-koba-success flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    <span className="leading-relaxed">{tip}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Footer */}
          <div className="pt-4 border-t border-koba-border">
            <p className="text-koba-text-muted text-sm">
              Still have questions? Contact your administrator for help.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
