'use client';

import { useState } from 'react';
import HelpDrawer from './HelpDrawer';
import { HelpContent } from '@/lib/helpContent';

interface HelpButtonProps {
  content: HelpContent;
}

export default function HelpButton({ content }: HelpButtonProps) {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <>
      <button
        onClick={() => setIsOpen(true)}
        className="w-8 h-8 rounded-full bg-koba-accent/15 border border-koba-accent/30 text-koba-accent hover:bg-koba-accent hover:text-white flex items-center justify-center transition-all duration-200 hover:shadow-glow-sm focus:outline-none focus:ring-2 focus:ring-koba-accent/50"
        aria-label={`Help: ${content.title}`}
        title="What is this page?"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01" />
        </svg>
      </button>

      <HelpDrawer
        isOpen={isOpen}
        onClose={() => setIsOpen(false)}
        content={content}
      />
    </>
  );
}
