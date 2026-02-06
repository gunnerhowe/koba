import type { Metadata } from 'next';
import './globals.css';
import { Providers } from './providers';

export const metadata: Metadata = {
  title: 'Koba - AI Governance Platform',
  description: 'Cryptographic AI governance — protection for you, not from your AI',
  openGraph: {
    title: 'Koba - AI Governance Platform',
    description: 'Independent, cryptographic governance for AI agents. Every action verified, every decision auditable.',
    type: 'website',
    siteName: 'Koba',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Koba - AI Governance Platform',
    description: 'Independent, cryptographic governance for AI agents.',
  },
  icons: {
    icon: '/favicon.ico',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-koba-bg text-koba-text min-h-screen">
        <Providers>
          {children}
        </Providers>
      </body>
    </html>
  );
}
