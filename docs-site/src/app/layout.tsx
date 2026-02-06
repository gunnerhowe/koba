import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

export const metadata: Metadata = {
  title: "Koba - Independent AI Oversight Infrastructure",
  description:
    "Cryptographic containment and independent third-party governance for AI agents. Default-deny policy engine, signed action receipts, Merkle transparency logs, sandbox execution, and anomaly detection.",
  openGraph: {
    title: "Koba - Independent AI Oversight Infrastructure",
    description:
      "Cryptographic containment for current AI, AGI, and ASI. Third-party governance infrastructure with signed receipts, policy enforcement, and transparency logs.",
    type: "website",
    url: "https://github.com/gunnerhowe/koba",
    siteName: "Koba",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark scroll-smooth">
      <body
        className={`${inter.variable} font-sans bg-gray-950 text-white antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
